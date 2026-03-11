use aws_sdk_s3::error::ProvideErrorMetadata;
use axum::{Extension, Json, Router, extract::State, middleware::from_fn_with_state, routing::get};
use axum_extra::extract::CookieJar;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Claims, DeleteJob, RustFSError, TokenPayload, UserProfile,
    delete_account_db, delete_user_bucket, extract_refresh_token, fetch_profile_info,
    get_redis_con, revoke_refresh_token, send_delete_jobs_to_worker, update_account_username,
    validate_jwt_access_token,
};
use tracing::{error, info, instrument};
//------------------------------------user management-------

pub fn user_management(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route(
            "/api/users/me",
            get(user_profile)
                .patch(update_user_username)
                .delete(delete_account),
        )
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
}
#[instrument(skip_all,fields(
    user_id=%claims.sub
))]
async fn user_profile(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
) -> Result<Json<UserProfile>, ApiError> {
    let user_info = fetch_profile_info(&appstate.db_pool, claims.sub)
        .await
        .inspect_err(|e| error!("failed to obtain user profile info: {e}"))?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(user_info))
}
#[instrument(skip_all,err,fields(
    user_id=%claims.sub,
    new_username=username.user_name,

))]
async fn update_user_username(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(mut username): Json<UpdateUserNameOps>,
) -> Result<Json<UpdateUserNameOps>, ApiError> {
    if username.user_name.len() > 50 {
        return Err(ApiError::BadRequest(anyhow::anyhow!(
            "username is longer than 50 chars: {}",
            username.user_name
        )));
    }
    let db_result = update_account_username(&appstate.db_pool, claims.sub, &username.user_name)
        .await
        .inspect_err(|e| error!("failed to update username: {e}"))?;
    username.user_name = db_result;
    Ok(Json(username))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserNameOps {
    pub user_name: String,
}

#[instrument(skip_all,fields(
    user_id=%claims.sub,
))]
async fn delete_account(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    cookie_jar: CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<(), ApiError> {
    info!("performing delete account operation.");
    let hmac_sec = appstate.settings.secrets.hmac.expose_secret();
    info!("extracting refresh token from body or cookies.");
    let refresh_token = extract_refresh_token(&cookie_jar, body)?;
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    info!("deleting refresh token from redis.");
    info!("deleting account and retreiving all files ids.");
    let f_ids: Vec<_> = delete_account_db(&appstate.db_pool, claims.sub)
        .await?
        .into_iter()
        .map(|v| DeleteJob {
            f_id: v,
            bucket: claims.sub,
            account_deletion: true,
        })
        .collect();
    if f_ids.is_empty() {
        info!("user has no files.");
        let delete_result = delete_user_bucket(&appstate.rustfs_con, claims.sub).await;
        if let Err(e) = delete_result
            && ![Some("BucketNotEmpty"), Some("NoSuchBucket")].contains(&e.code())
        {
            return Err(RustFSError::Delete(e.into()))?;
        }
    } else {
        info!("sending delete jobs with account_deletion=true.");
        send_delete_jobs_to_worker(f_ids).await?;
    }
    revoke_refresh_token(hmac_sec, refresh_token.expose_secret(), &mut redis_con).await?;
    info!("delete account success.");
    Ok(())
}
