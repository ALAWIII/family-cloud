use aws_sdk_s3::error::ProvideErrorMetadata;
use axum::{Extension, Json, extract::State};
use axum_extra::extract::CookieJar;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Claims, DeleteJob, RustFSError, TokenPayload, UserProfile, UserStorageInfo,
    delete_account_db, delete_user_bucket, extract_refresh_token, fetch_profile_info,
    get_redis_con, get_user_available_storage, revoke_refresh_token, send_delete_jobs_to_worker,
    update_account_username,
};
use tracing::{info, instrument};
//------------------------------------user management-------

#[instrument(skip_all,fields(
    user_id=%claims.sub
))]
pub(super) async fn user_profile(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
) -> Result<Json<UserProfile>, ApiError> {
    let user_info = fetch_profile_info(&appstate.db_pool, claims.sub)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(user_info))
}
#[instrument(skip_all,err,fields(
    user_id=%claims.sub,
    new_username=username.user_name,

))]
pub(super) async fn update_user_username(
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
    let db_result =
        update_account_username(&appstate.db_pool, claims.sub, &username.user_name).await?;
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
pub(super) async fn delete_account(
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
    info!("deleting account and retreiving all files ids.");
    let f_ids: Vec<_> = delete_account_db(&appstate.db_pool, claims.sub)
        .await?
        .into_iter()
        .map(|id| DeleteJob {
            f_id: id,
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
    info!("deleting refresh token from redis.");
    revoke_refresh_token(hmac_sec, refresh_token.expose_secret(), &mut redis_con).await?;
    info!("delete account success.");
    Ok(())
}

#[instrument(skip_all, fields(
    user_id=%claims.sub
))]
pub(super) async fn fetch_storage_info(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
) -> Result<Json<UserStorageInfo>, ApiError> {
    let s = get_user_available_storage(&appstate.db_pool, claims.sub).await?;
    Ok(Json(s))
}
