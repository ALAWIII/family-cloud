use axum::{Extension, Json, Router, extract::State, middleware::from_fn_with_state, routing::get};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{
    ApiError, AppState, Claims, UserProfile, fetch_profile_info, update_account_username,
    validate_jwt_access_token,
};
use tracing::{error, instrument};
//------------------------------------user management-------

pub fn user_management(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route(
            "/api/users/me",
            get(user_profile).patch(update_user_username),
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
