use axum::{Extension, Json, Router, extract::State, middleware::from_fn_with_state, routing::get};
use secrecy::SecretString;
use tracing::instrument;

use crate::{
    ApiError, AppState, Claims, UserStorageInfo, get_user_available_storage,
    validate_jwt_access_token,
};

//---------------------------------------storage usage information -------------------

pub fn storage_status(hmac: SecretString) -> Router<AppState> {
    Router::new()
        .route("/api/storage/usage", get(fetch_storage_info))
        .layer(from_fn_with_state(hmac, validate_jwt_access_token))
}

#[instrument(skip_all, fields(
    user_id=%claims.sub
))]
async fn fetch_storage_info(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
) -> Result<Json<UserStorageInfo>, ApiError> {
    let s = get_user_available_storage(&appstate.db_pool, claims.sub).await?;
    Ok(Json(s))
}
