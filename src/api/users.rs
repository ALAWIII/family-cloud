use aws_sdk_s3::error::ProvideErrorMetadata;
use axum::{Extension, Json, extract::State};
use axum_extra::extract::CookieJar;
use secrecy::ExposeSecret;

use crate::{
    ApiError, AppState, Claims, DeleteJob, RustFSError, TokenPayload, UpdateUserNameOps,
    UserProfile, UserStorageInfo, delete_account_db, delete_user_bucket, extract_refresh_token,
    fetch_profile_info, get_redis_con, get_user_available_storage, revoke_refresh_token,
    send_delete_jobs_to_worker, update_account_username,
};
use tracing::{info, instrument};
//------------------------------------user management-------

/// Returns the authenticated user’s profile information by:
/// 1. Looking up the user by id from `Claims` in Postgres via
///    `fetch_profile_info`.
/// 2. Failing with `NotFound` if the account no longer exists, otherwise
///    returning a `UserProfile` as JSON.
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

/// Updates the authenticated user’s username by:
/// 1. Validating the new username length (max 50 characters) and rejecting
///    invalid values as bad requests.
/// 2. Calling `update_account_username` in Postgres with the user id and
///    new name, using the DB‑returned value to normalize the username
///    (e.g., case or trimming).
/// 3. Returning the updated `UpdateUserNameOps` payload as JSON.
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

/// Permanently deletes a user account, its data, and associated refresh
/// token by:
/// 1. Extracting the refresh token from cookies/body
///    (`extract_refresh_token`) and opening a Redis connection.
/// 2. Deleting the user account and collecting all owned file ids from
///    Postgres via `delete_account_db`, mapping them into `DeleteJob`s
///    flagged as `account_deletion = true`.
/// 3. If no files exist, attempting to delete the user’s storage bucket
///    (`delete_user_bucket`), tolerating `BucketNotEmpty` and
///    `NoSuchBucket` errors only.
/// 4. If files exist, sending all `DeleteJob`s to the delete worker
///    (`send_delete_jobs_to_worker`) to asynchronously remove objects from
///    storage.
/// 5. Finally revoking the refresh token in Redis (`revoke_refresh_token`)
///    so the user cannot reauthenticate, and returning success.
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

/// Fetches the authenticated user’s storage usage and quota by:
/// 1. Querying Postgres via `get_user_available_storage` using the user id
///    from `Claims`.
/// 2. Returning a `UserStorageInfo` JSON payload that reports used bytes and
///    total quota for client‑side display and checks.
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
