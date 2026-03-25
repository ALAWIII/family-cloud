use anyhow::anyhow;
use axum::{
    Extension, Json, debug_handler,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use deadpool_redis::{
    Connection,
    redis::{self, AsyncTypedCommands, ExpireOption},
};

use sqlx::PgPool;
use tracing::{error, info, instrument};
use uuid::Uuid;

use crate::{
    AccessQuery, ApiError, AppState, CRedisError, Claims, FileRecord, FileShared, FileSystemObject,
    FolderRecord, FolderShared, ObjectKind, SharedObjectReq, SharedTokenResponse, TokenType,
    create_redis_key, deserialize_content, fetch_obj_info, get_redis_con, serialize_content,
    validate_object_ancestor,
};

//------------------------------------share objects links ----------------------------
static CHECK_AND_SET: &str = r#"
local token = redis.call('HGET', KEYS[1], KEYS[2])
   if token and token ~= false then
       redis.call('EXPIRE', 'shared:' .. token, ARGV[1])
       redis.call('HEXPIRE', KEYS[1], ARGV[1], 'FIELDS', 1, KEYS[2])
       return token
   else
       return nil
   end
"#;

/// Resolves metadata access via a public share token by:
/// 1. Validating optional access parameters (`AccessQuery::validate`) and
///    loading the root shared object from Redis using the token key,
///    failing with `Forbidden` if missing or unreadable.
/// 2. Deserializing the stored `FileSystemObject` and immediately returning
///    file metadata when the shared object itself is a file.
/// 3. For shared folders, interpreting optional child id + kind parameters
///    and using `validate_object_ancestor` to ensure the requested
///    file/folder is a descendant of the shared root and owned by the same
///    user.
/// 4. Returning the resolved `FolderShared` or `FileShared` metadata as an
///    HTTP response, or `Forbidden` when the requested child is not within
///    the shared subtree.
#[instrument(skip_all,fields(
    token=%token,
    access_params=?access_params
))]
#[debug_handler]
pub async fn access_object(
    State(appstate): State<AppState>,
    Path(token): Path<Uuid>,
    Query(access_params): Query<AccessQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let params = access_params.validate().inspect_err(|e| error!("{e}"))?;
    info!("obtaining redis connection.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let redis_key = create_redis_key(TokenType::Shared, &token.to_string());
    info!("fetching metadata of shared object from redis.");
    let r_obj = redis_con
        .get(redis_key)
        .await
        .map_err(CRedisError::Connection)
        .map(|v| v.ok_or(ApiError::Forbidden))
        .inspect_err(|e| {
            error!("failed to access object information by shared token maybe not found: {e}")
        })??;
    let obj: FileSystemObject = deserialize_content(&r_obj)?;
    if !obj.is_folder() {
        // its a file just return it. because it has the higher priority
        info!("the object requested is the same as stored in redis and is file.");
        return Ok(FileShared::from(obj.get_file().unwrap()).into_response());
    }
    let (f_id, is_folder) = params.unwrap_or((obj.id(), true));
    // the obj is a folder , and we have to check if id is a sub-folder/sub-file of the obj.id
    // when the k_id is a value then it means that the user requests metadata for that file!
    // we have to check recursively up tree if the requested id belongs to one of the folder id of the token !!!
    // recursively check if parent_id = obj.id and owner_id = obj.owner_id
    // if true fetch the information metadata of a given file/folder id with a list of its children if it was a folder.
    let response = if is_folder {
        info!("requested metadata for sub-folder");
        validate_object_ancestor::<FolderShared>(
            &appstate.db_pool,
            obj.owner_id(),
            obj.id(),
            f_id,
            ObjectKind::Folder,
        )
        .await
        .map(|v| {
            v.ok_or(ApiError::Forbidden)
                .inspect_err(|e| error!("access folder is unauthorized: {e}"))
        })?
        .into_response()
    } else {
        info!("requested metadata for sub-file");
        validate_object_ancestor::<FileShared>(
            &appstate.db_pool,
            obj.owner_id(),
            obj.id(),
            f_id,
            ObjectKind::File,
        )
        .await
        .map(|v| {
            v.ok_or(ApiError::Forbidden)
                .inspect_err(|e| error!("access file is unauthorized: {e}"))
        })?
        .into_response()
    };
    info!("fetching metadata success.");
    Ok(response)
}
/// Creates or refreshes a share link token for a user‑owned file or folder by:
/// 1. Validating the requested TTL is positive, rejecting zero or negative
///    values as bad requests.
/// 2. Looking up an existing share token for the given object id in Redis
///    via a Lua script (`CHECK_AND_SET`) that both returns an existing token
///    and extends its TTL when present.
/// 3. When no existing token is found, delegating to `create_share_token` to
///    fetch the object metadata, generate a new token, and store the mapping
///    in Redis.
/// 4. Returning the active token (new or reused) in a `SharedTokenResponse`
///    so clients can construct share URLs.
#[debug_handler]
#[instrument(skip_all,fields(
    user_id=%claims.sub,
    f_info=?f_info,
))]
pub async fn create_link_share(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(f_info): Json<SharedObjectReq>,
) -> Result<Json<SharedTokenResponse>, ApiError> {
    info!("start new generating shared link transaction.");
    if f_info.ttl <= 0 {
        error!("invalid ttl less than or equals 0.");
        return Err(ApiError::BadRequest(anyhow!("invalid ttl equals 0.")));
    }
    // check if user has the token
    // if has the token set new ttl for it.
    // otherwise create new one and add it.
    info!("obtain redis connection.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let user_shares_key = create_redis_key(TokenType::Shared, &claims.sub.to_string());
    info!("parse lua redis script.");
    let script = redis::Script::new(CHECK_AND_SET);
    info!("execute lua script.");
    let existing_token: Option<String> = script
        .key(&user_shares_key)
        .key(f_info.f_id.to_string())
        .arg(f_info.ttl)
        .invoke_async(&mut redis_con)
        .await
        .map_err(CRedisError::Connection)
        .inspect_err(|e| error!("failed to execute share link redis code: {e}"))?;
    let token = match existing_token {
        Some(t) => t,
        _ => {
            info!("token not existed, creating new one.");
            create_share_token(
                f_info,
                &appstate.db_pool,
                claims.sub,
                &user_shares_key,
                redis_con,
            )
            .await
            .inspect_err(|e| error!("failed to create new shared token: {e}"))?
        }
    };
    info!("success creating/updating shared token.");
    Ok(Json(SharedTokenResponse { token }))
}
/// Helper that creates a brand‑new share token and persists its metadata in
/// Redis by:
/// 1. Fetching the target file or folder from Postgres (`fetch_obj_info`)
///    for the given user, returning `NotFound` if it does not exist or is
///    not owned by them.
/// 2. Generating a fresh UUID share token and building the Redis key for
///    that token.
/// 3. Serializing the `FileSystemObject` representation of the target so it
///    can later be used by access and streaming endpoints.
/// 4. Executing an atomic Redis pipeline that:
///    - Stores the token → object mapping with an expiry (`set_ex`).
///    - Records the object id → token mapping in the per‑user hash
///      (`HSET user_shares_key f_id token`).
///    - Applies a TTL to that specific hash field (`HEXPIRE`) so it expires
///      in sync with the token.
/// 5. Returning the token string for use in responses.
async fn create_share_token(
    f_info: SharedObjectReq,
    db_pool: &PgPool,
    user_id: Uuid,
    user_shares_key: &str,
    mut rds_con: Connection,
) -> Result<String, ApiError> {
    let f: FileSystemObject = if f_info.object_kind.is_folder() {
        info!("fetching a folder information.");
        fetch_obj_info::<FolderRecord>(db_pool, f_info.f_id, user_id, crate::ObjectKind::Folder)
            .await?
            .ok_or(ApiError::NotFound)?
            .into()
    } else {
        info!("fetching a file information.");
        fetch_obj_info::<FileRecord>(db_pool, f_info.f_id, user_id, crate::ObjectKind::File)
            .await?
            .ok_or(ApiError::NotFound)?
            .into()
    };
    info!("creating new token.");
    let share_token = Uuid::new_v4();
    let token_str = share_token.to_string();
    let f_id_str = f_info.f_id.to_string();
    let redis_key = create_redis_key(TokenType::Shared, &token_str);
    info!("serialize file/folder content.");
    let serialized = serialize_content(&f)?;
    // shared:user_id
    //      f_id1:token1
    //      f_id2:token2
    info!("storing in redis.");
    let _: () = redis::pipe()
        .atomic()
        .set_ex(&redis_key, &serialized, f_info.ttl as u64)
        .hset(user_shares_key, &f_id_str, &token_str) // used to set the field value.
        .hexpire(
            // used to set the ttl to a given field
            user_shares_key,
            f_info.ttl,
            ExpireOption::NONE,
            &[&f_id_str],
        )
        .query_async(&mut rds_con)
        .await
        .map_err(CRedisError::Connection)?;
    info!("success generating new shared token.");
    Ok(token_str)
}
