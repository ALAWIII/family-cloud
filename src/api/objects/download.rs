use std::net::SocketAddr;

use axum::{
    Extension, Json, debug_handler,
    extract::{ConnectInfo, Path, Query, State},
};
use deadpool_redis::redis::AsyncTypedCommands;

use tracing::{info, instrument};
use uuid::Uuid;

use crate::{
    ApiError, AppState, CRedisError, Claims, DownloadTokenData, FileSystemObject, ObjectKindQuery,
    TokenPayload, TokenType, create_redis_key, fetch_file_info, fetch_folder_info, get_redis_con,
    serialize_content,
};

/// user -> request (object_id) -> server .
///
/// if user cancels download and the connection dies --- server should implement a mechanisim to clean the token from redis and decrement the user counter.
///
/// server -> verifies user identity using JWT access token.
///
/// redis stores key : user_id:download , values : set(active download tokens)
///
/// server -> checks if the user owns the file .
///
/// server -> checks if the user concurrent downloads was exceeded .
///
/// server -> if owns(user_id,file_id) && ~ exceeded(user_id,x) then : generate(token,24h) -> user
#[instrument(skip_all,err,fields(
    user_id=%claims.sub,
    user_ip=%addr.ip(),
    object_id=%f_id,
    kind=query.kind.to_string()
))]
#[debug_handler]
pub async fn download(
    Extension(claims): Extension<Claims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(appstate): State<AppState>,
    Path(f_id): Path<Uuid>,
    Query(query): Query<ObjectKindQuery>,
) -> Result<Json<TokenPayload>, ApiError> {
    info!("recieving new download request.");
    // search database for file ownership and existance .
    // if deleted(file_id) || ~ found(file_id) || ~ own(user_id,file_id) || error(db)   = return error(NotFound)
    let obj: FileSystemObject = if query.kind.is_folder() {
        fetch_folder_info(&appstate.db_pool, f_id, claims.sub)
            .await?
            .ok_or(ApiError::NotFound)?
            .into()
    } else {
        fetch_file_info(&appstate.db_pool, f_id, claims.sub)
            .await?
            .ok_or(ApiError::NotFound)?
            .into()
    };
    info!("getting redis connection");
    // fetch redis for download:user_id and get the set of tokens .
    // if not exists ,it means that the user is not inserted into redis and it means that he has no downloads at all ! (0 downloads)
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let user_d_key = create_redis_key(TokenType::Download, &claims.sub.to_string());

    // count number of active downloads , the number of tokens in set.
    // c_valid= count them .
    // if c_valid >= allowed , reject the request , error.
    // if c_valid < allowed , create new download token add it to redis , add it to the set of tokens per user in redis.
    info!("checking number of valid concurrent downloads for a user.");
    let active_count = redis_con
        .hlen(&user_d_key)
        .await
        .map_err(CRedisError::Connection)? as u64;

    if active_count >= appstate.settings.token_options.max_concurrent_download {
        return Err(ApiError::TooManyDownloads); // 429 status to many requests
    }
    //---------------------------
    info!("creating new 24h download token.");
    let day = appstate.settings.token_options.download_token_ttl * 60; // converts to seconds
    let new_d_token = Uuid::new_v4();
    let token_key = create_redis_key(TokenType::Download, &new_d_token.to_string());
    let token_data = DownloadTokenData {
        object_d: obj,
        ip_address: Some(addr.ip().to_string()), // extract from request headers if needed
    };
    // insert the new download token with its associated info into redis.
    let serialized = serialize_content(&token_data)?;
    info!(
        "storing the download token into redis with it's associated information for {} seconds",
        day
    );
    // 5. ATOMIC WRITE (Pipeline)
    // We write to BOTH keys simultaneously.
    redis_con
        .set_ex(&token_key, &serialized, day)
        .await
        .map_err(CRedisError::Connection)?;
    info!("successfully finishing creating the download transaction.");
    // adding new generated d_token to the set of user d_tokens.
    // return the new generated token to the user client.
    Ok(Json(TokenPayload {
        token: new_d_token.to_string().into(),
    }))
}
