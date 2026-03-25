use std::net::SocketAddr;

use crate::{
    ApiError, AppState, CRedisError, CleanupGuard, DownloadTokenData, FileDownload, FileShared,
    FileStream, FileSystemObject, FolderShared, ObjectKind, RustFSError, StreamQuery,
    StreamShareQuery, TokenType, create_redis_key, deserialize_content, fetch_all_file_ids_paths,
    fetch_redis_data, get_redis_con, validate_object_ancestor,
};

use anyhow::anyhow;
use async_zip::{Compression, ZipEntryBuilder, base::write::ZipFileWriter};
use aws_sdk_s3::Client;
use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_redis::{
    Connection,
    redis::{self},
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument};

use regex::Regex;
use std::sync::LazyLock;

static RANGE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^bytes=(\d+-\d*|-\d+)(,(\d+-\d*|-\d+))*$").unwrap());

static CONCURRENT_DOWNLOAD_CHECK_HASH: &str = r#"
        local count = redis.call('HLEN', KEYS[1])
        if count >= tonumber(ARGV[1]) then
            return 0
        end
        redis.call('HSET', KEYS[1], KEYS[2], 1)
        redis.call('HEXPIRE', KEYS[1], ARGV[2], 'FIELDS', 1, KEYS[2])
        return 1
    "#;
static CONCURRENT_DOWNLOAD_CHECK_COUNTER: &str = r#"
        local count = redis.call('GET', KEYS[1])
        if count and tonumber(count) >= tonumber(ARGV[1]) then
            return 0
        end
        redis.call('INCR', KEYS[1])
        redis.call('EXPIRE', KEYS[1], ARGV[2])
        return 1
    "#;

fn parse_range(value: &str) -> anyhow::Result<&str> {
    if !RANGE_RE.is_match(value) {
        let e = anyhow!("failed to parse range: {}", value);
        error!("{}", e);
        return Err(e);
    }
    Ok(value)
}
/// Streams either a single file or an entire folder for an authenticated
/// user based on a short‑lived download token by:
/// 1. Resolving the download token from Redis (`fetch_redis_data`,
///    `deserialize_content`) and validating the caller’s IP against the
///    stored IP from token issuance.
/// 2. Enforcing per‑user concurrent download limits by registering the
///    token in Redis (`try_register_stream_token`) with a TTL bound to the
///    download token lifetime.
/// 3. Creating a `CleanupGuard` tied to the user’s concurrent‑download key
///    so limits are released automatically when streaming completes.
/// 4. If the target is a folder, fetching all descendant files and their
///    full paths from Postgres (`fetch_all_file_ids_paths`) and piping them
///    through `stream_folder` as a ZIP stream.
/// 5. If the target is a file, parsing and validating an optional `Range`
///    header (`parse_range`) and delegating the actual bytes to `stream_file`
///    to support partial content and inline vs. download modes.
/// 6. Attaching the cleanup guard to the response extensions so it lives
///    for the duration of the stream and then returning the final response.
#[instrument(skip_all)]
pub async fn stream(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(appstate): State<AppState>,
    Query(stream_info): Query<StreamQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    info!("start new object streaming process.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let raw_token = stream_info.token.to_string();
    let token_key = create_redis_key(TokenType::Download, &raw_token);
    info!("fetch redis information using the download token.");
    let d_content: DownloadTokenData = fetch_redis_data(&mut redis_con, &token_key)
        .await?
        .ok_or(ApiError::Unauthorized)
        .and_then(|v| deserialize_content(&v))?;

    info!(
        f_id = %d_content.object_d.id(),
        user_id = d_content.object_d.bucket_name(),
        user_ip = %addr.ip(),
        stored_ip = d_content.ip_address,
        is_folder = d_content.object_d.is_folder(),
        download_mode = stream_info.download.unwrap_or(false),
        "Processing download request, object_key=f_id, user_id=bucket_name"
    );
    if Some(addr.ip().to_string()) != d_content.ip_address {
        error!("user ip address has changed.");
        return Err(ApiError::Unauthorized);
    }

    //--------------------------- checking number of concurrent downloads
    info!("incrementing the number of concurrent downloads for the user.");
    let expire = appstate.settings.token_options.download_token_ttl * 60;
    let user_d_key = create_redis_key(TokenType::Download, &d_content.object_d.bucket_name()); // user_id = bucket_name
    let allowed = try_register_stream_token(
        &mut redis_con,
        &user_d_key,
        Some(&raw_token),
        appstate.settings.token_options.max_concurrent_auth_stream,
        expire as i64,
    )
    .await
    .inspect_err(|e| error!("stream check script failed: {e}"))?;
    if !allowed {
        error!("user exceeded the stream limit allowed!");
        return Err(ApiError::TooManyDownloads);
    }
    //-------------------------- adding token to set of tokens

    info!("Creating cleanup guard");
    let c_guard = CleanupGuard::hash(appstate.redis_pool.clone(), stream_info.token, user_d_key);
    //--------------------------------- streaming object -------------------
    let mut response = if d_content.object_d.is_folder() {
        // fetch all its name prefixes/postfixes .
        // loop over all those names and pipe them to a giant zip file.
        // success ? Ok(())
        let folder = d_content.object_d.get_folder().unwrap();
        info!("getting all file ids and their full paths to start streaming the whole folder.");
        let files: Vec<FileDownload> =
            fetch_all_file_ids_paths(&appstate.db_pool, folder.owner_id, folder.id).await?;
        if files.is_empty() {
            return Err(ApiError::Conflict);
            // nothing to stream !!
        }
        stream_folder(
            appstate.rustfs_con.clone(),
            &folder.bucket_name(),
            &folder.name,
            files,
        )
        .await
    } else {
        //if Range header persists then use its value to resume download or stream.
        let range: Option<&str> = headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().map(|v| v.trim()).ok())
            .map(parse_range)
            .transpose()?;

        stream_file(
            appstate.rustfs_con.clone(),
            FileStream::from(d_content.object_d.get_file().unwrap()),
            stream_info.download.unwrap_or(false),
            range,
        )
        .await
    }
    .inspect_err(|e| error!("{}", e))?;
    info!("adding clean up guard as extension to continue working until the end of stream.");
    response.extensions_mut().insert(c_guard);
    Ok(response)
}
/// Streams shared files or folders using a public share token, with optional
/// navigation into descendants, by:
/// 1. Validating query parameters (`StreamShareQuery::validate`) and
///    resolving the shared object from Redis (`fetch_redis_data`,
///    `deserialize_content`) using the share token.
/// 2. Rejecting attempts to treat a shared file as a folder (when extra
///    params are present) to prevent bypassing the shared root.
/// 3. Enforcing per‑IP concurrent anonymous stream limits via
///    `try_register_stream_token`, keyed by the client IP with a bounded TTL.
/// 4. Creating a `CleanupGuard::counter` for the IP key so the concurrent
///    counter is decremented when the stream ends.
/// 5. For folder targets (root or validated descendant), checking ancestry
///    in Postgres (`validate_object_ancestor`) when needed, gathering all
///    descendant files (`fetch_all_file_ids_paths`), and delegating to
///    `stream_folder` to stream a ZIP archive.
/// 6. For file targets (root or validated child), optionally enforcing
///    ancestry via `validate_object_ancestor`, building a `FileStream`,
///    handling an optional `Range` header, and delegating to `stream_file`
///    for partial or full streaming.
/// 7. Attaching the cleanup guard to the response and returning the stream.
#[instrument(skip_all)]
pub async fn stream_share(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(appstate): State<AppState>,
    Query(stream_info): Query<StreamShareQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let params = stream_info.validate().inspect_err(|e| error!("{e}"))?;
    info!("start new object streaming process.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let raw_token = stream_info.token.to_string();
    let token_key = create_redis_key(TokenType::Shared, &raw_token);
    info!("fetch redis information using the download token.");
    let d_content: FileSystemObject = fetch_redis_data(&mut redis_con, &token_key)
        .await?
        .ok_or(ApiError::Unauthorized)
        .and_then(|v| deserialize_content(&v))?;

    info!(
        f_id = %d_content.id(), user_id = d_content.bucket_name(),
        user_ip = %addr.ip(), is_folder = d_content.is_folder(),
        download_mode = stream_info.download.unwrap_or(false),
        "Processing share stream request"
    );
    // --------------- check if d_content is file and params is Some then return error conflict (file cant have childs) !!!

    if params.is_some() && !d_content.is_folder() {
        // if the stored object with token is file , no matter what the other, should return bad request.
        let e = ApiError::BadRequest(anyhow!(
            "file can't have childs. user tries to bypass the token and download non-authorized objects.",
        ));
        error!("{e}");
        return Err(e);
    }

    //--------------------------- checking number of concurrent downloads
    info!("getting the number of concurrent downloads user currently have.");
    let user_ip_key = create_redis_key(TokenType::Shared, &addr.ip().to_string()); // user_id = bucket_name
    let allowed = try_register_stream_token(
        &mut redis_con,
        &user_ip_key,
        None,
        appstate.settings.token_options.max_concurrent_unauth_stream,
        (appstate.settings.token_options.download_token_ttl * 60) as i64,
    )
    .await
    .inspect_err(|e| error!("stream check script failed: {e}"))?;
    if !allowed {
        error!("user exceeded the stream limit allowed!");
        return Err(ApiError::TooManyDownloads);
    }
    info!("Creating cleanup guard");
    let c_guard = CleanupGuard::counter(appstate.redis_pool.clone(), user_ip_key);
    let (target_id, is_folder) = params.unwrap_or((d_content.id(), d_content.is_folder()));
    //--------------------------------- streaming object -------------------
    let mut response = if is_folder {
        let f_name = if target_id != d_content.id() {
            validate_object_ancestor::<FolderShared>(
                &appstate.db_pool,
                d_content.owner_id(),
                d_content.id(),
                target_id,
                ObjectKind::Folder,
            )
            .await?
            .ok_or(ApiError::Forbidden)
            .inspect_err(|e| error!("accessing folder is unauthorized: {e}"))?
            .name
        } else {
            d_content.name().to_string()
        };

        // fetch all its name prefixes/postfixes .
        // loop over all those names and pipe them to a giant zip file.
        // success ? Ok(())
        info!("getting all file ids and their full paths to start streaming the whole folder.");
        let files: Vec<FileDownload> =
            fetch_all_file_ids_paths(&appstate.db_pool, d_content.owner_id(), target_id).await?;
        stream_folder(
            appstate.rustfs_con.clone(),
            &d_content.bucket_name(),
            &f_name,
            files,
        )
        .await
    } else {
        let file = if target_id != d_content.id() {
            let v: FileShared = validate_object_ancestor(
                &appstate.db_pool,
                d_content.owner_id(),
                d_content.id(),
                target_id,
                ObjectKind::File,
            )
            .await?
            .ok_or(ApiError::Forbidden)
            .inspect_err(|e| error!("accessing file is unauthorized: {e}"))?;
            FileStream::from_file_shared(v, d_content.owner_id())
        } else {
            FileStream::from(d_content.get_file().unwrap())
        }; // converts from &FileRecord

        //if Range header persists then use its value to resume download or stream.
        let range: Option<&str> = headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().map(|v| v.trim()).ok())
            .map(parse_range)
            .transpose()?;

        stream_file(
            appstate.rustfs_con.clone(),
            file,
            stream_info.download.unwrap_or(false),
            range,
        )
        .await
    }
    .inspect_err(|e| error!("{}", e))?;
    info!("adding clean up guard as extension to continue working until the end of stream.");
    response.extensions_mut().insert(c_guard);
    Ok(response)
}

/// Streams an individual file from RustFS/S3, optionally honoring HTTP
/// range requests and download vs. inline disposition, by:
/// 1. Building a `get_object` request using the file’s bucket (owner id)
///    and key (file id), and applying a validated `Range` header when
///    present to support resume/partial content.
/// 2. Sending the request to RustFS/S3 and checking that the returned ETag
///    still matches the expected file ETag to detect changes during
///    streaming (`RustFSError::ETagChanged` on mismatch).
/// 3. Preparing appropriate response headers: status `200` or `206`,
///    `Content-Type` from the file’s MIME, `Content-Length`, `Accept-Ranges`,
///    `Content-Disposition` based on the `download` flag, and `Content-Range`
///    when the backend provides it.
/// 4. Wrapping the object body into an async reader and Axum `Body` stream
///    (`ReaderStream`) and building the final `Response` that can be sent
///    directly to the client.
async fn stream_file(
    rustfs_con: Client,
    file: FileStream,
    download: bool,
    range: Option<&str>,
) -> Result<Response, RustFSError> {
    debug!("start streaming the individual file.");
    let mut obj_req = rustfs_con // This is your Client
        .get_object()
        .bucket(file.owner_id.to_string()) // Bucket = User ID
        .key(file.id.to_string()); // key = file_id

    if let Some(range) = range {
        debug!("setting incoming Range header value and direct it to RustFS.");
        obj_req = obj_req.range(range);
    }
    debug!("sending RustFS get_object request.");
    let obj_res = obj_req
        .send()
        .await
        .map_err(|e| RustFSError::S3(e.into()))?; // send the request to RustFS
    let stored_etag = obj_res.e_tag.as_ref();
    if stored_etag != Some(&file.etag) {
        debug!(
            "etag of an object has changed, decrementing number of concurrent downloads for user...."
        );
        // the file has changed !!! start streaming from zero and ignore Range header , or just revoke the token from redis
        return Err(RustFSError::ETagChanged);
    }
    debug!("preparing streaming headers.");
    let content_length = obj_res.content_length().unwrap_or(file.size) as u64;
    let content_type = &file.mime_type; // general unknown format , used as a valid fallback

    let status_code = range
        .map(|_| StatusCode::PARTIAL_CONTENT)
        .unwrap_or(StatusCode::OK);

    let stream_as = if download {
        format!("attachment; filename=\"{}\"", file.name) // download directly
    } else {
        format!("inline; filename=\"{}\"", file.name) // play it in browser or the required player
    };
    let mut resp_build = Response::builder()
        .status(status_code)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CONTENT_DISPOSITION, stream_as)
        .header(header::ACCEPT_RANGES, "bytes");

    // Pass back Content-Range if S3 sent it (Required for 206)
    let _ = obj_res.content_range().is_some_and(|cr| {
        resp_build
            .headers_mut()
            .unwrap()
            .insert(header::CONTENT_RANGE, cr.parse().unwrap())
            .is_some()
    });
    debug!("transforming the RustFS body into an AsyncBufRead compatible to Axum Body stream.");
    let stream = obj_res.body.into_async_read();
    let body = Body::from_stream(ReaderStream::new(stream));
    debug!("success file response.");
    Ok(resp_build.body(body).unwrap())
}
//------------------------------------------------------
/// Compresses and streams an entire folder as a ZIP archive by:
/// 1. Creating a duplex in‑memory channel (`tokio::io::duplex`) to bridge
///    the async ZIP writer and the HTTP response body.
/// 2. Spawning a background task that calls `create_zip`, which pulls file
///    contents from RustFS/S3 and writes ZIP entries into the duplex writer,
///    logging any compression errors as `RustFSError::Compress`.
/// 3. Preparing download‑style response headers (`Content-Type:
///    application/zip`, `Content-Disposition` with `<name>.zip` or
///    `archive.zip` fallback).
/// 4. Exposing the duplex reader as an Axum streaming body via
///    `ReaderStream`, and returning a `Response` that streams ZIP bytes as
///    they are produced.
async fn stream_folder(
    rustfs_con: Client,
    bucket: &str,
    f_name: &str,
    files: Vec<FileDownload>,
) -> Result<Response, RustFSError> {
    debug!("start streaming the compressed folder.");
    // fetches a list of names that starts with a folder prefix
    debug!("allocating a new channel buffer with 1MB in size.");
    let (writer, reader) = tokio::io::duplex(1048576);
    let bucket = bucket.to_string();
    tokio::spawn(async move {
        debug!("start compressing arrived chunks of files from RustFS.");
        let e = create_zip(rustfs_con, bucket, files, writer)
            .await
            .map_err(RustFSError::Compress);
        _ = e.is_err_and(|e| {
            error!("{}", e);
            true
        });
    });
    debug!("preparing the response headers.");
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/zip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!(
            "attachment; filename=\"{}.zip\"",
            if f_name.is_empty() { "archive" } else { f_name }
        )
        .parse()
        .unwrap(),
    );
    debug!("preparing the body and converting headers and body into response.");
    let body = Body::from_stream(ReaderStream::new(reader));
    Ok((headers, body).into_response())
}

/// Builds a ZIP archive on the fly from a list of objects in RustFS/S3 and
/// writes it into the provided `writer` by:
/// 1. Wrapping the `writer` in an `async_zip::ZipFileWriter` so entries can
///    be appended incrementally over an async stream.
/// 2. Iterating over each `FileDownload`, creating a ZIP entry using its
///    path (`zip_path_ref`) and a Deflate compression builder.
/// 3. For each entry, requesting the corresponding object from RustFS/S3,
///    converting its body into an async reader, and copying its bytes into
///    the entry writer (`futures::io::copy`).
/// 4. Closing each entry stream when its object completes, then finally
///    closing the ZIP writer to flush the central directory and finish the
///    archive.
/// 5. Returning `Ok(())` on success or an appropriate error if any S3 or
///    compression operation fails.
async fn create_zip(
    rfs_client: Client,
    bucket: String,
    files: Vec<FileDownload>,
    writer: tokio::io::DuplexStream,
) -> anyhow::Result<()> {
    debug!("connecting the duplex writer gate to zip file writter.");
    let mut zip = ZipFileWriter::new(writer.compat_write());

    debug!("looping over object names and fetching a streams from RustFS.");
    for file in files {
        // Create ZIP entry with the same name of the object
        let builder = ZipEntryBuilder::new(file.zip_path_ref().into(), Compression::Deflate);
        // open the gate of giant zip file and set a new entry settings.
        let mut entry_writer = zip.write_entry_stream(builder).await?;

        // Get S3 object
        let response = rfs_client
            .get_object()
            .bucket(&bucket)
            .key(file.key()) // key=file_id
            .send()
            .await?;
        // Stream S3 data into ZIP
        let mut reader = response.body.into_async_read().compat();
        // start copying the stream of arrived bytes from Rustfs response into the open gate.
        futures::io::copy(&mut reader, &mut entry_writer).await?;
        // Close entry
        entry_writer.close().await?;
    }

    // Finalize ZIP
    zip.close().await?;
    debug!("success streaming all required files.");
    Ok(())
}
/// Enforces concurrent download limits per user or per IP by registering a
/// stream token or incrementing a counter in Redis, by:
/// 1. Choosing between a hash‑based script (`CONCURRENT_DOWNLOAD_CHECK_HASH`)
///    when a concrete `raw_token` is provided, or a simple counter script
///    (`CONCURRENT_DOWNLOAD_CHECK_COUNTER`) when only a key is tracked.
/// 2. Executing the selected Lua script with the given `user_key`, limit,
///    and expiration, allowing the script to check the current count and
///    either deny or register the new stream atomically.
/// 3. Returning `Ok(true)` when the Redis script allows the new stream
///    (token/counter registered) or `Ok(false)` when the limit has already
///    been reached, with any Redis‑level problems surfaced as `CRedisError`.
async fn try_register_stream_token(
    rds_con: &mut Connection,
    user_key: &str,
    raw_token: Option<&str>,
    limit: u64,
    expire: i64,
) -> Result<bool, CRedisError> {
    let added: u8 = match raw_token {
        Some(token) => redis::Script::new(CONCURRENT_DOWNLOAD_CHECK_HASH)
            .key(user_key)
            .key(token)
            .arg(limit)
            .arg(expire)
            .invoke_async(rds_con)
            .await
            .map_err(CRedisError::Connection)?,
        None => redis::Script::new(CONCURRENT_DOWNLOAD_CHECK_COUNTER)
            .key(user_key)
            .arg(limit)
            .arg(expire)
            .invoke_async(rds_con)
            .await
            .map_err(CRedisError::Connection)?,
    };

    Ok(added == 1)
}
