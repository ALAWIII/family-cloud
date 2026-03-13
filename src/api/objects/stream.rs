use std::net::SocketAddr;

use crate::{
    ApiError, AppState, CRedisError, CleanupGuard, DownloadTokenData, FileDownload, FileShared,
    FileStream, FileSystemObject, FolderShared, ObjectKind, RustFSError, StreamQuery, TokenType,
    create_redis_key, deserialize_content, fetch_all_file_ids_paths, fetch_redis_data,
    get_redis_con, validate_object_ancestor,
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
use serde::{Deserialize, Serialize};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument};

use regex::Regex;
use std::sync::LazyLock;
use uuid::Uuid;

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
/// # Streaming Supports :
/// 1. individual files.
/// 2. streaming videos/audios , streaming videos/audios as download requests.
/// 3. streaming zipped folders with their contents recursively
/// # object_kind=folder
/// - fetch database recursively for all file_id=object_key and their name in order to name them in zip file ,
/// - fetch all folder_parent names of all files to create the zip file strucutre !!
/// - doesn't support pause/resuming.
/// # object_key=file
/// - stream it directly without compressing.
/// - supports pause/resuming.
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
            fetch_all_file_ids_paths(&appstate.db_pool, folder.owner_id, folder.id)
                .await
                .inspect_err(|e| error!("{}", e))?;
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
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamShareQuery {
    pub token: Uuid,
    pub f_id: Option<Uuid>,
    pub kind: Option<ObjectKind>,
    pub download: Option<bool>,
}
impl StreamShareQuery {
    pub fn validate(&self) -> Result<Option<(Uuid, bool)>, ApiError> {
        match (self.f_id, &self.kind) {
            (Some(id), Some(k)) => Ok(Some((id, k.is_folder()))),
            (None, None) => Ok(None),
            _ => Err(ApiError::BadRequest(anyhow!(
                "Partially provided parameters for stream share endpoint"
            ))),
        }
    }
}
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
/// Responsible for compressing and streaming an entire folder.
async fn stream_folder(
    rustfs_con: Client,
    bucket: &str,
    f_name: &str,
    files: Vec<FileDownload>,
) -> Result<Response, RustFSError> {
    debug!("start streaming the compressed folder.");
    // fetches a list of names that starts with a folder prefix
    if files.is_empty() {
        return Err(RustFSError::EmptyFolder);
        // nothing to stream !!
    }
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

/// Accepts rustfs client , bucket_name, list of objects and writer (portal gate) .
///
/// The `writer` gate used to write the recieved bytes from rustfs into it.
/// 1. attach a reference of stream writer to a zip writer.
/// 2. loop over list objects
/// 3. create/allocate zip entry with object key or name.
/// 4. request an object stream from RustFS .
/// 5. convert the body of object stream to a compatible object reader stream buffer.
/// 6. copy the arrived bytes from the reader buffer into its allocated entry_writer buffer.
/// 7. once finished , close the entry_writer buffer.
/// # The flow of attached buffers:
/// writer <- zip <- entry_writer[x] <- reader[x] , where x stands for the objects number.
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
