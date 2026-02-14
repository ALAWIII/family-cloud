use std::net::SocketAddr;

use crate::{
    ApiError, AppState, CRedisError, CleanupGuard, DownloadTokenData, RustFSError, StreamQuery,
    TokenType, create_redis_key, deserialize_content, fetch_redis_data, get_redis_con,
};

use async_zip::{Compression, ZipEntryBuilder, base::write::ZipFileWriter};
use aws_sdk_s3::Client;
use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_redis::redis::{self, AsyncTypedCommands};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, instrument};

/// # Streaming Supports :
/// 1. individual files.
/// 2. streaming videos/audios , streaming videos/audios as download requests.
/// 3. streaming zipped folders with their contents recursively
/// # object_key=folder
/// - loop over the content of folder recursively , collect all nested files/objects and compress them all in one zip file then stream it.
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
    let token_info = fetch_redis_data(&mut redis_con, &token_key)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let d_content: DownloadTokenData = deserialize_content(&token_info)?;
    info!(
        file_id = %d_content.object_d.id,
        user_id = %d_content.object_d.user_id,
        user_ip = %addr.ip(),
        stored_ip=d_content.ip_address,
        object_key = %d_content.object_d.object_key,
        is_folder = d_content.object_d.is_folder,
        download_mode = stream_info.download.unwrap_or(false),
        "Processing download request"
    );
    if Some(addr.ip().to_string()) != d_content.ip_address {
        error!("user ip address has changed.");
        return Err(ApiError::Unauthorized);
    }

    //--------------------------- checking number of concurrent downloads
    info!("getting the number of concurrent downloads user currently have.");
    let user_d_key = create_redis_key(TokenType::Download, &d_content.object_d.user_id.to_string());
    let active_count = redis_con
        .hlen(&user_d_key)
        .await
        .map_err(CRedisError::Connection)?;

    if active_count >= 10 {
        let e = ApiError::TooManyDownloads;
        error!("{}", e);
        return Err(e); // 429 status to many requests
    }
    //-------------------------- adding token to set of tokens
    info!("incrementing the number of concurrent downloads for the user.");
    let day = 24 * 60 * 60;
    let _: () = redis::pipe()
        .atomic() // ensures all commands succeed or fail together
        .hset_nx(&user_d_key, &raw_token, 1) // 2) Add token to user's hash only if it doesn't exist , download:user_id , fields:  token:1
        .hexpire(
            // 3) Set TTL on that hash field
            &user_d_key,
            day as i64,
            redis::ExpireOption::NONE,
            &[&raw_token],
        )
        .query_async(&mut redis_con)
        .await
        .map_err(CRedisError::Connection)?;
    info!("Creating cleanup guard");
    let c_guard = CleanupGuard::new(appstate.redis_pool.clone(), stream_info.token, user_d_key);
    //--------------------------------- streaming object -------------------
    let object_name = d_content.object_d.object_name();
    let mut response = if d_content.object_d.is_folder {
        // fetch all its name prefixes/postfixes .
        // loop over all those names and pipe them to a giant zip file.
        // success ? Ok(())
        stream_folder(
            &appstate.rustfs_con,
            &d_content.object_d.user_id.to_string(),
            d_content.object_d.object_key.to_string(),
            &object_name,
        )
        .await
    } else {
        stream_file(
            headers,
            &appstate,
            &d_content,
            &object_name,
            stream_info.download.unwrap_or(false),
        )
        .await
    }
    .inspect_err(|e| error!("{}", e))?;
    info!("adding clean up guard as extension to continue working until the end of stream.");
    response.extensions_mut().insert(c_guard);
    Ok(response)
}

async fn stream_file(
    headers: HeaderMap,
    appstate: &AppState,
    d_content: &DownloadTokenData,
    f_name: &str,
    download: bool,
) -> Result<Response, RustFSError> {
    debug!("start streaming the individual file.");
    let range = headers //if Range header persists then use its value to resume download or stream.
        .get(header::RANGE)
        .map(|v| v.to_str())
        .transpose()
        .ok()
        .flatten();
    let mut obj_req = appstate
        .rustfs_con // This is your Client
        .get_object()
        .bucket(d_content.object_d.user_id.to_string()) // Bucket = User ID
        .key(&d_content.object_d.object_key);

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
    if stored_etag != d_content.object_d.etag.as_ref() {
        debug!(
            "etag of an object has changed, decrementing number of concurrent downloads for user...."
        );
        // the file has changed !!! start streaming from zero and ignore Range header , or just revoke the token from redis
        return Err(RustFSError::ETagChanged);
    }
    debug!("preparing streaming headers.");
    let content_length = obj_res.content_length().unwrap_or(0) as u64;
    let content_type = obj_res.content_type().unwrap_or("application/octet-stream"); // general unknown format , used as a valid fallback

    let status_code = range
        .map(|_| StatusCode::PARTIAL_CONTENT)
        .unwrap_or(StatusCode::OK);

    let stream_as = if download {
        format!("attachment; filename=\"{}\"", f_name) // download directly
    } else {
        format!("inline; filename=\"{}\"", f_name) // play it in browser or the required player
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
    rustfs_con: &Client,
    bucket_name: &str,
    mut object_key: String,
    f_name: &str,
) -> Result<Response, RustFSError> {
    debug!("start streaming the compressed folder.");
    if object_key.starts_with("/") {
        object_key.remove(0);
    }
    if !object_key.ends_with("/") {
        object_key.push('/');
    }
    // fetches a list of names that starts with a folder prefix
    let name_list = rustfs_con
        .list_objects_v2()
        .bucket(bucket_name)
        .prefix(&object_key)
        .send()
        .await
        .map_err(|e| RustFSError::S3(e.into()))?;
    // convert them into a list of objects and filter out the empty folders!
    let objects = name_list
        .contents()
        .to_vec()
        .into_iter()
        .filter(|o| o.key().is_some_and(|k| !k.ends_with('/')))
        .collect::<Vec<_>>();

    if objects.is_empty() {
        return Err(RustFSError::EmptyFolder);
        // nothing to stream !!
    }
    debug!("allocating a new channel buffer with 1MB in size.");
    let (writer, reader) = tokio::io::duplex(1048576);
    let client = rustfs_con.clone();
    let bucket = bucket_name.to_string();

    tokio::spawn(async move {
        debug!("start compressing arrived chunks of files from RustFS.");
        let e = create_zip(client, bucket, objects, writer)
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
        format!("attachment; filename=\"{}.zip\"", f_name)
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
    objects: Vec<aws_sdk_s3::types::Object>,
    writer: tokio::io::DuplexStream,
) -> anyhow::Result<()> {
    debug!("connecting the duplex writer gate to zip file writter.");
    let mut zip = ZipFileWriter::new(writer.compat_write());

    debug!("looping over object names and fetching a streams from RustFS.");
    for obj in objects {
        let key = obj.key(); // we should not propogating error here !
        if let Some(key) = key {
            // Create ZIP entry with the same name of the object
            let builder = ZipEntryBuilder::new(key.into(), Compression::Deflate);
            // open the gate of giant zip file and set a new entry settings.
            let mut entry_writer = zip.write_entry_stream(builder).await?;

            // Get S3 object
            let response = rfs_client
                .get_object()
                .bucket(&bucket)
                .key(key)
                .send()
                .await?;
            // Stream S3 data into ZIP
            let mut reader = response.body.into_async_read().compat();
            // start copying the stream of arrived bytes from Rustfs response into the open gate.
            futures::io::copy(&mut reader, &mut entry_writer).await?;
            // Close entry
            entry_writer.close().await?;
        }
    }

    // Finalize ZIP
    zip.close().await?;
    debug!("success streaming all required files.");
    Ok(())
}
