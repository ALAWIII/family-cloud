use crate::{
    ApiError, AppState, Claims, ObjectKind, ObjectRecord, RustFSError, fetch_object_metadata,
    get_user_available_storage, insert_obj, is_object_exists,
};
use anyhow::anyhow;
use aws_sdk_s3::Client;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use axum::Json;
use axum::body::Bytes;
use axum::{
    Extension,
    body::Body,
    extract::State,
    http::{
        HeaderMap, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
};
use futures::future::join_all;
use path_clean::PathClean;
use std::path::Path;

use mime_guess::mime;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::bytes::BytesMut;
use tracing::{debug, error, info, instrument};

const PART_SIZE: usize = 5 * 1024 * 1024;
const MAX_CONCURRENT_UPLOADS: usize = 4;

struct PartToUpload {
    part_number: i32,
    data: Bytes,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserStorageInfo {
    pub storage_quota_bytes: i64,
    pub storage_used_bytes: i64,
}

#[derive(Debug)]
struct UploadHeaders {
    pub object_kind: ObjectKind,
    pub object_key: String,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub checksum: Option<String>,
}

/// # WorkFlow
/// -
#[instrument(skip_all, fields(
    user_id=%claims.sub,
    username=claims.username
))]
pub async fn upload(
    State(appstate): State<AppState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<ObjectRecord>), ApiError> {
    info!("uploading new file.");
    let uphead = extract_headers(&headers).inspect_err(|e| error!("{}", e))?;
    info!("validating object key path structure.");
    validate_file_path(&claims.sub.to_string(), &uphead.object_key)
        .inspect_err(|e| error!("{}", e))?;
    // checking whether the object already existed in RustFS and database.
    if let Some(obj) = is_object_exists(&appstate.db_pool, claims.sub, &uphead.object_key)
        .await
        .inspect_err(|e| error!("{}", e))?
    {
        error!(object_id=%obj,object_kind=%uphead.object_kind,object_key=uphead.object_key,"already existed and active in the database.");
        return Err(ApiError::Conflict);
    }
    //-------------------------------
    let mut obj = ObjectRecord::new(claims.sub, &uphead.object_key, true);
    if uphead.object_kind.is_folder() {
        info!("creating new folder.");
        // if obj_kind is folder -> create the folder quickly -> grab the metadata store in database -> and return success
        insert_obj(&appstate.db_pool, &obj)
            .await
            .inspect_err(|e| error!("{}", e))?;
        info!("folder created successfully.");
        return Ok((StatusCode::CREATED, Json(obj)));
    }

    //--------------- check the available space user have . space_used + content_length >= maximum_space -> reject the upload. ---------------
    info!("fetching user available storage to store new file.");
    let s_info = get_user_available_storage(&appstate.db_pool, claims.sub)
        .await
        .inspect_err(|e| error!("{}", e))?;
    if s_info.storage_used_bytes + uphead.content_length.unwrap_or(0) > s_info.storage_quota_bytes {
        return Err(ApiError::Unauthorized);
    }
    let bucket = obj.bucket_name();
    //-------------------------- update object metadata ----------------------
    info!("preparing new file object instance with metadata.");
    obj.is_folder(false);
    obj.mime_type(uphead.content_type.unwrap());
    obj.checksum_sha256(uphead.checksum.unwrap());
    info!("creating new multipart upload session.");
    // if obj_kind is file -> open the body and start recive the stream of bytes for that file -> pipe directly to RustFS -> return metadata->store in database -> response success.
    let upload_id = create_multipart_upload(
        &appstate.rustfs_con,
        &bucket,
        &obj.object_key,
        obj.mime_type.as_ref().unwrap(),
    )
    .await
    .inspect_err(|e| error!("{}", e))?;

    // ---------------------- streaming the file
    info!("start streaming the file to RustFS object storage.");
    let rs = stream_file_rustfs_parallel(
        &appstate.rustfs_con,
        body,
        &bucket,
        &obj.object_key,
        &upload_id,
    )
    .await
    .inspect_err(|e| error!("{}", e));
    //-------- abort on error --------------
    if let Err(r) = rs {
        info!("aborting the upload.");
        abort_upload(&appstate.rustfs_con, &bucket, &obj.object_key, &upload_id)
            .await
            .inspect_err(|e| error!("{}", e))?;
        return Err(r)?;
    }
    //--------------------- ask rustfs to complement the metadata of the object------------------
    info!("fetch object metadata from RustFS.");
    fetch_object_metadata(&appstate.rustfs_con, &mut obj)
        .await
        .inspect_err(|e| error!("{}", e))?;
    //-------- insert the object(file) information into the database-----------------------
    info!("inserting new object with metadata into database.");
    insert_obj(&appstate.db_pool, &obj)
        .await
        .inspect_err(|e| error!("database inserting failed: {}", e))?;
    info!("new file created successfully.");
    Ok((StatusCode::CREATED, Json(obj)))
}

/// validates a path that follows a parent path and does not escape its domain.
fn validate_file_path(bucket: &str, key: &str) -> Result<(), RustFSError> {
    // 1. Join manually to ensure no root replacement
    let full_path = Path::new(bucket).join(key.trim_start_matches('/'));

    // 2. Clean the path (resolves ".." and ".") strictly in memory
    let clean_path = full_path.clean();

    // 3. Security Check: ensure it still starts with the bucket
    if !clean_path.starts_with(bucket) || clean_path != full_path {
        return Err(RustFSError::Upload(anyhow!(
            "Path traversal detected, the object key provided is malformed or invalid: {}",
            key
        )));
    }

    Ok(())
}
/// extracts required and optional headers.
fn extract_headers(headers: &HeaderMap) -> Result<UploadHeaders, ApiError> {
    info!("extracting headers");
    let obj_kind = headers
        .get("Object-Type")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| match s.to_lowercase().as_str() {
            "file" => Some(ObjectKind::File),
            "folder" => Some(ObjectKind::Folder),
            _ => None,
        })
        .ok_or(ApiError::BadRequest(anyhow!(
            "Invalid or missing Object-Type header"
        )))?;

    let mut obj_key = headers
        .get("Object-Key")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(ApiError::BadRequest(anyhow!("Missing Object-Key header")))?;

    // REMOVE leading slash if present (S3 keys should not start with /)
    obj_key = obj_key.trim_start_matches('/').to_string();

    let (cont_len, cont_type, checksum) = if obj_kind.is_folder() {
        debug!("the object is folder");
        if !obj_key.ends_with('/') {
            obj_key.push('/');
        }
        if !obj_key.starts_with('/') {
            obj_key = format!("/{}", obj_key);
        }
        (None, None, None)
    } else {
        debug!("the object is file");
        let cont_len = headers
            .get(CONTENT_LENGTH)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or(ApiError::BadRequest(anyhow!(
                "Missing or invalid Content-Length header"
            )))?;

        let cont_type = headers
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok())
            .or_else(|| mime_guess::from_path(&obj_key).first())
            .unwrap_or(mime::APPLICATION_OCTET_STREAM)
            .to_string();

        let checksum = headers
            .get("x-amz-checksum-sha256")
            .map(|h| h.to_str().map(String::from).ok())
            .ok_or(ApiError::BadRequest(anyhow!(
                "missing or malformed checksum header."
            )))?;

        (Some(cont_len), Some(cont_type), checksum)
    };

    debug!("headers extracted successfully");
    Ok(UploadHeaders {
        object_key: obj_key,
        object_kind: obj_kind,
        content_type: cont_type,
        content_length: cont_len,
        checksum,
    })
}

/// ===== Create multipart session, returns upload id =====
async fn create_multipart_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    obj_type: &str,
) -> Result<String, RustFSError> {
    debug!(
        object_key = key,
        bucket = bucket,
        obj_type = obj_type,
        "creating multipart upload with obj_type: {}",
        obj_type
    );
    let response = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .content_type(obj_type)
        .send()
        .await
        .map_err(|e| {
            RustFSError::Upload(anyhow!(
                "failed to create multipart upload transaction: {:?}",
                e
            ))
        })?;

    response
        .upload_id()
        .map(|id| id.to_string())
        .ok_or_else(|| RustFSError::Upload(anyhow!("No upload ID returned")))
}
/// # Main entry point
/// - the function orchestrator for the whole streaming process.
/// 1. spawn_body_streamer: collects, chunks the arrived bytes into buffer and sends them into the channel (part_tx).
/// 2. spawn_uploaders: spawns multiple parllel uploaders, recives arrived Part's (part_rx) stream them to RustFS, the results returned are sent into the channel (result_tx).
/// 3. collect_results: recives a stream of completed parts using (result_rx) and then collects and return back.
/// 4. body streams -> spawn_uploaders uses upload_single_part(part_x) -> collect_results.
/// 5. collect_results is_failure ? abort the whole upload, otherwise when all parts are streamed with OK pass.
/// 6. complete_upload with a list of sorted success uploaded parts.
pub async fn stream_file_rustfs_parallel(
    client: &Client,
    body: Body,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<(), RustFSError> {
    debug!("initalizing Parts communicating channels.");
    let (part_tx, part_rx) = mpsc::channel::<PartToUpload>(10);
    let (result_tx, result_rx) = mpsc::channel::<Result<CompletedPart, RustFSError>>(10);

    debug!("spawn parallel uploaders");
    // Spawn parallel uploaders
    let uploader_handle = spawn_uploaders(
        client.clone(),
        bucket.to_string(),
        key.to_string(),
        upload_id.to_string(),
        part_rx,
        result_tx.clone(),
    );
    debug!("start consuming the body and stream the arrived bytes to spawn_uploaders.");
    // Stream and buffer body into parts
    let streamer_handle = spawn_body_streamer(body, part_tx);

    // Collect upload results
    debug!("droppint the result_tx<CompletePart> sender.");
    drop(result_tx); // drop the channel send None to the reciever
    let completed_parts = collect_results(result_rx).await?; // if it receieves an error will hang everything

    // Wait for tasks
    debug!("waiting streamer and uploader handles to finish.");
    let _ = streamer_handle.await;
    let _ = uploader_handle.await;
    debug!("commiting and validating the uploaded file.");
    // Complete upload
    complete_upload(client, bucket, key, upload_id, completed_parts).await
}

/// # ===== Stream body and buffer into parts =====
/// 1. collects bytes from  body into buffer.
/// 2. len(buffer) = 5MB -> wrap the 5MB bytes into Part type and send it using part_tx
fn spawn_body_streamer(
    body: Body,
    part_tx: mpsc::Sender<PartToUpload>,
) -> tokio::task::JoinHandle<Result<(), RustFSError>> {
    tokio::spawn(async move {
        debug!("consuming body.");
        let mut stream = body.into_data_stream();
        let mut buffer = BytesMut::new();
        let mut part_number = 1;

        loop {
            // Fill buffer to PART_SIZE
            while buffer.len() < PART_SIZE {
                match stream.next().await {
                    Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                    Some(Err(e)) => {
                        return Err(RustFSError::Upload(anyhow!("Stream error: {}", e)));
                    }
                    None => break,
                }
            }

            if buffer.is_empty() {
                debug!("buffer is empty.");
                break;
            }

            // Extract part data ~ 5MB
            let data = if buffer.len() >= PART_SIZE {
                buffer.split_to(PART_SIZE).freeze()
            } else {
                buffer.split().freeze()
            };

            // Send to uploaders
            part_tx
                .send(PartToUpload { part_number, data })
                .await
                .map_err(|_| RustFSError::Upload(anyhow!("Upload channel closed")))?;

            part_number += 1;
        }

        Ok(())
    })
}

/// ===== Spawn parallel uploader tasks =====
/// # Concurrent Uploading
/// - consumes the part_rx receive channel endpoint
/// - new part arraived 5MB -> acquire a permit -> spawn new upload thread -> fead to upload_single_part -> start stream the part to RustFS.
/// - returns a result -> stream it back using result_tx send endpoint channel.
/// - drop the permit to free a slot.
fn spawn_uploaders(
    client: Client,
    bucket: String,
    key: String,
    upload_id: String,
    mut part_rx: mpsc::Receiver<PartToUpload>,
    result_tx: mpsc::Sender<Result<CompletedPart, RustFSError>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOADS));
        let mut handles = vec![];
        // if None means the sender is dropped and streaming has finished.
        while let Some(part) = part_rx.recv().await {
            debug!(
                "receiving a new Part to upload. part no: {}",
                part.part_number
            );
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let bucket = bucket.clone();
            let key = key.clone();
            let result_tx = result_tx.clone();
            let upload_id = upload_id.clone();
            let handle = tokio::spawn(async move {
                // sending the individual byte of data
                let result = upload_single_part(
                    &client,
                    &bucket,
                    &key,
                    &upload_id,
                    part.part_number,
                    part.data,
                )
                .await;
                debug!(
                    "redirecting the result of a part to result channel. part no: {}",
                    part.part_number
                );
                drop(permit);
                let _ = result_tx.send(result).await;
            });
            debug!("storing new upload part handle.");
            handles.push(handle); // storing for later awaiting all payloads to be sent
        }
        debug!("awaiting all parts to finish uploading.");
        join_all(handles).await;
    })
}
/// ===== Collect upload results, on error should abort the whole upload. =====
async fn collect_results(
    mut result_rx: mpsc::Receiver<Result<CompletedPart, RustFSError>>,
) -> Result<Vec<CompletedPart>, RustFSError> {
    debug!("collecting parts.");
    let mut completed_parts = Vec::new();

    while let Some(part) = result_rx.recv().await {
        completed_parts
            .push(part.map_err(|e| RustFSError::Upload(anyhow!("corrupted part: {}", e)))?);
    }
    completed_parts.sort_by_key(|p| p.part_number);
    debug!("collecting parts and sorting them success.");
    Ok(completed_parts)
}

// ===== Upload single part with retry =====
async fn upload_single_part(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: i32,
    data: Bytes,
) -> Result<CompletedPart, RustFSError> {
    for attempt in 1..=3 {
        match client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(data.clone().into())
            .send()
            .await
        {
            Ok(output) => {
                debug!("uploading success {}", part_number);
                return Ok(CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(output.e_tag.unwrap_or_default())
                    .build());
            }
            Err(_) if attempt < 3 => {
                tokio::time::sleep(tokio::time::Duration::from_secs(attempt * 2)).await;
            }
            Err(e) => {
                return Err(RustFSError::Upload(anyhow!(
                    "Part {} failed after {} retries: {}",
                    part_number,
                    attempt,
                    e
                )));
            }
        }
    }
    unreachable!()
}

/// ===== Complete multipart upload, commits the uploaded file to RustFS.=====
async fn complete_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    completed_parts: Vec<CompletedPart>,
) -> Result<(), RustFSError> {
    let completed = CompletedMultipartUpload::builder()
        .set_parts(Some(completed_parts))
        .build();

    client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .multipart_upload(completed)
        .send()
        .await
        .map_err(|e| RustFSError::Upload(anyhow!("Complete upload failed: {}", e)))?;

    Ok(())
}

/// ===== Abort multipart upload on error =====
/// - cleans any unfinshed upload on failure.
async fn abort_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<(), RustFSError> {
    client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
        .map_err(|e| RustFSError::Upload(anyhow!("Abort upload failed: {}", e)))?;

    Ok(())
}
