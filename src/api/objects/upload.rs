use std::path::Path;

use crate::{
    ApiError, AppState, Claims, ObjectKind, ObjectRecord, fetch_object_metadata,
    get_user_available_storage, insert_obj,
};
use anyhow::anyhow;
use aws_sdk_s3::Client;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
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

use mime_guess::mime;
use path_security::validate_path;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::bytes::BytesMut;
use tracing::instrument;

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

#[instrument(skip_all, err)]
pub async fn upload(
    State(appstate): State<AppState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, ApiError> {
    let uphead = extract_headers(&headers)?;
    let bucket_p = format!("/{}", claims.sub);
    let f_path = format!("{}{}", bucket_p, uphead.object_key); // assuming obj_key should start with '/'
    validate_path(Path::new(&f_path), Path::new(&bucket_p))?;
    let mut obj = ObjectRecord::new(claims.sub, &uphead.object_key, true);
    if uphead.object_kind.is_folder() {
        // if obj_kind is folder -> create the folder quickly -> grab the metadata store in database -> and return success
        insert_obj(&appstate.db_pool, obj).await?;
        return Ok(StatusCode::CREATED);
    }
    //--------------- check the available space user have . space_used + content_length >= maximum_space -> reject the upload. ---------------
    let s_info = get_user_available_storage(&appstate.db_pool, claims.sub).await?;
    if s_info.storage_used_bytes + uphead.content_length.unwrap_or(0) > s_info.storage_quota_bytes {
        return Err(ApiError::Unauthorized);
    }
    let bucket = obj.bucket_name();
    //-------------------------- update object metadata ----------------------
    obj.is_folder(false);
    obj.mime_type(uphead.content_type.unwrap());
    obj.checksum_sha256(uphead.checksum.unwrap());

    // if obj_kind is file -> open the body and start recive the stream of bytes for that file -> pipe directly to RustFS -> return metadata->store in database -> response success.
    let upload_id = create_multipart_upload(
        &appstate.rustfs_con,
        &bucket,
        &obj.object_key,
        obj.mime_type.as_ref().unwrap(),
    )
    .await?;
    // ---------------------- streaming the file
    let rs = stream_file_rustfs_parallel(
        &appstate.rustfs_con,
        body,
        &bucket,
        &obj.object_key,
        &upload_id,
    )
    .await;
    //-------- abort on error --------------
    if let Err(r) = rs {
        abort_upload(&appstate.rustfs_con, &bucket, &obj.object_key, &upload_id).await?;
        return Err(r)?;
    }
    //--------------------- ask rustfs to complement the metadata of the object------------------
    fetch_object_metadata(&appstate.rustfs_con, &mut obj).await?;
    //-------- insert the object(file) information into the database-----------------------
    insert_obj(&appstate.db_pool, obj).await?;
    Ok(StatusCode::CREATED)
}

fn extract_headers(headers: &HeaderMap) -> Result<UploadHeaders, ApiError> {
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
        .map(|s| s.to_string()) // Own the String
        .ok_or(ApiError::BadRequest(anyhow!("Missing Object-Key header")))?;

    let (cont_len, cont_type, checksum) = if obj_kind.is_folder() {
        if !obj_key.ends_with('/') {
            obj_key.push('/');
        }
        if !obj_key.starts_with("/") {
            obj_key = format!("/{}", obj_key);
        }
        (None, None, None)
    } else {
        let cont_len = headers
            .get(CONTENT_LENGTH) // Use const axum::http::header::CONTENT_LENGTH
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or(ApiError::BadRequest(anyhow!(
                "Missing or invalid Content-Length header"
            )))?;

        let cont_type = headers
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok()) // mime::Mime
            .or_else(|| mime_guess::from_path(&obj_key).first())
            .unwrap_or(mime::APPLICATION_OCTET_STREAM)
            .to_string();
        let checksum = headers
            .get("x-amz-checksum-sha256")
            .map(|h| h.to_str().map(String::from).ok())
            .ok_or(ApiError::BadRequest(anyhow!(
                "missing or malformed checksum header."
            )))?;
        if !obj_key.starts_with("/") {
            obj_key = format!("/{}", obj_key);
        }

        (Some(cont_len), Some(cont_type), checksum)
    };

    Ok(UploadHeaders {
        object_key: obj_key,
        object_kind: obj_kind,
        content_type: cont_type,
        content_length: cont_len,
        checksum,
    })
}

// ===== Main entry point =====
pub async fn stream_file_rustfs_parallel(
    client: &Client,
    body: Body,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> anyhow::Result<()> {
    let (part_tx, part_rx) = mpsc::channel::<PartToUpload>(10);
    let (result_tx, result_rx) = mpsc::channel::<Result<CompletedPart, anyhow::Error>>(10);

    // Spawn parallel uploaders
    let uploader_handle = spawn_uploaders(
        client.clone(),
        bucket.to_string(),
        key.to_string(),
        upload_id.to_string(),
        part_rx,
        result_tx.clone(),
    );

    // Stream and buffer body into parts
    let streamer_handle = spawn_body_streamer(body, part_tx);

    // Collect upload results
    drop(result_tx); // drop the channel send None to the reciever
    let completed_parts = collect_results(result_rx).await?; // if it receieves an error will hang everything

    // Wait for tasks
    let _ = streamer_handle.await;
    let _ = uploader_handle.await;

    // Complete upload
    complete_upload(client, bucket, key, upload_id, completed_parts).await
}

// ===== Create multipart session =====
async fn create_multipart_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    obj_type: &str,
) -> anyhow::Result<String> {
    let response = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .content_type(obj_type)
        .send()
        .await?;

    response
        .upload_id()
        .map(|id| id.to_string())
        .ok_or_else(|| anyhow!("No upload ID returned"))
}

// ===== Spawn parallel uploader tasks =====
fn spawn_uploaders(
    client: Client,
    bucket: String,
    key: String,
    upload_id: String,
    mut part_rx: mpsc::Receiver<PartToUpload>,
    result_tx: mpsc::Sender<Result<CompletedPart, anyhow::Error>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOADS));
        let mut handles = vec![];
        // if None means the sender is dropped and streaming has finished.
        while let Some(part) = part_rx.recv().await {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let bucket = bucket.clone();
            let key = key.clone();
            let upload_id = upload_id.clone();
            let result_tx = result_tx.clone();

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

                drop(permit);
                let _ = result_tx.send(result).await;
            });

            handles.push(handle); // storing for later awaiting all payloads to be sent
        }
        join_all(handles).await;
    })
}

// ===== Stream body and buffer into parts =====
fn spawn_body_streamer(
    body: Body,
    part_tx: mpsc::Sender<PartToUpload>,
) -> tokio::task::JoinHandle<Result<(), anyhow::Error>> {
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        let mut buffer = BytesMut::new();
        let mut part_number = 1;

        loop {
            // Fill buffer to PART_SIZE
            while buffer.len() < PART_SIZE {
                match stream.next().await {
                    Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                    Some(Err(e)) => return Err(anyhow!("Stream error: {}", e)),
                    None => break,
                }
            }

            if buffer.is_empty() {
                break;
            }

            // Extract part data ~ 5MB
            let data = if buffer.len() >= PART_SIZE {
                buffer.split_to(PART_SIZE).freeze()
            } else {
                buffer.split().freeze()
            };

            // Send to uploaders
            if part_tx
                .send(PartToUpload { part_number, data })
                .await
                .is_err()
            {
                return Err(anyhow!("Upload channel closed"));
            }

            part_number += 1;
        }

        Ok(())
    })
}

// ===== Collect upload results =====
async fn collect_results(
    mut result_rx: mpsc::Receiver<Result<CompletedPart, anyhow::Error>>,
) -> anyhow::Result<Vec<CompletedPart>> {
    let mut completed_parts = Vec::new();

    while let Some(part) = result_rx.recv().await {
        completed_parts.push(part?);
    }
    completed_parts.sort_by_key(|p| p.part_number);
    Ok(completed_parts)
}

// ===== Complete multipart upload =====
async fn complete_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    completed_parts: Vec<CompletedPart>,
) -> anyhow::Result<()> {
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
        .map_err(|e| anyhow!("Complete upload failed: {}", e))?;

    Ok(())
}

// ===== Abort multipart upload on error =====
async fn abort_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> anyhow::Result<()> {
    client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
        .map_err(|e| anyhow!("Abort upload failed: {}", e))?;

    Ok(())
}

// ===== Upload single part with retry =====
async fn upload_single_part(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: i32,
    data: Bytes,
) -> anyhow::Result<CompletedPart> {
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
                return Ok(CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(output.e_tag.unwrap_or_default())
                    .build());
            }
            Err(e) if attempt < 3 => {
                tokio::time::sleep(tokio::time::Duration::from_secs(attempt * 2)).await;
            }
            Err(e) => {
                return Err(anyhow!(
                    "Part {} failed after {} retries: {}",
                    part_number,
                    attempt,
                    e
                ));
            }
        }
    }
    unreachable!()
}
