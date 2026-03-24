use crate::{
    ApiError, AppState, Claims, DatabaseError, FileRecord, FolderRecord, ObjectKind, ObjectStatus,
    RustFSError, UserStorageInfo, get_user_available_storage, increment_storage_used_for_user,
    insert_folder, is_obj_exists, upsert_file, validate_display_name,
};
use anyhow::anyhow;
use aws_sdk_s3::Client;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use axum::body::Bytes;
use axum::extract::Query;
use axum::response::IntoResponse;
use axum::{
    Extension,
    body::Body,
    extract::State,
    http::{
        HeaderMap, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE},
    },
};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use futures::future::join_all;

use ironsaga::{IronSagaAsync, ironcmd};
use mime_guess::mime;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::bytes::BytesMut;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

const PART_SIZE: usize = 5 * 1024 * 1024;
const MAX_CONCURRENT_UPLOADS: usize = 4;

struct PartToUpload {
    part_number: i32,
    data: Bytes,
}

#[derive(Debug)]
struct UploadHeaders {
    pub object_kind: ObjectKind,
    pub f_name: String,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub checksum: Option<String>,
}
pub struct StreamResult {
    pub checksum: String,
    pub file_size: usize,
}
#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    pub parent_id: Uuid,
}
/// # WorkFlow
/// consider refactor this function and using Compensating Transaction/Command design pattrens.
#[instrument(skip_all, fields(
    user_id=%claims.sub,
    username=claims.username
))]
pub async fn upload(
    Query(upq): Query<UploadQuery>,
    State(appstate): State<AppState>,
    Extension(claims): Extension<Claims>,
    headers: HeaderMap,
    body: Body, // parent_id , file_name
) -> Result<impl IntoResponse, ApiError> {
    info!("uploading new file.");
    let uphead = extract_headers(&headers).inspect_err(|e| error!("{}", e))?;
    // checking whether the object already existed in RustFS and database.
    if uphead.object_kind.is_folder() {
        info!("the object is folder: {}", uphead.f_name);
        if let Some(id) = is_obj_exists(
            &appstate.db_pool,
            claims.sub,
            upq.parent_id,
            &uphead.f_name,
            ObjectKind::Folder,
        )
        .await?
        {
            error!(folder_id=%id,object_kind=%uphead.object_kind,folder_name=uphead.f_name,"already existed and active in the database.");
            return Err(ApiError::Conflict);
        }
        info!("creating new folder.");
        let folder = FolderRecord::new(claims.sub, Some(upq.parent_id), uphead.f_name);
        // if obj_kind is folder -> create the folder quickly -> grab the metadata store in database -> and return success
        insert_folder(&appstate.db_pool, &folder).await?;
        info!("folder created successfully.");
        return Ok((StatusCode::CREATED, folder).into_response());
    }

    //--------------- check the available space user have . space_used + content_length >= maximum_space -> reject the upload. ---------------
    info!("fetching user available storage to store new file.");
    let s_info = get_user_available_storage(&appstate.db_pool, claims.sub).await?;
    if s_info.storage_used_bytes + uphead.content_length.unwrap_or(0) > s_info.storage_quota_bytes {
        return Err(ApiError::ObjectTooLarge);
    }
    //-------------------------------- check if file exists under the same parent_id -----------------------
    if let Some(id) = is_obj_exists(
        &appstate.db_pool,
        claims.sub,
        upq.parent_id,
        &uphead.f_name,
        ObjectKind::File,
    )
    .await?
    {
        error!(file_id=%id,kind=%uphead.object_kind,file_name=uphead.f_name,"already existed and active in the database.");
        return Err(ApiError::Conflict);
    }

    //-------------------------- update object metadata ----------------------
    info!("preparing new file object instance with metadata.");
    let mut file = FileRecord::new(claims.sub, upq.parent_id, uphead.f_name);
    let f_id = file.id;
    file.mime_type(uphead.content_type.unwrap());
    file.checksum(uphead.checksum.as_ref().unwrap());
    let bucket = file.bucket_name();
    info!("creating new multipart upload session.");
    // if obj_kind is file -> open the body and start recive the stream of bytes for that file -> pipe directly to RustFS -> return metadata->store in database -> response success.
    let upload_id =
        create_multipart_upload(&appstate.rustfs_con, &bucket, file.id, &file.mime_type)
            .await
            .inspect_err(|e| error!("{}", e))?;

    // ---------------------- streaming the file
    info!("start streaming the file to RustFS object storage.");
    let mut bus = IronSagaAsync::default();
    let mut up_ctx = UploadContext::default();
    up_ctx.file = Some(file);
    let upctx = Arc::new(Mutex::new(up_ctx));
    let mut tmp_cmd = TempCmd::new();
    let abort_upload_rb = AbortUpload::new(&appstate.rustfs_con, &bucket, f_id, &upload_id);
    tmp_cmd.set_rollback(abort_upload_rb);
    let stream_cmd = StreamFileRustfs::new(
        appstate.rustfs_con.clone(),
        body,
        &upload_id,
        s_info,
        upctx.clone(),
    );

    debug!("commiting and validating the uploaded file.");
    // Complete upload
    let mut c_up = CompleteUpload::new(&appstate.rustfs_con, &upload_id, upctx.clone());
    let del_f_rfs_rb = DeleteFileRustfs::new(&appstate.rustfs_con, upctx.clone());
    c_up.set_rollback(del_f_rfs_rb);
    let mut ins_f = InsertFileDb::new(&appstate.db_pool, upctx.clone());
    let de_f_rb = DeleteFileDb::new(&appstate.db_pool, upctx.clone());
    ins_f.set_rollback(de_f_rb);
    let inc_cmd = IncrementStorage::new(&appstate.db_pool, claims.sub, upctx.clone());
    bus.add_command(tmp_cmd);
    bus.add_command(stream_cmd);
    bus.add_command(c_up);
    bus.add_command(ins_f);
    bus.add_command(inc_cmd);
    let rs = bus.execute_all().await;
    let mut upctxl = upctx.lock().await;
    if let Some(e) = upctxl.checksum_er.take().or(upctxl.exceed_quota.take()) {
        return Err(e);
    }
    rs?;
    info!("new file uploaded successfully.");
    let f = upctxl.file.take().unwrap();
    Ok((StatusCode::CREATED, f).into_response())
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

    let obj_name = headers
        .get("Object-Name")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_string())
        .ok_or(ApiError::BadRequest(anyhow!("Missing Object-Name header")))?;
    debug!(f_name = obj_name, "validating file/folder name.");
    validate_display_name(&obj_name)?;

    let (cont_len, cont_type, checksum) = if obj_kind.is_folder() {
        debug!("the object is folder");
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
            .or_else(|| mime_guess::from_path(&obj_name).first())
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
        f_name: obj_name,
        object_kind: obj_kind,
        content_type: cont_type,
        content_length: cont_len,
        checksum,
    })
}
/// ===== Create multipart session, returns upload id ===== file_id == object key in rustfs
async fn create_multipart_upload(
    client: &Client,
    bucket: &str,
    f_id: Uuid,
    obj_type: &str,
) -> Result<String, RustFSError> {
    debug!(
        file_id = %f_id,
        bucket = bucket,
        obj_type = obj_type,
        "creating multipart upload with obj_type: {}",
        obj_type
    );
    let response = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(f_id.to_string())
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
#[ironcmd(result)]
pub async fn stream_file_rustfs<'a>(
    client: Client,
    body: Body,
    upload_id: &'a str,
    s_info: UserStorageInfo,
    upctx: Arc<Mutex<UploadContext>>,
) -> Result<(), ApiError> {
    let mut ctx = upctx.lock().await;
    let f = ctx.file.as_mut().unwrap();
    debug!("initalizing Parts communicating channels.");
    let (part_tx, part_rx) = mpsc::channel::<PartToUpload>(10);
    let (result_tx, result_rx) = mpsc::channel::<Result<CompletedPart, RustFSError>>(10);
    debug!("spawn parallel uploaders");
    // Spawn parallel uploaders
    let uploader_handle = spawn_uploaders(
        client.clone(),
        f.bucket_name(),
        f.key(),
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
    let stream_result = streamer_handle
        .await
        .map_err(|e| RustFSError::Upload(anyhow!("stream_body error: {}", e)))??;
    let _ = uploader_handle.await;

    info!("validate checksum.");
    if let Some(c) = f.checksum.as_ref()
        && &stream_result.checksum != c
    {
        error!(
            expected = c,
            actual = stream_result.checksum,
            "checksum mismatch"
        );
        ctx.checksum_er = Some(ApiError::ChecksumMismatch);
        return Err(ApiError::ChecksumMismatch); // 422 unproccessible entity
    }
    info!("check real usage of file.");
    if s_info.storage_used_bytes + stream_result.file_size as i64 > s_info.storage_quota_bytes {
        ctx.exceed_quota = Some(ApiError::ObjectTooLarge);
        return Err(ApiError::ObjectTooLarge);
    }
    f.size(stream_result.file_size as i64);
    ctx.completed_part = Some(completed_parts);
    Ok(())
}

/// # ===== Stream body and buffer into parts =====
/// 1. collects bytes from  body into buffer.
/// 2. len(buffer) = 5MB -> wrap the 5MB bytes into Part type and send it using part_tx
fn spawn_body_streamer(
    body: Body,
    part_tx: mpsc::Sender<PartToUpload>,
) -> tokio::task::JoinHandle<Result<StreamResult, RustFSError>> {
    tokio::spawn(async move {
        debug!("consuming body.");
        let mut stream = body.into_data_stream();
        let mut buffer = BytesMut::new();
        let mut hasher = Sha256::new();
        let mut total_size = 0;
        let mut part_number = 1;

        loop {
            // Fill buffer to PART_SIZE
            while buffer.len() < PART_SIZE {
                match stream.next().await {
                    Some(Ok(chunk)) => {
                        hasher.update(&chunk);
                        total_size += chunk.len();
                        buffer.extend_from_slice(&chunk);
                    }
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
        let checksum = STANDARD.encode(hasher.finalize());
        let strs = StreamResult {
            checksum,
            file_size: total_size,
        };
        Ok(strs)
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
#[ironcmd(result)]
async fn complete_upload<'a>(
    client: &'a Client,
    upload_id: &'a str,
    upctx: Arc<Mutex<UploadContext>>,
) -> Result<(), RustFSError> {
    let mut upctxl = upctx.lock().await;
    let completed = CompletedMultipartUpload::builder()
        .set_parts(upctxl.completed_part.take())
        .build();
    let f = upctxl.file.as_mut().unwrap();

    let metadata_output = client
        .complete_multipart_upload()
        .bucket(f.bucket_name())
        .key(f.key())
        .upload_id(upload_id)
        .multipart_upload(completed)
        .send()
        .await
        .map_err(|e| RustFSError::Upload(anyhow!("Complete upload failed: {}", e)))
        .inspect_err(|e| error!("{}", e))?;
    info!("update object metadata with etag RustFS.");
    f.etag(metadata_output.e_tag.unwrap_or_default());
    f.last_modified(Utc::now());
    f.status(ObjectStatus::Active);
    Ok(())
}

/// ===== Abort multipart upload on error =====
/// - cleans any unfinshed upload on failure.
#[ironcmd(result)]
async fn abort_upload<'a, 'b, 'c>(
    client: &'a Client,
    bucket: &'b str,
    f_id: Uuid,
    upload_id: &'c str,
) -> Result<(), RustFSError> {
    client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(f_id.to_string())
        .upload_id(upload_id)
        .send()
        .await
        .map_err(|e| RustFSError::Upload(anyhow!("Abort upload failed: {}", e)))?;

    Ok(())
}
#[ironcmd(result)]
async fn insert_file_db<'a>(
    db_pool: &'a PgPool,
    upctx: Arc<Mutex<UploadContext>>,
) -> Result<(), DatabaseError> {
    let mut upctxl = upctx.lock().await;
    let f = upctxl.file.as_mut().unwrap();

    //-------- insert the object(file) information into the database-----------------------
    info!("updating file metadata info in database.");
    // if this fails → file exists in RustFS but DB not updated
    // not critical — can be reconciled later, or add delete_object fallback
    upsert_file(db_pool, f)
        .await
        .inspect_err(|e| error!("database updating metadata failed: {}", e))?;

    Ok(())
}
#[ironcmd(result)]
async fn delete_file_db<'a>(
    db_pool: &'a PgPool,
    upctx: Arc<Mutex<UploadContext>>,
) -> Result<(), DatabaseError> {
    info!("delete file because of unexpected failure.");
    let mut upctxl = upctx.lock().await;
    let f = upctxl.file.as_mut().unwrap();
    f.status(ObjectStatus::Deleted);
    upsert_file(db_pool, f)
        .await
        .inspect_err(|e| error!("database marking file as deleted failed: {}", e))?;
    Ok(())
}

#[ironcmd]
async fn temp_cmd() {}
#[derive(Default)]
struct UploadContext {
    pub completed_part: Option<Vec<CompletedPart>>,
    pub checksum_er: Option<ApiError>,
    pub exceed_quota: Option<ApiError>,
    pub file: Option<FileRecord>,
}

#[ironcmd(result)]
async fn increment_storage<'a>(
    con: &'a PgPool,
    user_id: Uuid,
    upctx: Arc<Mutex<UploadContext>>,
) -> Result<(), DatabaseError> {
    let upctxl = upctx.lock().await;
    increment_storage_used_for_user(con, user_id, upctxl.file.as_ref().unwrap().size).await?;
    Ok(())
}

#[ironcmd(result)]
async fn delete_file_rustfs<'a>(
    rfs_con: &'a Client,
    upctx: Arc<Mutex<UploadContext>>,
) -> anyhow::Result<()> {
    let up = upctx.lock().await;
    let f = up.file.as_ref().unwrap();
    rfs_con
        .delete_object()
        .bucket(f.bucket_name())
        .key(f.key())
        .send()
        .await?;
    Ok(())
}
