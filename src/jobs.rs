use crate::{JobError, delete_user_bucket, finalize_copy};
use anyhow::anyhow;
use apalis::{
    layers::retry::{
        RetryPolicy,
        backoff::{ExponentialBackoffMaker, MakeBackoff},
    },
    prelude::*,
};
use aws_sdk_s3::{
    error::ProvideErrorMetadata,
    types::{CompletedMultipartUpload, CompletedPart},
};
use std::{sync::OnceLock, time::Duration};

use apalis::layers::retry::HasherRng;
use apalis_codec::json::JsonCodec;
use apalis_postgres::{
    Config, PostgresStorage,
    shared::{SharedFetcher, SharedPostgresStorage},
};
use aws_sdk_s3::Client;
use futures::stream;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, prelude::FromRow};
use tokio::sync::mpsc::{self, Sender};
use tracing::{debug, error, instrument};
use uuid::Uuid;
type SharedStorage<J> = PostgresStorage<J, Vec<u8>, JsonCodec<Vec<u8>>, SharedFetcher>;

const MULTIPART_THRESHOLD: i64 = 4 * 1024 * 1024 * 1024;
static DELETE_SENDER: OnceLock<Sender<DeleteJob>> = OnceLock::new();
static COPY_SENDER: OnceLock<Sender<CopyJob>> = OnceLock::new();

#[instrument(skip_all)]
pub async fn init_apalis(con: &PgPool, rfs: Client, w_names: WorkersName) -> Result<(), JobError> {
    let jobstate = JobState {
        rfs_client: rfs,
        db_pool: con.clone(),
    };
    debug!("getting number of cpus.");
    let cpus = num_cpus::get();
    debug!("setting up job postgres table.");
    PostgresStorage::migrations()
        .set_ignore_missing(true)
        .run(con)
        .await
        .map_err(|e| {
            JobError::Postgres(anyhow::anyhow!(
                "failed to establish connection to db: {}",
                e
            ))
        })
        .inspect_err(|e| error!("{e}"))?;
    debug!("creating shared storage for multiple workers.");
    let mut store = SharedPostgresStorage::new(con.clone());
    let e_msg = "failed to create a shared backend: ";
    debug!("creating delete/copy backends for the two distinct jobs.");
    let delete_backend = store
        .make_shared_with_config(Config::new(&w_names.delete))
        .map_err(|e| JobError::SharedCreation(anyhow::anyhow!("{}{}", e_msg, e)))?;
    let copy_backend = store
        .make_shared_with_config(Config::new(&w_names.copy))
        .map_err(|e| JobError::SharedCreation(anyhow::anyhow!("{}{}", e_msg, e)))?;
    debug!("creating the back_off retry policy");
    let mut backoff_maker = ExponentialBackoffMaker::new(
        Duration::from_millis(1000),
        Duration::from_secs(64),
        1.25,
        HasherRng::default(),
    )
    .map_err(|e| JobError::Worker(anyhow::anyhow!("failed to create backoff: {}", e)))
    .inspect_err(|e| error!("{e}"))?;

    debug!("creating two workers for copy/delete jobs.");
    // add retry policy.
    let delete_worker = WorkerBuilder::new(w_names.delete)
        .backend(delete_backend.clone())
        .retry(RetryPolicy::retries(usize::MAX).with_backoff(backoff_maker.make_backoff()))
        .concurrency(cpus * 4)
        .data(jobstate.clone())
        .build(delete_file_rustfs);
    let copy_worker = WorkerBuilder::new(w_names.copy)
        .backend(copy_backend.clone())
        .retry(RetryPolicy::retries(usize::MAX).with_backoff(backoff_maker.make_backoff()))
        .concurrency(cpus * 4)
        .data(jobstate)
        .build(copy_file_rustfs);
    debug!("initalizing delete/copy channels.");
    init_delete_channel(delete_backend).await?;
    init_copy_channel(copy_backend).await?;
    debug!("starting the two workers in background.");

    tokio::spawn(async move {
        _ = tokio::try_join!(copy_worker.run(), delete_worker.run())
            .map_err(|e| JobError::Worker(anyhow::anyhow!("failed to run worker: {}", e)))
            .inspect_err(|e| error!("{}", e));
    });

    Ok(())
}
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DeleteJob {
    pub f_id: Uuid,
    pub bucket: Uuid,
    pub account_deletion: bool,
}
#[derive(Debug, Deserialize, Serialize, Clone, Copy, FromRow)]
pub struct FileId {
    pub id: Option<Uuid>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CopyJob {
    pub record: CopyJobRecord,
    pub bucket: Uuid, // user bucket.
}
#[derive(Debug, Deserialize, Serialize, Clone, FromRow)]
pub struct CopyJobRecord {
    pub source_file_id: Uuid, // the source file_id we want to copy its object.
    pub new_file_id: Uuid, // target name of the file wanted to name when copy the file that is name file_id, this field is needed in order to update he files table in database !!
    pub new_parent_folder_id: Uuid, // folder that will contain the file , this field is needed to update the database later with parent_id of target_file_id!!
}
#[derive(Debug, Clone)]
pub struct JobState {
    pub rfs_client: Client,
    pub db_pool: PgPool,
}
#[derive(Debug, Clone)]
pub struct WorkersName {
    pub delete: String,
    pub copy: String,
}
async fn delete_file_rustfs(
    job: DeleteJob,
    ctx: WorkerContext,
    jobstate: Data<JobState>,
) -> Result<(), BoxDynError> {
    debug!(worker_ready = ctx.is_ready(),file_id=?job.f_id,bucket=%job.bucket, "proccessing new delete job.");
    let bucket = job.bucket.to_string();
    let key = job.f_id.to_string();

    debug!("sending delete request to RustFS.");
    // No need to check existence first — delete_object is idempotent
    let d_resp = jobstate
        .rfs_client
        .delete_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await
        .inspect_err(
            |e| error!(f_id=?job.f_id,user_id=%job.bucket, "failed to delete from RustFS: {}", e),
        ); // only fails on transient errors → apalis retries
    if let Err(e) = d_resp
        && ![Some("NoSuchKey"), Some("NoSuchBucket")].contains(&e.code())
    {
        return Err(e.into());
    }

    if job.account_deletion {
        let delete_result = delete_user_bucket(&jobstate.rfs_client, job.bucket).await;
        if let Err(e) = delete_result
            && ![Some("BucketNotEmpty"), Some("NoSuchBucket")].contains(&e.code())
        {
            return Err(e.into());
        }
    }
    debug!("deleting file success.");
    Ok(())
}

async fn copy_file_rustfs(
    job: CopyJob,
    ctx: WorkerContext,
    jobstate: Data<JobState>,
) -> Result<(), BoxDynError> {
    debug!(worker_ready = ctx.is_ready(),
        file_id=%job.record.source_file_id,
        bucket=%job.bucket,
        dest_file_id=%job.record.new_file_id,
        parent_folder=%job.record.new_parent_folder_id,
        "proccessing new copy job."
    );
    let client = &jobstate.rfs_client;
    let bucket = job.bucket.to_string();
    let src_key = job.record.source_file_id.to_string();
    let dst_key = job.record.new_file_id.to_string();
    // 1. Check source exists — permanent failure if not
    debug!("asserting that the source file already exists.");
    let f_source_info = client
        .head_object()
        .bucket(&bucket)
        .key(&src_key)
        .send()
        .await;
    match f_source_info {
        Ok(_) => {} // exists, proceed
        Err(e) if e.as_service_error().is_some_and(|v| v.is_not_found()) => {
            // permanent — file genuinely doesn't exist
            tracing::warn!(file_id = %job.record.source_file_id, "source file/bucket not found, skipping");
            return Ok(());
        }
        Err(e) => {
            // transient — network/timeout, let apalis retry
            return Err(e.into());
        }
    }
    let f_source_info = f_source_info.unwrap();
    let size = f_source_info.content_length().unwrap_or(0);
    // 2. Always overwrite destination (handles partial + full copy cases)
    debug!(file_size = size, "sending copy object request to RustFS.");
    if size <= MULTIPART_THRESHOLD {
        client
            .copy_object()
            .bucket(&bucket)
            .copy_source(format!("{}/{}", bucket, src_key))
            .key(&dst_key)
            .send()
            .await
            .inspect_err(|e| error!("failed to copy object: {}", e))?; // transient failure — apalis retries
    } else {
        debug!(file_size = size, "create multi-part upload copy.");
        // Step 1: Initiate multipart upload — RustFS reserves a slot and returns an upload_id
        // All subsequent parts must reference this upload_id
        let upload = client
            .create_multipart_upload()
            .bucket(&bucket)
            .key(&dst_key)
            .send()
            .await?;
        let upload_id = upload.upload_id().unwrap();
        let resp = multipart_copy(client, &bucket, &src_key, &dst_key, size, upload_id).await;
        // if multipart_copy returns Err, abort the upload
        if let Err(e) = resp {
            error!(
                bucket = bucket,
                source_file = src_key,
                "error happend due copying object, cleaning orphaned parts : {}",
                e
            );
            let _ = client
                .abort_multipart_upload()
                .bucket(bucket)
                .key(dst_key)
                .upload_id(upload_id) // need to pass this out of the fn for this
                .send()
                .await;
            debug!("abortion success.");
            return Err(e);
        }
    }
    // update database and insert the new record in files!!
    debug!("marks file status as active and decrementing folder copying counter.");
    finalize_copy(
        &jobstate.db_pool,
        job.record.new_file_id,
        job.record.new_parent_folder_id,
    ) // marks the destination file as active !
    .await?;
    debug!("job copying success.");
    Ok(())
}
/// invoked once in the main function but kicked to a secondary thread to start consuming the channel.
async fn init_copy_channel(mut copy_pusher: SharedStorage<CopyJob>) -> Result<(), JobError> {
    debug!("creating the copyjob channel.");
    let (tx, mut rx) = mpsc::channel::<CopyJob>(1_000_000); // if copyJob size = 200 byte then 1000000*200 = 200 MB memory consumption
    COPY_SENDER
        .set(tx)
        .map_err(|_| JobError::AlreadyInitalized(anyhow!("copy sender already initalized.")))
        .inspect_err(|e| error!("{e}"))?;
    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(500);
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        debug!("start working and awaiting new copy jobs.");
        loop {
            tokio::select! {
                Some(job) = rx.recv() => {
                    batch.push(job);
                    if batch.len() >= 500 {
                        copy_pusher
                            .push_stream(&mut stream::iter(batch.drain(..)))
                            .await.ok();
                    }
                }
                _ = ticker.tick() => {
                    if !batch.is_empty() {
                        copy_pusher
                            .push_stream(&mut stream::iter(batch.drain(..)))
                            .await.ok();
                    }
                }
            }
        }
    });
    Ok(())
}

/// invoked once in the main function but kicked to a secondary thread to start consuming the channel.
async fn init_delete_channel(mut delete_pusher: SharedStorage<DeleteJob>) -> Result<(), JobError> {
    debug!("creating deletJob channel.");
    let (tx, mut rx) = mpsc::channel::<DeleteJob>(1_000_000); // if deletejob size = 100 bytes then 1000000*100 = 100 MB memory
    DELETE_SENDER
        .set(tx)
        .map_err(|_| JobError::AlreadyInitalized(anyhow!("delete sender already initalized.")))
        .inspect_err(|e| error!("{e}"))?;

    tokio::spawn(async move {
        let mut batch = Vec::with_capacity(500);
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        debug!("start working and awaiting new delete jobs.");
        loop {
            tokio::select! {
                Some(job) = rx.recv() => {
                    batch.push(job);
                    if batch.len() >= 500 {
                        delete_pusher
                            .push_stream(&mut stream::iter(batch.drain(..)))
                            .await.ok();
                    }
                }
                _ = ticker.tick() => {
                    if !batch.is_empty() {
                        delete_pusher
                            .push_stream(&mut stream::iter(batch.drain(..)))
                            .await.ok();
                    }
                }
            }
        }
    });
    Ok(())
}
/// invoked in the delete endpoint only!!
pub async fn send_delete_jobs_to_worker(f_ids: Vec<DeleteJob>) -> Result<(), JobError> {
    let snd = DELETE_SENDER.get().ok_or(JobError::NotInitalized(anyhow!(
        "Delete sender not initalized yet"
    )))?;
    for id in f_ids {
        snd.send(id)
            .await
            .map_err(|e| JobError::Send(anyhow!("Sending delete job error: {}", e)))?;
    }
    Ok(())
}

/// invoked in the copy endpoint only!!
pub async fn send_copy_jobs_to_worker(f_ids: Vec<CopyJob>) -> Result<(), JobError> {
    let snd = COPY_SENDER.get().ok_or(JobError::NotInitalized(anyhow!(
        "Copy sender not initalized yet"
    )))?;
    for id in f_ids {
        snd.send(id)
            .await
            .map_err(|e| JobError::Send(anyhow!("Sending copy job error: {}", e)))?;
    }
    Ok(())
}

const PART_SIZE: i64 = 100 * 1024 * 1024; // 100MB per part (min 5MB, max 5GB)

pub async fn multipart_copy(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    src_key: &str,
    dst_key: &str,
    file_size: i64,
    upload_id: &str,
) -> Result<(), BoxDynError> {
    debug!("start multipart copy.");
    let mut completed_parts: Vec<CompletedPart> = Vec::new();
    // byte_offset serves as the starting byte on every new part copy request and tracks where the next part starts.
    let mut byte_offset: i64 = 0;
    let mut part_number: i32 = 1;

    // Step 2: Copy the source object in 100MB chunks
    // Each part is a server-side range copy — no data flows through your app
    while byte_offset < file_size {
        // Calculate inclusive end byte for this part; clamp to last valid byte (file_size - 1) to avoid out-of-bounds range
        let end = (byte_offset + PART_SIZE - 1).min(file_size - 1);
        debug!(
            part_number = part_number,
            start_byte = byte_offset,
            end_byte = end,
            "requesting a copy for a given part"
        );
        let part_result = client
            .upload_part_copy()
            .bucket(bucket)
            .key(dst_key)
            .upload_id(upload_id)
            .copy_source(format!("{}/{}", bucket, src_key))
            .copy_source_range(format!("bytes={}-{}", byte_offset, end)) // byte range of source
            .part_number(part_number)
            .send()
            .await?;
        debug!("extracting the etag from the response.");
        // Collect the ETag returned for each part — required for the final complete call
        let etag = part_result
            .copy_part_result()
            .and_then(|r| r.e_tag())
            .unwrap_or_default()
            .to_string();
        debug!("storing a new finished part.");
        completed_parts.push(
            CompletedPart::builder()
                .e_tag(etag)
                .part_number(part_number)
                .build(),
        );
        debug!("incrementing the part_number and the byte_offset.");
        byte_offset = end + 1;
        part_number += 1;
    }

    // Step 3: Finalize — tell RustFS to assemble all parts into one object
    // Until this call, the destination object does NOT exist yet
    debug!("running complete multipart upload copy request.");
    client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(dst_key)
        .upload_id(upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(completed_parts))
                .build(),
        )
        .send()
        .await?;
    debug!("copying new object success.");
    Ok(())
}
