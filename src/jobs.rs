use std::{sync::OnceLock, time::Duration};

use crate::{JobError, decrement_delete_count_folder, finalize_copy};
use anyhow::anyhow;
use apalis::{
    layers::retry::{
        RetryPolicy,
        backoff::{ExponentialBackoffMaker, MakeBackoff},
    },
    prelude::*,
};

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
    PostgresStorage::setup(con)
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
    pub record: DeleteJobRecord,
    pub bucket: Uuid,
}
#[derive(Debug, Deserialize, Serialize, Clone, FromRow)]
pub struct DeleteJobRecord {
    pub id: Option<Uuid>,
    pub parent_id: Option<Uuid>,
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
    debug!(worker_ready = ctx.is_ready(),file_id=?job.record.id,bucket=%job.bucket, "proccessing new delete job.");
    let bucket = job.bucket.to_string();
    let key = job.record.id.unwrap().to_string();

    debug!("sending delete request to RustFS.");
    // No need to check existence first — delete_object is idempotent
    jobstate
        .rfs_client
        .delete_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await.inspect_err(|e|
            error!(f_id=?job.record.id,user_id=%job.bucket, "failed to delete from RustFS: {}", e))?; // only fails on transient errors → apalis retries
    // Update DB: mark file as deleted
    debug!("decrement the folder delete child counter.");
    decrement_delete_count_folder(&jobstate.db_pool, job.record.parent_id.unwrap())
        .await
        .inspect_err(|e| error!("failed to decrement delete counter: {}", e))?;
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
            tracing::warn!(file_id = %job.record.source_file_id, "source file not found, skipping");
            return Ok(());
        }
        Err(e) => {
            // transient — network/timeout, let apalis retry
            return Err(e.into());
        }
    }
    // 2. Always overwrite destination (handles partial + full copy cases)
    debug!("sending copy object request to RustFS.");
    client
        .copy_object()
        .bucket(&bucket)
        .copy_source(format!("{}/{}", bucket, src_key))
        .key(&dst_key)
        .send()
        .await
        .inspect_err(|e| error!("failed to copy object: {}", e))?; // transient failure — apalis retries
    // update database and insert the new record in files!!
    debug!("marks file status as active and decrementing folder copying counter.");
    finalize_copy(
        &jobstate.db_pool,
        job.record.new_file_id,
        job.record.new_parent_folder_id,
    ) // marks the destination file as active !
    .await
    .inspect_err(|e| {
        error!("failed to set active status or to decrement folder copy counter: {e}")
    })?;
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
