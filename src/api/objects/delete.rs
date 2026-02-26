use anyhow::anyhow;
use axum::{Extension, Json, debug_handler, extract::State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ApiError, AppState, Claims, DeleteJob, JobError, ObjectKind, delete_files, delete_folders,
    send_delete_jobs_to_worker,
};
use tracing::{error, info, instrument};
#[debug_handler]
#[instrument(skip_all,fields(
    user_id=%claims.sub,
))]
pub async fn delete(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(f_list): Json<Vec<DeleteRequest>>,
) -> Result<(), ApiError> {
    info!("start deleting process with {} items", f_list.len());
    if f_list.is_empty() {
        return Err(ApiError::BadRequest(anyhow!(
            "list is empty, no items to delete!"
        )));
    }
    let folders = f_list
        .iter()
        .filter(|v| v.kind.is_folder())
        .map(|v| v.f_id)
        .collect::<Vec<_>>();
    let files = f_list
        .iter()
        .filter(|v| !v.kind.is_folder())
        .map(|v| v.f_id)
        .collect::<Vec<_>>();
    info!(
        folders = folders.len(),
        files = files.len(),
        "filtering items into files/folders lists."
    );
    info!("sending delete_folders request to database.");
    let (folder_results, file_results) = tokio::join!(
        delete_folders(&appstate.db_pool, claims.sub, &folders),
        delete_files(&appstate.db_pool, claims.sub, &files)
    );
    let folder_results = folder_results.map(|v| {
        v.ok_or(JobError::DeleteBlocked(anyhow!(
            "delete job is blocked by at least one copy job."
        )))
        .inspect_err(|e| error!("{}", e))
    });
    let files_list: Vec<DeleteJob> = match (folder_results, file_results) {
        (Err(f_e1), Err(_)) => return Err(f_e1.into()),
        (Ok(Err(f_e1)), Err(_)) => return Err(f_e1.into()),
        (Ok(Ok(list)), Err(_)) | (Ok(Err(_)), Ok(list)) | (Err(_), Ok(list)) => list
            .into_iter()
            .map(|v| DeleteJob {
                record: v,
                bucket: claims.sub,
            })
            .collect(),
        (Ok(Ok(mut list1)), Ok(list2)) => {
            info!("collecting the new delete job files/folders lists into one list.");
            list1.extend(list2);
            list1
                .into_iter()
                .map(|v| DeleteJob {
                    record: v,
                    bucket: claims.sub,
                })
                .collect()
        }
    };

    info!(
        number_jobs = files_list.len(),
        "start streaming all jobs to the delete worker."
    );
    send_delete_jobs_to_worker(files_list)
        .await
        .inspect_err(|e| error!("{}", e))?;
    info!("finish sending all jobs successfully.");
    Ok(())
}
#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteRequest {
    pub f_id: Uuid,
    pub kind: ObjectKind,
}
