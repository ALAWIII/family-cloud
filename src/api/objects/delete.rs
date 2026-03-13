use anyhow::anyhow;
use axum::{Extension, Json, debug_handler, extract::State};
use itertools::{Either, Itertools};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ApiError, AppState, Claims, DatabaseError, DeleteJob, ObjectKind, delete_objects,
    send_delete_jobs_to_worker,
};
#[derive(Debug, Deserialize, Serialize)]
pub struct DeleteRequest {
    pub f_id: Uuid,
    pub kind: ObjectKind,
}

use tracing::{error, info, instrument};
#[debug_handler]
#[instrument(skip_all,fields(
    user_id=%claims.sub,
))]
pub async fn delete(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(f_list): Json<Vec<DeleteRequest>>,
) -> Result<Json<usize>, ApiError> {
    info!("start deleting process with {} items", f_list.len());
    if f_list.is_empty() {
        return Err(ApiError::BadRequest(anyhow!(
            "list is empty, no items to delete!"
        )));
    }
    let (folders, files): (Vec<_>, Vec<_>) = f_list.iter().partition_map(|v| {
        if v.kind.is_folder() {
            Either::Left(v.f_id)
        } else {
            Either::Right(v.f_id)
        }
    });
    info!(
        folders = folders.len(),
        files = files.len(),
        "filtering items into files/folders lists."
    );

    info!("sending delete_folders request to database.");
    let (folder_results, file_results) = tokio::join!(
        delete_objects(&appstate.db_pool, claims.sub, &folders, ObjectKind::Folder),
        delete_objects(&appstate.db_pool, claims.sub, &files, ObjectKind::File),
    );
    let to_job = |id| DeleteJob {
        f_id: id,
        bucket: claims.sub,
        account_deletion: false,
    };
    let folder_results = folder_results.map(|v| {
        v.ok_or(DatabaseError::DeleteBlocked(anyhow!(
            "delete job is blocked by at least one copy job."
        )))
        .inspect_err(|e| error!("{}", e))
    });
    let file_results = file_results.map(|v| v.unwrap_or_default());
    let files_list: Vec<DeleteJob> = match (folder_results, file_results) {
        (Err(f_e1), Err(_)) => return Err(f_e1.into()),
        (Ok(Err(f_e1)), Err(_)) => return Err(f_e1.into()),
        (Ok(Ok(list)), Err(e)) | (Ok(Err(e)), Ok(list)) | (Err(e), Ok(list)) => {
            error!("partial delete failure: {}", e);
            list.into_iter().map(to_job).collect()
        }
        (Ok(Ok(mut list1)), Ok(list2)) => {
            info!("collecting the new delete job files/folders lists into one list.");
            list1.extend(list2);
            list1.into_iter().map(to_job).collect()
        }
    };
    let length = files_list.len();
    info!(
        number_jobs = length,
        "start streaming all jobs to the delete worker."
    );
    send_delete_jobs_to_worker(files_list)
        .await
        .inspect_err(|e| error!("{}", e))?;
    info!("finish sending all jobs successfully.");
    Ok(Json(length))
}
