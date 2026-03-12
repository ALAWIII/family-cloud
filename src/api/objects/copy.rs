use anyhow::anyhow;
use axum::{Extension, Json, debug_handler, extract::State};
use itertools::{Either, Itertools};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ApiError, AppState, Claims, CopyJob, ObjectKind, copy_objects, send_copy_jobs_to_worker,
};
use tracing::{error, info, instrument};
#[debug_handler]
#[instrument(skip_all, fields(
    user_id=%claims.sub,
    dest_folder_id=%copy_list.dest_folder_id
))]
pub async fn copy(
    State(appstate): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(copy_list): Json<CopyRequest>,
) -> Result<Json<usize>, ApiError> {
    info!("start new copy transaction.");
    if copy_list.f_list.is_empty() {
        return Err(ApiError::BadRequest(anyhow!(
            "list is empty, no items to copy!"
        )));
    }
    let (folders, files): (Vec<_>, Vec<_>) = copy_list.f_list.iter().partition_map(|v| {
        if v.kind.is_folder() {
            Either::Left(v.f_id)
        } else {
            Either::Right(v.f_id)
        }
    });

    info!(
        files_count = files.len(),
        folders_count = folders.len(),
        "filterd files and folders."
    );
    info!("fetching all files ids of folders recursively and mark files as copying in database.");

    let (folder_results, file_results) = tokio::join!(
        copy_objects(
            &appstate.db_pool,
            &folders,
            copy_list.dest_folder_id,
            claims.sub,
            true,
        ),
        copy_objects(
            &appstate.db_pool,
            &files,
            copy_list.dest_folder_id,
            claims.sub,
            false,
        )
    );

    let list: Vec<CopyJob> = match (folder_results, file_results) {
        (Err(e1), Err(_)) => return Err(e1.into()),
        (Ok(f), Err(_)) | (Err(_), Ok(f)) => f,
        (Ok(mut f1), Ok(f2)) => {
            f1.extend(f2);
            f1
        }
    }
    .into_iter()
    .map(|v| CopyJob {
        record: v,
        bucket: claims.sub,
    })
    .collect();

    let length = list.len();
    info!("sending list of copy jobs to appropriate worker.");
    send_copy_jobs_to_worker(list)
        .await
        .inspect_err(|e| error!("{e}"))?;
    info!("copying files success.");
    Ok(Json(length))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CopyRequest {
    pub dest_folder_id: Uuid,
    pub f_list: Vec<CopyItemRequest>,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct CopyItemRequest {
    pub f_id: Uuid,
    pub kind: ObjectKind,
}
