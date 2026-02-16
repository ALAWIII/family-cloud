use axum::{
    Extension, Json, debug_handler,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info, instrument};
use uuid::Uuid;

use crate::{
    ApiError, AppState, Claims, ObjectRecord, fetch_all_object_info, fetch_all_user_objects_ids,
    update_object_metadata_db,
};
#[instrument(skip_all,fields(
    user_id=%claims.sub,
))]
pub async fn list_objects(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
) -> Result<Json<Vec<Uuid>>, ApiError> {
    info!("sending all objects id's for user: {}", claims.sub);
    Ok(fetch_all_user_objects_ids(&appstate.db_pool, claims.sub)
        .await
        .map(Json)
        .inspect_err(|e| error!("{}", e))?)
}

#[instrument(skip_all,fields(
    user_id=%claims.sub,
    file_id=%f_id,
))]
pub async fn get_metadata(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Path(f_id): Path<Uuid>,
) -> Result<Json<ObjectRecord>, ApiError> {
    info!("fetching metadata for a given file_id:{}", f_id);
    // it will search postgres if the file is 'active' and the claims.sub=user_id .
    fetch_all_object_info(&appstate.db_pool, f_id, claims.sub)
        .await
        .inspect_err(|e| error!("{}", e))?
        .ok_or(ApiError::NotFound)
        .inspect_err(|e| error!("{}", e))
        .map(Json)
}

#[instrument(skip_all,fields(
    user_id=%claims.sub,
    file_id=%f_id,
))]
#[debug_handler]
pub async fn update_metadata(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Path(f_id): Path<Uuid>,
    Json(metadata): Json<UpdateMetadata>,
) -> Result<Json<UpdateMetadata>, ApiError> {
    info!("updating file metadata id:{}", f_id);
    Ok(
        update_object_metadata_db(&appstate.db_pool, f_id, claims.sub, metadata)
            .await
            .map(Json)
            .inspect_err(|e| error!("{}", e))?,
    )
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateMetadata {
    pub metadata: serde_json::Value,
}
