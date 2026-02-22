use axum::{
    Extension, Json, debug_handler,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument};
use uuid::Uuid;

use crate::{
    ApiError, AppState, Claims, ObjectKind, ObjectKindQuery, fetch_all_user_object_ids,
    fetch_file_info, fetch_folder_info, update_file_metadata,
};
#[instrument(skip_all,fields(
    user_id=%claims.sub,
))]
pub async fn list_objects(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
) -> Result<Json<Vec<Uuid>>, ApiError> {
    info!("sending all objects id's for user: {}", claims.sub);
    Ok(fetch_all_user_object_ids(&appstate.db_pool, claims.sub)
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
    Query(query): Query<ObjectKindQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // it will search postgres if the file is 'active' and the claims.sub=user_id .
    let result = match query.kind {
        ObjectKind::File => fetch_file_info(&appstate.db_pool, f_id, claims.sub)
            .await
            .map(|opt| opt.map(IntoResponse::into_response)),
        ObjectKind::Folder => fetch_folder_info(&appstate.db_pool, f_id, claims.sub)
            .await
            .map(|opt| opt.map(IntoResponse::into_response)),
    };

    result
        .inspect_err(|e| error!("{}", e))?
        .ok_or(ApiError::NotFound)
        .inspect_err(|e| error!("{}", e))
}

/// folders table has no metadata field, only the files table has it!!
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
        update_file_metadata(&appstate.db_pool, claims.sub, f_id, metadata.metadata)
            .await
            .map(Json)
            .inspect_err(|e| error!("{}", e))?,
    )
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateMetadata {
    pub metadata: serde_json::Value,
}
impl UpdateMetadata {
    pub fn new(metadata: serde_json::Value) -> Self {
        Self { metadata }
    }
}
