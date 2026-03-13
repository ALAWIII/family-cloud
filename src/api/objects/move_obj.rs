use axum::{Extension, Json, debug_handler, extract::State};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, prelude::FromRow};
use uuid::Uuid;

use crate::{ApiError, AppState, Claims, DatabaseError, ObjectKind};
use tracing::{error, info, instrument};

static MOVE_FILE: &str = include_str!("../../../db_queries/move_file.sql");
static MOVE_FOLDER: &str = include_str!("../../../db_queries/move_folder.sql");

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveRequest {
    pub source_id: Uuid,
    pub destination_id: Uuid,
    pub object_kind: ObjectKind,
}
#[derive(Debug, Serialize)]
pub struct MoveResponse {
    pub f_id: Uuid,
}
#[derive(Debug, Deserialize, FromRow)]
pub struct MoveDbResponse {
    pub moved_id: Option<Uuid>,
    pub not_found: bool,
    pub conflict: bool,
}

#[debug_handler]
#[instrument(skip_all,fields(
    user_id=%claims.sub,
    move_request=?mreq
))]
pub async fn move_object(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(mreq): Json<MoveRequest>,
) -> Result<Json<MoveResponse>, ApiError> {
    info!("starting new moving request.");
    let mvresp = if mreq.object_kind.is_folder() {
        info!("the object is folder.");
        change_object_parent_id(
            &appstate.db_pool,
            claims.sub,
            mreq.source_id,
            mreq.destination_id,
            MOVE_FOLDER,
        )
    } else {
        info!("the object is file.");
        change_object_parent_id(
            &appstate.db_pool,
            claims.sub,
            mreq.source_id,
            mreq.destination_id,
            MOVE_FILE,
        )
    }
    .await?;
    if mvresp.moved_id.is_none() {
        if mvresp.conflict {
            error!(
                "discoverd a name file/folder conflict or cyclic refernces source_id>=destination_id (the destination is a child of soruce folder.)."
            );
            return Err(ApiError::Conflict);
        }
        if mvresp.not_found {
            error!("either the source or destination are not found or deleted.");
            return Err(ApiError::NotFound);
        }
    }
    let resp = MoveResponse {
        f_id: mvresp.moved_id.unwrap(),
    };
    info!("move file/folder success.");
    Ok(Json(resp))
}

pub async fn change_object_parent_id(
    con: &PgPool,
    owner_id: Uuid,
    source_id: Uuid,
    dest_folder_id: Uuid,
    query: &str,
) -> Result<MoveDbResponse, DatabaseError> {
    let v = sqlx::query_as::<_, MoveDbResponse>(query)
        .bind(source_id)
        .bind(owner_id)
        .bind(dest_folder_id)
        .fetch_one(con)
        .await
        .inspect_err(|e| error!("failed to execute change parent query: {}", e))?;
    Ok(v)
}
