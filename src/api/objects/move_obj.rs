use axum::{Extension, Json, debug_handler, extract::State};

use crate::{ApiError, AppState, Claims, MoveRequest, MoveResponse, change_object_parent_id};
use tracing::{error, info, instrument};

/// Moves a file or folder to a new parent folder for the authenticated user by:
/// 1. Accepting a `MoveRequest` that specifies source id, destination id, and
///    object kind, then calling `change_object_parent_id` in Postgres with
///    the user id to perform the move.
/// 2. Inspecting the result flags to detect name conflicts or cyclic moves
///    (e.g., moving a folder into its own descendant) and returning
///    `Conflict` when such conditions are found.
/// 3. Returning `NotFound` when either the source or destination no longer
///    exists or is deleted.
/// 4. On success, wrapping the moved object id in `MoveResponse` and
///    returning it as JSON.
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
    info!("the object is {}.", mreq.object_kind);
    let mvresp = change_object_parent_id(
        &appstate.db_pool,
        claims.sub,
        mreq.source_id,
        mreq.destination_id,
        mreq.object_kind,
    )
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
