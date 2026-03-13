use crate::{
    CopyJobRecord, DatabaseError, FileDownload, FileId, FileRecord, FolderChild, FolderRecord,
    ObjectKind, UpdateMetadata,
};
use anyhow::anyhow;
use serde::de::DeserializeOwned;
use sqlx::{
    FromRow,
    postgres::{PgPool, PgQueryResult, PgRow},
};
use tracing::error;
use uuid::Uuid;
static DELETE_FILES: &str = include_str!("../../db_queries/delete_files.sql");
static DELETE_FOLDERS: &str = include_str!("../../db_queries/delete_folders.sql");
static COPY_FILES: &str = include_str!("../../db_queries/copy_files.sql");
static COPY_FOLDERS: &str = include_str!("../../db_queries/copy_folders.sql");
static STREAM_FOLDER: &str = include_str!("../../db_queries/stream_folder.sql");
static VALIDATE_FILE_QUERY: &str = include_str!("../../db_queries/validate_file_ancestor.sql");
static VALIDATE_FOLDER_QUERY: &str = include_str!("../../db_queries/validate_folder_ancestor.sql");
static FOLDER_INFO: &str = r#"
SELECT *
FROM folders
WHERE id = $1 AND owner_id = $2 AND status in ('active','copying')
"#;
static FILE_INFO: &str = r#"
SELECT *
FROM files
WHERE id = $1 AND owner_id = $2 AND status in ('active','copying')
"#;
static FILE_EXISTENCE: &str = r#"
SELECT id
FROM files
WHERE parent_id=$1 AND owner_id=$2 AND status !='deleted' AND name=$3
"#;
static FOLDER_EXISTENCE: &str = r#"
SELECT id
FROM folders
WHERE parent_id=$1 AND owner_id=$2 AND status !='deleted' AND name=$3
"#;
static UPSERT_FILE: &str = r#"
INSERT INTO files(
    id, owner_id, parent_id, name, size, etag, mime_type,
    last_modified, created_at, deleted_at, metadata, status, visibility, checksum
)
VALUES(
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13, $14
)
ON CONFLICT (id) DO UPDATE SET
    name          = EXCLUDED.name,
    size          = EXCLUDED.size,
    etag          = EXCLUDED.etag,
    mime_type     = EXCLUDED.mime_type,
    last_modified = EXCLUDED.last_modified,
    deleted_at    = EXCLUDED.deleted_at,
    metadata      = EXCLUDED.metadata,
    status        = EXCLUDED.status,
    visibility    = EXCLUDED.visibility,
    checksum      = EXCLUDED.checksum
"#;

/// gets the metadata of an object by its id and the owner_id. T either FileRecord or FolderRecord.
pub async fn fetch_obj_info<T>(
    con: &PgPool,
    obj_id: Uuid,
    owner_id: Uuid,
    kind: ObjectKind,
) -> Result<Option<T>, DatabaseError>
where
    T: DeserializeOwned + for<'r> FromRow<'r, PgRow> + Send + Unpin,
{
    let rec = sqlx::query_as::<_, T>(if kind.is_folder() {
        FOLDER_INFO
    } else {
        FILE_INFO
    })
    .bind(obj_id)
    .bind(owner_id)
    .fetch_optional(con)
    .await
    .inspect_err(|e| error!("failed to fetch {} info: {e}", kind))?;

    Ok(rec)
}
/// insert new file or update if already exists.
pub async fn upsert_file(con: &PgPool, file: &FileRecord) -> Result<PgQueryResult, DatabaseError> {
    Ok(sqlx::query(UPSERT_FILE)
        .bind(file.id)
        .bind(file.owner_id)
        .bind(file.parent_id)
        .bind(&file.name)
        .bind(file.size)
        .bind(&file.etag)
        .bind(&file.mime_type)
        .bind(file.last_modified)
        .bind(file.created_at)
        .bind(file.deleted_at)
        .bind(&file.metadata)
        .bind(&file.status)
        .bind(&file.visibility)
        .bind(&file.checksum)
        .execute(con)
        .await
        .inspect_err(|e| error!("failed to insert or update file: {e}"))?)
}

/// used to add a logical folder in database when user request to upload folder.
pub async fn insert_folder(
    con: &PgPool,
    folder: &FolderRecord,
) -> Result<PgQueryResult, DatabaseError> {
    Ok(sqlx::query(
        r#"
            INSERT INTO folders(
            id, owner_id, parent_id, name, created_at, deleted_at, status, visibility
            )
            VALUES(
            $1, $2, $3, $4, $5, $6, $7,$8 )
            "#,
    )
    .bind(folder.id)
    .bind(folder.owner_id)
    .bind(folder.parent_id)
    .bind(&folder.name)
    .bind(folder.created_at)
    .bind(folder.deleted_at)
    .bind(&folder.status)
    .bind(&folder.visibility)
    .execute(con)
    .await
    .inspect_err(|e| error!("failed to insert folder: {}", e))?)
}

/// for searching if a given file/folder id exists and active in db.
pub async fn is_obj_exists(
    con: &PgPool,
    owner_id: Uuid,
    parent_id: Uuid,
    name: &str,
    kind: ObjectKind,
) -> Result<Option<Uuid>, DatabaseError> {
    let q = if kind.is_folder() {
        FOLDER_EXISTENCE
    } else {
        FILE_EXISTENCE
    };
    Ok(sqlx::query_scalar::<_, Uuid>(q)
        .bind(parent_id)
        .bind(owner_id)
        .bind(name)
        .fetch_optional(con)
        .await
        .inspect_err(|e| error!("failed to query if {} exists: {e}", kind))?)
}

/// used to obtain all user file/folder ids for syncing purposes.
pub async fn fetch_all_user_object_ids(
    con: &PgPool,
    owner_id: Uuid,
) -> Result<Vec<FolderChild>, DatabaseError> {
    Ok(sqlx::query_as::<_, FolderChild>(
        r#"
        SELECT id, 'file'::text as kind FROM files  WHERE owner_id = $1 AND status='active'
        UNION ALL
        SELECT id, 'folder'::text as kind FROM folders WHERE owner_id = $1 AND status='active'
        "#,
    )
    .bind(owner_id)
    .fetch_all(con)
    .await
    .inspect_err(|e| error!("failed to get all user object ids: {e}"))?)
}
/// used to modify/update the metadata field of a file.
pub async fn update_file_metadata(
    con: &PgPool,
    owner_id: Uuid,
    f_id: Uuid,
    metadata: serde_json::Value,
) -> Result<UpdateMetadata, DatabaseError> {
    sqlx::query!(
        r#"
        UPDATE files
        SET metadata = COALESCE(metadata, '{}'::jsonb) || $1
        WHERE id = $2 AND owner_id = $3
        RETURNING metadata
        "#,
        metadata,
        f_id,
        owner_id
    )
    .fetch_optional(con)
    .await
    .inspect_err(|e| error!("failed to update file metadata: {e}"))?
    .ok_or(DatabaseError::NotFound(anyhow!("update metadata faliled")))
    .inspect_err(|e| error!("{e}")) // row didn't exist or wrong owner
    .map(|v| UpdateMetadata::new(v.metadata.unwrap_or(metadata)))
}

/// used to get all ids of active files from database to prepare them for streaming/downloading.
pub async fn fetch_all_file_ids_paths(
    con: &PgPool,
    owner_id: Uuid,
    folder_id: Uuid,
) -> Result<Vec<FileDownload>, DatabaseError> {
    let files = sqlx::query_as::<_, FileDownload>(STREAM_FOLDER)
        .bind(folder_id) // $1
        .bind(owner_id) // $2
        .fetch_all(con)
        .await
        .inspect_err(|e| error!("failed fetching all files: {e}"))?;

    Ok(files)
}
/// used in the copy job handler for marking the copying file as active and decrementing its parent copying children count by 1 , so that releasing the lock of modifing the file in database.
pub async fn finalize_copy(
    pool: &PgPool,
    file_id: Uuid,
    folder_id: Uuid,
) -> Result<(), DatabaseError> {
    let mut tx = pool
        .begin()
        .await
        .inspect_err(|e| error!("failed to start finalize copy transaction: {}", e))?;

    sqlx::query!(
        "UPDATE files SET status = 'active' WHERE id = $1 AND status = 'copying'",
        file_id
    )
    .execute(&mut *tx)
    .await
    .inspect_err(|e| error!("failed to mark file as active: {}", e))?;

    sqlx::query!(
        r#"UPDATE folders
        SET copying_children_count = GREATEST(copying_children_count - 1, 0)
        WHERE id = $1"#,
        folder_id
    )
    .execute(&mut *tx)
    .await
    .inspect_err(|e| error!("failed to decrement folder copying_children_count: {}", e))?;

    tx.commit()
        .await
        .inspect_err(|e| error!("failed to commit finalize copy transaction: {}", e))?;
    Ok(())
}

/// accepts a list of folders/files and then tries to mark the folders and their files as deleted recursively and returns all files ids that are decendant of the deleted folders.
///
/// accepts a list of files ids and then marks all of them as deleted.
pub async fn delete_objects(
    con: &PgPool,
    owner_id: Uuid,
    objects: &[Uuid],
    kind: ObjectKind,
) -> Result<Option<Vec<Uuid>>, DatabaseError> {
    if objects.is_empty() {
        return Ok(Some(vec![]));
    }
    let mut tx = con
        .begin()
        .await
        .inspect_err(|e| error!("failed to start delete {} transaction: {}", kind, e))?;

    let files_id: Vec<FileId> = sqlx::query_as::<_, FileId>(if kind.is_folder() {
        DELETE_FOLDERS
    } else {
        DELETE_FILES
    })
    .bind(objects)
    .bind(owner_id)
    .fetch_all(&mut *tx)
    .await
    .inspect_err(|e| error!("failed to execute delete {} query: {}", kind, e))?;

    tx.commit()
        .await
        .inspect_err(|e| error!("failed to commit delete {} transaction: {}", kind, e))?;
    if kind.is_folder() && files_id.first().is_some_and(|v| v.id.is_none()) {
        return Ok(None);
    }
    Ok(Some(files_id.into_iter().filter_map(|f| f.id).collect()))
}

/// accepts list of files or folders and then replicate them under the target destination.
pub async fn copy_objects(
    con: &PgPool,
    objects_ids: &[Uuid],
    dest_folder_id: Uuid, // the new parent id to be attached to the
    owner_id: Uuid,
    is_folder: bool,
) -> Result<Vec<CopyJobRecord>, DatabaseError> {
    if objects_ids.is_empty() {
        return Ok(vec![]);
    }
    let mut tx = con
        .begin()
        .await
        .inspect_err(|e| error!("failed to start copy {} transaction: {}", is_folder, e))?;

    let files_id: Vec<CopyJobRecord> =
        sqlx::query_as::<_, CopyJobRecord>(if is_folder { COPY_FOLDERS } else { COPY_FILES })
            .bind(objects_ids)
            .bind(dest_folder_id)
            .bind(owner_id)
            .fetch_all(&mut *tx)
            .await
            .inspect_err(|e| error!("failed to execute copy {} query: {}", is_folder, e))?;

    tx.commit()
        .await
        .inspect_err(|e| error!("failed to commit copy {} transaction: {}", is_folder, e))?;
    Ok(files_id)
}
/// accepts folder id and fetches all its direct children as a response.
pub async fn fetch_folder_children(
    con: &PgPool,
    f_id: Uuid,
    owner_id: Uuid,
) -> Result<Vec<FolderChild>, DatabaseError> {
    Ok(sqlx::query_as::<_, FolderChild>(
        r#"
        SELECT id, 'file'::text AS kind FROM files WHERE parent_id=$1 AND owner_id=$2 AND status='active'
        UNION ALL
        SELECT id, 'folder'::text as kind FROM folders WHERE parent_id=$1 AND owner_id=$2 AND status='active'
        "#,
    )
    .bind(f_id)
    .bind(owner_id)
    .fetch_all(con)
    .await.inspect_err(|e|error!("failed to get all folder children: {e}"))?)
}
/// used in sharing purposes to validate if a given object id is within the shared scooped token .
pub async fn validate_object_ancestor<T>(
    con: &PgPool,
    owner_id: Uuid,
    grand_p_id: Uuid,
    f_id: Uuid,
    kind: ObjectKind,
) -> Result<Option<T>, DatabaseError>
where
    T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
{
    let query = if kind.is_folder() {
        VALIDATE_FOLDER_QUERY
    } else {
        VALIDATE_FILE_QUERY
    };
    let r = sqlx::query_as::<_, T>(query)
        .bind(f_id)
        .bind(owner_id)
        .bind(grand_p_id)
        .fetch_optional(con)
        .await
        .inspect_err(|e| {
            error!("failed to execute validate child and obtain folder metadata and children : {e}")
        })?;
    Ok(r)
}
