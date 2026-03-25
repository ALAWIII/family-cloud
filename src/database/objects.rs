use crate::{
    CopyJobRecord, DatabaseError, FileDownload, FileId, FileRecord, FolderChild, FolderRecord,
    MoveDbResponse, ObjectKind, UpdateMetadata,
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
static MOVE_FILE: &str = include_str!("../../db_queries/move_file.sql");
static MOVE_FOLDER: &str = include_str!("../../db_queries/move_folder.sql");

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

/// Fetches metadata for a single file or folder owned by a given user by:
/// 1. Selecting from `files` or `folders` based on `kind`, restricted to
///    `status IN ('active','copying')`.
/// 2. Filtering by `id` and `owner_id` to enforce ownership.
/// 3. Returning `Ok(Some(T))` when found, or `Ok(None)` if no matching
///    active object exists.
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
/// Inserts or updates a file row in the `files` table by:
/// 1. Executing an `INSERT ... ON CONFLICT (id) DO UPDATE` using all
///    fields from `FileRecord`.
/// 2. Updating key mutable columns on conflict (name, size, etag,
///    mime_type, timestamps, metadata, status, visibility, checksum).
/// 3. Returning the underlying `PgQueryResult` for callers that need
///    affected‑row information.
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

/// Inserts a new logical folder row into the `folders` table by:
/// 1. Writing id, owner, parent, name, timestamps, status, and visibility
///    from the provided `FolderRecord`.
/// 2. Returning the `PgQueryResult`, or a `DatabaseError` if insertion
///    fails (e.g., constraint violations).
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

/// Checks whether an active file or folder with the given name already
/// exists under a specific parent for an owner by:
/// 1. Choosing the appropriate existence query (files or folders) based on
///    `kind`.
/// 2. Filtering by `parent_id`, `owner_id`, `name`, and `status != 'deleted'`.
/// 3. Returning `Some(id)` when a conflicting object exists, or `None`
///    otherwise.
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

/// Returns all active file and folder ids for a user, used for client sync
/// or reconciliation, by:
/// 1. Selecting active file ids from `files` and active folder ids from
///    `folders` for the given `owner_id`.
/// 2. Tagging each row with a logical `kind` (`'file'` or `'folder'`) and
///    mapping into `FolderChild`.
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
/// Merges new metadata into a file’s `metadata` JSONB column by:
/// 1. Running an `UPDATE` that does `metadata = COALESCE(metadata, '{}') || $1`
///    for the given `id` and `owner_id`.
/// 2. Returning `NotFound` if no matching row exists (wrong id or owner).
/// 3. Wrapping the resulting JSONB in `UpdateMetadata`, using the input
///    value as a fallback when the DB returns `NULL`.
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

/// Fetches all active files under a folder (recursively) with their full
/// paths for streaming/downloading by:
/// 1. Executing the `STREAM_FOLDER` SQL against `files` with the target
///    `folder_id` and `owner_id`.
/// 2. Returning a list of `FileDownload` records that contain object keys
///    and ZIP path information.
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
/// Finalizes a copy operation for a single file by:
/// 1. Starting a DB transaction.
/// 2. Updating the file’s `status` from `copying` to `active`.
/// 3. Decrementing the parent folder’s `copying_children_count` (never
///    below zero) to release modification locks.
/// 4. Committing the transaction, or returning an error if any step fails.
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

/// Marks files or whole folder subtrees as deleted and returns affected
/// file ids by:
/// 1. Early‑returning an empty `Some(vec![])` when `objects` is empty.
/// 2. Starting a transaction and running either `DELETE_FOLDERS` (for
///    recursive folder deletes) or `DELETE_FILES` based on `kind`.
/// 3. Collecting `FileId` rows and committing the transaction.
/// 4. For folder deletes, returning `Ok(None)` when the first row has
///    `id = NULL` (indicating deletion was blocked), otherwise returning
///    `Ok(Some(Vec<Uuid>))` with all non‑NULL file ids to be removed from
///    storage.
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

/// Replicates files or folders under a destination folder by:
/// 1. Early‑returning an empty vector when `objects_ids` is empty.
/// 2. Starting a transaction and running `COPY_FOLDERS` (for recursive
///    folder copies) or `COPY_FILES` (for flat file copies) depending on
///    `is_folder`.
/// 3. Returning `Vec<CopyJobRecord>` describing all logical copies to be
///    mirrored in object storage by background workers.
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
/// Fetches all direct (non‑recursive) children of a folder by:
/// 1. Selecting active file ids from `files` and active folder ids from
///    `folders` where `parent_id = f_id` and `owner_id` matches.
/// 2. Tagging each as `'file'` or `'folder'` and returning them as
///    `Vec<FolderChild>` for listing endpoints.
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
/// Validates that a target object is within a shared ancestor subtree and
/// optionally returns its metadata by:
/// 1. Choosing `VALIDATE_FOLDER_QUERY` or `VALIDATE_FILE_QUERY` based on
///    `kind`.
/// 2. Executing the query with `(f_id, owner_id, grand_p_id)` to ensure the
///    object is a descendant of the shared root and owned by the same user.
/// 3. Returning `Ok(Some(T))` when the object is validly in scope, or
///    `Ok(None)` when outside the shared subtree.
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
/// Changes the parent folder of a file or folder by:
/// 1. Selecting the appropriate move query (`MOVE_FOLDER` or `MOVE_FILE`)
///    based on `kind`.
/// 2. Executing it with `source_id`, `owner_id`, and `dest_folder_id`,
///    which performs validation (e.g., conflicts, cycles) at the SQL level.
/// 3. Returning a `MoveDbResponse` that encodes whether the move
///    succeeded, conflicted, or failed due to missing objects.
pub async fn change_object_parent_id(
    con: &PgPool,
    owner_id: Uuid,
    source_id: Uuid,
    dest_folder_id: Uuid,
    kind: ObjectKind,
) -> Result<MoveDbResponse, DatabaseError> {
    let query = if kind.is_folder() {
        MOVE_FOLDER
    } else {
        MOVE_FILE
    };
    let v = sqlx::query_as::<_, MoveDbResponse>(query)
        .bind(source_id)
        .bind(owner_id)
        .bind(dest_folder_id)
        .fetch_one(con)
        .await
        .inspect_err(|e| error!("failed to execute change parent query: {}", e))?;
    Ok(v)
}
