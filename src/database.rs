use std::sync::OnceLock;

use crate::{
    CopyJobRecord, DatabaseConfig, DatabaseError, DeleteJobRecord, FileDownload, FileRecord,
    FolderChild, FolderRecord, ObjectStatus, UpdateMetadata, User, UserStorageInfo,
};
use anyhow::anyhow;
use sqlx::postgres::{PgPool, PgPoolOptions, PgQueryResult};
use sqlx::{Postgres, Transaction};
use tracing::{Level, debug, error, instrument};
use uuid::Uuid;

static DB_POOL: OnceLock<PgPool> = OnceLock::new();

#[instrument(skip_all,ret(level=Level::DEBUG),fields(
    init_id=%Uuid::new_v4(),
    db_name=db.db_name,
    host=db.host,
    port=db.port,
    user_name=db.user_name,
))]
pub async fn init_db(db: &DatabaseConfig) -> Result<(), DatabaseError> {
    debug!("configuring and initializing the database.");
    let pool = PgPoolOptions::new()
        .max_connections(200)
        .connect(&db.url())
        .await
        .inspect_err(|e| error!("failed to establish connection to database: {}", e))?;

    sqlx::migrate!("./migrations")
        .set_ignore_missing(true)
        .run(&pool.clone())
        .await
        .inspect_err(|e| error!("{e}"))?;
    DB_POOL
        .set(pool)
        .map_err(|_| DatabaseError::PoolAlreadyInitialized)
        .inspect_err(|e| error!("{}", e))?;
    debug!("establishing database connection successfully");
    Ok(())
}
pub fn get_db() -> Result<PgPool, DatabaseError> {
    debug!("trying to get a reference of database pool connection");
    DB_POOL
        .get()
        .ok_or(DatabaseError::PoolNotInitialized)
        .inspect_err(|e| error!("{}", e))
        .cloned()
}

pub async fn insert_user_with_root_folder(
    user: &User,
    folder: &FolderRecord,
    db_pool: &PgPool,
) -> Result<(), DatabaseError> {
    let mut tx: Transaction<'_, Postgres> =
        db_pool.begin().await.map_err(DatabaseError::Connection)?;

    // insert folder first (we need its id for users.root_folder)
    sqlx::query!(
        r#"INSERT INTO folders (id, owner_id, parent_id, name, created_at)
           VALUES ($1, $2, $3, $4, $5)"#,
        folder.id,
        folder.owner_id,
        folder.parent_id,
        folder.name,
        folder.created_at,
    )
    .execute(&mut *tx)
    .await
    .map_err(DatabaseError::Connection)?;

    // insert user referencing folder.id
    sqlx::query!(
        r#"INSERT INTO users
           (id, username, email, password_hash, created_at,
            storage_quota_bytes, storage_used_bytes, root_folder)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"#,
        user.id,
        user.username,
        user.email,
        user.password_hash,
        user.created_at,
        user.storage_quota_bytes,
        user.storage_used_bytes,
        folder.id, // set root_folder here
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        e.as_database_error()
            .filter(|db_err| db_err.constraint() == Some("users_email_key"))
            .map(|_| DatabaseError::Duplicate)
            .unwrap_or(DatabaseError::Connection(e))
    })?;

    tx.commit().await.map_err(DatabaseError::Connection)?;

    Ok(())
}
pub async fn insert_new_account(user: &User, db_pool: &PgPool) -> Result<(), DatabaseError> {
    debug!(
    user_id=%user.id,
    user_name=user.username,
    email=user.email,
    "inserting new account user information into database");
    sqlx::query!(
        r#"INSERT INTO users (id, username, email, password_hash, created_at, storage_quota_bytes, storage_used_bytes,root_folder)
         VALUES ($1, $2, $3, $4, $5, $6, $7,$8)"#,
        user.id,
        user.username,
        user.email,
        user.password_hash,
        user.created_at,
        user.storage_quota_bytes ,
        user.storage_used_bytes,
        user.root_folder
    )
    .execute(db_pool)
    .await.map_err(|e|{
        e.as_database_error()
            .filter(|db_err|
                db_err.constraint()==Some("users_email_key"))
            .map(|_|DatabaseError::Duplicate)
            .unwrap_or(DatabaseError::Connection(e))
            })
    .inspect_err(|e| error!("{}", e))?;
    debug!("successfully inserting new user");
    Ok(())
}
/// searching for a user by its email ,
///
/// # Error
/// If the email not found : DatabaseError::NotFound
///
/// otherwise : DatabaseError::Connection(e)
pub async fn fetch_account_info(con: &PgPool, email: &str) -> Result<User, DatabaseError> {
    debug!(email = email, "searching user account by using email.");

    sqlx::query_as!(
        User,
        "SELECT id,root_folder, username, email, password_hash, created_at,
                storage_quota_bytes, storage_used_bytes
         FROM users WHERE email = $1",
        email
    )
    .fetch_optional(con)
    .await
    .inspect_err(|e| error!("database error: {}", e))? // connection error propogation
    .ok_or(DatabaseError::NotFound(anyhow!(
        "failed to fetch account information"
    )))
    .inspect_err(|e| error!("{}", e))
    // if user not found !!
}

/// Check if email exists/verified and stored in database. (returns user_id)
pub async fn is_account_exist(con: &PgPool, email: &str) -> Result<Option<Uuid>, DatabaseError> {
    debug!(
        email = email,
        "searching for account existence by email : {}.", email
    );

    Ok(
        sqlx::query_scalar!("SELECT id FROM users WHERE email = $1", email)
            .fetch_optional(con)
            .await
            .inspect_err(|e| error!("database error when searching for id by email : {}", e))?,
    )
}

pub async fn fetch_email_by_id(con: &PgPool, id: Uuid) -> Result<Option<String>, DatabaseError> {
    debug!(user_id=%id,"fetching email by user id.");
    Ok(
        sqlx::query_scalar!("select email from users where id=$1", id)
            .fetch_optional(con)
            .await
            .inspect_err(|e| {
                error!("database error when searching for email by user id : {}", e)
            })?,
    )
}

pub async fn update_account_email(
    con: &PgPool,
    id: Uuid,
    email: &str,
) -> Result<PgQueryResult, DatabaseError> {
    debug!(user_id=%id,email=email,"updating user account email.");
    sqlx::query!("UPDATE users SET email=$2 where id=$1", id, email)
        .execute(con)
        .await
        .map_err(|e| {
            e.as_database_error()
                .filter(|db_err| db_err.constraint() == Some("users_email_key"))
                .map(|_| DatabaseError::Duplicate)
                .unwrap_or(DatabaseError::Connection(e))
        })
        .inspect_err(|e| error!("error updating account email : {}", e))
}
/// Update password
pub async fn update_account_password(
    con: &PgPool,
    user_id: Uuid,
    password_hash: &str,
) -> Result<PgQueryResult, DatabaseError> {
    debug!(user_id=%user_id,"updating account password");
    Ok(sqlx::query!(
        "UPDATE users SET password_hash = $2 WHERE id = $1",
        user_id,
        password_hash
    )
    .execute(con)
    .await
    .inspect_err(|e| error!("database error: {}", e))?)
}

//------------------------------------------ database object download endpoint fetch ----------------------
// FIX: Tell sqlx to treat this column as your Rust type 'ObjectStatus'

pub async fn fetch_file_info(
    con: &PgPool,
    file_id: Uuid,
    owner_id: Uuid,
) -> Result<Option<FileRecord>, DatabaseError> {
    let rec = sqlx::query_as::<_, FileRecord>(
        r#"
        SELECT *
        FROM files
        WHERE id = $1 AND owner_id = $2 AND status in ('active','copying')
        "#,
    )
    .bind(file_id)
    .bind(owner_id)
    .fetch_optional(con)
    .await?;

    Ok(rec)
}

pub async fn fetch_folder_info(
    con: &PgPool,
    folder_id: Uuid,
    owner_id: Uuid,
) -> Result<Option<FolderRecord>, DatabaseError> {
    let rec = sqlx::query_as::<_, FolderRecord>(
        r#"
        SELECT *
        FROM folders
        WHERE id = $1 AND owner_id = $2 AND status in ('active','copying')
        "#,
    )
    .bind(folder_id)
    .bind(owner_id)
    .fetch_optional(con)
    .await?;

    Ok(rec)
}

pub async fn upsert_file(con: &PgPool, file: &FileRecord) -> Result<PgQueryResult, DatabaseError> {
    Ok(sqlx::query(
        r#"
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
        "#,
    )
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
    .await?)
}

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

pub async fn is_file_exists(
    con: &PgPool,
    owner_id: Uuid,
    parent_id: Uuid,
    file_name: &str,
) -> Result<Option<Uuid>, DatabaseError> {
    Ok(sqlx::query_scalar!(
        "SELECT id
        FROM files
        WHERE parent_id=$1 AND owner_id=$2 AND status !='deleted' AND name=$3",
        parent_id,
        owner_id,
        file_name,
    )
    .fetch_optional(con)
    .await?)
}
pub async fn is_folder_exists(
    con: &PgPool,
    owner_id: Uuid,
    parent_id: Uuid,
    folder_name: &str,
) -> Result<Option<Uuid>, DatabaseError> {
    Ok(sqlx::query_scalar!(
        "SELECT id
        FROM folders
        WHERE parent_id=$1 AND owner_id=$2 AND status !='deleted' AND name=$3",
        parent_id,
        owner_id,
        folder_name,
    )
    .fetch_optional(con)
    .await?)
}

pub async fn get_user_available_storage(
    con: &PgPool,
    user_id: Uuid,
) -> Result<UserStorageInfo, DatabaseError> {
    Ok(sqlx::query_as!(
        UserStorageInfo,
        "SELECT storage_quota_bytes,storage_used_bytes FROM users where id=$1",
        user_id
    )
    .fetch_one(con)
    .await?)
}

// fetch folder/ file metadata

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
    .await?)
}
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
    .await?
    .ok_or(DatabaseError::NotFound(anyhow!("update metadata faliled"))) // row didn't exist or wrong owner
    .map(|v| UpdateMetadata::new(v.metadata.unwrap_or(metadata)))
}
pub async fn fetch_all_file_ids_paths(
    con: &PgPool,
    owner_id: Uuid,
    folder_id: Uuid,
) -> Result<Vec<FileDownload>, DatabaseError> {
    let query = include_str!("../db_queries/stream_folder.sql");
    let files = sqlx::query_as::<_, FileDownload>(query)
        .bind(folder_id) // $1
        .bind(owner_id) // $2
        .fetch_all(con)
        .await?;

    Ok(files)
}
pub async fn mark_file_as(
    con: &PgPool,
    f_ids: &[Uuid],
    status: ObjectStatus,
) -> Result<u64, DatabaseError> {
    let r = sqlx::query!(
        "UPDATE files
        SET status=$1
        WHERE id=ANY($2)",
        status as _,
        f_ids
    )
    .execute(con)
    .await
    .inspect_err(|e| error!("failed to mark file as {} : {}", status, e))?;
    Ok(r.rows_affected())
}

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
/// accepts a list of folders and the tries to mark the folders and their files as deleted recursively and returns all files ids that are decendant of the deleted folders.
///
/// marks every parent_id folder of every file by 1.
pub async fn delete_folders(
    con: &PgPool,
    owner_id: Uuid,
    folders: &[Uuid],
) -> Result<Option<Vec<DeleteJobRecord>>, DatabaseError> {
    if folders.is_empty() {
        return Ok(Some(vec![]));
    }
    let mut tx = con
        .begin()
        .await
        .inspect_err(|e| error!("failed to start delete folders transaction: {}", e))?;

    let query = include_str!("../db_queries/delete_folders.sql");

    let files_id: Vec<DeleteJobRecord> = sqlx::query_as::<_, DeleteJobRecord>(query)
        .bind(folders)
        .bind(owner_id)
        .fetch_all(&mut *tx)
        .await
        .inspect_err(|e| error!("failed to execute delete folders query: {}", e))?;

    tx.commit()
        .await
        .inspect_err(|e| error!("failed to commit delete folders transaction: {}", e))?;
    if files_id.first().is_some_and(|v| v.id.is_none()) {
        return Ok(None);
    }
    Ok(Some(files_id))
}
/// accepts a list of files ids and then marks all of them as deleted , it also increments the parent_id of every file by 1.
pub async fn delete_files(
    con: &PgPool,
    owner_id: Uuid,
    files: &[Uuid],
) -> Result<Vec<DeleteJobRecord>, DatabaseError> {
    if files.is_empty() {
        return Ok(vec![]);
    }
    let mut tx = con
        .begin()
        .await
        .inspect_err(|e| error!("failed to start delete files transaction: {}", e))?;

    let query = include_str!("../db_queries/delete_files.sql");

    let files_id: Vec<DeleteJobRecord> = sqlx::query_as::<_, DeleteJobRecord>(query)
        .bind(files)
        .bind(owner_id)
        .fetch_all(&mut *tx)
        .await
        .inspect_err(|e| error!("failed to execute delete files query: {}", e))?;

    tx.commit()
        .await
        .inspect_err(|e| error!("failed to commit delete files transaction: {}", e))?;
    Ok(files_id)
}

pub async fn copy_folders(
    con: &PgPool,
    folders_ids: &[Uuid],
    dest_folder_id: Uuid, // the new parent id to be attached to the
    owner_id: Uuid,
) -> Result<Vec<CopyJobRecord>, DatabaseError> {
    if folders_ids.is_empty() {
        return Ok(vec![]);
    }
    let mut tx = con
        .begin()
        .await
        .inspect_err(|e| error!("failed to start copy folders transaction: {}", e))?;
    let query = include_str!("../db_queries/copy_folders.sql");

    let files_id: Vec<CopyJobRecord> = sqlx::query_as::<_, CopyJobRecord>(query)
        .bind(folders_ids)
        .bind(dest_folder_id)
        .bind(owner_id)
        .fetch_all(&mut *tx)
        .await
        .inspect_err(|e| error!("failed to execute copy folders query: {}", e))?;

    tx.commit()
        .await
        .inspect_err(|e| error!("failed to commit copy folders transaction: {}", e))?;
    Ok(files_id)
}

pub async fn copy_files(
    con: &PgPool,
    files_ids: &[Uuid],
    dest_folder_id: Uuid, // the new parent id to be attached to the
    owner_id: Uuid,
) -> Result<Vec<CopyJobRecord>, DatabaseError> {
    if files_ids.is_empty() {
        return Ok(vec![]);
    }
    let mut tx = con
        .begin()
        .await
        .inspect_err(|e| error!("failed to start copy files transaction: {}", e))?;
    let query = include_str!("../db_queries/copy_files.sql");

    let files_id: Vec<CopyJobRecord> = sqlx::query_as::<_, CopyJobRecord>(query)
        .bind(files_ids)
        .bind(dest_folder_id)
        .bind(owner_id)
        .fetch_all(&mut *tx)
        .await
        .inspect_err(|e| error!("failed to execute copy files query: {}", e))?;

    tx.commit()
        .await
        .inspect_err(|e| error!("failed to commit copy files transaction: {}", e))?;
    Ok(files_id)
}

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
    .await?)
}
pub async fn increment_storage_used_for_user(
    con: &PgPool,
    user_id: Uuid,
    size: i64,
) -> Result<u64, DatabaseError> {
    let r = sqlx::query!(
        r#"
        UPDATE users SET storage_used_bytes=storage_used_bytes+$1 WHERE id=$2
        "#,
        size,
        user_id
    )
    .execute(con)
    .await?;
    Ok(r.rows_affected())
}

pub async fn update_user_maximum_storage(
    con: &PgPool,
    user_id: Uuid,
    b: i64,
) -> Result<u64, DatabaseError> {
    let r = sqlx::query!(
        r#"UPDATE users SET storage_quota_bytes=$1 WHERE id=$2"#,
        b,
        user_id
    )
    .execute(con)
    .await?;
    Ok(r.rows_affected())
}
