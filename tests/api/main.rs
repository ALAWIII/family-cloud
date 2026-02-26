mod auth;
mod utils;
use std::{net::SocketAddr, time::Duration};
mod metadata;
use aws_sdk_s3::Client;
use axum::{body::Bytes, extract::connect_info::MockConnectInfo};
use base64::{Engine, engine::general_purpose::STANDARD};
use family_cloud::{
    FileRecord, FolderRecord, LoginResponse, TokenOptions, WorkersName, create_user_bucket,
    get_rustfs, init_apalis, init_tracing, insert_folder, upsert_file,
};
use sqlx::PgPool;
pub use utils::*;
mod delete;
mod download;
mod upload;
use axum::http::header::CONTENT_LENGTH;
// ============================================================================
// Shared Test Setup - Initialize All Infrastructure
// ============================================================================
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub fn calculate_checksum(f: &[u8]) -> String {
    // 2. Calculate SHA-256 checksum
    let mut hasher = Sha256::new();
    hasher.update(f);
    let hash = hasher.finalize();
    STANDARD.encode(hash)
}
/// Helper to initialize complete test infrastructure
pub async fn setup_test_env(mhog_cont: bool) -> anyhow::Result<(AppTest, family_cloud::AppState)> {
    dotenv::dotenv()?;
    init_tracing("familycloud", "family_cloud=error,warn", "./family_cloud")?;
    let mut mailhog_server = None;
    if mhog_cont {
        mailhog_server = Some(init_test_containers().await?);
    }

    let db_config = get_database_config("localhost", 5432).await?;
    let redis_config = get_redis_config("localhost", 6379).await?;
    let rustfs_config = get_rustfs_config();
    let secrets = family_cloud::Secrets {
        hmac: "OIodbFUiNK34xthjR0newczMC6HaAyksJS1GXfYZ".into(),
        rustfs: "OIodbFUiNK34xthjR0newczMC6HaAyksJS1GXfYZ".into(),
    };
    family_cloud::init_db(&db_config).await?;
    family_cloud::init_redis_pool(&redis_config).await?;
    family_cloud::init_rustfs(&rustfs_config, &secrets.rustfs).await?;

    let db_pool = family_cloud::get_db()?;

    let state = family_cloud::AppState {
        settings: family_cloud::AppSettings {
            app: family_cloud::AppConfig {
                name: "familycloud".into(),
                host: "localhost".into(),
                port: 5050,
                log_level: family_cloud::LogLevel::Info,
                log_directory: "./family_cloud".into(),
            },
            database: db_config,
            email: mailhog_server.as_ref().map(|v| v.email_conf.clone()),
            rustfs: rustfs_config,
            secrets,
            redis: redis_config,
            token_options: TokenOptions {
                max_concurrent_download: 10,
                download_token_ttl: 1440,
                change_email_token: 10,
                refresh_token: 43200,
                jwt_token: 15,           //15 minutes
                password_reset_token: 5, // 5 minutes
                signup_token: 5,         // 5 minutes
            },
        },
        db_pool,
        rustfs_con: family_cloud::get_rustfs()?,
        redis_pool: family_cloud::get_redis_pool()?,
        mail_client: if mhog_cont {
            Some(family_cloud::get_mail_client()?)
        } else {
            None
        },
    };

    let app_test = AppTest::new(
        family_cloud::build_router(state.clone())?
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345)))),
        state.clone(),
        mailhog_server,
    )?;

    Ok((app_test, state))
}

pub async fn setup_with_authenticated_user() -> anyhow::Result<(AppTest, TestAccount, LoginResponse)>
{
    let (app, _state) = setup_test_env(false).await?;
    let db_pool = family_cloud::get_db()?;

    // Create verified account
    let account = TestDatabase::create_verified_account(&db_pool).await?;
    let (email, password) = account.credentials();
    create_user_bucket(&get_rustfs()?, &account.id.to_string()).await?;
    // Login to get access token
    let login_response = app.login(&email, &password).await;
    assert!(
        login_response.status_code().is_success(),
        "Login should succeed"
    );

    let login_data: LoginResponse = login_response.json();

    Ok((app, account, login_data))
}
async fn upload_file(
    app: &AppTest,
    f_name: &str,
    parent_id: Uuid,
    data: Vec<u8>,
    jwt: &str,
) -> FileRecord {
    let checksum = calculate_checksum(&data);
    let resp = app
        .upload(jwt, parent_id)
        .add_header("Object-Type", "file")
        .add_header("Object-Name", f_name)
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, data.len())
        .content_type("text/plain")
        .bytes(Bytes::from(data))
        .await;
    resp.assert_status_success();
    resp.json()
}
async fn upload_folder(app: &AppTest, f_name: &str, parent_id: Uuid, jwt: &str) -> FolderRecord {
    let resp = app
        .upload(jwt, parent_id)
        .add_header("Object-Type", "folder")
        .add_header("Object-Name", f_name) // "banana/sandawitch"
        .await;
    resp.assert_status_success();

    resp.json()
}

pub async fn init_workers(con: &PgPool, rfs: Client) -> anyhow::Result<WorkersName> {
    let n_worker = WorkersName {
        delete: Uuid::new_v4().to_string(),
        copy: Uuid::new_v4().to_string(),
    };
    init_apalis(con, rfs, n_worker.clone()).await?;
    Ok(n_worker)
}
#[derive(Debug, Clone)]
pub struct Tree {
    pub folders: Vec<FolderRecord>,
    pub files: Vec<FileRecord>,
    pub workers: WorkersName,
}

async fn wait_job_until_finishes(con: &PgPool, workers: &WorkersName) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let value = sqlx::query!(
                r#"SELECT (
                    -- Phase 1: jobs must exist first
                    (
                    SELECT COUNT(*)
                        FROM apalis.jobs j
                        WHERE j.job_type IN ($1,$2)) > 0
                    AND
                    -- Phase 2: all of them must be done
                    (
                    SELECT COUNT(*)
                        FROM apalis.jobs j
                     WHERE j.job_type IN ($1,$2) AND j.done_at IS NULL) = 0
                ) AS "done!: bool""#,
                workers.delete,
                workers.copy,
            )
            .fetch_one(con)
            .await?;
            if value.done {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok::<_, sqlx::Error>(())
    })
    .await
    .expect("worker did not finish in time")?;
    Ok(())
}
async fn create_folders_files_tree(app: &AppTest, account: &TestAccount) -> anyhow::Result<Tree> {
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let fo1 = FolderRecord::new(account.id, account.root_folder, "fo1".to_string());
    let fo2 = FolderRecord::new(account.id, Some(fo1.id), "fo2".to_string());
    let fo2_1 = FolderRecord::new(account.id, Some(fo2.id), "fo2_1".to_string());
    let fo2_2 = FolderRecord::new(account.id, Some(fo2.id), "fo2_2".to_string());
    let fi1 = FileRecord::new(account.id, fo2_2.id, "fi1_2".to_string());
    let fi2 = FileRecord::new(account.id, fo2_2.id, "fi2_2".to_string());
    let fi3 = FileRecord::new(account.id, fo1.id, "fi1_1".to_string());
    let folders = vec![fo1, fo2, fo2_1, fo2_2];
    let files = vec![fi1, fi2, fi3];
    for fo in &folders {
        insert_folder(&app.state.db_pool, fo).await?;
    }
    for fi in &files {
        upsert_file(&app.state.db_pool, fi).await?;
    }

    Ok(Tree {
        folders,
        files,
        workers,
    })
}
