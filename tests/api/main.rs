mod auth;
mod utils;
use std::net::SocketAddr;
mod metadata;
use axum::{body::Bytes, extract::connect_info::MockConnectInfo};
use base64::{Engine, engine::general_purpose::STANDARD};
use family_cloud::{
    FileRecord, FolderRecord, LoginResponse, TokenOptions, create_user_bucket, get_rustfs,
    init_tracing,
};
pub use utils::*;
mod download;
mod upload;
use axum::http::header::CONTENT_LENGTH;
// ============================================================================
// Shared Test Setup - Initialize All Infrastructure
// ============================================================================
use sha2::{Digest, Sha256};
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
    init_tracing("familycloud", "family_cloud=debug,warn", "./family_cloud")?;
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
    parent_id: &str,
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
async fn upload_folder(app: &AppTest, f_name: &str, parent_id: &str, jwt: &str) -> FolderRecord {
    let resp = app
        .upload(jwt, parent_id)
        .add_header("Object-Type", "folder")
        .add_header("Object-Name", f_name) // "banana/sandawitch"
        .await;
    resp.assert_status_success();

    resp.json()
}
