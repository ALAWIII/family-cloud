mod auth;
mod utils;
use family_cloud::{LoginResponse, create_user_bucket, get_rustfs, init_tracing};
pub use utils::*;
mod upload;
// ============================================================================
// Shared Test Setup - Initialize All Infrastructure
// ============================================================================

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
        family_cloud::build_router(state.clone())?,
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
