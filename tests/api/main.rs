mod signup;
mod utils;
pub use utils::*;
mod change_email;
mod login;
mod logout;
mod password_reset;
mod refresh;
/*
*/

// ============================================================================
// Shared Test Setup - Initialize All Infrastructure
// ============================================================================

/// Helper to initialize complete test infrastructure
pub async fn setup_test_env() -> anyhow::Result<(AppTest, family_cloud::AppState)> {
    dotenv::dotenv()?;
    let containers = init_test_containers().await?;

    let db_config = get_database_config("localhost", 5432).await?;
    let redis_config = get_redis_config("localhost", 6379).await?;
    let email_config = get_email_config(&containers.mailhog).await?;
    let rustfs_config = get_rustfs_config();
    let secrets = family_cloud::Secrets {
        hmac: "OIodbFUiNK34xthjR0newczMC6HaAyksJS1GXfYZ".into(),
        rustfs: "OIodbFUiNK34xthjR0newczMC6HaAyksJS1GXfYZ".into(),
    };
    family_cloud::init_db(&db_config).await?;
    family_cloud::init_mail_client(&email_config)?;
    family_cloud::init_redis_pool(&redis_config).await?;
    family_cloud::init_rustfs(&rustfs_config, &secrets.rustfs).await;

    let db_pool = family_cloud::get_db()?;
    let mailhog_url = std::env::var("MAILHOG_URL")?;

    let state = family_cloud::AppState {
        settings: family_cloud::AppSettings {
            app: family_cloud::AppConfig {
                host: "localhost".into(),
                port: 5050,
            },
            database: db_config,
            email: email_config,
            rustfs: rustfs_config,
            secrets,
            redis: redis_config,
        },
        db_pool,
        rustfs_con: family_cloud::get_rustfs(),
        redis_pool: family_cloud::get_redis_pool()?,
        mail_client: family_cloud::get_mail_client()?,
    };

    let app_test = AppTest::new(
        family_cloud::build_router(state.clone())?,
        state.clone(),
        mailhog_url,
        containers,
    )?;

    Ok((app_test, state))
}
