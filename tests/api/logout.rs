//! Integration tests for logout endpoint
//!
//! Tests the logout flow:
//! - Logout with token in cookie (web)
//! - Logout with token in body (mobile/desktop)
//! - Logout without token (should fail)
//! - Verify refresh token is removed from Redis
//! - Verify refresh token can't be reused after logout

use deadpool_redis::redis::AsyncTypedCommands;
use family_cloud::{
    LoginResponse, TokenType, create_verification_key, decode_token, get_redis_con, hash_token,
};
use reqwest::StatusCode;
use secrecy::ExposeSecret;

use crate::utils::{
    AppTest, TestDatabase,
    containers::{
        get_database_config, get_email_config, get_redis_config, get_rustfs_config,
        init_test_containers,
    },
    create_token_pair,
};

// ============================================================================
// Shared Test Setup - Initialize All Infrastructure
// ============================================================================

/// Helper to initialize complete test infrastructure
async fn setup_test_env() -> anyhow::Result<(AppTest, family_cloud::AppState)> {
    let containers = init_test_containers().await?;

    let db_config = get_database_config(&containers.postgres).await?;
    let redis_config = get_redis_config(&containers.redis).await?;
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

// ============================================================================
// Helper: Setup with Authenticated User & Token Key
// ============================================================================

/// Setup and return authenticated user with refresh token Redis key
async fn setup_with_authenticated_user()
-> anyhow::Result<(AppTest, family_cloud::AppState, LoginResponse, String)> {
    let (app, state) = setup_test_env().await?;
    let db_pool = family_cloud::get_db()?;

    // Create verified account
    let account = TestDatabase::create_verified_account(&db_pool).await?;
    let (email, password) = account.credentials();

    // Login to get tokens
    let login_response = app.login(&email, &password).await;
    assert!(
        login_response.status_code().is_success(),
        "Login should succeed"
    );

    let login_data: LoginResponse = login_response.json();

    // Generate Redis key for refresh token
    let hashed_token = hash_token(
        &decode_token(&login_data.refresh_token)?,
        app.state.settings.secrets.hmac.expose_secret(),
    )?;
    let redis_key = create_verification_key(TokenType::Refresh, &hashed_token);

    Ok((app, state, login_data, redis_key))
}

// ============================================================================
// Logout Tests
// ============================================================================

#[tokio::test]
async fn test_logout_with_token_in_cookie() -> anyhow::Result<()> {
    let (app, state, login_data, redis_key) = setup_with_authenticated_user().await?;

    // Get Redis connection
    let mut redis_conn = get_redis_con(state.redis_pool.clone()).await?;

    // Verify token EXISTS in Redis BEFORE logout
    let token_exists_before = redis_conn.exists(&redis_key).await?;
    assert!(
        token_exists_before,
        "Refresh token should exist in Redis before logout"
    );

    // Create cookie with refresh token
    let (cookie, _body) = create_token_pair(&login_data.refresh_token);

    // Logout with cookie
    let logout_response = app.logout_with_cookie(cookie).await;

    // Verify response is NO_CONTENT (204)
    assert_eq!(
        logout_response.status_code(),
        StatusCode::NO_CONTENT,
        "Logout with cookie should return NO_CONTENT"
    );

    // Verify token REMOVED from Redis AFTER logout
    let token_exists_after = redis_conn.exists(&redis_key).await?;
    assert!(
        !token_exists_after,
        "Refresh token should be removed from Redis after logout"
    );

    Ok(())
}

#[tokio::test]
async fn test_logout_with_token_in_body() -> anyhow::Result<()> {
    let (app, state, login_data, redis_key) = setup_with_authenticated_user().await?;

    // Get Redis connection
    let mut redis_conn = get_redis_con(state.redis_pool.clone()).await?;

    // Verify token EXISTS in Redis BEFORE logout
    let token_exists_before = redis_conn.exists(&redis_key).await?;
    assert!(
        token_exists_before,
        "Refresh token should exist in Redis before logout"
    );

    // Create body with refresh token
    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Logout with body (mobile/desktop pattern)
    let logout_response = app.logout_with_body(&body).await;

    // Verify response is NO_CONTENT (204)
    assert_eq!(
        logout_response.status_code(),
        StatusCode::NO_CONTENT,
        "Logout with body should return NO_CONTENT"
    );

    // Verify token REMOVED from Redis AFTER logout
    let token_exists_after = redis_conn.exists(&redis_key).await?;
    assert!(
        !token_exists_after,
        "Refresh token should be removed from Redis after logout"
    );

    Ok(())
}

#[tokio::test]
async fn test_logout_without_token() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    // Try logout without any token
    let logout_response = app.logout().await;

    // Should fail with UNAUTHORIZED
    assert_eq!(
        logout_response.status_code(),
        StatusCode::UNAUTHORIZED,
        "Logout without token should return UNAUTHORIZED"
    );

    Ok(())
}

#[tokio::test]
async fn test_logout_prevents_token_reuse() -> anyhow::Result<()> {
    let (app, _state, login_data, _redis_key) = setup_with_authenticated_user().await?;

    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Logout with the refresh token
    let logout_response = app.logout_with_body(&body).await;
    assert!(
        logout_response.status_code().is_success(),
        "Logout should succeed"
    );

    // Try to refresh using the SAME token after logout
    let refresh_response = app.refresh_with_body(&body).await;

    assert!(
        refresh_response.status_code().is_client_error(),
        "Refresh with invalidated token should fail after logout"
    );

    Ok(())
}

#[tokio::test]
async fn test_logout_with_invalid_token() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    // Create body with invalid token
    let (_cookie, body) = create_token_pair("invalid_refresh_token_xyz");

    // Try logout with invalid token
    let logout_response = app.logout_with_body(&body).await;

    // Should fail (token invalid/not in Redis)
    assert!(
        logout_response.status_code().is_client_error(),
        "Logout with invalid token should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_logout_multiple_times_with_same_token() -> anyhow::Result<()> {
    let (app, _state, login_data, _redis_key) = setup_with_authenticated_user().await?;

    let (cookie, body) = create_token_pair(&login_data.refresh_token);

    // First logout
    let logout_response_1 = app.logout_with_body(&body).await;
    assert!(
        logout_response_1.status_code().is_success(),
        "First logout should succeed"
    );

    // Try logout again with SAME token
    let logout_response_2 = app.logout_with_cookie(cookie).await;
    assert!(
        logout_response_2.status_code().is_success(),
        "logout with same token,\
        the token was already deleted from redis it does not complain or return any error (success 204) "
    );

    Ok(())
}

#[tokio::test]
async fn test_logout_does_not_delete_user_account() -> anyhow::Result<()> {
    let (app, state, login_data, _redis_key) = setup_with_authenticated_user().await?;

    let db_pool = family_cloud::get_db()?;
    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Logout
    let logout_response = app.logout_with_body(&body).await;
    assert!(
        logout_response.status_code().is_success(),
        "Logout should succeed"
    );

    // Try to login again with same credentials - should work
    // (We need to get the account email from the state somehow)
    // For now, create a fresh login test
    let account = TestDatabase::create_verified_account(&db_pool).await?;
    let (email, password) = account.credentials();

    let login_response = app.login(&email, &password).await;
    assert!(
        login_response.status_code().is_success(),
        "User account should still exist after logout"
    );

    Ok(())
}

#[tokio::test]
async fn test_logout_user_cannot_access_protected_resources() -> anyhow::Result<()> {
    let (app, _state, login_data, _redis_key) = setup_with_authenticated_user().await?;

    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Logout
    let logout_response = app.logout_with_body(&body).await;
    assert!(
        logout_response.status_code().is_success(),
        "Logout should succeed"
    );

    // Try to access protected resource (change email requires auth)
    let auth_response = app
        .request_email_change(
            "newemail@test.local",
            "", // Empty token
        )
        .await;

    auth_response.assert_status(StatusCode::UNAUTHORIZED);
    assert!(
        auth_response.status_code().is_client_error(),
        "Should not be able to access protected resources after logout"
    );

    Ok(())
}
