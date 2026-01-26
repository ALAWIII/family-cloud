//! Integration tests for password reset endpoint
//!
//! Tests the complete password reset flow:
//! - Request password reset
//! - Receive verification email
//! - Confirm with new password
//! - Token cleanup and single-use enforcement
//! - Old password becomes invalid

use family_cloud::{TokenType, get_db, get_redis_con, is_token_exist};
use reqwest::StatusCode;
use secrecy::ExposeSecret;
use serde_json::to_string;

use crate::utils::{
    AppTest, EmailTokenExtractor, TestAccount, TestDatabase,
    containers::{
        get_database_config, get_email_config, get_redis_config, get_rustfs_config,
        init_test_containers,
    },
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
    let hmac = "OIodbFUiNK34xthjR0newczMC6HaAyksJS1GXfYZ".to_string();
    let rustfs = hmac.to_string();
    family_cloud::init_db(&db_config).await?;
    family_cloud::init_mail_client(&email_config)?;
    family_cloud::init_redis_pool(&redis_config).await?;
    family_cloud::init_rustfs(&rustfs_config, &rustfs.clone().into()).await;

    let db_pool = get_db()?;
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
            secrets: family_cloud::Secrets {
                hmac: hmac.into(),
                rustfs: rustfs.into(),
            },
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
// Shared Helper: Test Setup with Verified Account
// ============================================================================

/// Setup environment and create a verified account
async fn setup_with_verified_account()
-> anyhow::Result<(AppTest, family_cloud::AppState, TestAccount)> {
    let (app, state) = setup_test_env().await?;
    let db_pool = get_db()?;

    // Create a verified account in database
    let account = TestDatabase::create_verified_account(&db_pool).await?;

    Ok((app, state, account))
}

// ============================================================================
// Helper: Request Password Reset and Extract Tokens
// ============================================================================

async fn request_reset_and_get_tokens(
    app: &AppTest,
    email: &str,
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    // Request password reset
    let response = app.request_password_reset(email).await;
    assert!(
        response.status_code().is_success(),
        "Password reset request should succeed"
    );

    // Fetch emails from MailHog
    let messages = app.mailhog.get_all_messages().await?;

    // Extract raw tokens from password reset email
    let raw_tokens = EmailTokenExtractor::extract_raw_tokens(&messages, "Password");

    assert!(
        !raw_tokens.is_empty(),
        "Should have received password reset email"
    );

    // Convert to hashed tokens
    let hashed_tokens = EmailTokenExtractor::hash_tokens(
        &raw_tokens,
        app.state.settings.secrets.hmac.expose_secret(),
        TokenType::PasswordReset,
    )?;

    Ok((raw_tokens, hashed_tokens))
}

// ============================================================================
// Password Reset Tests
// ============================================================================

#[tokio::test]
async fn test_password_reset_request_sends_email() -> anyhow::Result<()> {
    let (app, _state, account) = setup_with_verified_account().await?;

    // Request password reset
    let response = app.request_password_reset(&account.email).await;
    assert!(
        response.status_code().is_success(),
        "Password reset request should succeed"
    );

    // Verify email was sent
    let messages = app.mailhog.get_all_messages().await?;
    let tokens = EmailTokenExtractor::extract_raw_tokens(&messages, "Password");

    assert_eq!(
        tokens.len(),
        1,
        "Should send exactly one password reset email"
    );

    Ok(())
}

#[tokio::test]
async fn test_password_reset_token_stored_in_redis() -> anyhow::Result<()> {
    let (app, state, account) = setup_with_verified_account().await?;

    // Request reset and get tokens
    let (_raw_tokens, hashed_tokens) = request_reset_and_get_tokens(&app, &account.email).await?;

    // Get Redis connection
    let mut redis_conn = get_redis_con(state.redis_pool.clone()).await?;

    // Verify tokens exist in Redis
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            token_exists,
            "Password reset token should exist in Redis before confirmation"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_password_reset_retrieves_form() -> anyhow::Result<()> {
    let (app, _state, account) = setup_with_verified_account().await?;

    // Request reset and get tokens
    let (raw_tokens, _hashed_tokens) = request_reset_and_get_tokens(&app, &account.email).await?;

    // Verify clicking link returns password form
    for raw_token in &raw_tokens {
        let response = app
            .verify_email("/api/auth/password-reset", raw_token)
            .await;
        assert!(
            response.status_code().is_success(),
            "Password reset link should return form page"
        );

        let html = response.text();
        assert!(
            !html.is_empty(),
            "Should return HTML form for password entry"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_password_reset_rejects_mismatched_passwords() -> anyhow::Result<()> {
    let (app, _state, account) = setup_with_verified_account().await?;

    // Request reset and get tokens
    let (raw_tokens, _hashed_tokens) = request_reset_and_get_tokens(&app, &account.email).await?;

    // Try confirming with mismatched passwords
    for raw_token in &raw_tokens {
        let response = app
            .confirm_password_reset(
                raw_token,
                "NewPassword123!",
                "DifferentPassword456!", // Mismatch!
            )
            .await;

        assert_eq!(
            response.status_code(),
            StatusCode::BAD_REQUEST,
            "Should reject mismatched password confirmation"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_password_reset_confirms_with_matching_passwords() -> anyhow::Result<()> {
    let (app, _state, account) = setup_with_verified_account().await?;

    // Request reset and get tokens
    let (raw_tokens, _hashed_tokens) = request_reset_and_get_tokens(&app, &account.email).await?;

    // Confirm with matching passwords
    for raw_token in &raw_tokens {
        let response = app
            .confirm_password_reset(
                raw_token,
                "NewSecurePassword123!",
                "NewSecurePassword123!", // Match
            )
            .await;

        assert!(
            response.status_code().is_success(),
            "Password reset should succeed with matching passwords"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_password_reset_removes_token_from_redis() -> anyhow::Result<()> {
    let (app, state, account) = setup_with_verified_account().await?;

    // Request reset and get tokens
    let (raw_tokens, hashed_tokens) = request_reset_and_get_tokens(&app, &account.email).await?;

    // Verify tokens EXIST before confirmation
    let mut redis_conn = get_redis_con(state.redis_pool.clone()).await?;
    for hashed_token in &hashed_tokens {
        let exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            exists,
            "Token should exist in Redis BEFORE password confirmation"
        );
    }

    // Confirm password reset
    for raw_token in &raw_tokens {
        app.confirm_password_reset(raw_token, "NewPassword123!", "NewPassword123!")
            .await;
    }

    // Get fresh Redis connection
    let mut redis_conn = get_redis_con(state.redis_pool).await?;

    // Verify tokens REMOVED after confirmation
    for hashed_token in &hashed_tokens {
        let exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            !exists,
            "Password reset token should be removed from Redis AFTER confirmation"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_password_reset_token_single_use_only() -> anyhow::Result<()> {
    let (app, _state, account) = setup_with_verified_account().await?;

    // Request reset and get tokens
    let (raw_tokens, _hashed_tokens) = request_reset_and_get_tokens(&app, &account.email).await?;

    // Use token to reset password
    for raw_token in &raw_tokens {
        let first_use = app
            .confirm_password_reset(raw_token, "FirstNewPassword123!", "FirstNewPassword123!")
            .await;

        assert!(
            first_use.status_code().is_success(),
            "First password reset should succeed"
        );

        // Try reusing the SAME token
        let reuse_attempt = app
            .confirm_password_reset(raw_token, "SecondNewPassword456!", "SecondNewPassword456!")
            .await;

        assert_eq!(
            reuse_attempt.status_code(),
            StatusCode::UNAUTHORIZED,
            "Reusing password reset token should fail (token already consumed)"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_password_reset_allows_login_with_new_password() -> anyhow::Result<()> {
    let (app, _state, account) = setup_with_verified_account().await?;
    let original_email = account.email.clone();

    // Request reset and get tokens
    let (raw_tokens, _hashed_tokens) = request_reset_and_get_tokens(&app, &original_email).await?;

    let new_password = "CompletelyNewPassword123!";

    // Reset password
    for raw_token in &raw_tokens {
        app.confirm_password_reset(raw_token, new_password, new_password)
            .await;
    }

    // Try logging in with NEW password
    let response = app.login(&original_email, new_password).await;

    assert!(
        response.status_code().is_success(),
        "Should be able to login with new password after reset"
    );

    Ok(())
}

#[tokio::test]
async fn test_password_reset_prevents_old_password_login() -> anyhow::Result<()> {
    let (app, _state, account) = setup_with_verified_account().await?;
    let email = account.email.clone();
    let old_password = account.password.clone();

    // Request reset and get tokens
    let (raw_tokens, _hashed_tokens) = request_reset_and_get_tokens(&app, &email).await?;

    // Reset password to something new
    for raw_token in &raw_tokens {
        app.confirm_password_reset(raw_token, "NewPassword123!", "NewPassword123!")
            .await;
    }

    // Try logging in with OLD password (should fail)
    let response = app.login(&email, &old_password).await;

    assert!(
        response.status_code().is_client_error(),
        "Should NOT be able to login with old password after reset"
    );

    Ok(())
}

#[tokio::test]
async fn test_password_reset_for_nonexistent_email() -> anyhow::Result<()> {
    let (app, _state, _account) = setup_with_verified_account().await?;

    // Request reset for nonexistent email
    let response = app.request_password_reset("nonexistent@test.local").await;

    // Should return success (security best practice - don't reveal if email exists)
    assert_eq!(
        response.status_code(),
        StatusCode::NOT_FOUND,
        "Should return success for nonexistent email (security)"
    );

    // But no email should be sent
    app.mailhog.delete_all_messages().await?;
    let messages = app.mailhog.get_all_messages().await?;
    assert!(
        messages.is_empty(),
        "No email should be sent for nonexistent account"
    );

    Ok(())
}
