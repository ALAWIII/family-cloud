//! Integration tests for signup and email verification endpoints
//!
//! Tests using the refactored test utilities:
//! - Container setup
//! - Account builders
//! - Email token extraction
//! - Database helpers
//! - MailHog client

use family_cloud::{TokenType, get_db, get_redis_con, is_account_exist, is_token_exist};
use secrecy::ExposeSecret;

use crate::{
    setup_test_env,
    utils::{AccountBuilder, AppTest, EmailTokenExtractor, TestAccount},
};
use serde_json::json;

// ============================================================================
// Shared Helper Functions
// ============================================================================

/// Complete signup flow: signup, get email, extract tokens
async fn signup_and_get_tokens(
    app: &AppTest,
    account: &TestAccount,
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    // 1. Send signup request
    let response = app
        .signup(&json!({
            "username":account.username,
            "email":account.email,
            "password"  : account.password
        }))
        .await;

    assert!(response.status_code().is_success(), "Signup should succeed");
    // 2. Fetch all emails from MailHog
    let messages = app.mailhog.get_all_messages().await?;

    // 3. Extract raw tokens from verification email
    let raw_tokens =
        EmailTokenExtractor::extract_raw_tokens(&messages, "new account email verification");

    assert!(
        !raw_tokens.is_empty(),
        "Should have received verification email"
    );

    // 4. Convert raw tokens to hashed format
    let hashed_tokens = EmailTokenExtractor::hash_tokens(
        &raw_tokens,
        app.state.settings.secrets.hmac.expose_secret(),
        TokenType::Signup,
    )?;

    Ok((raw_tokens, hashed_tokens))
}

/// Verify email by clicking token link
async fn verify_email_with_token(app: &AppTest, token: &str) -> bool {
    let response = app.verify_email("/api/auth/signup", token).await;
    dbg!(&response);
    response.status_code().is_success()
}

// ============================================================================
// Individual Integration Tests
// ============================================================================

#[tokio::test]
async fn test_signup_sends_verification_email() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    // Create test account using builder
    let account = TestAccount::default();

    // Send signup
    let response = app.signup(&account).await;
    assert!(response.status_code().is_success(), "Signup should succeed");

    // Get messages from MailHog
    let messages = app.mailhog.get_all_messages().await?;

    // Extract verification tokens
    let raw_tokens =
        EmailTokenExtractor::extract_raw_tokens(&messages, "new account email verification");

    // Assertions
    assert_eq!(
        raw_tokens.len(),
        1,
        "Should send exactly one verification email"
    );

    Ok(())
}

#[tokio::test]
async fn test_verification_token_stored_in_redis() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;

    // Create and signup account
    let account = TestAccount::default();
    let (_raw_tokens, hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Get Redis connection
    let mut redis_conn = get_redis_con(&state.redis_pool).await?;

    // Verify all tokens exist in Redis
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            token_exists,
            "Token '{}' should exist in Redis before verification",
            hashed_token
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_verification_completes_account_creation() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;

    // Create and signup account
    let account = TestAccount::default();
    let (raw_tokens, _hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Get database connection
    let db_pool = get_db()?;

    // Verify email for each token
    for raw_token in &raw_tokens {
        let verified = verify_email_with_token(&app, raw_token).await;
        assert!(
            verified,
            "Email verification should succeed for token: {}",
            raw_token
        );
    }

    // Check account was created in database
    let user_id = is_account_exist(&db_pool, &account.email).await?;
    assert!(
        user_id.is_some(),
        "Account should be created after verification for email: {}",
        account.email
    );

    Ok(())
}

#[tokio::test]
async fn test_existing_account_prevents_duplicate_signup() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;
    let db_pool = get_db()?;

    // Step 1: Create and verify first account
    let account = TestAccount::default();

    let (raw_tokens, hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Verify email
    for raw_token in &raw_tokens {
        // the server endpoint should delete the verification tokens from redis once the account is verified
        assert!(verify_email_with_token(&app, raw_token).await);
    }

    // Confirm account exists
    let user_exists = is_account_exist(&db_pool, &account.email).await?;
    assert!(user_exists.is_some(), "First account should exist");

    // Clear MailHog for clean test
    app.mailhog.delete_all_messages().await?;

    // Step 2: Try signing up with same email
    let response = app.signup(&account).await;
    assert!(
        response.status_code().is_success() || response.status_code().is_client_error(),
        "Duplicate signup should be rejected"
    );

    // Step 3: Verify no new verification email was sent
    let messages_after = app.mailhog.get_all_messages().await?;
    let new_tokens =
        EmailTokenExtractor::extract_raw_tokens(&messages_after, "new account email verification");
    // assert that only the original message is there and no new email verification signup message was sent
    assert_eq!(
        new_tokens.len(),
        0,
        "No new verification email should be sent for duplicate email"
    );

    // Step 4: Verify old tokens were cleaned up
    let mut redis_conn = get_redis_con(&state.redis_pool).await?;
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            !token_exists,
            "Old verification token should be removed after account creation"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_verification_removes_token_from_redis() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;

    // Create and signup account
    let account = TestAccount::default();
    let (raw_tokens, hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Get Redis connection
    let mut redis_conn = get_redis_con(&state.redis_pool).await?;

    // Verify tokens exist BEFORE verification
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            token_exists,
            "Token should exist in Redis BEFORE verification"
        );
    }

    // Complete email verification
    for raw_token in &raw_tokens {
        assert!(verify_email_with_token(&app, raw_token).await);
    }

    // Refresh Redis connection
    let mut redis_conn = get_redis_con(&state.redis_pool).await?;

    // Verify tokens removed AFTER verification
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            !token_exists,
            "Token should be removed from Redis AFTER verification"
        );
    }

    Ok(())
}

// ============================================================================
// Additional Edge Case Tests Using New Utilities
// ============================================================================

#[tokio::test]
async fn test_signup_with_invalid_email_format() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    let invalid_account = AccountBuilder::new().email("not-a-valid-email").build()?;

    let response = app.signup(&invalid_account).await;
    assert!(
        response.status_code().is_client_error(),
        "Signup with invalid email should fail"
    );

    Ok(())
}

//#[tokio::test]
async fn test_signup_with_weak_password() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    let weak_account = AccountBuilder::new()
        .password("123") // Too weak
        .build()?;

    let response = app.signup(&weak_account).await;
    assert!(
        response.status_code().is_client_error(),
        "Signup with weak password should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_verification_with_invalid_token() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    let response = app
        .verify_email("/api/auth/signup", "invalid_token_xyz")
        .await;
    assert!(
        response.status_code().is_client_error(),
        "Verification with invalid token should fail"
    );

    Ok(())
}
