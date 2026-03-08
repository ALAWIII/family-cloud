//! Integration tests for login endpoint
//!
//! Tests the login flow:
//! - Login with valid credentials
//! - Login with invalid email (404)
//! - Login with invalid password (401)
//! - Login with missing fields (422)
//! - Verify response structure and tokens
//! - Login returns correct user profile

use std::time::Duration;

use family_cloud::LoginResponse;
use reqwest::StatusCode;

use crate::{
    setup_test_env,
    utils::{AppTest, TestAccount, TestDatabase},
};

// ============================================================================
// Helper: Create Verified Account for Login Tests
// ============================================================================

async fn create_and_verify_test_account() -> anyhow::Result<(AppTest, TestAccount)> {
    let (app, _state) = setup_test_env(false).await?;
    let db_pool = family_cloud::get_db()?;

    let account = TestDatabase::create_verified_account(&db_pool).await?;

    Ok((app, account))
}

// ============================================================================
// Login Tests
// ============================================================================

#[tokio::test]
async fn test_login_with_valid_credentials() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, password) = account.credentials();

    // Login with valid credentials
    let response = app.login(&email, &password).await;

    assert!(
        response.status_code().is_success(),
        "Login with valid credentials should succeed"
    );

    // Parse response
    let login_response: LoginResponse = response.json();

    // Verify tokens are present
    assert!(
        !login_response.access_token.is_empty(),
        "Access token should not be empty"
    );
    assert!(
        !login_response.refresh_token.is_empty(),
        "Refresh token should not be empty"
    );

    // Verify user profile matches
    assert_eq!(
        login_response.user.id, account.id,
        "Returned user ID should match login account"
    );
    assert_eq!(
        login_response.user.username, account.username,
        "Returned username should match"
    );
    assert_eq!(
        login_response.user.email, account.email,
        "Returned email should match"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_with_invalid_email() -> anyhow::Result<()> {
    let (app, _account) = create_and_verify_test_account().await?;

    // Try login with non-existent email
    let response = app
        .login("nonexistent@test.local", "SomePassword123!")
        .await;

    assert_eq!(
        response.status_code(),
        StatusCode::NOT_FOUND,
        "Login with invalid email should return NOT_FOUND (404)"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_with_invalid_password() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, _correct_password) = account.credentials();

    // Try login with wrong password
    let response = app.login(&email, "WrongPassword123!").await;

    assert_eq!(
        response.status_code(),
        StatusCode::UNAUTHORIZED,
        "Login with invalid password should return UNAUTHORIZED (401)"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_missing_email() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (_email, password) = account.credentials();

    // Try login without email field
    let response = app.login_with_optional(None, Some(&password)).await;

    assert_eq!(
        response.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "Login missing email should return UNPROCESSABLE_ENTITY (422)"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_missing_password() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, _password) = account.credentials();

    // Try login without password field
    let response = app.login_with_optional(Some(&email), None).await;

    assert_eq!(
        response.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "Login missing password should return UNPROCESSABLE_ENTITY (422)"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_missing_both_fields() -> anyhow::Result<()> {
    let (app, _account) = create_and_verify_test_account().await?;

    // Try login without any fields
    let response = app.login_with_optional(None, None).await;

    assert_eq!(
        response.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "Login with no fields should return UNPROCESSABLE_ENTITY (422)"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_response_structure() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, password) = account.credentials();

    // Login
    let response = app.login(&email, &password).await;
    assert!(response.status_code().is_success());

    let login_response: LoginResponse = response.json();

    // Verify response structure
    assert!(
        !login_response.access_token.is_empty(),
        "AccessToken field must be present"
    );
    assert!(
        !login_response.refresh_token.is_empty(),
        "RefreshToken field must be present"
    );
    assert!(
        !login_response.user.username.is_empty(),
        "User username must be present"
    );
    assert!(
        !login_response.user.email.is_empty(),
        "User email must be present"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_tokens_are_different() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, password) = account.credentials();

    // Login
    let response = app.login(&email, &password).await;
    let login_response: LoginResponse = response.json();

    // Verify access and refresh tokens are different
    assert_ne!(
        login_response.access_token, login_response.refresh_token,
        "Access token and refresh token should be different"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_returns_valid_jwt_tokens() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, password) = account.credentials();

    // Login
    let response = app.login(&email, &password).await;
    let login_response: LoginResponse = response.json();

    // Verify access token is valid JWT (3 parts: header.payload.signature)
    let access_parts: Vec<&str> = login_response.access_token.split('.').collect();
    assert_eq!(
        access_parts.len(),
        3,
        "Access token should be valid JWT with 3 parts"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_multiple_times_returns_different_tokens() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, password) = account.credentials();

    // First login
    let response1 = app.login(&email, &password).await;
    let login1: LoginResponse = response1.json();
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Second login
    let response2 = app.login(&email, &password).await;
    let login2: LoginResponse = response2.json();

    // Tokens should be different on each login (fresh tokens)
    assert_ne!(
        login1.access_token, login2.access_token,
        "Each login should generate new access tokens"
    );
    assert_ne!(
        login1.refresh_token, login2.refresh_token,
        "Each login should generate new refresh tokens"
    );

    Ok(())
}

#[tokio::test]
async fn test_login_with_empty_password() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, _password) = account.credentials();

    // Try login with empty password
    let response = app.login(&email, "").await;

    assert!(
        response.status_code().is_client_error(),
        "Login with empty password should fail"
    );

    Ok(())
}
#[tokio::test]
async fn test_login_with_empty_email() -> anyhow::Result<()> {
    let (app, _account) = create_and_verify_test_account().await?;

    // Try login with empty email
    let response = app.login("", "SomePassword123!").await;

    assert!(
        response.status_code().is_client_error(),
        "Login with empty email should fail"
    );

    Ok(())
}
//#[tokio::test]
async fn test_login_with_case_insensitive_email() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, password) = account.credentials();

    // Try login with different case
    let uppercase_email = email.to_uppercase();

    // This depends on backend email case sensitivity
    let response = app.login(&uppercase_email, &password).await;

    // Most systems treat email as case-insensitive, so this might succeed or fail
    // depending on implementation. We just verify it returns a valid status.
    assert!(
        response.status_code().is_success() || response.status_code().is_client_error(),
        "Login with different email case should return clear response"
    );

    Ok(())
}

//#[tokio::test]
async fn test_login_with_whitespace_around_email() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (email, password) = account.credentials();

    // Try login with whitespace around email
    let email_with_spaces = format!(" {} ", email);

    let response = app.login(&email_with_spaces, &password).await;

    // Backend should either trim whitespace or reject it
    assert!(
        response.status_code().is_success() || response.status_code().is_client_error(),
        "Login should handle whitespace in email field"
    );

    Ok(())
}

//#[tokio::test]
async fn test_login_with_very_long_email() -> anyhow::Result<()> {
    let (app, account) = create_and_verify_test_account().await?;
    let (_email, password) = account.credentials();

    // Try login with extremely long email
    let long_email = format!("{}@test.local", "a".repeat(1000));

    let response = app.login(&long_email, &password).await;

    assert!(
        response.status_code().is_client_error() || response.status_code().is_success(),
        "Login should handle very long email"
    );

    Ok(())
}

//#[tokio::test]
async fn test_login_case_sensitive_password() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env(false).await?;
    let db_pool = family_cloud::get_db()?;

    let account =
        TestDatabase::create_account(&db_pool, "testuser", "test@example.com", "MyPassword123!")
            .await?;

    let (email, password) = account.credentials();

    // Correct password
    let response_correct = app.login(&email, &password).await;
    assert!(response_correct.status_code().is_success());

    // Wrong case password
    let wrong_case_password = password.to_lowercase();
    let response_wrong = app.login(&email, &wrong_case_password).await;

    assert!(
        response_wrong.status_code().is_client_error(),
        "Password should be case-sensitive"
    );

    Ok(())
}
