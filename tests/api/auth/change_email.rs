//! Integration tests for email change endpoints
//!
//! Tests the email change flow:
//! - Request email change (sends 2 emails: cancel + verify)
//! - Verify new email (completes email change)
//! - Cancel email change (reverts to original email)
//! - Verify response status codes (202 ACCEPTED for request, 200 OK for verify/cancel)

use family_cloud::{LoginResponse, fetch_account_info};
use reqwest::StatusCode;
use uuid::Uuid;

use crate::{
    setup_test_env,
    utils::{AppTest, EmailTokenExtractor, TestAccount, TestDatabase},
};

// ============================================================================
// Helper: Setup with Authenticated User
// ============================================================================

async fn setup_with_authenticated_user() -> anyhow::Result<(AppTest, TestAccount, LoginResponse)> {
    let (app, _state) = setup_test_env().await?;
    let db_pool = family_cloud::get_db()?;

    // Create verified account
    let account = TestDatabase::create_verified_account(&db_pool).await?;
    let (email, password) = account.credentials();

    // Login to get access token
    let login_response = app.login(&email, &password).await;
    assert!(
        login_response.status_code().is_success(),
        "Login should succeed"
    );

    let login_data: LoginResponse = login_response.json();

    Ok((app, account, login_data))
}

// ============================================================================
// Helper: Request Email Change and Extract Tokens
// ============================================================================

async fn request_email_change_and_get_tokens(
    app: &AppTest,
    new_email: &str,
    access_token: &str,
) -> anyhow::Result<(String, String)> {
    // Request email change
    let response = app.request_email_change(new_email, access_token).await;

    assert_eq!(
        response.status_code(),
        StatusCode::ACCEPTED,
        "Email change request should return ACCEPTED (202)"
    );

    // Get emails from MailHog
    let messages = app.mailhog.get_all_messages().await?;

    // Extract tokens from both emails
    let verify_tokens = EmailTokenExtractor::extract_raw_tokens(&messages, "Change Email Request");
    let cancel_tokens =
        EmailTokenExtractor::extract_raw_tokens(&messages, "Cancel Changing Email Request");

    assert!(
        !verify_tokens.is_empty(),
        "Should receive email verification message"
    );
    assert!(
        !cancel_tokens.is_empty(),
        "Should receive email cancel message"
    );

    // Return first token from each type
    Ok((
        verify_tokens.first().cloned().unwrap_or_default(),
        cancel_tokens.first().cloned().unwrap_or_default(),
    ))
}

// ============================================================================
// Change Email Tests
// ============================================================================

#[tokio::test]
async fn test_request_email_change_returns_accepted() -> anyhow::Result<()> {
    let (app, _account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request email change
    let response = app
        .request_email_change(&new_email, &login_data.access_token)
        .await;

    assert_eq!(
        response.status_code(),
        StatusCode::ACCEPTED,
        "Email change request should return ACCEPTED (202)"
    );

    Ok(())
}

#[tokio::test]
async fn test_request_email_change_sends_two_emails() -> anyhow::Result<()> {
    let (app, _account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request email change
    let _response = app
        .request_email_change(&new_email, &login_data.access_token)
        .await;

    // Get emails from MailHog
    let messages = app.mailhog.get_all_messages().await?;

    // Verify we received both verification and cancel emails
    let verify_emails = EmailTokenExtractor::extract_raw_tokens(&messages, "Change Email Request");
    let cancel_emails =
        EmailTokenExtractor::extract_raw_tokens(&messages, "Cancel Changing Email Request");

    assert_eq!(
        verify_emails.len(),
        1,
        "Should send exactly one email verification message"
    );
    assert_eq!(
        cancel_emails.len(),
        1,
        "Should send exactly one email cancel message"
    );

    Ok(())
}

#[tokio::test]
async fn test_verify_email_change_completes_change() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request email change
    let (verify_token, _cancel_token) =
        request_email_change_and_get_tokens(&app, &new_email, &login_data.access_token).await?;

    // Verify the email change
    let verify_response = app.verify_email_change(&verify_token).await;

    assert_eq!(
        verify_response.status_code(),
        StatusCode::OK,
        "Email verification should return OK (200)"
    );

    // Verify account email was updated and stored in the database
    let db_pool = family_cloud::get_db()?;
    let updated_account = fetch_account_info(&db_pool, &new_email).await?;

    assert_eq!(
        updated_account.id, account.id,
        "User ID should remain the same"
    );
    assert_eq!(
        updated_account.email, new_email,
        "Email should be updated to new email"
    );

    Ok(())
}

#[tokio::test]
async fn test_cancel_email_change_reverts_email() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request email change
    let (_verify_token, cancel_token) =
        request_email_change_and_get_tokens(&app, &new_email, &login_data.access_token).await?;

    // Cancel the email change
    let cancel_response = app.cancel_email_change(&cancel_token).await;

    assert_eq!(
        cancel_response.status_code(),
        StatusCode::OK,
        "Email cancel should return OK (200)"
    );

    // Verify account email was NOT updated
    let db_pool = family_cloud::get_db()?;
    let current_account = fetch_account_info(&db_pool, &account.email).await?;

    assert_eq!(
        current_account.id, account.id,
        "User ID should remain the same"
    );
    assert_eq!(
        current_account.email, account.email,
        "Email should remain original email after cancel"
    );

    // Verify old email is not in database
    let result = fetch_account_info(&db_pool, &new_email).await;
    assert!(
        result.is_err(),
        "New email should not exist in database after cancel"
    );

    Ok(())
}

#[tokio::test]
async fn test_email_change_requires_authentication() -> anyhow::Result<()> {
    let (app, _account, _login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Try to request email change without access token
    let response = app.request_email_change(&new_email, "").await;

    assert!(
        response.status_code().is_client_error(),
        "Email change without auth should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_email_change_with_invalid_access_token() -> anyhow::Result<()> {
    let (app, _account, _login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Try with invalid token
    let response = app
        .request_email_change(&new_email, "invalid_token_xyz")
        .await;

    assert!(
        response.status_code().is_client_error(),
        "Email change with invalid token should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_verify_with_invalid_token() -> anyhow::Result<()> {
    let (app, _account, _login_data) = setup_with_authenticated_user().await?;

    // Try to verify with invalid token
    let response = app.verify_email_change("invalid_token_xyz").await;

    assert!(
        response.status_code().is_client_error(),
        "Email verification with invalid token should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_cancel_with_invalid_token() -> anyhow::Result<()> {
    let (app, _account, _login_data) = setup_with_authenticated_user().await?;

    // Try to cancel with invalid token
    let response = app.cancel_email_change("invalid_token_xyz").await;

    assert!(
        response.status_code().is_client_error(),
        "Email cancel with invalid token should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_verify_token_single_use_only() -> anyhow::Result<()> {
    let (app, _account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request and get tokens
    let (verify_token, _cancel_token) =
        request_email_change_and_get_tokens(&app, &new_email, &login_data.access_token).await?;

    // First verification
    let first_verify = app.verify_email_change(&verify_token).await;
    assert!(
        first_verify.status_code().is_success(),
        "First verification should succeed"
    );

    // Try to verify again with same token
    let second_verify = app.verify_email_change(&verify_token).await;

    assert!(
        second_verify.status_code().is_client_error(),
        "Reusing verification token should fail (token already consumed)"
    );

    Ok(())
}

#[tokio::test]
async fn test_cancel_token_single_use_only() -> anyhow::Result<()> {
    let (app, _account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request and get tokens
    let (_verify_token, cancel_token) =
        request_email_change_and_get_tokens(&app, &new_email, &login_data.access_token).await?;

    // First cancellation
    let first_cancel = app.cancel_email_change(&cancel_token).await;
    assert!(
        first_cancel.status_code().is_success(),
        "First cancel should succeed"
    );

    // Try to cancel again with same token
    let second_cancel = app.cancel_email_change(&cancel_token).await;

    assert!(
        second_cancel.status_code().is_client_error(),
        "Reusing cancel token should fail (token already consumed)"
    );

    Ok(())
}

#[tokio::test]
async fn test_email_change_new_email_must_be_unique() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;

    // Create another account
    let db_pool = family_cloud::get_db()?;
    let other_account = TestDatabase::create_verified_account(&db_pool).await?; // it automatically creates and stores the email in db

    // Try to change to existing account's email
    let response = app
        .request_email_change(&other_account.email, &login_data.access_token)
        .await;

    // Should fail because email is already in use
    assert!(
        response.status_code().is_client_error(),
        "Cannot change to email that's already in use"
    );

    Ok(())
}

#[tokio::test]
async fn test_email_change_cannot_verify_after_cancel() -> anyhow::Result<()> {
    let (app, _account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request and get tokens
    let (verify_token, cancel_token) =
        request_email_change_and_get_tokens(&app, &new_email, &login_data.access_token).await?;

    // Cancel first
    let cancel_response = app.cancel_email_change(&cancel_token).await;
    assert!(
        cancel_response.status_code().is_success(),
        "Cancel should succeed"
    );

    // Try to verify after cancel
    let verify_response = app.verify_email_change(&verify_token).await;

    assert!(
        verify_response.status_code().is_client_error(),
        "Cannot verify after email change has been cancelled"
    );

    Ok(())
}

#[tokio::test]
async fn test_old_email_cannot_login_after_change() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());
    let old_email = account.email.clone();

    // Request and verify email change
    let (verify_token, _cancel_token) =
        request_email_change_and_get_tokens(&app, &new_email, &login_data.access_token).await?;

    let verify_response = app.verify_email_change(&verify_token).await;
    assert!(
        verify_response.status_code().is_success(),
        "Verification should succeed"
    );

    // Try to login with old email
    let login_response = app.login(&old_email, &account.password).await;

    assert!(
        login_response.status_code().is_client_error(),
        "Cannot login with old email after email change"
    );

    Ok(())
}

#[tokio::test]
async fn test_new_email_can_login_after_change() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;

    let new_email = format!("{}@test.local", Uuid::new_v4());

    // Request and verify email change
    let (verify_token, _cancel_token) =
        request_email_change_and_get_tokens(&app, &new_email, &login_data.access_token).await?;

    let verify_response = app.verify_email_change(&verify_token).await;
    assert!(
        verify_response.status_code().is_success(),
        "Verification should succeed"
    );

    // Try to login with new email
    let login_response = app.login(&new_email, &account.password).await;

    assert!(
        login_response.status_code().is_success(),
        "Can login with new email after email change"
    );

    let new_login_data: LoginResponse = login_response.json();
    assert_eq!(
        new_login_data.user.email, new_email,
        "User profile should show new email"
    );

    Ok(())
}
