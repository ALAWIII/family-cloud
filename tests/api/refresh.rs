//! Integration tests for token refresh endpoint
//!
//! Tests the refresh token flow:
//! - Refresh with token in body (desktop/mobile)
//! - Refresh with token in cookie (web)
//! - Refresh without token (should fail)
//! - Verify new access tokens are generated
//! - Verify tokens are different on each refresh

use std::{sync::Arc, time::Duration};

use crate::{
    setup_test_env,
    utils::{AppTest, TestAccount, TestDatabase, create_token_pair},
};
use axum::http::StatusCode;
use family_cloud::{LoginResponse, TokenPayload};
use secrecy::ExposeSecret;

// ============================================================================
// Helper: Setup with Verified & Logged-In Account
// ============================================================================

/// Setup and get authenticated user
async fn setup_with_authenticated_user()
-> anyhow::Result<(AppTest, family_cloud::AppState, TestAccount, LoginResponse)> {
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

    Ok((app, state, account, login_data))
}

// ============================================================================
// Refresh Token Tests
// ============================================================================

#[tokio::test]
async fn test_refresh_with_token_in_body() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    // Create body with refresh token
    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Refresh using body (desktop/mobile pattern)
    let response = app.refresh_with_body(&body).await;

    assert!(
        response.status_code().is_success(),
        "Refresh with body token should succeed"
    );

    let token_response: TokenPayload = response.json();
    assert!(
        !token_response.token.expose_secret().is_empty(),
        "Should receive new access token"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_with_token_in_cookie() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    // Create cookie with refresh token
    let (cookie, _body) = create_token_pair(&login_data.refresh_token);

    // Refresh using cookie (web browser pattern)
    let response = app.refresh_with_cookie(cookie).await;

    assert!(
        response.status_code().is_success(),
        "Refresh with cookie token should succeed"
    );

    let token_response: TokenPayload = response.json();
    assert!(
        !token_response.token.expose_secret().is_empty(),
        "Should receive new access token"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_without_token() -> anyhow::Result<()> {
    let (app, _state, _account, _login_data) = setup_with_authenticated_user().await?;

    // Try refreshing without any token
    let response = app.refresh().await;

    assert_eq!(
        response.status_code(),
        StatusCode::UNAUTHORIZED,
        "Refresh without token should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_generates_new_access_token() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // First refresh
    let response1 = app.refresh_with_body(&body).await;
    assert!(response1.status_code().is_success());
    let token1: TokenPayload = response1.json();

    // Second refresh (same refresh token)
    let response2 = app.refresh_with_body(&body).await;
    assert!(response2.status_code().is_success());
    let token2: TokenPayload = response2.json();

    // Both should have tokens
    assert!(
        !token1.token.expose_secret().is_empty(),
        "First refresh should return access token"
    );
    assert!(
        !token2.token.expose_secret().is_empty(),
        "Second refresh should return access token"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_with_body_and_cookie_different_tokens() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    let (cookie, body) = create_token_pair(&login_data.refresh_token);

    // Refresh with body
    let response_body = app.refresh_with_body(&body).await;
    assert!(response_body.status_code().is_success());
    let token_body: TokenPayload = response_body.json();
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Refresh with cookie
    let response_cookie = app.refresh_with_cookie(cookie).await;
    assert!(response_cookie.status_code().is_success());
    let token_cookie: TokenPayload = response_cookie.json();

    // Both should have tokens but they might be different (depends on implementation)
    assert!(
        !token_body.token.expose_secret().is_empty(),
        "Body refresh should return token"
    );
    assert!(
        !token_cookie.token.expose_secret().is_empty(),
        "Cookie refresh should return token"
    );
    assert_ne!(
        token_cookie.token.expose_secret(),
        token_body.token.expose_secret(),
        "Different access tokens for the same account"
    );
    Ok(())
}

#[tokio::test]
async fn test_refresh_with_invalid_token() -> anyhow::Result<()> {
    let (app, _state, _account, _login_data) = setup_with_authenticated_user().await?;

    // Create body with invalid token
    let (_cookie, body) = create_token_pair("invalid_refresh_token_xyz");

    // Try refreshing with invalid token
    let response = app.refresh_with_body(&body).await;

    assert!(
        response.status_code().is_client_error(),
        "Refresh with invalid token should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_multiple_times_in_sequence() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    let (_cookie, body) = create_token_pair(&login_data.refresh_token);
    let mut tokens = Vec::new();

    // Refresh 3 times
    for i in 0..3 {
        let response = app.refresh_with_body(&body).await;
        assert!(
            response.status_code().is_success(),
            "Refresh attempt {} should succeed",
            i + 1
        );

        let token: TokenPayload = response.json();
        assert!(
            !token.token.expose_secret().is_empty(),
            "Refresh {} should return valid token",
            i + 1
        );

        tokens.push(token);
    }

    // Verify we got 3 tokens
    assert_eq!(tokens.len(), 3, "Should have 3 tokens from 3 refreshes");

    Ok(())
}

#[tokio::test]
async fn test_refresh_returns_valid_jwt() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Refresh
    let response = app.refresh_with_body(&body).await;
    assert!(response.status_code().is_success());

    let token_response: TokenPayload = response.json();
    let token_secret = token_response.token.expose_secret();

    // JWT should have 3 parts separated by dots
    let parts: Vec<&str> = token_secret.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "Access token should be valid JWT with 3 parts (header.payload.signature)"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_can_be_used_for_authenticated_requests() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Refresh to get new access token
    let response = app.refresh_with_body(&body).await;
    assert!(response.status_code().is_success());

    let token_response: TokenPayload = response.json();
    let new_access_token = token_response.token.expose_secret();

    // Use new access token for authenticated request
    // (example: change email endpoint requires auth)
    let auth_response = app
        .request_email_change("newemail@test.local", new_access_token)
        .await;

    // Should be successful (not 401/403)
    assert_ne!(
        auth_response.status_code(),
        StatusCode::UNAUTHORIZED,
        "New access token from refresh should be valid for authenticated requests"
    );

    Ok(())
}

#[tokio::test]
async fn test_refresh_after_logout_fails() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    let (cookie, body) = create_token_pair(&login_data.refresh_token);

    // Logout first
    let logout_response = app.logout_with_body(&body).await;
    assert!(
        logout_response.status_code().is_success(),
        "Logout should succeed"
    );

    // Try refreshing with same token after logout
    let refresh_response = app.refresh_with_body(&body).await;

    assert!(
        refresh_response.status_code().is_client_error(),
        "Refresh with invalidated refresh token should fail after logout"
    );

    Ok(())
}

#[tokio::test]
async fn test_concurrent_refreshes_succeed() -> anyhow::Result<()> {
    let (app, _state, _account, login_data) = setup_with_authenticated_user().await?;

    let (_cookie, body) = create_token_pair(&login_data.refresh_token);

    // Simulate concurrent refresh requests
    let body1 = body.clone();
    let body2 = body.clone();
    let app = Arc::new(app);
    let handle1 = tokio::spawn({
        let app = app.clone();
        async move {
            app.refresh_with_body(&body1)
                .await
                .status_code()
                .is_success()
        }
    });

    let handle2 = tokio::spawn({
        let app = app.clone();
        async move {
            app.refresh_with_body(&body2)
                .await
                .status_code()
                .is_success()
        }
    });

    let result1 = handle1.await?;
    let result2 = handle2.await?;

    assert!(result1, "First concurrent refresh should succeed");
    assert!(result2, "Second concurrent refresh should succeed");

    Ok(())
}
