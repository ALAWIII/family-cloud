use anyhow::Ok;
use family_cloud::{create_verification_key, get_db, get_redis_pool, is_token_exist};
use reqwest::StatusCode;
use secrecy::ExposeSecret;

use crate::{
    convert_raw_tokens_to_hashed, create_verified_account, extract_raw_token_list, setup_app,
};

#[tokio::test]
async fn password_reset_endpoint() -> anyhow::Result<()> {
    let app = setup_app().await?;
    let db_pool = get_db()?;
    let user = create_verified_account(&db_pool).await;
    let response = app.password_reset_request(&user.email).await;
    //dbg!(&response);
    assert!(response.status_code().is_success());

    let verify_url = "/api/auth/password-reset";
    let token_type = family_cloud::TokenType::PasswordReset;
    let messages = app.get_all_messages_mailhog().await;

    let mut redis_conn = get_redis_pool()?.get().await.unwrap();
    let raw_tokens = extract_raw_token_list(&messages, "Password");
    let hashed_tokens: Vec<String> =
        convert_raw_tokens_to_hashed(&raw_tokens, app.state.settings.secrets.hmac.expose_secret())
            .iter()
            .map(|v| create_verification_key(token_type, v))
            .collect();
    // === Phase 3: Verify Tokens Stored in Redis ===
    for hashed_token in &hashed_tokens {
        let pending_account = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            pending_account,
            "Token should exist in Redis before confirming the new password"
        );
    }

    // === Phase 4: Complete Verification ===
    for raw_token in &raw_tokens {
        // it will return a page to fill in the password
        let response = app
            .click_verify_url_in_email_message(verify_url, raw_token)
            .await;
        response.assert_status_ok();
        let html_password_form = response.text();
        assert!(!html_password_form.is_empty());
        // chicking mismatched passwords
        let mismatched_resp = app
            .password_reset_confirm(raw_token, "password1", "password2")
            .await;
        // assert_eq!(mismatched_resp.text(), "Passwords do not match");
        //-------------------------adding the new password-----------
        mismatched_resp.assert_status(StatusCode::BAD_REQUEST);
        app.password_reset_confirm(raw_token, "shakashaka", "shakashaka")
            .await
            .assert_status_ok();

        // re-using the same token again , it must be deleted from redis so that recieving bad request
        let confirm_resp = app
            .password_reset_confirm(raw_token, "newpass", "newpass")
            .await;

        confirm_resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    // === Phase 5: Verify Tokens are Deleted from Redis ===
    for hashed_token in &hashed_tokens {
        let password_reset = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            !password_reset,
            "Token should not exist in Redis after confirming the new password"
        );
    }
    Ok(())
}
