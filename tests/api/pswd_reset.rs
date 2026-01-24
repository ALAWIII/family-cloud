use anyhow::Ok;
use family_cloud::{create_verification_key, get_db, get_redis_pool};
use reqwest::StatusCode;
use secrecy::ExposeSecret;

use crate::{
    clean_mailhog, convert_raw_tokens_to_hashed, create_verified_account,
    get_mailhog_msg_id_and_extract_raw_token_list, search_redis_for_hashed_token_id, setup_app,
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
    let msg_id_and_raw_token = get_mailhog_msg_id_and_extract_raw_token_list(&messages, "Password");
    let hashed_tokens: Vec<String> = convert_raw_tokens_to_hashed(
        msg_id_and_raw_token
            .iter()
            .map(|(_, token)| token)
            .collect(),
        app.state.settings.secrets.hmac.expose_secret(),
    )
    .iter()
    .map(|v| create_verification_key(token_type, v))
    .collect();
    // === Phase 3: Verify Tokens Stored in Redis ===
    for hashed_token in &hashed_tokens {
        let pending_account = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            pending_account.is_some(),
            "Token should exist in Redis before confirming the new password"
        );
    }

    // === Phase 4: Complete Verification ===
    for (_, raw_token) in &msg_id_and_raw_token {
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
        let password_reset = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            password_reset.is_none(),
            "Token should not exist in Redis after confirming the new password"
        );
    }
    // === Phase 6: cleaning and deleting all password reset messages from mailhog inbox ===
    clean_mailhog(&msg_id_and_raw_token, &app).await;
    Ok(())
}
