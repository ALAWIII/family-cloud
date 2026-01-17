use family_cloud::{create_verification_key, get_db, get_redis_pool};

use crate::{
    clean_mailhog, convert_raw_tokens_to_hashed, create_app, create_verified_account,
    get_mailhog_msg_id_and_extract_raw_token_list, search_redis_for_hashed_token_id,
};

#[tokio::test]
async fn password_reset() {
    let app = create_app().await;
    let user = create_verified_account(&get_db()).await;
    let response = app.password_reset_request(&user.email).await;
    //dbg!(&response);
    assert!(response.status_code().is_success());

    let verify_url = "/api/auth/password-reset";
    let token_type = family_cloud::TokenType::PasswordReset;
    let messages = app.get_all_messages_mailhog().await;

    let mut redis_conn = get_redis_pool().get().await.unwrap();
    let msg_id_and_raw_token = get_mailhog_msg_id_and_extract_raw_token_list(&messages, "Password");
    let hashed_tokens: Vec<String> = convert_raw_tokens_to_hashed(
        msg_id_and_raw_token
            .iter()
            .map(|(_, token)| token)
            .collect(),
    )
    .iter()
    .map(|v| create_verification_key(v, token_type))
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
        app.password_reset_confirm(raw_token, "shakashaka", "shakashaka")
            .await
            .assert_status_ok();
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
}
