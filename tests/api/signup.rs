use family_cloud::{get_db, get_redis_pool};

use crate::{
    clean_mailhog, convert_raw_tokens_to_hashed, create_app,
    get_mailhog_msg_id_and_extract_raw_token_list, search_database_for_email,
    search_redis_for_hashed_token_id,
};

#[tokio::test]
async fn signup_endpoint() {
    let app = create_app().await;
    let mut redis_conn = get_redis_pool().get().await.unwrap();
    let verify_url = "/api/auth/signup";
    // === Phase 1: New Account Signup ===
    let response = app.signup_request_new_account().await;
    assert_eq!(
        response.text(),
        "If this email is new, you'll receive a verification email"
    );

    // === Phase 2: Verify Email Sent with Token ===
    let messages = app.get_all_messages_mailhog().await;
    let msg_id_token_pairs =
        get_mailhog_msg_id_and_extract_raw_token_list(&messages, "verification");
    let hashed_tokens =
        convert_raw_tokens_to_hashed(msg_id_token_pairs.iter().map(|(_, token)| token).collect());

    // === Phase 3: Verify Tokens Stored in Redis ===
    for hashed_token in &hashed_tokens {
        let pending_account = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            pending_account.is_some(),
            "Token should exist in Redis before verification"
        );
    }

    // === Phase 4: Complete Verification ===
    for (_, raw_token) in &msg_id_token_pairs {
        app.click_verify_url_in_email_message(verify_url, raw_token)
            .await
            .assert_status_ok();
    }

    // Verify account now exists in database
    let user_id = search_database_for_email(&get_db(), &app.email).await;
    assert!(
        user_id.is_some(),
        "Account should be created after verification"
    );

    // === Phase 5: Test Existing Account Protection ===
    app.signup_request_new_account().await.assert_status_ok();

    // Should not send new email for existing account
    let messages_after = app.get_all_messages_mailhog().await;
    assert_eq!(
        messages_after.len(),
        1,
        "No new email should be sent for existing account"
    );

    // Tokens should be removed from Redis after verification
    for hashed_token in &hashed_tokens {
        let token = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            token.is_none(),
            "Token should be removed from Redis after verification"
        );
    }

    // === Cleanup ===
    clean_mailhog(&msg_id_token_pairs, &app).await;
}
