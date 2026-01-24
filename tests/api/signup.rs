use family_cloud::{TokenType, create_verification_key, get_db, get_redis_pool};
use secrecy::ExposeSecret;

use crate::{
    TestAccount, clean_mailhog, convert_raw_tokens_to_hashed,
    get_mailhog_msg_id_and_extract_raw_token_list, search_database_for_email,
    search_redis_for_hashed_token_id, setup_app,
};

#[tokio::test]
async fn signup_new_account() -> anyhow::Result<()> {
    let app = setup_app().await?;
    let user = TestAccount::default();
    let token_type = TokenType::Signup;
    let mut redis_conn = get_redis_pool()?.get().await.unwrap();
    let verify_url = "/api/auth/signup";
    // === Phase 1: New Account Signup ===
    let response = app.signup_request_new_account(&user).await; //
    assert!(response.text().is_empty());

    // === Phase 2: Verify Email Sent with Token ===
    let messages_before = app.get_all_messages_mailhog().await;
    let msg_id_token_pairs = get_mailhog_msg_id_and_extract_raw_token_list(
        &messages_before,
        "new account email verification",
    );
    let token_type_prefixed_hashed_tokens: Vec<String> = convert_raw_tokens_to_hashed(
        msg_id_token_pairs.iter().map(|(_, token)| token).collect(),
        app.state.settings.secrets.hmac.expose_secret(),
    )
    .iter()
    .map(|v| create_verification_key(token_type, v))
    .collect();

    // === Phase 3: Verify Tokens Stored in Redis ===
    //
    // verify:signup:<token>
    for hashed_token in &token_type_prefixed_hashed_tokens {
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
            .assert_status_success();
    }
    let db_pool = get_db()?;
    // Verify account now exists in database
    let user_id = search_database_for_email(&db_pool, &user.email).await;
    assert!(
        user_id.is_some(),
        "Account should be created after verification"
    );

    // === Phase 5: Test Existing Account Protection (should assert that the existing account should not recieve an email verification) ===
    app.signup_request_new_account(&user)
        .await
        .assert_status_ok();

    // Should not send new email for existing account
    let messages_after = app.get_all_messages_mailhog().await;
    let filterd = get_mailhog_msg_id_and_extract_raw_token_list(
        &messages_after,
        "new account email verification",
    );
    assert_eq!(
        filterd.len(),
        1,
        "No new email should be sent for existing account"
    );

    // Tokens should be removed from Redis after verification,
    //
    //  verify:signup:<token>
    for hashed_token in &token_type_prefixed_hashed_tokens {
        // dbg!(hashed_token);
        let token = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            token.is_none(),
            "Token should be removed from Redis after verification"
        );
    }

    // === Cleanup ===
    clean_mailhog(&msg_id_token_pairs, &app).await;
    Ok(())
}
