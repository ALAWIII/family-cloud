use family_cloud::{
    TokenType, create_verification_key, get_db, get_redis_con, get_redis_pool, is_token_exist,
};
use secrecy::ExposeSecret;

use crate::{
    AppTest, TestAccount, clean_mailhog, convert_raw_tokens_to_hashed,
    get_mailhog_msg_id_and_extract_raw_token_list, search_database_for_email,
    search_redis_for_hashed_token_id, setup_app,
};

// === Shared Helper Functions ===

async fn signup_and_get_token()
-> anyhow::Result<(AppTest, TestAccount, Vec<(String, String)>, Vec<String>)> {
    let app = setup_app().await?;
    let user = TestAccount::default();

    app.signup_request_new_account(&user).await;

    let messages = app.get_all_messages_mailhog().await;
    let msg_id_token_pairs =
        get_mailhog_msg_id_and_extract_raw_token_list(&messages, "new account email verification");

    let hashed_tokens: Vec<String> = convert_raw_tokens_to_hashed(
        msg_id_token_pairs.iter().map(|(_, token)| token).collect(),
        app.state.settings.secrets.hmac.expose_secret(),
    )
    .iter()
    .map(|v| create_verification_key(TokenType::Signup, v))
    .collect();

    Ok((app, user, msg_id_token_pairs, hashed_tokens))
}

// === Individual Tests ===

#[tokio::test]
async fn signup_sends_verification_email() -> anyhow::Result<()> {
    let (app, _user, msg_id_token_pairs, _hashed_tokens) = signup_and_get_token().await?;

    assert_eq!(
        msg_id_token_pairs.len(),
        1,
        "Should send exactly one verification email"
    );

    Ok(())
}

#[tokio::test]
async fn verification_token_stored_in_redis() -> anyhow::Result<()> {
    let (app, _user, msg_id_token_pairs, hashed_tokens) = signup_and_get_token().await?;
    let mut redis_conn = get_redis_con(app.state.redis_pool).await?;

    for hashed_token in &hashed_tokens {
        let pending_account = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            pending_account.is_some(),
            "Token should exist in Redis before verification"
        );
    }

    Ok(())
}

#[tokio::test]
async fn verification_completes_account_creation() -> anyhow::Result<()> {
    let (app, user, msg_id_token_pairs, _) = signup_and_get_token().await?;
    let db_pool = get_db()?;
    let verify_url = "/api/auth/signup";

    for (_, raw_token) in &msg_id_token_pairs {
        app.click_verify_url_in_email_message(verify_url, raw_token)
            .await
            .assert_status_success();
    }

    let user_id = search_database_for_email(&db_pool, &user.email).await;

    assert!(
        user_id.is_some(),
        "Account should be created after verification"
    );

    Ok(())
}

#[tokio::test]
async fn existing_account_prevents_duplicate_signup() -> anyhow::Result<()> {
    let (app, user, msg_id_token_pairs, hashed_tokens) = signup_and_get_token().await?;
    let verify_url = "/api/auth/signup";

    // Complete verification
    for (_, raw_token) in &msg_id_token_pairs {
        app.click_verify_url_in_email_message(verify_url, raw_token)
            .await;
    }

    // Try signing up again with the same user account
    app.signup_request_new_account(&user)
        .await
        .assert_status_ok();

    let messages_after = app.get_all_messages_mailhog().await;
    let new_tokens = get_mailhog_msg_id_and_extract_raw_token_list(
        &messages_after,
        "new account email verification",
    );

    assert_eq!(
        new_tokens.len(),
        1,
        "No new email should be sent for existing account"
    );
    let mut rds_con = get_redis_con(get_redis_pool()?).await?;
    for h in hashed_tokens {
        assert!(!is_token_exist(&mut rds_con, &h).await?);
    }

    Ok(())
}

#[tokio::test]
async fn verification_removes_token_from_redis() -> anyhow::Result<()> {
    let (app, _user, msg_id_token_pairs, hashed_tokens) = signup_and_get_token().await?;
    let mut redis_conn = get_redis_con(app.state.redis_pool.clone()).await?;
    let verify_url = "/api/auth/signup";

    // Complete verification
    for (_, raw_token) in &msg_id_token_pairs {
        app.click_verify_url_in_email_message(verify_url, raw_token)
            .await;
    }

    // Verify tokens removed from Redis
    for hashed_token in &hashed_tokens {
        let token = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            token.is_none(),
            "Token should be removed from Redis after verification"
        );
    }

    Ok(())
}
