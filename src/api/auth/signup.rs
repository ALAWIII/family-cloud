use crate::{
    AppState, EmailSender, PendingAccount, SignupRequest, TokenPayload, User,
    api::{encode_token, generate_token_bytes, hash_password, hash_token},
    create_verification_key, decode_token, delete_token_from_redis, get_verification_data,
    insert_new_account, is_account_exist, store_token_redis, verification_body,
};
use axum::{
    Json, debug_handler,
    extract::{Query, State},
    http::status::StatusCode,
};
use secrecy::ExposeSecret;

/// if email_exist is true then send an email message to tell him that his email is already signup and the token must be used to reset password if he wants too
///
/// if email_exist is false then send a verfication message ask him to click the url inside the email message to verify his signup within 5 minutes
#[debug_handler]
pub(super) async fn signup(
    State(appstate): State<AppState>,
    Json(signup_info): Json<SignupRequest>,
) -> Result<StatusCode, StatusCode> {
    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();

    let user_id = is_account_exist(&appstate.db_pool, &signup_info.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; // sqlx database error
    if user_id.is_none() {
        let base_url = std::env::var("APP_URL").expect("FRONTEND_URL not set");
        // if email is new
        let token = generate_token_bytes(32);
        let raw_token = encode_token(&token); // used to send as a url in email message
        let hashed_token = hash_token(&token); // store in redis database
        let pending_account = create_account(&signup_info).unwrap();
        let email_body = verification_body(
            &signup_info.username,
            &format!("{}/api/auth/signup?token={}", base_url, raw_token),
            5,
            "family_cloud",
        );
        //---------------------------------
        store_token_redis(
            &mut appstate
                .redis_pool
                .get()
                .await
                .expect("Failed to obtain a redis connection from the pool"),
            &create_verification_key(crate::TokenType::Signup, &hashed_token),
            &pending_account,
            5 * 60,
        )
        .await
        .expect("Failed to store token in redis");
        //-------------------------
        EmailSender::default()
            .from_sender(from_sender)
            .email_recipient(signup_info.email)
            .subject("new account email verification".to_string())
            .email_body(email_body)
            .send_email(appstate.mail_client)
            .await;
    } else {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    Ok(
        StatusCode::OK,
        //"If this email is new, you'll receive a verification email".to_string(),
    )
}

//confirm-email?token={}

/// if the email is new and not already used !
fn create_account(
    signup_info: &SignupRequest,
) -> Result<PendingAccount, argon2::password_hash::Error> {
    let hashed_psswd = hash_password(&signup_info.password)?;
    let pending_account =
        PendingAccount::new(&signup_info.username, &signup_info.email, hashed_psswd);
    Ok(pending_account)
}

#[debug_handler]
pub async fn verify_signup_token(
    State(appstate): State<AppState>,
    Query(token): Query<TokenPayload>,
) {
    //  dbg!(&token);
    let mut redis_con = appstate.redis_pool.get().await.unwrap();
    let decoded = decode_token(token.token.expose_secret()).unwrap();
    let hashed_token = hash_token(&decoded);
    let key = create_verification_key(crate::TokenType::Signup, &hashed_token);
    let account: PendingAccount = serde_json::from_str(
        &get_verification_data(&mut redis_con, &key)
            .await
            .expect("fail to find a pending account"),
    )
    .expect("failed to deserialize");
    let user = User::new(account.username, account.email, account.password_hash);
    insert_new_account(user, &appstate.db_pool)
        .await
        .expect("Failed to insert into database");
    delete_token_from_redis(&mut redis_con, &key).await.unwrap()
}
