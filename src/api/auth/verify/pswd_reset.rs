use std::time::Duration;

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};

use crate::{
    AppState, EmailSender, PasswordRequestReset, TokenQuery, create_verification_key, decode_token,
    encode_token, generate_token_bytes, get_user_password_reset_info_by_email, hash_token,
    password_reset_body, search_redis_for_token, store_token_redis,
};

pub async fn password_rest(
    State(appstate): State<AppState>,
    Json(pswd_info): Json<PasswordRequestReset>,
) -> (StatusCode, String) {
    let user_info =
        get_user_password_reset_info_by_email(&appstate.db_pool, &pswd_info.email).await;
    if let Some(user_info) = user_info {
        let base_url = std::env::var("APP_URL").expect("FRONTEND_URL not set");

        let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();
        let token = generate_token_bytes(32);
        let raw_token = encode_token(&token);
        let hashed_token = hash_token(&token);

        //---------------------
        store_token_redis(
            appstate
                .redis_pool
                .get()
                .await
                .expect("Failed to obtain a redis connection"),
            create_verification_key(&hashed_token, crate::TokenType::PasswordReset),
            &user_info,
            5 * 60,
        )
        .await
        .expect("Failed to store in redis");

        //---------------------------------
        let reset_link = format!("{}/api/auth/password-reset?token={}", base_url, raw_token);
        let body = password_reset_body(&user_info.username, &reset_link, 5, "family cloud");
        EmailSender::default()
            .from_sender(from_sender)
            .email_recipient(pswd_info.email)
            .subject("Password reset account".into())
            .email_body(body)
            .send_email(appstate.mail_client)
            .await;
    } else {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    (StatusCode::OK, "If account exists, check your email".into())
}

pub async fn confirm_password_reset() {}
