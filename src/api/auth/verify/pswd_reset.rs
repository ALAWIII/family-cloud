use std::time::Duration;

use askama::Template;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::StatusCode,
    response::Html,
};
use secrecy::{SecretBox, SecretString};
use serde::Deserialize;

use crate::{
    AppState, EmailSender, PasswordRequestReset, PasswordUserReset, TokenQuery,
    create_verification_key, decode_token, delete_token_from_redis, encode_token,
    generate_token_bytes, get_user_password_reset_info_by_email, get_verification_data,
    hash_password, hash_token, is_token_exist, password_reset_body, store_token_redis,
    update_password,
};
#[derive(Deserialize)]
pub struct PasswordResetForm {
    token: String,
    new_password: String,
    confirm_password: String,
}
#[derive(Template)]
#[template(path = "pswd_reset_form.html")]
struct PasswordResetTemplate<'a> {
    token: &'a str,
}
fn password_form_page(token: &str) -> Html<String> {
    Html(PasswordResetTemplate { token }.render().unwrap())
}

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
pub async fn verify_password_reset(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenQuery>,
) -> Result<Html<String>, (StatusCode, &'static str)> {
    let decoded_token = decode_token(&raw_token.token).expect("Faield to convert to bytes");
    let hashed_token = hash_token(&decoded_token);
    let token_exist = is_token_exist(
        &create_verification_key(&hashed_token, crate::TokenType::PasswordReset),
        appstate
            .redis_pool
            .get()
            .await
            .expect("Failed to obtain redis connection"),
    )
    .await;
    token_exist
        .then(|| password_form_page(&raw_token.token))
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Your request expired. Please request a new password reset link.",
        ))
}
pub async fn confirm_password_reset(
    State(appstate): State<AppState>,
    Form(form): Form<PasswordResetForm>,
) -> (StatusCode, &'static str) {
    if form.new_password != form.confirm_password {
        return (StatusCode::BAD_REQUEST, "Passwords do not match");
    }
    let token_byte = decode_token(&form.token).expect("Failed to decode raw token to bytes");
    let hashed_token = hash_token(&token_byte);
    let key = create_verification_key(&hashed_token, crate::TokenType::PasswordReset);
    let redis_con = appstate
        .redis_pool
        .get()
        .await
        .expect("Failed to get connection ");
    let user_data = get_verification_data(&key, redis_con)
        .await
        .map(|v| PasswordUserReset::from_str(&v).expect("Failed to deserialize content"));
    if user_data.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "Your request expired. Please request a new password reset link.",
        );
    }
    let password_hash = hash_password(&SecretBox::new(Box::new(form.new_password)))
        .expect("Failed to hash password");
    update_password(&appstate.db_pool, user_data.unwrap().id, &password_hash).await;
    delete_token_from_redis(
        appstate
            .redis_pool
            .get()
            .await
            .expect("Failed to get connection "),
        &hashed_token,
    )
    .await
    .expect("Failed to delete token");
    (StatusCode::OK, "Password updated successfully")
}
