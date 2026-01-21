use std::time::Duration;

use askama::Template;
use axum::{
    Form, Json,
    extract::{Query, State},
    http::StatusCode,
    response::Html,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;

use crate::{
    ApiError, AppState, EmailInput, EmailSender, TokenPayload, User, UserVerification,
    create_verification_key, decode_token, delete_token_from_redis, deserialize_content,
    encode_token, fetch_account_info, generate_token_bytes, get_redis_con, get_verification_data,
    hash_password, hash_token, is_token_exist, password_reset_body, serialize_content,
    store_token_redis, update_account_password,
};
//const EXPIRED_TOKEN_MSG: &str = "Your request expired. Please request a new password reset link.";

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
    Html(
        PasswordResetTemplate { token }
            .render()
            .unwrap_or("".into()),
    )
}

pub async fn password_reset(
    State(appstate): State<AppState>,
    Json(pswd_info): Json<EmailInput>,
) -> Result<StatusCode, ApiError> {
    let user_info: User = match fetch_account_info(&appstate.db_pool, &pswd_info.email).await {
        Ok(v) => v,
        Err(e) => {
            tokio::time::sleep(Duration::from_millis(fastrand::u64(80..120))).await; // prevent timing attack
            return Err(e.into());
        } // if user not found
    };

    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();
    let base_url = std::env::var("APP_URL").expect("FRONTEND_URL not set");

    let token = generate_token_bytes(32)?;
    let raw_token = encode_token(&token);
    let hashed_token = hash_token(&token)?;
    let key = create_verification_key(crate::TokenType::PasswordReset, &hashed_token);
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    //---------------------
    let content = serialize_content(&user_info)?;
    store_token_redis(&mut redis_con, &key, &content, 5 * 60).await?;

    //---------------------------------
    let reset_link = format!("{}/api/auth/password-reset?token={}", base_url, raw_token);
    let body = password_reset_body(&user_info.username, &reset_link, 5, "family cloud");
    EmailSender::default()
        .from_sender(from_sender)
        .email_recipient(pswd_info.email)
        .subject("Password reset account".into())
        .email_body(body)
        .send_email(appstate.mail_client)
        .await?;

    Ok(StatusCode::OK)

    //  (, "If account exists, check your email".into())
}
pub async fn verify_password_reset(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenPayload>,
) -> Result<Html<String>, ApiError> {
    let decoded_token = decode_token(raw_token.token.expose_secret())?;
    let hashed_token = hash_token(&decoded_token)?;
    let key = create_verification_key(crate::TokenType::PasswordReset, &hashed_token);
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let token_exist = is_token_exist(&mut redis_con, &key).await?;
    token_exist
        .then(|| password_form_page(raw_token.token.expose_secret()))
        .ok_or(ApiError::BadRequest)
}
pub async fn confirm_password_reset(
    State(appstate): State<AppState>,
    Form(form): Form<PasswordResetForm>,
) -> Result<StatusCode, ApiError> {
    if form.new_password != form.confirm_password {
        return Err(ApiError::BadRequest); // malformed ,invalid password matching
    }
    let token_byte = decode_token(&form.token)?;
    let hashed_token = hash_token(&token_byte)?;
    let key = create_verification_key(crate::TokenType::PasswordReset, &hashed_token);
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let udata = get_verification_data(&mut redis_con, &key)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let user_ver = deserialize_content::<UserVerification>(&udata)?;

    let password_hash = hash_password(&SecretBox::new(Box::new(form.new_password)))?;
    update_account_password(&appstate.db_pool, user_ver.id, &password_hash).await;
    delete_token_from_redis(&mut redis_con, &key).await?;

    Ok(StatusCode::OK)
}
