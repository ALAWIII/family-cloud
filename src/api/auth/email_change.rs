use axum::{Extension, Json, debug_handler, extract::State, http::StatusCode};

use crate::{
    AppState, Claims, EmailInput, EmailSender, UserVerification, create_verification_key,
    email_change_body, encode_token, generate_token_bytes, hash_token, is_account_exist,
    store_token_redis,
};

#[debug_handler]
pub async fn change_email(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(email_info): Json<EmailInput>,
) -> Result<StatusCode, StatusCode> {
    let user_id = is_account_exist(&appstate.db_pool, &email_info.email).await;
    if user_id.is_some() {
        // check if email exist
        return Err(StatusCode::CONFLICT);
    }
    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();
    let app_url = std::env::var("APP_URL").unwrap();
    let token_bytes = generate_token_bytes(32);
    let raw_token = encode_token(&token_bytes);
    let token_hash = hash_token(&token_bytes);
    let key = create_verification_key(crate::TokenType::EmailChange, &token_hash);
    let content = UserVerification::new(claims.sub, &claims.username, &email_info.email);
    store_token_redis(
        appstate
            .redis_pool
            .get()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        key,
        &content,
        10 * 60,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    //-------------------------------- sending email change verification to the new email ---------
    let email_link = format!(
        "{}/api/auth/change-email/verify?token={}",
        app_url, raw_token
    );
    EmailSender::default()
        .from_sender(from_sender)
        .email_recipient(email_info.email)
        .subject("Email Change Request".into())
        .email_body(email_change_body(
            &claims.username,
            &email_link,
            10,
            "Family Cloud",
        ))
        .send_email(appstate.mail_client)
        .await;
    Ok(StatusCode::ACCEPTED)
}
pub async fn verify_change_email() {}

pub async fn cancel_change_email() {}
