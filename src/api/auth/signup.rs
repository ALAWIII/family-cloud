use crate::{
    AppState, EmailSender, PendingAccount, SignupRequest,
    api::{encode_token, generate_token_bytes, hash_password, hash_token},
    store_token_redis, verification_body,
};
use axum::{Json, debug_handler, extract::State, http::status::StatusCode};
use sqlx::{PgPool, types::Uuid};

/// if email_exist is true then send an email message to tell him that his email is already signup and the token must be used to reset password if he wants too
///
/// if email_exist is false then send a verfication message ask him to click the url inside the email message to verify his signup within 5 minutes
#[debug_handler]
pub(super) async fn signup(
    State(appstate): State<AppState>,
    Json(signup_info): Json<SignupRequest>,
) -> (StatusCode, String) {
    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();

    let user_id = is_email_exist(&signup_info.email, &appstate.db_pool)
        .await
        .expect("Failed to retrieve from database"); // sqlx database error
    if user_id.is_none() {
        let token = generate_token_bytes(32);
        let raw_token = encode_token(&token); // used to send as a url in email message
        let hashed_token = hash_token(&token); // store in redis database
        let pending_account = create_account(&signup_info).unwrap();
        let email_body = verification_body(
            &signup_info.username,
            &format!("verify?token={}", raw_token),
            5,
            "family_cloud",
        );
        EmailSender::default()
            .from_sender(from_sender)
            .email_recipient(signup_info.email)
            .msg_id(raw_token)
            .subject("new account email verification".to_string())
            .email_body(email_body)
            .send_email(appstate.mail_client)
            .await;
        store_token_redis(
            appstate
                .redis_pool
                .get()
                .await
                .expect("Failed to obtain a redis connection from the pool"),
            hashed_token,
            &pending_account,
            5 * 60,
        )
        .await
        .expect("Failed to store token in redis");
    } else {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    (
        StatusCode::OK,
        "If this email is new, you'll receive a verification email".to_string(),
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

/// if it returns a value means that the email is already signedup
async fn is_email_exist(email: &str, pool: &PgPool) -> Result<Option<Uuid>, sqlx::Error> {
    let record: Option<_> = sqlx::query!("select id from users where email=$1", email)
        .fetch_optional(pool)
        .await?;
    Ok(record.map(|v| v.id))
}
