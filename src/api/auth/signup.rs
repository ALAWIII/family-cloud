use axum::{Json, debug_handler, extract::State};
use deadpool_redis::{
    Pool,
    redis::{AsyncTypedCommands, RedisError},
};

use sqlx::{PgPool, types::Uuid};

use crate::{
    AppState, EmailSender, PendingAccount, SignupPayload, SignupRequest, TokenPayload,
    api::{encode_token, generate_token_bytes, hash_password, hash_token},
    password_reset_body, verification_body,
};

/// if email_exist is true then send an email message to tell him that his email is already signup and the token must be used to reset password if he wants too
///
/// if email_exist is false then send a verfication message ask him to click the url inside the email message to verify his signup within 5 minutes
#[debug_handler]
pub(super) async fn signup(
    State(appstate): State<AppState>,
    Json(signup_info): Json<SignupRequest>,
) {
    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();

    let user_id = is_email_exist(&signup_info.email, &appstate.db_pool)
        .await
        .expect("Failed to retrieve from database"); // sqlx database error
    let token = generate_token_bytes(32);
    let raw_token = encode_token(&token); // used to send as a url in email message
    let hashed_token = hash_token(&token); // store in redis database
    let (subject, email_body, payload) =
        signup_email_type(user_id, &signup_info.username, &raw_token, &signup_info);
    EmailSender::default()
        .from_sender(from_sender)
        .email_recipient(signup_info.email)
        .msg_id(raw_token)
        .subject(subject)
        .email_body(email_body)
        .send_email(appstate.mail_client)
        .await;
    store_token_redis(
        &appstate.redis_pool,
        hashed_token,
        payload
            .to_json()
            .expect("failed to convert payload to json string"),
        5 * 60,
    )
    .await
    .expect("Failed to store token in redis");
}
fn signup_email_type(
    user_id: Option<Uuid>,
    username: &str,
    raw_token: &str,
    signup_info: &SignupRequest,
) -> (String, String, SignupPayload) {
    if let Some(user_id) = user_id {
        return (
            "signup existing account".to_string(),
            password_reset_body(
                username,
                &format!("reset-password?token={}", raw_token),
                5,
                "family_cloud",
                true,
            ),
            SignupPayload::Existing(TokenPayload { user_id }),
        );
    }
    (
        "new account email verification".to_string(),
        verification_body(
            username,
            &format!("verify?token={}", raw_token),
            5,
            "family_cloud",
        ),
        SignupPayload::New(create_account(signup_info).unwrap()),
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

/// accepts key_token an hmac hashed version of the raw token , ttl (seconds) is the time to set to expire the entry in database
async fn store_token_redis(
    conn: &Pool,
    key_token: String,
    content: String,
    ttl: u64,
) -> Result<(), RedisError> {
    let mut conn = conn
        .get()
        .await
        .expect("Failed to get a connection from pool");
    conn.set_ex(key_token, content, ttl).await
}
