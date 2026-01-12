use axum::{Json, debug_handler, extract::State};
use chrono::{DateTime, Utc};
use deadpool_redis::{
    Pool,
    redis::{self, AsyncTypedCommands, RedisError},
};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, types::Uuid};

use crate::{
    AppState,
    api::{encode_token, generate_token_bytes, hash_password, hash_token},
};

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: Uuid,
    username: String,
    email: String,
    password_hash: String,
    created_at: DateTime<Utc>,
    storage_quota_bytes: u64,
    storage_used_bytes: u64,
}
impl User {
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            created_at: Utc::now(),
            storage_quota_bytes: 2147483648,
            storage_used_bytes: 0,
        }
    }
    pub fn set_storage_quota_bytes(&mut self, sqb: u64) {
        self.storage_quota_bytes = sqb;
    }
    pub fn set_storage_used_bytes(&mut self, sub: u64) {
        self.storage_used_bytes = sub;
    }
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub email: String,
    pub password: SecretBox<String>, // Received as plain text
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingSignup {
    token_type: TokenType,
    username: String,
    email: String,
    password_hash: String, // store hashed, not plain
}
impl PendingSignup {
    pub fn new(username: &str, email: &str, hashed_password: String) -> Self {
        Self {
            token_type: TokenType::SignupVerification,
            username: username.into(),
            email: email.into(),
            password_hash: hashed_password,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum TokenType {
    SignupVerification,
    PasswordReset,
    EmailChange,
}

/// if email_exist is true then send an email message to tell him that his email is already signup and the token must be used to reset password if he wants too
///
/// if email_exist is false then send a verfication message ask him to click the url inside the email message to verify his signup within 5 minutes
#[debug_handler]
pub(super) async fn signup(
    State(appstate): State<AppState>,
    Json(signup_info): Json<SignupRequest>,
) {
    let id = is_email_exist(&signup_info.email, &appstate.db_pool)
        .await
        .expect("Failed to retrieve from database"); // sqlx database error
    let token = generate_token_bytes(32);
    let raw_token = encode_token(&token); // used to send as a url in email message
    let hashed_token = hash_token(&token); // store in redis database
    // let hos = hashed_token.to_string();
    if id.is_some() {
        //the email already exist
        send_reset_password_message(&signup_info.email, hashed_token);
    } else {
        let pending_account = send_verify_email_message(signup_info, raw_token)
            .await
            .expect("Failed to send email");
        store_token_redis(&appstate.redis_pool, hashed_token, &pending_account, 5 * 60)
            .await
            .expect("Failed to store in redis ");
    }
}
async fn send_verify_email_message(
    signup_info: SignupRequest,
    raw_token: String,
) -> Result<PendingSignup, argon2::password_hash::Error> {
    let new_account = create_account(signup_info).expect("Failed to hash with argon2");
    // send(message)

    Ok(new_account)
}

fn send_reset_password_message(email: &str, hashed_token: String) {}
/// if the email is new and not already used !
fn create_account(
    signup_info: SignupRequest,
) -> Result<PendingSignup, argon2::password_hash::Error> {
    let hashed_psswd = hash_password(&signup_info.password)?;
    let pending_account =
        PendingSignup::new(&signup_info.username, &signup_info.email, hashed_psswd);
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
async fn store_token_redis<T: Serialize>(
    conn: &Pool,
    key_token: String,
    content: &T,
    ttl: u64,
) -> Result<(), RedisError> {
    let json_data = serde_json::to_string(content)
        .map_err(|_| RedisError::from((redis::ErrorKind::TypeError, "Serialization failed")))?;
    let mut conn = conn
        .get()
        .await
        .expect("Failed to get a connection from pool");
    conn.set_ex(key_token, json_data, ttl).await
}
