use crate::{
    ApiError, AppState, CryptoError, DatabaseError, EmailSender, PendingAccount, SignupRequest,
    TokenPayload, User, create_verification_key, decode_token, delete_token_from_redis,
    deserialize_content, encode_token, generate_token_bytes, get_redis_con, get_verification_data,
    hash_password, hash_token, insert_new_account, is_account_exist, serialize_content,
    store_token_redis, verification_body,
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
) -> Result<StatusCode, ApiError> {
    let user_id = is_account_exist(&appstate.db_pool, &signup_info.email).await?; // sqlx database error
    if user_id.is_some() {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        return Ok(StatusCode::OK);
    }

    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();
    let base_url = std::env::var("APP_URL").expect("FRONTEND_URL not set");
    // if email is new
    let token = generate_token_bytes(32)?;
    let raw_token = encode_token(&token); // used to send as a url in email message
    let hashed_token = hash_token(&token)?; // store in redis database
    let pending_account = create_account(&signup_info)?;
    let email_body = verification_body(
        &signup_info.username,
        &format!("{}/api/auth/signup?token={}", base_url, raw_token),
        5,
        "family_cloud",
    );
    //---------------------------------
    let mut con = get_redis_con(appstate.redis_pool).await?;
    let content = serialize_content(&pending_account)?;
    store_token_redis(
        &mut con,
        &create_verification_key(crate::TokenType::Signup, &hashed_token),
        &content,
        5 * 60,
    )
    .await?;
    //-------------------------
    EmailSender::default()
        .from_sender(from_sender)
        .email_recipient(signup_info.email)
        .subject("new account email verification".to_string())
        .email_body(email_body)
        .send_email(appstate.mail_client)
        .await?;
    Ok(StatusCode::OK)
}

//confirm-email?token={}

/// if the email is new and not already used !
fn create_account(signup_info: &SignupRequest) -> Result<PendingAccount, CryptoError> {
    let hashed_psswd = hash_password(&signup_info.password)?;
    let pending_account =
        PendingAccount::new(&signup_info.username, &signup_info.email, hashed_psswd);
    Ok(pending_account)
}

#[debug_handler]
pub async fn verify_signup_token(
    State(appstate): State<AppState>,
    Query(token): Query<TokenPayload>,
) -> Result<StatusCode, ApiError> {
    //  dbg!(&token);
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let decoded = decode_token(token.token.expose_secret())?;
    let hashed_token = hash_token(&decoded)?;
    let key = create_verification_key(crate::TokenType::Signup, &hashed_token);
    let vdata = get_verification_data(&mut redis_con, &key)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let account: PendingAccount = deserialize_content(&vdata)?;
    let user = User::new(account.username, account.email, account.password_hash);
    insert_new_account(user, &appstate.db_pool)
        .await
        .map_err(|e| match e {
            DatabaseError::Duplicate => ApiError::Conflict, // Edge case
            other => ApiError::Database(other),
        })?;
    delete_token_from_redis(&mut redis_con, &key).await?;
    Ok(StatusCode::CREATED)
}
