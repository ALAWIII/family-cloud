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
use tracing::{info, instrument};

/// if the email is new and not already used !
fn create_account(signup_info: &SignupRequest) -> Result<PendingAccount, CryptoError> {
    info!("creating new pending account");
    let hashed_psswd = hash_password(&signup_info.password)?;
    let pending_account =
        PendingAccount::new(&signup_info.username, &signup_info.email, hashed_psswd);
    info!("account created successfully.");
    Ok(pending_account)
}

/// if email_exist is true then send an email message to tell him that his email is already signup and the token must be used to reset password if he wants too
///
/// if email_exist is false then send a verfication message ask him to click the url inside the email message to verify his signup within 5 minutes
#[debug_handler]
#[instrument(skip_all,fields(
    user_name=signup_info.username,
    user_email=signup_info.email
))]
pub(super) async fn signup(
    State(appstate): State<AppState>,
    Json(signup_info): Json<SignupRequest>,
) -> Result<StatusCode, ApiError> {
    info!("signup new account.");
    let user_id = is_account_exist(&appstate.db_pool, &signup_info.email).await?; // sqlx database error
    if user_id.is_some() {
        info!("The email address already uesed by some existing accounts.");
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        return Ok(StatusCode::OK);
    }
    //---------------------------------------------------------------
    let secret = appstate.settings.secrets.hmac.expose_secret();
    let from_sender = appstate.settings.email.from_sender;
    let app_url = appstate.settings.app.url();
    // if email is new

    info!("generating new verfication token and hash it.");

    let token = generate_token_bytes(32)?;
    let raw_token = encode_token(&token); // used to send as a url in email message
    let hashed_token = hash_token(&token, secret)?; // store in redis database
    let pending_account = create_account(&signup_info)?;

    info!("creating the signup verification body for email message");

    let email_body = verification_body(
        &signup_info.username,
        &format!("{}/api/auth/signup?token={}", app_url, raw_token),
        5,
        "family_cloud",
    );
    //---------------------------------
    info!("storing the new signup email verfication token to redis.");
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
    info!("sending signup email verfication to the email recipent");
    EmailSender::default()
        .from_sender(from_sender)
        .email_recipient(signup_info.email)
        .subject("new account email verification".to_string())
        .email_body(email_body)
        .send_email(appstate.mail_client)
        .await?;
    info!("Signup request success.");
    Ok(StatusCode::OK)
}

#[debug_handler]
#[instrument(skip_all)]
pub async fn verify_signup(
    State(appstate): State<AppState>,
    Query(token): Query<TokenPayload>,
) -> Result<StatusCode, ApiError> {
    info!("processing new signup verfication token.");
    let secret = appstate.settings.secrets.hmac.expose_secret();

    info!("decoding the signup verification token");
    let decoded = decode_token(token.token.expose_secret())?;
    let hashed_token = hash_token(&decoded, secret)?;
    let key = create_verification_key(crate::TokenType::Signup, &hashed_token);
    //-------------------------- search redis for the token

    info!("searching redis for the signup verification token and retrieving its content.");
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let vdata = get_verification_data(&mut redis_con, &key)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let account: PendingAccount = deserialize_content(&vdata)?;

    info!("initalizing new User account instance and storing it into Postgres database.");
    let user = User::new(account.username, account.email, account.password_hash);
    insert_new_account(user, &appstate.db_pool)
        .await
        .map_err(|e| match e {
            DatabaseError::Duplicate => ApiError::Conflict, // Edge case
            other => ApiError::Database(other),
        })?;

    info!("deleting or invalidating the signup verification token from redis");
    delete_token_from_redis(&mut redis_con, &key).await?;
    info!("successfully verifing new account signup.");
    Ok(StatusCode::CREATED)
}
