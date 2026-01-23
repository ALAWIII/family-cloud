use axum::{
    Extension, Json, debug_handler,
    extract::{Query, State},
    http::StatusCode,
};
use secrecy::ExposeSecret;

use crate::{
    ApiError, AppState, Claims, DatabaseError, EmailInput, EmailSender, TokenPayload,
    UserVerification, create_verification_key, decode_token, delete_token_from_redis,
    deserialize_content, email_cancel_body, email_change_body, encode_token, fetch_email_by_id,
    generate_token_bytes, get_redis_con, get_verification_data, hash_token, is_account_exist,
    is_token_exist, serialize_content, store_token_redis, update_account_email,
};

#[debug_handler]
pub async fn change_email(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(email_info): Json<EmailInput>,
) -> Result<StatusCode, ApiError> {
    // searching whether this new email provided is already in use with specific account
    let user_id = is_account_exist(&appstate.db_pool, &email_info.email) // this ID maybe for another user account not this user who tries to change to it!
        .await?;

    if user_id.is_some() {
        return Err(ApiError::Conflict);
    }

    let old_email = fetch_email_by_id(&appstate.db_pool, claims.sub) // user_id
        .await?
        .ok_or(DatabaseError::NotFound)?;

    //-------------------------
    let secret = appstate.settings.secrets.hmac;
    let from_sender = appstate.settings.email.from_sender;
    let app_url = appstate.settings.app.url();
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let token_bytes = generate_token_bytes(32)?;
    let raw_token = encode_token(&token_bytes);
    let token_hash = hash_token(&token_bytes, secret.expose_secret())?;
    let key = create_verification_key(crate::TokenType::EmailChange, &token_hash);
    let content = UserVerification::new(claims.sub, &claims.username, &email_info.email);
    let scontent = serialize_content(&content)?;
    //--------------------storing token in redis ------------------
    store_token_redis(&mut redis_con, &key, &scontent, 10 * 60).await?;
    //-------------------------------- sending email change verification to the new email ---------

    let verify_change_email_link = format!(
        "{}/api/auth/change-email/verify?token={}",
        app_url, raw_token
    );
    EmailSender::default()
        .from_sender(from_sender.clone())
        .email_recipient(email_info.email)
        .subject("Change Email Request".into())
        .email_body(email_change_body(
            &claims.username,
            &verify_change_email_link,
            10,
            "Family Cloud",
        ))
        .send_email(appstate.mail_client.clone())
        .await?;
    //----------------------------send cancel email for the old email-----------------
    let cancel_change_email_link = format!(
        "{}/api/auth/change-email/cancel?token={}",
        app_url, raw_token
    );
    EmailSender::default()
        .from_sender(from_sender)
        .email_recipient(old_email)
        .subject("Cancel Changing Email Request".into())
        .email_body(email_cancel_body(
            &claims.username,
            &cancel_change_email_link,
            10,
            "Family Cloud",
        ))
        .send_email(appstate.mail_client)
        .await?;
    Ok(StatusCode::ACCEPTED)
}
pub async fn verify_change_email(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenPayload>,
) -> Result<StatusCode, ApiError> {
    let secret = appstate.settings.secrets.hmac.expose_secret();
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let token_bytes = decode_token(raw_token.token.expose_secret())?;
    let hashed_token = hash_token(&token_bytes, secret)?;
    let key = create_verification_key(crate::TokenType::EmailChange, &hashed_token);

    let data = get_verification_data(&mut redis_con, &key)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let user_data: UserVerification = deserialize_content(&data)?;
    let result = update_account_email(&appstate.db_pool, user_data.id, &user_data.email).await?;

    if result.rows_affected() != 1 {
        return Err(DatabaseError::NotFound.into()); // User doesn't exist
    }
    delete_token_from_redis(&mut redis_con, &key).await?;
    Ok(StatusCode::OK)
}

pub async fn cancel_change_email(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenPayload>,
) -> Result<StatusCode, ApiError> {
    let secret = appstate.settings.secrets.hmac.expose_secret();
    let mut redis_con = get_redis_con(appstate.redis_pool).await?;
    let token_bytes = decode_token(raw_token.token.expose_secret())?;
    let hashed_token = hash_token(&token_bytes, secret)?;
    let key = create_verification_key(crate::TokenType::EmailChange, &hashed_token);
    let t = is_token_exist(&mut redis_con, &key).await?;

    if !t {
        return Err(ApiError::BadRequest);
    }
    delete_token_from_redis(&mut redis_con, &key).await?;
    Ok(StatusCode::OK)
}
