use axum::{
    Extension, Json, debug_handler,
    extract::{Query, State},
    http::StatusCode,
};

use crate::{
    AppState, Claims, EmailInput, EmailSender, TokenQuery, UserVerification,
    create_verification_key, decode_token, delete_token_from_redis, email_cancel_body,
    email_change_body, encode_token, generate_token_bytes, get_email_by_id, get_verification_data,
    hash_token, is_account_exist, is_token_exist, store_token_redis, update_account_email,
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
    let old_email = get_email_by_id(&appstate.db_pool, claims.sub)
        .await
        .map_err(|e| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    //-------------------------
    let from_sender = std::env::var("SMTP_FROM_ADDRESS").unwrap();
    let app_url = std::env::var("APP_URL").unwrap();
    let token_bytes = generate_token_bytes(32);
    let raw_token = encode_token(&token_bytes);
    let token_hash = hash_token(&token_bytes);
    let key = create_verification_key(crate::TokenType::EmailChange, &token_hash);
    let content = UserVerification::new(claims.sub, &claims.username, &email_info.email);

    //--------------------storing token in redis ------------------
    store_token_redis(
        &mut appstate
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

    let verify_change_email_link = format!(
        "{}/api/auth/change-email/verify?token={}",
        app_url, raw_token
    );
    EmailSender::default()
        .from_sender(from_sender.clone())
        .email_recipient(email_info.email)
        .subject("Email Change Request".into())
        .email_body(email_change_body(
            &claims.username,
            &verify_change_email_link,
            10,
            "Family Cloud",
        ))
        .send_email(appstate.mail_client.clone())
        .await;
    //----------------------------send cancel email for the old email-----------------
    let cancel_change_email_link = format!(
        "{}/api/auth/change-email/cancel?token={}",
        app_url, raw_token
    );
    EmailSender::default()
        .from_sender(from_sender)
        .email_recipient(old_email)
        .subject("Email Change Request".into())
        .email_body(email_cancel_body(
            &claims.username,
            &cancel_change_email_link,
            10,
            "Family Cloud",
        ))
        .send_email(appstate.mail_client)
        .await;
    Ok(StatusCode::ACCEPTED)
}
pub async fn verify_change_email(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenQuery>,
) -> Result<StatusCode, StatusCode> {
    let mut redis_connection = appstate
        .redis_pool
        .get()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token_bytes =
        decode_token(&raw_token.token).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let hashed_token = hash_token(&token_bytes);
    let key = create_verification_key(crate::TokenType::EmailChange, &hashed_token);

    let data = get_verification_data(&mut redis_connection, &key)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let user_data: UserVerification =
        serde_json::from_str(&data).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let result = update_account_email(&appstate.db_pool, user_data.id, &user_data.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if result.rows_affected() != 1 {
        return Err(StatusCode::NOT_FOUND); // User doesn't exist
    }
    delete_token_from_redis(&mut redis_connection, &key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

pub async fn cancel_change_email(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenQuery>,
) -> Result<StatusCode, StatusCode> {
    let mut redis_connection = appstate
        .redis_pool
        .get()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let token_bytes = decode_token(&raw_token.token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let hashed_token = hash_token(&token_bytes);
    let key = create_verification_key(crate::TokenType::EmailChange, &hashed_token);
    let t = is_token_exist(&mut redis_connection, &key).await;
    if !t {
        return Err(StatusCode::NOT_FOUND);
    }
    delete_token_from_redis(&mut redis_connection, &key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}
