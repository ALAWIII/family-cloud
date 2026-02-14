use axum::{
    Extension, Json, debug_handler,
    extract::{Query, State},
    http::StatusCode,
};
use secrecy::ExposeSecret;
use tracing::{error, info, instrument};

use crate::{
    ApiError, AppState, Claims, DatabaseError, EmailError, EmailInput, EmailSender, TokenPayload,
    UserVerification, create_redis_key, decode_token, delete_token_from_redis, deserialize_content,
    email_cancel_body, email_change_body, encode_token, fetch_email_by_id, fetch_redis_data,
    generate_token_bytes, get_redis_con, hash_token, is_account_exist, is_token_exist,
    serialize_content, store_token_redis, update_account_email,
};

#[debug_handler]
#[instrument(skip_all,fields(new_email=email_info.email))]
pub async fn change_email(
    Extension(claims): Extension<Claims>,
    State(appstate): State<AppState>,
    Json(email_info): Json<EmailInput>,
) -> Result<StatusCode, ApiError> {
    info!("new change email request.");
    // searching whether this new email provided is already in use with specific account
    let user_id = is_account_exist(&appstate.db_pool, &email_info.email) // this ID maybe for another user account not this user who tries to change to it!
        .await?;

    if user_id.is_some() {
        error!("new email is already attached to existed account");
        return Err(ApiError::Conflict);
    }
    info!("fetching the old email.");
    let old_email = fetch_email_by_id(&appstate.db_pool, claims.sub) // user_id
        .await?
        .ok_or(DatabaseError::NotFound)?;

    //-------------------------
    let secret = appstate.settings.secrets.hmac;
    let from_sender = appstate
        .settings
        .email
        .ok_or(EmailError::ClientNotInitialized)?
        .from_sender;
    let mail_client = appstate
        .mail_client
        .ok_or(EmailError::ClientNotInitialized)?;
    let app_url = appstate.settings.app.url();
    //-----------------
    info!("generating,encoding and hashing new change email verification token.");
    let token_bytes = generate_token_bytes(32)?;
    let raw_token = encode_token(&token_bytes);
    let token_hash = hash_token(&token_bytes, secret.expose_secret())?;
    let key = create_redis_key(crate::TokenType::EmailChange, &token_hash);
    //-------------
    info!("creating new user verification info from claims.");
    let content = UserVerification::new(claims.sub, &claims.username, &email_info.email);
    let scontent = serialize_content(&content)?;
    //--------------------storing token in redis ------------------
    info!("storing change email verification token in redis.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    store_token_redis(
        &mut redis_con,
        &key,
        &scontent,
        appstate.settings.token_options.change_email_token * 60,
    )
    .await?;
    //-------------------------------- sending email change verification to the new email ---------
    info!("sending email verification message to the new email address.");
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
            appstate.settings.token_options.change_email_token as u32,
            "Family Cloud",
        ))
        .send_email(mail_client.clone())
        .await?;
    //----------------------------send cancel email for the old email-----------------
    info!("sending cancel email message to the old email address.");
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
            appstate.settings.token_options.change_email_token as u32,
            "Family Cloud",
        ))
        .send_email(mail_client)
        .await?;

    info!("change email request success.");
    Ok(StatusCode::ACCEPTED)
}

#[instrument(skip_all)]
pub async fn verify_change_email(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenPayload>,
) -> Result<StatusCode, ApiError> {
    info!("performing change email verification.");
    let secret = appstate.settings.secrets.hmac.expose_secret();
    info!("decoding,hashing and creating key from a raw token.");
    let token_bytes = decode_token(raw_token.token.expose_secret())?;
    let hashed_token = hash_token(&token_bytes, secret)?;
    let key = create_redis_key(crate::TokenType::EmailChange, &hashed_token);

    info!("fetching associated info from redis using the hashed token.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let data = fetch_redis_data(&mut redis_con, &key)
        .await?
        .ok_or_else(|| {
            error!("failed to retreive change email verification information from redis.");
            ApiError::Unauthorized
        })?;
    let user_data: UserVerification = deserialize_content(&data)?;
    info!("updating account email to new email.");
    let result = update_account_email(&appstate.db_pool, user_data.id, &user_data.email).await?;
    let affected_rows = result.rows_affected();
    if affected_rows != 1 {
        error!(
            "number of affected records by this update is: {}",
            affected_rows
        );
        return Err(DatabaseError::NotFound.into()); // User doesn't exist
    }
    info!("deleting and cleaning change email verification token from redis.");
    delete_token_from_redis(&mut redis_con, &key).await?;
    info!("verification success.");
    Ok(StatusCode::OK)
}

#[instrument(skip_all)]
pub async fn cancel_change_email(
    State(appstate): State<AppState>,
    Query(raw_token): Query<TokenPayload>,
) -> Result<StatusCode, ApiError> {
    info!("performing change email cancelation.");
    let secret = appstate.settings.secrets.hmac.expose_secret();
    info!("decoding and hashing the change email cancel token.");
    let token_bytes = decode_token(raw_token.token.expose_secret())?;
    let hashed_token = hash_token(&token_bytes, secret)?;
    let key = create_redis_key(crate::TokenType::EmailChange, &hashed_token);

    info!("asking if the change email cancel token still valid in redis.");
    let mut redis_con = get_redis_con(&appstate.redis_pool).await?;
    let t = is_token_exist(&mut redis_con, &key).await?;
    if !t {
        error!("invalid cancel token.");
        return Err(ApiError::BadRequest(anyhow::anyhow!(
            "invalid cancel token"
        )));
    }
    info!("deleting token from redis");
    delete_token_from_redis(&mut redis_con, &key).await?;
    info!("cancel change email successfully");
    Ok(StatusCode::OK)
}
