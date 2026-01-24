use crate::{
    AppTest, TestAccount, clean_mailhog, get_mailhog_msg_id_and_extract_raw_token_list, login,
};
use axum::http::StatusCode;
use family_cloud::{LoginResponse, fetch_account_info, get_db};
use serde_json::Value;
use uuid::Uuid;

async fn change_email() -> anyhow::Result<(Vec<Value>, AppTest, String, TestAccount)> {
    let (logrs, user, app) = login(None, None).await?;
    let loginres: LoginResponse = logrs.json();
    let new_email = Uuid::new_v4();
    let new_email = format!("{}@chicken.net", new_email);

    let cemail_resp = app
        .change_email_request(&new_email, &loginres.access_token)
        .await;
    cemail_resp.assert_status(StatusCode::ACCEPTED);
    let messages = app.get_all_messages_mailhog().await;

    Ok((messages, app, new_email, user))
}
#[tokio::test]

async fn change_email_verify() -> anyhow::Result<()> {
    let (messages, app, new_email, account) = change_email().await?;
    let verify_ids_tokens =
        get_mailhog_msg_id_and_extract_raw_token_list(&messages, "Change Email Request");
    for (_, token) in &verify_ids_tokens {
        let ver_resp = app.verify_change_email(token).await;
        ver_resp.assert_status_success();
    }
    let db_pool = get_db()?;
    let user = fetch_account_info(&db_pool, &new_email).await?;
    assert_eq!(user.id, account.id);
    assert_eq!(user.email, new_email);
    clean_mailhog(
        &get_mailhog_msg_id_and_extract_raw_token_list(&messages, "Email Request"),
        &app,
    )
    .await;
    Ok(())
}

#[tokio::test]

async fn change_email_cancel() -> anyhow::Result<()> {
    let (messages, app, new_email, account) = change_email().await?;
    let cancel_ids_tokens =
        get_mailhog_msg_id_and_extract_raw_token_list(&messages, "Cancel Changing Email Request");
    //dbg!(&cancel_ids_tokens);
    for (_, token) in &cancel_ids_tokens {
        let ver_resp = app.cancel_change_email(token).await;
        ver_resp.assert_status_success();
    }
    let db_pool = get_db()?; //fetch the old email from the database that didnt change!
    let user = fetch_account_info(&db_pool, &account.email)
        .await
        .expect("failed to obtain the user with new email");
    assert_eq!(user.id, account.id);
    assert_eq!(user.email, account.email);
    assert_ne!(user.email, new_email);
    clean_mailhog(
        &get_mailhog_msg_id_and_extract_raw_token_list(&messages, "Email Request"),
        &app,
    )
    .await;
    Ok(())
}
