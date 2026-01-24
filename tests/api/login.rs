use family_cloud::{LoginResponse, get_db};

use crate::{create_verified_account, login, setup_app};

#[tokio::test]
async fn login_valid_credits_endpoint() -> anyhow::Result<()> {
    let (resp, user, app) = login(None, None).await?;
    resp.assert_status_ok();
    let login_resp: LoginResponse = resp.json();
    assert!(!login_resp.access_token.is_empty());
    assert!(!login_resp.refresh_token.is_empty());
    assert_eq!(login_resp.user.id, user.id);
    Ok(())
}

#[tokio::test]
async fn login_invalid_password() -> anyhow::Result<()> {
    login(None, Some("8d47gf8de4g8g4"))
        .await?
        .0 // wrong password = unauthorized
        .assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn login_invalid_email() -> anyhow::Result<()> {
    login(Some("titanic@fucked.com"), None)
        .await?
        .0 // wrong email = Not Found
        .assert_status_not_found();

    Ok(())
}
//--------------------- deserializing problems
#[tokio::test]
async fn login_missing_fields() -> anyhow::Result<()> {
    let app = setup_app().await?;
    let db_pool = get_db()?;
    let account = create_verified_account(&db_pool).await;
    app.login_request(Some(&account.email), None)
        .await
        .assert_status_unprocessable_entity();
    app.login_request(None, Some(&account.password))
        .await
        .assert_status_unprocessable_entity();
    app.login_request(None, None)
        .await
        .assert_status_unprocessable_entity();
    app.login_request(Some(&account.email), Some(&account.password))
        .await
        .assert_status_ok();

    // Test with unverified email
    Ok(())
}
