use axum_test::TestResponse;
use family_cloud::{LoginResponse, get_db};

use crate::{TestAccount, create_app, create_verified_account};

async fn login(
    email: Option<&str>,
    pswd: Option<&str>,
) -> anyhow::Result<(TestResponse, TestAccount)> {
    let app = create_app().await;
    let db_pool = get_db()?;
    let mut user = create_verified_account(&db_pool).await;
    let _ = email.is_some_and(|e| user.email(e));
    let _ = pswd.is_some_and(|p| user.pswd(p));

    Ok((
        app.login_request(Some(&user.email), Some(&user.password))
            .await,
        user,
    ))
}

#[tokio::test]
async fn login_valid_credits_endpoint() -> anyhow::Result<()> {
    let (resp, user) = login(None, None).await?;
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
    let app = create_app().await;
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
