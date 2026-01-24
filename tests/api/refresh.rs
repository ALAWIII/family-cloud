use std::time::Duration;

use family_cloud::{LoginResponse, TokenPayload};
use secrecy::ExposeSecret;

use crate::{login, refresh_token_body_cookie};
#[tokio::test]
async fn refresh() -> anyhow::Result<()> {
    let (loginres, account, app) = login(None, None).await?;
    let logres: LoginResponse = loginres.json();
    let (cookie, body) = refresh_token_body_cookie(&logres.refresh_token);
    let ref_bod = app.refresh_body_request(&body).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let ref_cok = app.refresh_cookie_request(cookie).await;
    let ref_non = app.refresh_non_request().await;

    ref_bod.assert_status_ok();
    ref_cok.assert_status_ok();
    ref_non.assert_status_unauthorized();

    let token_bod: TokenPayload = ref_bod.json();
    let token_cok: TokenPayload = ref_cok.json();
    assert!(!token_bod.token.expose_secret().is_empty());
    assert!(!token_cok.token.expose_secret().is_empty());
    assert_ne!(
        token_bod.token.expose_secret(),
        token_cok.token.expose_secret()
    );
    Ok(())
}
