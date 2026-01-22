use deadpool_redis::redis::AsyncTypedCommands;
use family_cloud::{
    LoginResponse, create_verification_key, decode_token, get_redis_con, get_redis_pool, hash_token,
};

use crate::{AppTest, create_app, login, refresh_token_body_cookie};

async fn logout() -> anyhow::Result<(AppTest, String, LoginResponse)> {
    let app = create_app().await;
    let (resp, user) = login(None, None).await?;
    let logres: LoginResponse = resp.json();

    let hashed_token = hash_token(&decode_token(&logres.refresh_token)?)?;
    let key = create_verification_key(family_cloud::TokenType::Refresh, &hashed_token);

    Ok((app, key, logres))
}

#[tokio::test]
async fn logout_cookie() -> anyhow::Result<()> {
    let (app, key, logres) = logout().await?;
    let (cook, _) = refresh_token_body_cookie(&logres.refresh_token);
    let mut redis_con = get_redis_con(get_redis_pool()?).await?;

    // assert is inserted in redis after login and before logout
    assert!(redis_con.exists(&key).await?);
    // logout to delete the refresh token
    let logout_resp = app.logout_cookie_request(cook).await;

    // assert is deleted from redis
    assert!(!redis_con.exists(&key).await?);
    logout_resp.assert_status_no_content();
    Ok(())
}

#[tokio::test]
async fn logout_body() -> anyhow::Result<()> {
    let (app, key, logres) = logout().await?;
    let (_, body) = refresh_token_body_cookie(&logres.refresh_token);
    let mut redis_con = get_redis_con(get_redis_pool()?).await?;

    // assert is inserted in redis after login and before logout
    assert!(redis_con.exists(&key).await?);
    // logout to delete the refresh token
    let logout_resp = app.logout_body_request(&body).await;

    // assert is deleted from redis
    assert!(!redis_con.exists(&key).await?);
    logout_resp.assert_status_no_content();
    Ok(())
}

#[tokio::test]
async fn logout_non() -> anyhow::Result<()> {
    let app = create_app().await;

    // logout to delete the refresh token
    let logout_resp = app.logout_request().await;

    logout_resp.assert_status_unauthorized();
    Ok(())
}
