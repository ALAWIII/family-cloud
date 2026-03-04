use family_cloud::{UpdateUserNameOps, UserProfile};
use uuid::Uuid;

use crate::setup_with_authenticated_user;

#[tokio::test]
async fn get_user_profile() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let resp = app.get_user_profile(&login_data.access_token).await;
    resp.assert_status_success();
    let profile = resp.json::<UserProfile>();
    assert_eq!(account.id, profile.id);
    assert_eq!(account.email, profile.email);
    assert_eq!(account.root_folder, profile.root_folder);
    assert_eq!(account.username, profile.username);

    Ok(())
}

#[tokio::test]
async fn update_username() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let resp = app
        .update_username(&login_data.access_token, "sandwitch")
        .await;
    resp.assert_status_success();
    assert_eq!(resp.json::<UpdateUserNameOps>().user_name, "sandwitch");
    let profile: UserProfile = app.get_user_profile(&login_data.access_token).await.json();
    assert_eq!(profile.username, "sandwitch");
    Ok(())
}

#[tokio::test]
async fn update_username_longer_than_maximum_chars() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let mut new_name = Uuid::new_v4().to_string();
    new_name.push_str(&Uuid::new_v4().to_string());
    let resp = app
        .update_username(&login_data.access_token, &new_name)
        .await;
    resp.assert_status_bad_request();

    Ok(())
}
