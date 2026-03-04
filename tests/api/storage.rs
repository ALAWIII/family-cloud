use family_cloud::UserStorageInfo;

use crate::setup_with_authenticated_user;

#[tokio::test]
async fn fetch_storage_info() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let resp = app.fetch_user_storage_info(&login_data.access_token).await;
    resp.assert_status_success();
    let s_info: UserStorageInfo = resp.json();
    assert_eq!(s_info.storage_quota_bytes, account.storage_quota_bytes);
    assert_eq!(s_info.storage_used_bytes, account.storage_used_bytes);
    Ok(())
}
