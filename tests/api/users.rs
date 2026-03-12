use aws_sdk_s3::{
    Client,
    error::SdkError,
    operation::head_bucket::{HeadBucketError, HeadBucketOutput},
};
use deadpool_redis::redis::AsyncTypedCommands;
use family_cloud::{
    FileRecord, UpdateUserNameOps, UserProfile, create_redis_key, fetch_obj_info,
    fetch_profile_info, get_redis_con,
};
use uuid::Uuid;

use crate::{
    create_folders_files_tree, init_workers, setup_with_authenticated_user, wait_job_until_finishes,
};

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
//--------------------------------
#[tokio::test]
async fn delete_user_account_has_no_files() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let v = app.delete_user_account(&login_data).await;
    v.assert_status_success();
    let deleted_user = fetch_profile_info(&app.state.db_pool, account.id).await?;
    assert!(deleted_user.is_none());
    let b = get_bucket(&app.state.rustfs_con, account.id).await;
    assert!(b.is_err_and(|e| e.into_service_error().is_not_found()));
    Ok(())
}
#[tokio::test]
async fn delete_user_account_with_some_files() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let v = app.delete_user_account(&login_data).await;
    v.assert_status_success();
    wait_job_until_finishes(&app.state.db_pool, &workers).await?;
    let deleted_user = fetch_profile_info(&app.state.db_pool, account.id).await?;
    assert!(
        deleted_user.is_none(),
        "the user must be deleted from database."
    );
    let b = get_bucket(&app.state.rustfs_con, account.id).await;
    assert!(
        b.is_err_and(|e| e.into_service_error().is_not_found()),
        "validate that the user bucket were deleted"
    );
    let f = fetch_obj_info::<FileRecord>(
        &app.state.db_pool,
        tree.files.first().unwrap().id,
        account.id,
        family_cloud::ObjectKind::File,
    )
    .await?;
    assert!(f.is_none(), "validate that all files were removed.");
    let key = create_redis_key(family_cloud::TokenType::Refresh, &login_data.refresh_token);
    let v = get_redis_con(&app.state.redis_pool).await?.get(key).await?;
    assert!(
        v.is_none(),
        "validate that the refresh token was deleted from redis."
    );
    Ok(())
}

async fn get_bucket(
    rfs_con: &Client,
    b: Uuid,
) -> Result<HeadBucketOutput, SdkError<HeadBucketError>> {
    rfs_con.head_bucket().bucket(b.to_string()).send().await
}
