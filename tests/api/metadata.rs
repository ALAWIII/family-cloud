use std::collections::HashSet;

use crate::{setup_with_authenticated_user, upload_file, upload_folder};
use family_cloud::{FileRecord, FolderRecord, UpdateMetadata};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn fetch_all_user_object_ids() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let mut objs = HashSet::new();
    objs.insert(account.root_folder.unwrap());
    for i in 0..10 {
        objs.insert(
            upload_file(
                &app,
                &format!("{}.txt", i),
                account.root_folder().unwrap(),
                vec![0u8; 10],
                &login_data.access_token,
            )
            .await
            .id,
        );
    }
    let resp = app.list_objects(&login_data.access_token).await;
    resp.assert_status_success();
    let ids: HashSet<Uuid> = resp.json();
    assert_eq!(
        ids.len(),
        11,
        "we upload 10 files , we must get 10 ids + the root folder = 11 ids"
    );
    assert_eq!(
        ids, objs,
        "make sure that all ids are identical to what we have uploaded."
    );
    Ok(())
}

#[tokio::test]
async fn fetch_file_metadata() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let mut file = upload_file(
        &app,
        "potato.txt",
        account.root_folder().unwrap(),
        vec![0u8; 10],
        &login_data.access_token,
    )
    .await;
    file.normalize_dates(); // to match the database microseconds , truncates the nanoseconds
    let metadata: FileRecord = app
        .get_metadata(
            &login_data.access_token,
            file.id,
            &family_cloud::ObjectKind::File,
        )
        .await
        .json();

    assert_eq!(file, metadata);
    Ok(())
}
#[tokio::test]
async fn fetch_folder_metadata() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let mut folder = upload_folder(
        &app,
        "potato.txt",
        account.root_folder().unwrap(),
        &login_data.access_token,
    )
    .await;
    folder.normalize_dates(); // to match the database microseconds , truncates the nanoseconds
    let metadata: FolderRecord = app
        .get_metadata(
            &login_data.access_token,
            folder.id,
            &family_cloud::ObjectKind::Folder,
        )
        .await
        .json();

    assert_eq!(folder, metadata);
    Ok(())
}

#[tokio::test]
async fn fetch_object_metadata_not_found() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let resp = app
        .get_metadata(
            &login_data.access_token,
            Uuid::new_v4(),
            &family_cloud::ObjectKind::File,
        )
        .await;
    resp.assert_status_not_found();
    Ok(())
}
#[tokio::test]
async fn update_metadata() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let up_obj = upload_file(
        &app,
        "potato.txt",
        account.root_folder().unwrap(),
        vec![0u8; 10],
        &login_data.access_token,
    )
    .await;
    let cmetadata = UpdateMetadata {
        metadata: json!({"food": "flafel" }),
    };
    let metadata = app
        .update_metadata(&login_data.access_token, up_obj.id, &cmetadata)
        .await;
    metadata.assert_status_success();
    let mm_r = metadata.json::<UpdateMetadata>();
    assert_eq!(mm_r, cmetadata);
    Ok(())
}
