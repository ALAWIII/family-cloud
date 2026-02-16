use std::collections::HashSet;

use crate::{setup_with_authenticated_user, upload_file};
use family_cloud::{ObjectRecord, UpdateMetadata};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn fetch_all_user_object_ids() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let mut objs = HashSet::new();
    for i in 0..10 {
        objs.insert(
            upload_file(
                &app,
                &format!("{}.txt", i),
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
    assert_eq!(ids.len(), 10, "we upload 10 files , we must get 10 ids");
    assert_eq!(
        ids, objs,
        "make sure that all ids are identical to what we have uploaded."
    );
    Ok(())
}

#[tokio::test]
async fn fetch_object_metadata() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let up_obj = upload_file(&app, "potato.txt", vec![0u8; 10], &login_data.access_token).await;
    let metadata: ObjectRecord = app
        .get_metadata(&login_data.access_token, up_obj.id)
        .await
        .json();

    assert_eq!(up_obj, metadata);
    Ok(())
}

#[tokio::test]
async fn fetch_object_metadata_not_found() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let resp = app
        .get_metadata(&login_data.access_token, Uuid::new_v4())
        .await;
    resp.assert_status_not_found();
    Ok(())
}
#[tokio::test]
async fn update_metadata() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let up_obj = upload_file(&app, "potato.txt", vec![0u8; 10], &login_data.access_token).await;
    let cmetadata = UpdateMetadata {
        metadata: json!({ "food": "flafel" }),
    };
    let metadata = app
        .update_metadata(&login_data.access_token, up_obj.id, &cmetadata)
        .await;
    assert_eq!(metadata.json::<UpdateMetadata>(), cmetadata);
    Ok(())
}
