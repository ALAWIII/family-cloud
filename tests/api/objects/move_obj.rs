use family_cloud::{FileRecord, FolderChild, FolderRecord, MoveRequest};
use uuid::Uuid;

use crate::{create_folders_files_tree, setup_with_authenticated_user};
use axum::http::StatusCode;
#[tokio::test]
async fn move_file_upper_tree_levels() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fi1 = tree.files.first().unwrap();
    let fo2_2 = tree.folders.last().unwrap();
    let req = MoveRequest {
        source_id: fi1.id,
        destination_id: account.root_folder().unwrap(),
        object_kind: family_cloud::ObjectKind::File,
    };
    let resp = app.move_obj(&login_data.access_token, req).await;
    resp.assert_status_success();
    let metadata = app
        .get_metadata(
            &login_data.access_token,
            fi1.id,
            &family_cloud::ObjectKind::File,
        )
        .await
        .json::<FileRecord>();
    assert_eq!(
        metadata.parent_id,
        account.root_folder().unwrap(),
        "asserting that the file parent id is moved up and equals to the root folder."
    );
    let children = app
        .list_children(&login_data.access_token, fo2_2.id)
        .await
        .json::<Vec<FolderChild>>();
    assert_eq!(
        children.len(),
        1,
        "after moving the file from old parent it should only contain 1 child instead of 2."
    );
    assert!(
        !children.iter().any(|v| v.id == fi1.id),
        "asserting that non of the old parent children ids equals the moved one!!"
    );

    Ok(())
}
#[tokio::test]
async fn move_file_same_tree_level() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fi1 = tree.files.first().unwrap();
    let fo2_1 = tree.folders.get(tree.folders.len() - 2).unwrap();
    let req = MoveRequest {
        source_id: fi1.id,
        destination_id: fo2_1.id,
        object_kind: family_cloud::ObjectKind::File,
    };
    let resp = app.move_obj(&login_data.access_token, req).await;
    resp.assert_status_success();
    let metadata = app
        .get_metadata(
            &login_data.access_token,
            fi1.id,
            &family_cloud::ObjectKind::File,
        )
        .await
        .json::<FileRecord>();
    assert_eq!(
        metadata.parent_id, fo2_1.id,
        "asserting that the file parent_id equals the new destination"
    );
    let children = app
        .list_children(&login_data.access_token, fo2_1.id)
        .await
        .json::<Vec<FolderChild>>();
    assert_eq!(children.len(), 1);
    assert!(
        children.iter().any(|v| v.id == fi1.id),
        "new parent should contain the new moved file as a child."
    );

    Ok(())
}

#[tokio::test]
async fn move_file_down_tree_level() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo1 = tree.folders.first().unwrap(); // older parent
    let fi3 = tree.files.last().unwrap();
    let fo2_1 = tree.folders.get(tree.folders.len() - 2).unwrap(); // new destination parent.
    let req = MoveRequest {
        source_id: fi3.id,
        destination_id: fo2_1.id,
        object_kind: family_cloud::ObjectKind::File,
    };
    let resp = app.move_obj(&login_data.access_token, req).await;
    resp.assert_status_success();
    let metadata = app
        .get_metadata(
            &login_data.access_token,
            fi3.id,
            &family_cloud::ObjectKind::File,
        )
        .await
        .json::<FileRecord>();
    assert_eq!(
        metadata.parent_id, fo2_1.id,
        "asserting that the file parent_id equals the new destination"
    );
    assert_ne!(
        metadata.parent_id, fo1.id,
        "the new parent must not equal to the past one."
    );
    let children = app
        .list_children(&login_data.access_token, fo2_1.id)
        .await
        .json::<Vec<FolderChild>>();
    assert_eq!(children.len(), 1);
    assert!(
        children.iter().any(|v| v.id == fi3.id),
        "new parent should contain the new moved file as a child."
    );
    let old_parent_children = app
        .list_children(&login_data.access_token, fo1.id)
        .await
        .json::<Vec<FolderChild>>();
    assert_eq!(
        old_parent_children.len(),
        1,
        "only now equals the child folder."
    );
    assert!(
        !old_parent_children.iter().any(|f| f.id == fi3.id),
        "old parent must not contain the child id."
    );
    Ok(())
}

#[tokio::test]
async fn move_folder_upper_tree_levels() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2_2 = tree.folders.last().unwrap();
    let req = MoveRequest {
        source_id: fo2_2.id,
        destination_id: account.root_folder().unwrap(),
        object_kind: family_cloud::ObjectKind::Folder,
    };
    let resp = app.move_obj(&login_data.access_token, req).await;
    resp.assert_status_success();
    let metadata = app
        .get_metadata(
            &login_data.access_token,
            fo2_2.id,
            &family_cloud::ObjectKind::Folder,
        )
        .await
        .json::<FolderRecord>();
    assert_eq!(
        metadata.parent_id.unwrap(),
        account.root_folder().unwrap(),
        "asserting that the folder parent id is moved up and equals to the root folder."
    );
    let children = app
        .list_children(&login_data.access_token, account.root_folder().unwrap())
        .await
        .json::<Vec<FolderChild>>();
    assert_eq!(
        children.len(),
        2,
        "after moving the folder from old parent , the destination should now contain 2 child instead of 1."
    );
    assert!(
        children.iter().any(|v| v.id == fo2_2.id),
        "asserting that one of the children ids in the root folder equals to the moved once!!"
    );
    let old_parent = tree.folders.get(1).unwrap();
    let old_parent_children = app
        .list_children(&login_data.access_token, old_parent.id)
        .await
        .json::<Vec<FolderChild>>();
    assert_eq!(old_parent_children.len(), 1);
    assert!(!old_parent_children.iter().any(|f| f.id == fo2_2.id));

    Ok(())
}

#[tokio::test]
async fn move_folder_at_same_tree_level() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2_2 = tree.folders.last().unwrap();
    let fo2_1 = tree.folders.get(tree.folders.len() - 2).unwrap();
    let mvreq = MoveRequest {
        source_id: fo2_2.id,
        destination_id: fo2_1.id,
        object_kind: family_cloud::ObjectKind::Folder,
    };
    let resp = app.move_obj(&login_data.access_token, mvreq).await;
    resp.assert_status_success();
    let dest_children = app
        .list_children(&login_data.access_token, fo2_1.id)
        .await
        .json::<Vec<FolderChild>>();
    assert!(
        dest_children.iter().any(|f| f.id == fo2_2.id),
        "fo2_1 must be the new parent of fo2_2 "
    );
    let old_parent_children = app
        .list_children(&login_data.access_token, fo2_2.parent_id.unwrap())
        .await
        .json::<Vec<FolderChild>>();
    assert!(
        !old_parent_children.iter().any(|f| f.id == fo2_2.id),
        "fo2_2 parent must not include fo2_2 as a child because its already moved."
    );

    Ok(())
}
#[tokio::test]
async fn move_folder_to_be_a_child_of_itself() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo1 = tree.folders.first().unwrap();
    let mvreq = MoveRequest {
        source_id: fo1.id,
        destination_id: fo1.id,
        object_kind: family_cloud::ObjectKind::Folder,
    };
    let resp = app.move_obj(&login_data.access_token, mvreq).await;
    assert_eq!(
        resp.status_code(),
        StatusCode::CONFLICT,
        "can't move folder to itself.(will create a cyclic referneces)"
    );
    let children = app
        .list_children(&login_data.access_token, fo1.id)
        .await
        .json::<Vec<FolderChild>>();
    assert!(
        !children.iter().any(|f| f.id == fo1.id),
        "to indicate that it didnt became a child of itself."
    );
    Ok(())
}

#[tokio::test]
async fn move_folder_to_a_child_of_its_descendents() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo1 = tree.folders.first().unwrap();
    let decendent_fo2_1 = tree.folders.get(tree.folders.len() - 2).unwrap();
    let mvreq = MoveRequest {
        source_id: fo1.id,
        destination_id: decendent_fo2_1.id,
        object_kind: family_cloud::ObjectKind::Folder,
    };
    let resp = app.move_obj(&login_data.access_token, mvreq).await;
    assert_eq!(
        resp.status_code(),
        StatusCode::CONFLICT,
        "can't move folder to its decendents. (will create a cyclic referneces)"
    );
    let children = app
        .list_children(&login_data.access_token, decendent_fo2_1.id)
        .await
        .json::<Vec<FolderChild>>();
    assert!(
        children.is_empty(),
        "no movement happened therefore has no children"
    );
    assert!(!children.iter().any(|f| f.id == fo1.id));

    Ok(())
}

#[tokio::test]
async fn move_obj_destination_not_found() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo1 = tree.folders.first().unwrap();
    let mvreq = MoveRequest {
        source_id: fo1.id,
        destination_id: Uuid::new_v4(),
        object_kind: family_cloud::ObjectKind::Folder,
    };
    let resp = app.move_obj(&login_data.access_token, mvreq).await;
    resp.assert_status_not_found();
    Ok(())
}

#[tokio::test]
async fn move_obj_source_not_found() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo1 = tree.folders.first().unwrap();
    let mvreq = MoveRequest {
        source_id: Uuid::new_v4(),
        destination_id: fo1.id,
        object_kind: family_cloud::ObjectKind::Folder,
    };
    let resp = app.move_obj(&login_data.access_token, mvreq).await;
    resp.assert_status_not_found();
    Ok(())
}
