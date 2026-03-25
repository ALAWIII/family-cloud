use family_cloud::{
    CopyItemRequest, CopyRequest, FileRecord, FolderChild, FolderRecord,
    get_user_available_storage, update_user_maximum_storage,
};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    create_folders_files_tree, init_workers, setup_with_authenticated_user, wait_job_until_finishes,
};
async fn check_copied_files_count_by_unique_names(
    con: &PgPool,
    f_names: &[String],
    owner_id: Uuid,
) -> anyhow::Result<Option<i64>> {
    let v = sqlx::query(
        "SELECT COUNT(*) as cts FROM files WHERE name=ANY($1) AND owner_id=$2 AND status='active'",
    )
    .bind(f_names)
    .bind(owner_id)
    .fetch_one(con)
    .await?;
    Ok(v.get("cts"))
}
async fn check_copied_folders_count_by_unique_names(
    con: &PgPool,
    f_names: &[String],
    owner_id: Uuid,
) -> anyhow::Result<Option<i64>> {
    let v = sqlx::query!(
        "SELECT COUNT(*) as cts FROM folders WHERE name=ANY($1) AND owner_id=$2",
        f_names,
        owner_id
    )
    .fetch_one(con)
    .await?;
    Ok(v.cts)
}

#[tokio::test]
async fn copy_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let source_folder = tree.folders.last().unwrap();
    let dest_folder = tree.folders.get(tree.folders.len() - 2).unwrap();
    let req = CopyRequest {
        dest_folder_id: dest_folder.id,
        f_list: vec![CopyItemRequest {
            f_id: source_folder.id,
            kind: family_cloud::ObjectKind::Folder,
        }],
    };
    let res = app.copy(&login_data.access_token, &req).await;
    res.assert_status_success();
    wait_job_until_finishes(&app.state.db_pool, &workers).await?;
    assert_eq!(res.json::<usize>(), 2);
    let fi_cts = check_copied_files_count_by_unique_names(
        &app.state.db_pool,
        &[
            tree.files.first().unwrap().name.to_string(),
            tree.files.get(1).unwrap().name.to_string(),
        ],
        account.id,
    )
    .await?;
    assert_eq!(fi_cts.unwrap(), 4);
    let fo_cts = check_copied_folders_count_by_unique_names(
        &app.state.db_pool,
        &[source_folder.name.to_string()],
        account.id,
    )
    .await?;
    assert_eq!(fo_cts.unwrap(), 2);
    let children: Vec<FolderChild> = app
        .list_children(&login_data.access_token, dest_folder.id)
        .await
        .json();
    assert_eq!(children.len(), 1);
    let new_folder_metadata: FolderRecord = app
        .get_metadata(
            &login_data.access_token,
            children.first().unwrap().id,
            &family_cloud::ObjectKind::Folder,
        )
        .await
        .json();
    assert_eq!(new_folder_metadata.parent_id.unwrap(), dest_folder.id);
    assert_eq!(new_folder_metadata.name, source_folder.name);
    assert_ne!(new_folder_metadata.id, source_folder.id);
    Ok(())
}

#[tokio::test]
async fn copy_files() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let dest_folder = tree.folders.get(tree.folders.len() - 2).unwrap();
    let req = CopyRequest {
        dest_folder_id: dest_folder.id,
        f_list: tree
            .files
            .iter()
            .map(|v| CopyItemRequest {
                f_id: v.id,
                kind: family_cloud::ObjectKind::File,
            })
            .collect(),
    };
    let res = app.copy(&login_data.access_token, &req).await;
    res.assert_status_success();
    wait_job_until_finishes(&app.state.db_pool, &workers).await?;
    assert_eq!(res.json::<usize>(), 3);
    let f_list_check = tree
        .files
        .iter()
        .map(|v| v.name.to_string())
        .collect::<Vec<_>>();
    let fi_cts =
        check_copied_files_count_by_unique_names(&app.state.db_pool, &f_list_check, account.id)
            .await?;
    assert_eq!(fi_cts.unwrap(), 3 + 3, "3 original 3 duplicated");
    let children: Vec<FolderChild> = app
        .list_children(&login_data.access_token, dest_folder.id)
        .await
        .json();
    assert_eq!(children.len(), 3, "only has 3 files");
    let mut files_list = vec![];
    for f in children {
        files_list.push(
            app.get_metadata(
                &login_data.access_token,
                f.id,
                &family_cloud::ObjectKind::File,
            )
            .await
            .json::<FileRecord>(),
        );
    }
    assert!(files_list.iter().all(|v| v.parent_id == dest_folder.id));
    let expected_names: Vec<&String> = tree.files.iter().map(|v| &v.name).collect();
    assert!(files_list.iter().all(|v| expected_names.contains(&&v.name)));
    Ok(())
}

#[tokio::test]
async fn copy_mix_files_folders() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let s_folder = tree.folders.last().unwrap();
    let s_file = tree.files.last().unwrap();
    let dest_folder = tree.folders.get(tree.folders.len() - 2).unwrap();
    let req = CopyRequest {
        dest_folder_id: dest_folder.id,
        f_list: vec![
            CopyItemRequest {
                f_id: s_folder.id,
                kind: family_cloud::ObjectKind::Folder,
            },
            CopyItemRequest {
                f_id: s_file.id,
                kind: family_cloud::ObjectKind::File,
            },
        ],
    };
    let res = app.copy(&login_data.access_token, &req).await;
    res.assert_status_success();

    wait_job_until_finishes(&app.state.db_pool, &workers).await?;

    assert_eq!(res.json::<usize>(), 3);
    let f_list_check = tree
        .files
        .iter()
        .map(|v| v.name.to_string())
        .collect::<Vec<_>>();
    let fi_cts =
        check_copied_files_count_by_unique_names(&app.state.db_pool, &f_list_check, account.id)
            .await?;
    assert_eq!(fi_cts.unwrap(), 3 + 3, "3 original 3 duplicated");
    let children: Vec<FolderChild> = app
        .list_children(&login_data.access_token, dest_folder.id)
        .await
        .json();
    assert_eq!(children.len(), 2, "has 1 file , 1 folder");
    let first_child = children.first().unwrap();
    let second_child = children.get(1).unwrap();
    let new_file = app
        .get_metadata(
            &login_data.access_token,
            if first_child.kind.is_folder() {
                second_child.id
            } else {
                first_child.id
            },
            &family_cloud::ObjectKind::File,
        )
        .await
        .json::<FileRecord>();
    let new_folder = app
        .get_metadata(
            &login_data.access_token,
            if first_child.kind.is_folder() {
                first_child.id
            } else {
                second_child.id
            },
            &family_cloud::ObjectKind::Folder,
        )
        .await
        .json::<FolderRecord>();
    assert_eq!(s_folder.name, new_folder.name);
    assert_eq!(s_file.name, new_file.name);
    assert_eq!(new_folder.parent_id.unwrap(), dest_folder.id);
    assert_eq!(new_file.parent_id, dest_folder.id);
    Ok(())
}

#[tokio::test]
async fn copy_exceed_available_storage() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let _workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let _rof = update_user_maximum_storage(&app.state.db_pool, account.id, 8).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let dest_folder = tree.folders.get(tree.folders.len() - 2).unwrap();
    let req = CopyRequest {
        dest_folder_id: dest_folder.id,
        f_list: tree
            .files
            .iter()
            .map(|v| CopyItemRequest {
                f_id: v.id,
                kind: family_cloud::ObjectKind::File,
            })
            .collect(),
    };
    let resp = app.copy(&login_data.access_token, &req).await;
    resp.assert_status_success();
    let children: Vec<FolderChild> = app
        .list_children(&login_data.access_token, dest_folder.id)
        .await
        .json();
    let s_info = get_user_available_storage(&app.state.db_pool, account.id).await?;
    assert!(
        children.is_empty(),
        "must be empty since the copied files exceeds the available space and therefore the copying operation is aborted and return success."
    );
    assert_eq!(
        resp.json::<u32>(),
        0,
        "zero because the copy operation aborted."
    );
    assert_eq!(s_info.storage_used_bytes, 6);
    assert_eq!(s_info.storage_quota_bytes, 8);
    Ok(())
}
