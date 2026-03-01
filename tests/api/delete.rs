use family_cloud::{DeleteRequest, get_user_available_storage, update_user_maximum_storage};

use crate::{
    create_folders_files_tree, init_workers, setup_with_authenticated_user, wait_job_until_finishes,
};

#[tokio::test]
pub async fn delete_list_of_folders() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2_1 = tree.folders.get(tree.folders.len() - 2).unwrap();
    let fo2_2 = tree.folders.last().unwrap();
    let fi1 = tree.files.first().unwrap();
    let fi2 = tree.files.get(1).unwrap();
    let d = app
        .delete(
            &login_data.access_token,
            &[
                DeleteRequest {
                    f_id: fo2_2.id,
                    kind: family_cloud::ObjectKind::Folder,
                },
                DeleteRequest {
                    f_id: fo2_1.id,
                    kind: family_cloud::ObjectKind::Folder,
                },
            ],
        )
        .await;
    d.assert_status_success();
    for v in [fo2_1, fo2_2] {
        app.get_metadata(
            &login_data.access_token,
            v.id,
            &family_cloud::ObjectKind::Folder,
        )
        .await
        .assert_status_not_found();
    }
    for v in [fi1, fi2] {
        app.get_metadata(
            &login_data.access_token,
            v.id,
            &family_cloud::ObjectKind::Folder,
        )
        .await
        .assert_status_not_found();
    }
    wait_job_until_finishes(&app.state.db_pool, &workers).await?;
    Ok(())
}

#[tokio::test]
pub async fn delete_list_of_files() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;

    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;

    let fi1 = tree.files.first().unwrap();
    let fi2 = tree.files.get(1).unwrap();
    let fi3 = tree.files.last().unwrap();
    let d = app
        .delete(
            &login_data.access_token,
            &[
                DeleteRequest {
                    f_id: fi1.id,
                    kind: family_cloud::ObjectKind::File,
                },
                DeleteRequest {
                    f_id: fi2.id,
                    kind: family_cloud::ObjectKind::File,
                },
                DeleteRequest {
                    f_id: fi3.id,
                    kind: family_cloud::ObjectKind::File,
                },
            ],
        )
        .await;
    d.assert_status_success();
    for v in [fi1, fi2, fi3] {
        app.get_metadata(
            &login_data.access_token,
            v.id,
            &family_cloud::ObjectKind::File,
        )
        .await
        .assert_status_not_found();
    }
    wait_job_until_finishes(&app.state.db_pool, &workers).await?;

    Ok(())
}

#[tokio::test]
pub async fn delete_mix_files_folders() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2_2 = tree.folders.last().unwrap();
    let fi3 = tree.files.last().unwrap();
    let d = app
        .delete(
            &login_data.access_token,
            &[
                DeleteRequest {
                    f_id: fo2_2.id,
                    kind: family_cloud::ObjectKind::Folder,
                },
                DeleteRequest {
                    f_id: fi3.id,
                    kind: family_cloud::ObjectKind::File,
                },
            ],
        )
        .await;
    d.assert_status_success();

    app.get_metadata(
        &login_data.access_token,
        fi3.id,
        &family_cloud::ObjectKind::File,
    )
    .await
    .assert_status_not_found();
    app.get_metadata(
        &login_data.access_token,
        fo2_2.id,
        &family_cloud::ObjectKind::Folder,
    )
    .await
    .assert_status_not_found();
    wait_job_until_finishes(&app.state.db_pool, &workers).await?;

    Ok(())
}
#[tokio::test]
pub async fn delete_empty_list() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    app.delete(&login_data.access_token, &[])
        .await
        .assert_status_bad_request();
    Ok(())
}
#[tokio::test]
pub async fn delete_already_deleted_object() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let workers = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2_2 = tree.folders.last().unwrap();
    let fi3 = tree.files.last().unwrap();
    let d = app
        .delete(
            &login_data.access_token,
            &[
                DeleteRequest {
                    f_id: fo2_2.id,
                    kind: family_cloud::ObjectKind::Folder,
                },
                DeleteRequest {
                    f_id: fi3.id,
                    kind: family_cloud::ObjectKind::File,
                },
            ],
        )
        .await;
    d.assert_status_success();

    let d = app
        .delete(
            &login_data.access_token,
            &[
                DeleteRequest {
                    f_id: fo2_2.id,
                    kind: family_cloud::ObjectKind::Folder,
                },
                DeleteRequest {
                    f_id: fi3.id,
                    kind: family_cloud::ObjectKind::File,
                },
            ],
        )
        .await;
    d.assert_status_success();
    wait_job_until_finishes(&app.state.db_pool, &workers).await?;
    Ok(())
}

#[tokio::test]
async fn delete_file_check_user_space() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let w = init_workers(&app.state.db_pool, app.state.rustfs_con.clone()).await?;
    let _i = update_user_maximum_storage(&app.state.db_pool, account.id, 8).await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let before_s_info = get_user_available_storage(&app.state.db_pool, account.id).await?;
    assert_eq!(before_s_info.storage_quota_bytes, 8);
    assert_eq!(before_s_info.storage_used_bytes, 6);
    let req = tree
        .files
        .iter()
        .map(|v| DeleteRequest {
            f_id: v.id,
            kind: family_cloud::ObjectKind::File,
        })
        .collect::<Vec<_>>();
    let resp = app.delete(&login_data.access_token, &req).await;
    resp.assert_status_success();
    assert_eq!(resp.json::<u32>(), 3);
    wait_job_until_finishes(&app.state.db_pool, &w).await?;
    let after_s_info = get_user_available_storage(&app.state.db_pool, account.id).await?;
    assert_eq!(after_s_info.storage_quota_bytes, 8);
    assert_eq!(after_s_info.storage_used_bytes, 0);
    Ok(())
}
