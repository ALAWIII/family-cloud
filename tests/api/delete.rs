use family_cloud::DeleteRequest;

use crate::{create_folders_files_tree, setup_with_authenticated_user, wait_job_until_finishes};

#[tokio::test]
pub async fn delete_list_of_folders() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account).await?;
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
    wait_job_until_finishes(&app.state.db_pool, &tree.workers).await?;
    Ok(())
}

#[tokio::test]
pub async fn delete_list_of_files() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account).await?;

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
    wait_job_until_finishes(&app.state.db_pool, &tree.workers).await?;

    Ok(())
}

#[tokio::test]
pub async fn delete_mix_files_folders() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account).await?;
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
    wait_job_until_finishes(&app.state.db_pool, &tree.workers).await?;

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
    let tree = create_folders_files_tree(&app, &account).await?;
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
    wait_job_until_finishes(&app.state.db_pool, &tree.workers).await?;
    Ok(())
}
