use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use deadpool_redis::{Connection, redis::AsyncTypedCommands};
use family_cloud::{
    AccessQuery, FileShared, FileSystemObject, FolderShared, ObjectKind, SharedObjectReq,
    SharedTokenResponse, create_redis_key, deserialize_content, get_redis_con,
};
use std::{collections::HashMap, io::Cursor, time::Duration};
use uuid::Uuid;
use zip::ZipArchive;

use crate::{create_folders_files_tree, setup_with_authenticated_user};

async fn fetch_token_from_redis(
    con: &mut Connection,
    token: &str,
    user_id: Uuid,
) -> anyhow::Result<(Option<FileSystemObject>, HashMap<String, String>)> {
    let user_d_key = create_redis_key(family_cloud::TokenType::Shared, &user_id.to_string());
    let token_key = create_redis_key(family_cloud::TokenType::Shared, token);
    let obj = con
        .get(token_key)
        .await?
        .and_then(|v| deserialize_content::<FileSystemObject>(&v).ok());
    let user_active_shared_links = con.hgetall(user_d_key).await?;
    Ok((obj, user_active_shared_links))
}

#[tokio::test]
async fn share_link_for_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let folder = tree.folders.last().unwrap();
    let token_resp = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: folder.id,
                object_kind: family_cloud::ObjectKind::Folder,
                ttl: 60, // 60 seconds
            },
        )
        .await;
    token_resp.assert_status_success();
    let token: SharedTokenResponse = token_resp.json();
    let mut redis_con = get_redis_con(&app.state.redis_pool).await?;
    let (obj, f_tokens) = fetch_token_from_redis(&mut redis_con, &token.token, account.id).await?;
    assert_eq!(f_tokens.len(), 1);
    assert_eq!(*f_tokens.get(&folder.id.to_string()).unwrap(), token.token);
    assert!(obj.is_some());
    assert!(obj.as_ref().unwrap().is_folder());
    assert_eq!(obj.unwrap().id(), folder.id);
    Ok(())
}
#[tokio::test]
async fn share_link_for_existing_file() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fi1 = tree.files.first().unwrap();
    let token_resp = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fi1.id,
                object_kind: family_cloud::ObjectKind::File,
                ttl: 60,
            },
        )
        .await;
    token_resp.assert_status_success();
    let token: SharedTokenResponse = token_resp.json();
    let mut redis_con = get_redis_con(&app.state.redis_pool).await?;
    let (obj, f_tokens) = fetch_token_from_redis(&mut redis_con, &token.token, account.id).await?;
    assert_eq!(
        f_tokens.len(),
        1,
        "check if the user has only one f_id:token"
    );
    assert_eq!(
        *f_tokens.get(&fi1.id.to_string()).unwrap(),
        token.token,
        "check if token stored in redis."
    );
    assert!(obj.is_some());
    assert!(!obj.as_ref().unwrap().is_folder());
    assert_eq!(obj.unwrap().id(), fi1.id);
    let token_resp2 = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fi1.id,
                object_kind: family_cloud::ObjectKind::File,
                ttl: 70,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let (_, f_tokens) = fetch_token_from_redis(&mut redis_con, &token.token, account.id).await?;
    assert_eq!(
        f_tokens.len(),
        1,
        "check that the number of tokens is still fixed per object."
    );
    assert_eq!(token_resp2.token, token.token);
    Ok(())
}
#[tokio::test]
async fn share_user_has_many_links() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fi1 = tree.files.first().unwrap();
    let fi2 = tree.folders.first().unwrap();
    let token_resp1 = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fi1.id,
                object_kind: family_cloud::ObjectKind::File,
                ttl: 60,
            },
        )
        .await;
    token_resp1.assert_status_success();
    let token_resp2 = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fi2.id,
                object_kind: family_cloud::ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await;
    token_resp2.assert_status_success();
    let token2: SharedTokenResponse = token_resp2.json();
    let mut redis_con = get_redis_con(&app.state.redis_pool).await?;
    let (obj, f_tokens) = fetch_token_from_redis(&mut redis_con, &token2.token, account.id).await?;
    assert_eq!(f_tokens.len(), 2);
    assert!(obj.unwrap().is_folder());
    Ok(())
}

#[tokio::test]
async fn share_ttl_negative() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fi1 = tree.files.first().unwrap();
    let token_resp = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fi1.id,
                object_kind: family_cloud::ObjectKind::File,
                ttl: 0,
            },
        )
        .await;
    token_resp.assert_status_bad_request();
    Ok(())
}

//----------------------------------- access_object tests --------------------------
#[tokio::test]
async fn fetch_shared_folder_metadata() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let folder = tree.folders.last().unwrap();
    let token: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: folder.id,
                object_kind: family_cloud::ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json();
    let obj_resp = app.access_object(&token.token, None).await; // request information about the shared folder, AccessQuery(f_id,kind)=None
    obj_resp.assert_status_success();
    let folder_shared: FolderShared = obj_resp.json();
    assert_eq!(folder_shared.id, folder.id);
    assert_eq!(folder_shared.parent_id, folder.parent_id);
    assert_eq!(folder_shared.name, folder.name);

    Ok(())
}
#[tokio::test]
async fn fetch_shared_file_metadata() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let file = tree.files.first().unwrap();
    let token: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: file.id,
                object_kind: family_cloud::ObjectKind::File,
                ttl: 60,
            },
        )
        .await
        .json();
    let obj_resp = app.access_object(&token.token, None).await;
    obj_resp.assert_status_success();
    let file_shared: FileShared = obj_resp.json();
    assert_eq!(file_shared.id, file.id);
    assert_eq!(file_shared.parent_id, file.parent_id);
    assert_eq!(file_shared.name, file.name);
    Ok(())
}
//-----------------------------------  test normal usage like if a file/folder can be accessed if they were within the scoop of the shared token.
#[tokio::test]
async fn fetch_file_of_shared_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let folder = tree.folders.last().unwrap();
    let son_of_shared = tree.files.first().unwrap();
    let token: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: folder.id,
                object_kind: family_cloud::ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json();
    let obj_resp = app
        .access_object(
            &token.token,
            Some(AccessQuery {
                f_id: Some(son_of_shared.id),
                kind: Some(family_cloud::ObjectKind::File),
            }),
        )
        .await;
    obj_resp.assert_status_success();
    let folder_shared: FolderShared = app.access_object(&token.token, None).await.json();
    let file_shared: FileShared = obj_resp.json();
    assert_eq!(file_shared.id, son_of_shared.id);
    assert_eq!(file_shared.parent_id, son_of_shared.parent_id);
    assert_eq!(file_shared.name, son_of_shared.name);
    assert_eq!(file_shared.parent_id, folder.id);
    assert_eq!(folder_shared.children.len(), 2);
    assert!(
        folder_shared
            .children
            .iter()
            .any(|v| v.id == file_shared.id)
    );
    Ok(())
}
#[tokio::test]
async fn fetch_sub_folder_of_shared_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2 = tree.folders.get(1).unwrap();
    let son_of_fo2 = tree.folders.last().unwrap();
    let resp: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fo2.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json();
    let son_of_fo2_resp: FolderShared = app
        .access_object(
            &resp.token,
            Some(AccessQuery {
                f_id: Some(son_of_fo2.id),
                kind: Some(ObjectKind::Folder),
            }),
        )
        .await
        .json();
    assert_eq!(son_of_fo2.id, son_of_fo2_resp.id);
    assert_eq!(son_of_fo2_resp.children.len(), 2);
    Ok(())
}
//--------------------------------------------------------- test if user tries to provide id of the same file/folder that the token is attached to.
#[tokio::test]
async fn fetch_folder_is_same_shared_root_sub_tree() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let folder = tree.folders.last().unwrap();
    let token: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: folder.id,
                object_kind: family_cloud::ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json();
    let obj_resp = app
        .access_object(
            &token.token,
            Some(AccessQuery {
                f_id: Some(folder.id), // same as the root shared of sub-tree
                kind: Some(ObjectKind::Folder),
            }),
        )
        .await;
    obj_resp.assert_status_success();
    let folder_shared: FolderShared = obj_resp.json();
    assert_eq!(folder_shared.id, folder.id);
    assert_eq!(folder_shared.children.len(), 2);
    Ok(())
}

#[tokio::test]
async fn fetch_file_is_same_shared_file() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fi3 = tree.files.last().unwrap();
    let token: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fi3.id,
                object_kind: family_cloud::ObjectKind::File,
                ttl: 60,
            },
        )
        .await
        .json();
    let obj_resp = app
        .access_object(
            &token.token,
            Some(AccessQuery {
                f_id: Some(fi3.id), // same as the root shared of sub-tree
                kind: Some(ObjectKind::File),
            }),
        )
        .await;
    obj_resp.assert_status_success();
    let file_shared: FileShared = obj_resp.json();
    assert_eq!(file_shared.id, fi3.id);
    assert_eq!(file_shared.name, fi3.name);
    Ok(())
}
//------------------------------------------------------ test if user cant access file/folder that arent in the scoop of a shared url link.
#[tokio::test]
async fn fetch_file_not_son_of_shared_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2_2 = tree.folders.last().unwrap();
    let fi3 = tree.files.last().unwrap();
    let folder_shared: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fo2_2.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json();
    let fetch_fi3 = app
        .access_object(
            &folder_shared.token,
            Some(AccessQuery {
                f_id: Some(fi3.id),
                kind: Some(ObjectKind::File),
            }),
        )
        .await;
    fetch_fi3.assert_status_forbidden();
    Ok(())
}
#[tokio::test]
async fn fetch_folder_not_son_of_shared_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let fo2_2 = tree.folders.last().unwrap();
    let folder = tree.folders.first().unwrap();
    let folder_shared: SharedTokenResponse = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: fo2_2.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json();
    let fetch_folder = app
        .access_object(
            &folder_shared.token,
            Some(AccessQuery {
                f_id: Some(folder.id),
                kind: Some(ObjectKind::Folder),
            }),
        )
        .await;
    fetch_folder.assert_status_forbidden();
    Ok(())
}
//------------------------------ test download file,folder,sub-file,sub-folder of shared token

#[tokio::test]
async fn download_root_file_using_shared_token() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let file = tree.files.last().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: file.id,
                object_kind: ObjectKind::File,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app.stream_share(&token.token, true, None, None, None).await;
    s.assert_status_success();
    assert_eq!(
        s.header(CONTENT_DISPOSITION).to_str().ok(),
        Some(format!("attachment; filename=\"{}\"", file.name).as_ref())
    );
    let data = s.into_bytes();
    assert_eq!(data.len() as i64, file.size);
    Ok(())
}

#[tokio::test]
async fn download_root_folder_using_shared_token() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let folder = tree.folders.last().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: folder.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app.stream_share(&token.token, true, None, None, None).await;
    s.assert_status_success();
    assert_eq!(
        s.header(CONTENT_DISPOSITION).to_str().ok(),
        Some(format!("attachment; filename=\"{}.zip\"", folder.name).as_ref())
    );
    let zip_bytes = s.into_bytes();
    let zip = ZipArchive::new(Cursor::new(zip_bytes))?;
    assert_eq!(zip.len(), 2);

    Ok(())
}
#[tokio::test]
async fn download_sub_folder_using_shared_token() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.folders.first().unwrap();
    let child_folder = tree.folders.last().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app
        .stream_share(
            &token.token,
            true,
            Some(child_folder.id),
            Some(ObjectKind::Folder),
            None,
        )
        .await;
    s.assert_status_success();
    assert_eq!(
        s.header(CONTENT_DISPOSITION).to_str().ok(),
        Some(format!("attachment; filename=\"{}.zip\"", child_folder.name).as_ref())
    );
    let zip_bytes = s.into_bytes();
    let zip = ZipArchive::new(Cursor::new(zip_bytes))?;
    assert_eq!(zip.len(), 2);

    Ok(())
}

#[tokio::test]
async fn download_sub_file_using_shared_token() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.folders.first().unwrap();
    let child_file = tree.files.first().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app
        .stream_share(
            &token.token,
            true,
            Some(child_file.id),
            Some(ObjectKind::File),
            None,
        )
        .await;
    s.assert_status_success();
    assert_eq!(
        s.header(CONTENT_DISPOSITION).to_str().ok(),
        Some(format!("attachment; filename=\"{}\"", child_file.name).as_ref())
    );
    let bytes = s.into_bytes();
    assert_eq!(bytes.len() as i64, child_file.size);
    Ok(())
}

#[tokio::test]
async fn download_file_not_within_token_scope() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.folders.last().unwrap();
    let child_file = tree.files.last().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app
        .stream_share(
            &token.token,
            true,
            Some(child_file.id),
            Some(ObjectKind::File),
            None,
        )
        .await;
    s.assert_status_forbidden();
    Ok(())
}
#[tokio::test]
async fn download_folder_not_within_token_scope() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.folders.last().unwrap();
    let child_folder = tree.folders.first().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::Folder,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app
        .stream_share(
            &token.token,
            true,
            Some(child_folder.id),
            Some(ObjectKind::Folder),
            None,
        )
        .await;
    s.assert_status_forbidden();
    Ok(())
}

#[tokio::test]
async fn download_folder_of_root_file() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.files.last().unwrap();
    let child_folder = tree.folders.first().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::File,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app
        .stream_share(
            &token.token,
            true,
            Some(child_folder.id),
            Some(ObjectKind::Folder),
            None,
        )
        .await;
    s.assert_status_bad_request();
    Ok(())
}
#[tokio::test]
async fn download_file_of_root_file() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.files.last().unwrap();
    let child_file = tree.files.first().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::File,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    let s = app
        .stream_share(
            &token.token,
            true,
            Some(child_file.id),
            Some(ObjectKind::File),
            None,
        )
        .await;
    s.assert_status_bad_request();
    Ok(())
}

#[tokio::test]
async fn download_file_expired_shared_token() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.files.last().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::File,
                ttl: 1,
            },
        )
        .await
        .json::<SharedTokenResponse>();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let resp = app.stream_share(&token.token, true, None, None, None).await;
    resp.assert_status_unauthorized();
    Ok(())
}
#[tokio::test]
async fn download_file_partial_parameters() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let tree = create_folders_files_tree(&app, &account, &login_data.access_token).await?;
    let root = tree.files.last().unwrap();
    let token = app
        .shares(
            &login_data.access_token,
            &SharedObjectReq {
                f_id: root.id,
                object_kind: ObjectKind::File,
                ttl: 60,
            },
        )
        .await
        .json::<SharedTokenResponse>();

    let resp = app
        .stream_share(&token.token, true, None, Some(ObjectKind::File), None)
        .await;
    resp.assert_status_bad_request();
    Ok(())
}
