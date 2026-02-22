use axum::{
    body::Bytes,
    http::{StatusCode, header::CONTENT_LENGTH},
};
use family_cloud::{FileRecord, FolderRecord};

use crate::{calculate_checksum, setup_with_authenticated_user, upload_file, upload_folder};

//test uploading existed file or folder.
#[tokio::test]
async fn upload_file_with_all_headers() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let length = file_bytes.len() as i64;
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    dbg!(account.root_folder());
    resp.assert_status_success();
    let file: FileRecord = resp.json();
    assert_eq!(file.name, "shawarma.txt");
    assert_eq!(file.checksum, Some(checksum));
    assert_eq!(file.bucket_name(), account.id.to_string());
    assert_eq!(file.size, length);
    Ok(())
}
#[tokio::test]
async fn upload_file_less_than_5mb() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 512]; // 512KB
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    resp.assert_status_success();
    let file: FileRecord = resp.json();
    assert_eq!(file.name, "shawarma.txt");
    assert_eq!(file.checksum, Some(checksum));
    assert_eq!(file.bucket_name(), account.id.to_string());
    Ok(())
}
#[tokio::test]
async fn upload_existed_file() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes.clone()))
        .await;
    resp.assert_status_success();
    let file: FileRecord = resp.json();
    assert_eq!(file.name, "shawarma.txt");
    assert_eq!(file.checksum, Some(checksum.to_string()));
    assert_eq!(file.bucket_name(), account.id.to_string());
    // ------------------ resending the same file.
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    assert_eq!(
        resp.status_code(),
        StatusCode::CONFLICT,
        "uploading existed file."
    );
    Ok(())
}
#[tokio::test]
async fn upload_folder_test() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "folder")
        .add_header("Object-Name", "sandawitch")
        .await;
    resp.assert_status_success();
    let folder: FolderRecord = resp.json();
    assert_eq!(folder.name, "sandawitch");
    assert_eq!(folder.bucket_name(), account.id.to_string());
    Ok(())
}
#[tokio::test]
async fn upload_existed_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "folder")
        .add_header("Object-Name", "sandawitch")
        .await;
    resp.assert_status_success();
    let folder: FolderRecord = resp.json();
    assert_eq!(folder.name, "sandawitch");
    assert_eq!(folder.bucket_name(), account.id.to_string());
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "folder")
        .add_header("Object-Name", "sandawitch")
        .await;
    assert_eq!(
        resp.status_code(),
        StatusCode::CONFLICT,
        "uploading existed folder."
    );
    Ok(())
}

#[tokio::test]
async fn upload_file_with_missing_headers() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let f_len = file_bytes.len();
    let res = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "shawarma.txt")
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes.clone()))
        .await;
    assert_eq!(
        res.status_code(),
        StatusCode::BAD_REQUEST,
        "missing checksum header"
    );
    let res = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Name", "shawarma.txt")
        .add_header(CONTENT_LENGTH, f_len)
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes.clone()))
        .await;
    assert_eq!(
        res.status_code(),
        StatusCode::BAD_REQUEST,
        "missing Object-Type header"
    );
    let res = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header(CONTENT_LENGTH, f_len)
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes.clone()))
        .await;
    assert_eq!(
        res.status_code(),
        StatusCode::BAD_REQUEST,
        "missing object-key header"
    );
    let res = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "shawarma.txt")
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes.clone()))
        .await;
    assert_eq!(
        res.status_code(),
        StatusCode::BAD_REQUEST,
        "missing Content-Length header"
    );
    Ok(())
}

#[tokio::test]
async fn upload_file_with_path_traversal_key() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "../banana/shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    assert_eq!(
        resp.status_code(),
        StatusCode::BAD_REQUEST,
        "path traversal error, a key not allowed to escape its domain."
    );

    Ok(())
}
#[tokio::test]
async fn upload_nested_folder_files() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let folder = upload_folder(
        &app,
        "sandwitch1",
        &account.root_folder(),
        &login_data.access_token,
    )
    .await;
    let file = upload_file(
        &app,
        "shawarma",
        &folder.id.to_string(),
        file_bytes,
        &login_data.access_token,
    )
    .await;
    assert_eq!(folder.parent_id, account.root_folder);
    assert_eq!(file.parent_id, folder.id);
    assert_ne!(file.parent_id.to_string(), account.root_folder());
    Ok(())
}
#[tokio::test]
async fn upload_file_invalid_checksum() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let resp = app
        .upload(&login_data.access_token, &account.root_folder())
        .add_header("Object-Type", "file")
        .add_header("Object-Name", "flafel.txt")
        .add_header("x-amz-checksum-sha256", "invalid checksum")
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    assert_eq!(resp.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    Ok(())
}
