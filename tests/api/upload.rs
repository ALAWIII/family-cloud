use axum::{
    body::Bytes,
    http::{StatusCode, header::CONTENT_LENGTH},
};
use family_cloud::ObjectRecord;

use crate::{calculate_checksum, setup_with_authenticated_user};

//test uploading existed file or folder.
#[tokio::test]
async fn upload_file_with_all_headers() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "file")
        .add_header("Object-Key", "banana/shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    resp.assert_status_success();
    let obj: ObjectRecord = resp.json();
    assert_eq!(obj.object_key, "banana/shawarma.txt");
    assert_eq!(obj.checksum_sha256, Some(checksum));
    assert_eq!(obj.bucket_name(), account.id.to_string());
    Ok(())
}
#[tokio::test]
async fn upload_file_less_than_5mb() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 512]; // 512KB
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "file")
        .add_header("Object-Key", "banana/shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    resp.assert_status_success();
    let obj: ObjectRecord = resp.json();
    assert_eq!(obj.object_key, "banana/shawarma.txt");
    assert_eq!(obj.checksum_sha256, Some(checksum));
    assert_eq!(obj.bucket_name(), account.id.to_string());
    Ok(())
}
#[tokio::test]
async fn upload_existed_file() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "file")
        .add_header("Object-Key", "banana/shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes.clone()))
        .await;
    resp.assert_status_success();
    let obj: ObjectRecord = resp.json();
    assert_eq!(obj.object_key, "banana/shawarma.txt");
    assert_eq!(obj.checksum_sha256, Some(checksum.to_string()));
    assert_eq!(obj.bucket_name(), account.id.to_string());
    // ------------------ resending the same file.
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "file")
        .add_header("Object-Key", "banana/shawarma.txt")
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
async fn upload_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "folder")
        .add_header("Object-Key", "banana/sandawitch")
        .await;
    resp.assert_status_success();
    let obj: ObjectRecord = resp.json();
    assert_eq!(obj.object_key, "/banana/sandawitch/");
    assert_eq!(obj.bucket_name(), account.id.to_string());
    Ok(())
}
#[tokio::test]
async fn upload_existed_folder() -> anyhow::Result<()> {
    let (app, account, login_data) = setup_with_authenticated_user().await?;
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "folder")
        .add_header("Object-Key", "banana/sandawitch")
        .await;
    resp.assert_status_success();
    let obj: ObjectRecord = resp.json();
    assert_eq!(obj.object_key, "/banana/sandawitch/");
    assert_eq!(obj.bucket_name(), account.id.to_string());
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "folder")
        .add_header("Object-Key", "banana/sandawitch")
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
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let f_len = file_bytes.len();
    let res = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "file")
        .add_header("Object-Key", "banana/shawarma.txt")
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
        .upload(&login_data.access_token)
        .add_header("Object-Key", "banana/shawarma.txt")
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
        .upload(&login_data.access_token)
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
        .upload(&login_data.access_token)
        .add_header("Object-Type", "file")
        .add_header("Object-Key", "banana/shawarma.txt")
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
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let file_bytes = vec![0u8; 1024 * 1024 * 10]; //10MB
    let checksum = calculate_checksum(&file_bytes);
    let resp = app
        .upload(&login_data.access_token)
        .add_header("Object-Type", "file")
        .add_header("Object-Key", "../banana/shawarma.txt")
        .add_header("x-amz-checksum-sha256", &checksum)
        .add_header(CONTENT_LENGTH, file_bytes.len())
        .content_type("text/plain")
        .bytes(Bytes::from(file_bytes))
        .await;
    assert_eq!(
        resp.status_code(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "path traversal error, a key not allowed to escape its domain."
    );

    Ok(())
}
