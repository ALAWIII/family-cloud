use std::{io::Cursor, sync::Arc};

use crate::{AppTest, setup_with_authenticated_user, upload_file};
use axum::{
    body::Bytes,
    http::{StatusCode, header::CONTENT_DISPOSITION},
};
use family_cloud::{ObjectRecord, TokenPayload};
use futures::future::join_all;
use secrecy::ExposeSecret;
use tokio::sync::Barrier;
use zip::ZipArchive;

async fn upload_folder(app: &AppTest, f_full_path: &str, jwt: &str) -> ObjectRecord {
    let resp = app
        .upload(jwt)
        .add_header("Object-Type", "folder")
        .add_header("Object-Key", f_full_path) // "banana/sandawitch"
        .await;
    resp.assert_status_success();
    resp.json()
}

#[tokio::test]
async fn download_file() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let obj_info = upload_file(
        &app,
        "/flafel/potato.txt",
        vec![0u8; 1024 * 1024 * 10],
        &login_data.access_token,
    )
    .await;
    let token: TokenPayload = app
        .download_token(&login_data.access_token, &obj_info.id.to_string())
        .await
        .json();
    assert!(!token.token.expose_secret().is_empty());
    let resp = app.stream(token.token.expose_secret(), true, None).await;
    resp.assert_status_success();
    let file_bytes: Bytes = resp.into_bytes();
    assert_eq!(file_bytes.len(), 1024 * 1024 * 10);
    Ok(())
}
#[tokio::test]
async fn download_entire_folder() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let obj_info: ObjectRecord =
        upload_folder(&app, "banana/sandwitch", &login_data.access_token).await;
    let mut files_info = vec![];
    for i in (0..10) {
        files_info.push(
            upload_file(
                &app,
                &format!("banana/sandwitch/{}.txt", i),
                vec![0u8; 1024 * 1024],
                &login_data.access_token,
            )
            .await,
        );
    }
    let token: TokenPayload = app
        .download_token(&login_data.access_token, &obj_info.id.to_string())
        .await
        .json();
    let resp = app.stream(token.token.expose_secret(), true, None).await;
    resp.assert_status_success();
    assert_eq!(resp.content_type(), "application/zip");
    assert_eq!(
        resp.header(CONTENT_DISPOSITION).to_str().ok(),
        Some("attachment; filename=\"sandwitch.zip\"")
    );
    let zip_bytes = resp.into_bytes();
    let mut zip = ZipArchive::new(Cursor::new(zip_bytes))?;

    assert_eq!(zip.len(), 10, "number of files in the zip archive");
    // calculate total size by summing all files size.
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let file = zip.by_index(i)?;
        if file.is_file() {
            total += file.size(); // uncompressed size per entry
        }
    }
    assert_eq!(total, 10 * 1024 * 1024);
    // check the names of files.
    for (x, f) in zip.file_names().enumerate() {
        assert_eq!(format!("banana/sandwitch/{}.txt", x), f);
    }
    Ok(())
}

#[tokio::test]
async fn download_part_using_range_header() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;
    let obj_info = upload_file(
        &app,
        "/flafel/potato.txt",
        vec![0u8; 1024],
        &login_data.access_token,
    )
    .await;
    let token: TokenPayload = app
        .download_token(&login_data.access_token, &obj_info.id.to_string())
        .await
        .json();
    let resp = app
        .stream(token.token.expose_secret(), true, Some("bytes=9-20")) // supplying the range to only download 12 bytes out of 1024
        .await;
    resp.assert_status_success();
    let part = resp.into_bytes();
    assert_eq!(part.len(), 12);
    Ok(())
}

#[tokio::test]
async fn concurrent_download_exceeded() -> anyhow::Result<()> {
    let (app, _, login_data) = setup_with_authenticated_user().await?;

    let up = upload_file(
        &app,
        "banana/chocolate.txt",
        vec![0u8; 1024 * 1024 * 5],
        &login_data.access_token,
    )
    .await;
    let mut d_tokens = vec![];
    for _ in 0..60 {
        d_tokens.push(
            app.download_token(&login_data.access_token, &up.id.to_string())
                .await
                .json::<TokenPayload>(),
        );
    }
    let mut stream_handles = vec![];

    let app = Arc::new(app);
    let barrier = Arc::new(Barrier::new(d_tokens.len()));
    for t in d_tokens {
        let c = barrier.clone();
        let app_clone = app.clone();
        stream_handles.push(tokio::spawn(async move {
            c.wait().await;
            app_clone.stream(t.token.expose_secret(), true, None).await
        }));
    }
    let result = join_all(stream_handles).await;
    let f_result: Vec<_> = result
        .iter()
        .filter(|resp| {
            if let Ok(resp) = resp {
                return resp.status_code() == StatusCode::TOO_MANY_REQUESTS;
            }
            false
        })
        .collect();
    assert!(!f_result.is_empty());
    Ok(())
}
