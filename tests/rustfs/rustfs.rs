use family_cloud::{get_rustfs, init_rustfs};

#[tokio::test]
async fn rustfs_con() {
    dotenv::dotenv().ok();
    let con = init_rustfs().await;
    assert!(con.is_ok());
    let client = get_rustfs();
    let buckets = client.list_buckets().send().await;
    assert!(buckets.is_ok());
}
