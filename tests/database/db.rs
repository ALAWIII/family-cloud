use family_cloud::{get_db, run};

#[tokio::test]
async fn db_connection() {
    let e = run().await;
    assert!(e.is_ok());
    let con = get_db();
    assert!(!con.is_closed())
}
