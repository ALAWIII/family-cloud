use family_cloud::{get_db, init_db};

#[tokio::test]
async fn db_connection() {
    dotenv::dotenv().ok();

    let e = init_db().await;
    assert!(e.is_ok());

    let pool = get_db();
    assert!(!pool.is_closed()); // to indicate its still open

    let result: i32 = sqlx::query_scalar("SELECT 1") // issuing a query to test if the pool is correctly connected to the database
        .fetch_one(pool)
        .await
        .expect("Query failed");
    assert_eq!(result, 1);
}
