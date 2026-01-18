use family_cloud::{get_db, init_db};

#[tokio::test]
async fn db_connection() {
    dotenv::dotenv().ok();

    init_db().await.expect("Failed to initialize database");

    let pool = get_db();
    assert!(!pool.is_closed());

    let result: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("Failed to execute test query");

    assert_eq!(result, 1);
}
