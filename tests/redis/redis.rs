use deadpool_redis::redis::{self, AsyncTypedCommands};
use family_cloud::{get_redis_pool, init_redis_pool};

#[tokio::test]
async fn redis_connection() -> anyhow::Result<()> {
    dotenv::dotenv().expect("Failed to load environment variables");
    init_redis_pool().await;
    let pool = get_redis_pool()?;

    // get a connection from the pool
    let mut conn = pool.get().await.expect("Failed to get Redis connection");

    // try a simple command
    let pong: String = redis::cmd("PING")
        .query_async(&mut conn)
        .await
        .expect("PING failed");

    assert_eq!(pong, "PONG");
    let key = "test_key";
    let _: () = conn.set_ex(key, "value", 5).await.unwrap(); // expires in 5 seconds
    let val: Option<String> = conn.get(key).await.unwrap();
    assert_eq!(val, Some("value".into()));
    Ok(())
}
