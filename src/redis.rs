use std::sync::OnceLock;

use deadpool_redis::{Config, Pool, Runtime};

static REDIS_POOL: OnceLock<Pool> = OnceLock::new();

pub async fn init_redis_pool() {
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    let cfg = Config::from_url(redis_url);
    let pool = cfg
        .builder()
        .expect("Failed to configure redis config")
        .max_size(50)
        .create_timeout(Some(std::time::Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()
        .expect("Falied to build redis configs");
    REDIS_POOL
        .set(pool)
        .expect("Falied to set redis connection pool");
}

pub fn get_redis_pool() -> Pool {
    REDIS_POOL
        .get()
        .expect("Failed to get redis connection pool")
        .clone()
}
