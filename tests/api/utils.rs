use axum::Router;
use axum_test::{TestResponse, TestServer};
use family_cloud::{build_router, init_db, init_redis_pool, init_rustfs};
use serde_json::json;
use uuid::Uuid;

pub struct AppTest {
    server: TestServer,
    username: String,
    email: String,
    password: String,
}

impl AppTest {
    pub fn new(app: Router) -> Self {
        let server = TestServer::new(app).unwrap();
        let x = Uuid::new_v4();
        Self {
            server,
            username: x.to_string(),
            email: x.to_string(),
            password: x.to_string(),
        }
    }
    pub async fn signup_request_new_account(&self) -> TestResponse {
        self.server
            .post("/api/auth/signup")
            .add_header("Content-Type", "application/json")
            .json(&json!({
                "username": self.username,
                "email": self.email,
                "password": self.password
            }))
            .await
    }
}

pub async fn establish_db_connection() {
    dotenv::dotenv();
    init_redis_pool().await;
    init_db().await;
    init_rustfs().await;
}

pub async fn create_app() -> AppTest {
    establish_db_connection().await;
    AppTest::new(build_router())
}
