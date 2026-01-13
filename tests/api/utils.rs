use axum::Router;
use axum_test::{TestResponse, TestServer};
use deadpool_redis::{
    Connection,
    redis::{AsyncTypedCommands, TypedCommands},
};

use family_cloud::{build_router, decode_token, hash_token, init_db, init_redis_pool, init_rustfs};
use reqwest::Response;
use serde_json::{Value, json};
use uuid::Uuid;

pub struct AppTest {
    server: TestServer,
    mailhog_client: reqwest::Client,
    username: String,
    email: String,
    password: String,
}

impl AppTest {
    pub fn new(app: Router) -> Self {
        let mailhog_client = reqwest::Client::new();
        let server = TestServer::new(app).unwrap();
        let x = Uuid::new_v4();
        Self {
            mailhog_client,
            server,
            username: x.to_string(),
            email: "shawarma@potato.com".into(),
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
    pub async fn get_all_messages_mailhog(&self) -> Vec<Value> {
        let response = self
            .mailhog_client
            .get("http://localhost:8025/api/v2/messages")
            .send()
            .await
            .expect("Failed to query MailHog API");
        let json: Value = response.json().await.expect("Failed to parse JSON");
        json["items"]
            .as_array()
            .expect("No messages found")
            .to_owned()
    }
    pub async fn delete_messages_mailhog(&self, msg_id: String) -> Response {
        self.mailhog_client
            .delete(format!("http://localhost:8025/api/v1/messages/{}", msg_id))
            .send()
            .await
            .expect("Failed to delete email message from server")
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

/// fetches the response and extracts every single mail hog message id from `ID` field.
///
/// and the assigned token from `Message-ID` header.
pub fn get_mailhog_msg_id_and_raw_token_list(
    msgs: &[Value],
    subject: &str,
) -> Vec<(String, String)> {
    msgs.iter()
        .filter_map(move |v| {
            if v["Content"]["Headers"]["Subject"][0]
                .as_str()
                .unwrap()
                .contains(subject)
            {
                return Some((
                    v["ID"].as_str().unwrap().to_string(),
                    v["Content"]["Headers"]["Message-ID"][0]
                        .as_str()
                        .unwrap()
                        .to_string(),
                ));
            }
            None
        })
        .collect()
}
pub fn get_msg_id_hashed_list(raw_id_list: Vec<&String>) -> Vec<String> {
    raw_id_list
        .iter()
        .map(|t| hash_token(&decode_token(&t).unwrap()))
        .collect()
}

pub async fn search_redis_for_hashed_token_id(
    hashed_token: &str,
    conn: &mut Connection,
) -> Option<String> {
    conn.get(hashed_token).await.unwrap()
}
