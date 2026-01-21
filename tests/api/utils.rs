use axum::Router;
use axum_test::{TestResponse, TestServer};
use deadpool_redis::{Connection, redis::AsyncTypedCommands};

use family_cloud::{
    TokenType, build_router, create_verification_key, decode_token, get_db, get_redis_pool,
    hash_password, hash_token, init_db, init_mail_client, init_redis_pool, init_rustfs,
};
use reqwest::Response;
use scraper::{Html, Selector};
use secrecy::SecretBox;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

pub struct AppTest {
    server: TestServer,
    pub mailhog_client: reqwest::Client,
}
#[derive(Debug, Serialize)]
pub struct TestAccount {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_hash: String,
}
impl TestAccount {
    pub fn new(id: Uuid, username: &str, email: &str, password: &str, password_hash: &str) -> Self {
        Self {
            id,
            username: username.into(),
            email: email.into(),
            password: password.into(),
            password_hash: password_hash.to_string(),
        }
    }
    pub fn email(&mut self, email: &str) -> bool {
        self.email = email.into();
        true
    }
    pub fn pswd(&mut self, password: &str) -> bool {
        self.password = password.into();
        true
    }
}
impl Default for TestAccount {
    fn default() -> Self {
        let x = Uuid::new_v4();
        let h_pas = hash_password(&SecretBox::new(Box::new(x.to_string()))).unwrap();
        Self {
            id: x,
            username: x.to_string(),
            email: format!("{}@potato.com", x),
            password: x.to_string(),
            password_hash: h_pas,
        }
    }
}

impl AppTest {
    pub fn new(app: Router) -> Self {
        let mailhog_client = reqwest::Client::new();
        let server = TestServer::new(app).unwrap();

        Self {
            mailhog_client,
            server,
        }
    }
    pub async fn signup_request_new_account<T: Serialize>(&self, user: &T) -> TestResponse {
        self.server
            .post("/api/auth/signup")
            .add_header("Content-Type", "application/json")
            .json(user)
            .await
    }
    pub async fn password_reset_request(&self, email: &str) -> TestResponse {
        self.server
            .post("/api/auth/password-reset")
            .json(&json!({"email":email}))
            .await
    }
    pub async fn password_reset_confirm(
        &self,
        raw_token: &str,
        new_password: &str,
        confirm_password: &str,
    ) -> TestResponse {
        self.server
            .post("/api/auth/password-reset/confirm")
            .form(&[
                ("token", raw_token),
                ("new_password", new_password),
                ("confirm_password", confirm_password),
            ])
            .await
    }
    pub async fn click_verify_url_in_email_message(&self, url: &str, token: &str) -> TestResponse {
        self.server
            .get(&format!("{}?token={}", url, token))
            .add_header("Content-Type", "application/json")
            .await
    }
    pub async fn login_request(&self, email: Option<&str>, password: Option<&str>) -> TestResponse {
        let mut body = json!({});

        if let Some(e) = email {
            body["email"] = json!(e);
        }
        if let Some(p) = password {
            body["password"] = json!(p);
        }
        self.server.post("/api/auth/login").json(&body).await
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
    pub async fn delete_messages_mailhog(&self, msg_id: &str) -> Response {
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
    init_mail_client();
}

pub async fn create_app() -> AppTest {
    establish_db_connection().await;
    AppTest::new(build_router().unwrap())
}

/// Fetches MailHog message ID and extracts token from email body
pub fn get_mailhog_msg_id_and_extract_raw_token_list(
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
                let mailhog_id = v["ID"].as_str().unwrap().to_string();
                let body = v["Content"]["Body"].as_str().unwrap();
                let raw_token = extract_token_from_body(body)?;

                return Some((mailhog_id, raw_token));
            }
            None
        })
        .collect()
}

pub fn convert_raw_tokens_to_hashed(raw_tokens: Vec<&String>) -> Vec<String> {
    raw_tokens
        .iter()
        .map(|t| hash_token(&decode_token(t).unwrap()).unwrap())
        .collect()
}

pub async fn search_redis_for_hashed_token_id(
    hashed_token: &str,
    conn: &mut Connection,
) -> Option<String> {
    conn.get(hashed_token).await.unwrap()
}
fn extract_token_from_body(email_body: &str) -> Option<String> {
    // Decode quoted-printable
    let decoded = email_body.replace("=3D", "=").replace("=\n", "");

    let document = Html::parse_document(&decoded);
    let selector = Selector::parse(r#"a[id="verify-button"]"#).ok()?;

    let element = document.select(&selector).next()?;
    let href = element.value().attr("href")?;

    href.split("token=").nth(1).map(|s| s.to_string())
}

pub async fn clean_mailhog(mailhog_id_list: &[(String, String)], app: &AppTest) {
    for (msg_id, _) in mailhog_id_list {
        assert!(
            app.delete_messages_mailhog(msg_id)
                .await
                .status()
                .is_success()
        );
    }
}

pub async fn search_database_for_email(con: &PgPool, email: &str) -> Option<Uuid> {
    sqlx::query!("select id from users where email=$1", email)
        .fetch_optional(con)
        .await
        .expect("Failed to execute query") // Handle sqlx error
        .map(|record| record.id) // Extract id if found
}

pub async fn create_verified_account(con: &PgPool) -> TestAccount {
    let user = TestAccount::default();
    sqlx::query!(
        "insert into users (id,username,email,password_hash) Values($1,$2,$3,$4)",
        user.id,
        user.username,
        user.email,
        user.password_hash
    )
    .execute(con)
    .await
    .unwrap();
    user
}
