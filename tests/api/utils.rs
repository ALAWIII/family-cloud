use axum::Router;
use axum_test::{TestResponse, TestServer};
use deadpool_redis::{Connection, redis::AsyncTypedCommands};

use family_cloud::{
    TokenType, build_router, create_verification_key, decode_token, get_db, get_redis_pool,
    hash_token, init_db, init_redis_pool, init_rustfs,
};
use reqwest::Response;
use scraper::{Html, Selector};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

pub struct AppTest {
    server: TestServer,
    pub mailhog_client: reqwest::Client,
}
#[derive(Debug, Serialize)]
pub struct UserTest {
    pub username: String,
    pub email: String,
    pub password: String,
}
impl UserTest {
    pub fn new(username: &str, email: &str, password: &str) -> Self {
        Self {
            username: username.into(),
            email: email.into(),
            password: password.into(),
        }
    }
}
impl Default for UserTest {
    fn default() -> Self {
        let x = Uuid::new_v4();
        Self {
            username: x.to_string(),
            email: format!("{}@potato.com", x),
            password: x.to_string(),
        }
    }
}

pub struct SignupTestSession {
    pub app: AppTest,
    pub user: UserTest,
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

    pub async fn click_verify_url_in_email_message(&self, url: &str, token: &str) -> TestResponse {
        self.server
            .get(&format!("{}?token={}", url, token))
            .add_header("Content-Type", "application/json")
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
}

pub async fn create_app() -> AppTest {
    establish_db_connection().await;
    AppTest::new(build_router())
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
        .map(|t| hash_token(&decode_token(t).unwrap()))
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

pub async fn create_new_verified_account() -> SignupTestSession {
    let app = create_app().await;
    let user = UserTest::default();
    let token_type = TokenType::Signup;
    let mut redis_conn = get_redis_pool().get().await.unwrap();
    let verify_url = "/api/auth/signup";
    // === Phase 1: New Account Signup ===
    let response = app.signup_request_new_account(&user).await; //
    assert_eq!(
        response.text(),
        "If this email is new, you'll receive a verification email"
    );

    // === Phase 2: Verify Email Sent with Token ===
    let messages = app.get_all_messages_mailhog().await;
    let msg_id_token_pairs =
        get_mailhog_msg_id_and_extract_raw_token_list(&messages, "verification");
    let hashed_tokens: Vec<String> =
        convert_raw_tokens_to_hashed(msg_id_token_pairs.iter().map(|(_, token)| token).collect())
            .iter()
            .map(|v| create_verification_key(v, token_type))
            .collect();

    // === Phase 3: Verify Tokens Stored in Redis ===
    for hashed_token in &hashed_tokens {
        let pending_account = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            pending_account.is_some(),
            "Token should exist in Redis before verification"
        );
    }

    // === Phase 4: Complete Verification ===
    for (_, raw_token) in &msg_id_token_pairs {
        app.click_verify_url_in_email_message(verify_url, raw_token)
            .await
            .assert_status_ok();
    }

    // Verify account now exists in database
    let user_id = search_database_for_email(&get_db(), &user.email).await;
    assert!(
        user_id.is_some(),
        "Account should be created after verification"
    );

    // === Phase 5: Test Existing Account Protection ===
    app.signup_request_new_account(&user)
        .await
        .assert_status_ok();

    // Should not send new email for existing account
    let messages_after = app.get_all_messages_mailhog().await;
    assert_eq!(
        messages_after.len(),
        1,
        "No new email should be sent for existing account"
    );

    // Tokens should be removed from Redis after verification
    for hashed_token in &hashed_tokens {
        // dbg!(hashed_token);
        let token = search_redis_for_hashed_token_id(hashed_token, &mut redis_conn).await;
        assert!(
            token.is_none(),
            "Token should be removed from Redis after verification"
        );
    }

    // === Cleanup ===
    clean_mailhog(&msg_id_token_pairs, &app).await;
    SignupTestSession { app, user }
}
