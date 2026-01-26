//! Application test harness with HTTP request helpers

use axum::Router;
use axum_extra::extract::cookie::Cookie;
use axum_test::{TestResponse, TestServer};
use family_cloud::AppState;
use serde::Serialize;
use serde_json::{Value, json};

use crate::TestContainers;

use super::MailHogClient;

/// Main test harness for authentication endpoints
pub struct AppTest {
    pub containers: TestContainers,
    pub state: AppState,
    server: TestServer,
    pub mailhog: MailHogClient,
}

impl AppTest {
    /// Create new test harness
    pub fn new(
        app: Router,
        state: AppState,
        mailhog_url: impl Into<String>,
        containers: TestContainers,
    ) -> anyhow::Result<Self> {
        let server = TestServer::new(app)?;
        let mailhog = MailHogClient::new(mailhog_url);

        Ok(Self {
            containers,
            state,
            server,
            mailhog,
        })
    }

    // ==================== Authentication Endpoints ====================

    /// POST /api/auth/signup
    pub async fn signup<T: Serialize>(&self, payload: &T) -> TestResponse {
        self.server.post("/api/auth/signup").json(payload).await
    }

    /// POST /api/auth/login
    pub async fn login(&self, email: &str, password: &str) -> TestResponse {
        self.server
            .post("/api/auth/login")
            .json(&json!({
                "email": email,
                "password": password
            }))
            .await
    }

    /// POST /api/auth/login with optional fields for error testing
    pub async fn login_with_optional(
        &self,
        email: Option<&str>,
        password: Option<&str>,
    ) -> TestResponse {
        let mut body = json!({});

        if let Some(e) = email {
            body["email"] = json!(e);
        }
        if let Some(p) = password {
            body["password"] = json!(p);
        }

        self.server.post("/api/auth/login").json(&body).await
    }

    // ==================== Logout Endpoints ====================

    /// POST /api/auth/logout with cookie
    pub async fn logout_with_cookie(&self, cookie: Cookie<'_>) -> TestResponse {
        self.server
            .post("/api/auth/logout")
            .add_cookie(cookie)
            .await
    }

    /// POST /api/auth/logout with token in body
    pub async fn logout_with_body(&self, token: &Value) -> TestResponse {
        self.server.post("/api/auth/logout").json(token).await
    }

    /// POST /api/auth/logout with no token
    pub async fn logout(&self) -> TestResponse {
        self.server.post("/api/auth/logout").await
    }

    // ==================== Refresh Token Endpoints ====================

    /// POST /api/auth/refresh with cookie
    pub async fn refresh_with_cookie(&self, cookie: Cookie<'_>) -> TestResponse {
        self.server
            .post("/api/auth/refresh")
            .add_cookie(cookie)
            .await
    }

    /// POST /api/auth/refresh with body
    pub async fn refresh_with_body(&self, token: &Value) -> TestResponse {
        self.server.post("/api/auth/refresh").json(token).await
    }

    /// POST /api/auth/refresh with no token
    pub async fn refresh(&self) -> TestResponse {
        self.server.post("/api/auth/refresh").await
    }

    // ==================== Email Change Endpoints ====================

    /// POST /api/auth/change-email
    pub async fn request_email_change(&self, new_email: &str, access_token: &str) -> TestResponse {
        self.server
            .post("/api/auth/change-email")
            .json(&json!({ "email": new_email }))
            .add_header("Authorization", format!("Bearer {}", access_token))
            .await
    }

    /// GET /api/auth/change-email/verify
    pub async fn verify_email_change(&self, token: &str) -> TestResponse {
        self.server
            .get(&format!("/api/auth/change-email/verify?token={}", token))
            .await
    }

    /// GET /api/auth/change-email/cancel
    pub async fn cancel_email_change(&self, token: &str) -> TestResponse {
        self.server
            .get(&format!("/api/auth/change-email/cancel?token={}", token))
            .await
    }

    // ==================== Password Reset Endpoints ====================

    /// POST /api/auth/password-reset
    pub async fn request_password_reset(&self, email: &str) -> TestResponse {
        self.server
            .post("/api/auth/password-reset")
            .json(&json!({ "email": email }))
            .await
    }

    /// POST /api/auth/password-reset/confirm
    pub async fn confirm_password_reset(
        &self,
        token: &str,
        new_password: &str,
        confirm_password: &str,
    ) -> TestResponse {
        self.server
            .post("/api/auth/password-reset/confirm")
            .form(&[
                ("token", token),
                ("new_password", new_password),
                ("confirm_password", confirm_password),
            ])
            .await
    }

    // ==================== Email Verification Endpoints ====================

    /// GET /api/auth/verify with token parameter
    pub async fn verify_email(&self, url: &str, token: &str) -> TestResponse {
        self.server
            .get(&format!("{}?token={}", url, token))
            .add_header("Content-Type", "application/json")
            .await
    }

    /// Helper: Get authorization header
    pub fn auth_header(access_token: &str) -> (String, String) {
        (
            "Authorization".to_string(),
            format!("Bearer {}", access_token),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_header() {
        let (key, value) = AppTest::auth_header("test_token_123");
        assert_eq!(key, "Authorization");
        assert_eq!(value, "Bearer test_token_123");
    }
}
