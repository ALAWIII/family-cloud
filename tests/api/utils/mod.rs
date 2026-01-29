//! Test utilities and fixtures
//!
//! Provides:
//! - Test account models
//! - Application test harness (AppTest)
//! - Email verification utilities
//! - Database helpers
//! - Common test patterns
pub mod containers;
pub use containers::*;
pub mod app_test;
pub mod db;
pub mod email;
pub mod models;

pub use app_test::AppTest;
pub use db::TestDatabase;
pub use email::{EmailTokenExtractor, MailHogClient};
pub use models::{AccountBuilder, TestAccount};

use axum_extra::extract::cookie::Cookie;
use serde_json::{Value, json};

/// Helper to create refresh token pair (cookie & body format)
pub fn create_token_pair(refresh_token: &str) -> (Cookie<'static>, Value) {
    // Note: Cookie lifetime is 'static but should be managed carefully
    let cookie = Cookie::new("token", refresh_token.to_string());
    let body = json!({ "token": refresh_token });
    (cookie, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_pair_creation() {
        let token = "test_refresh_token_12345";
        let (cookie, body) = create_token_pair(token);

        assert_eq!(cookie.name(), "token");
        assert_eq!(cookie.value(), token);
        assert_eq!(body["token"].as_str(), Some(token));
    }
}
