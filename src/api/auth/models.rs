use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingAccount {
    token_type: TokenType,
    username: String,
    email: String,
    password_hash: String, // store hashed, not plain
}
impl PendingAccount {
    pub fn new(username: &str, email: &str, hashed_password: String) -> Self {
        Self {
            token_type: TokenType::SignupVerification,
            username: username.into(),
            email: email.into(),
            password_hash: hashed_password,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenPayload {
    pub user_id: Uuid,
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub email: String,
    pub password: SecretBox<String>, // Received as plain text
}

#[derive(Serialize)]
pub enum SignupPayload {
    Existing(TokenPayload),
    New(PendingAccount),
}
impl SignupPayload {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Existing(t) => serde_json::to_string(t),
            Self::New(p) => serde_json::to_string(p),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub enum TokenType {
    SignupVerification,
    PasswordReset,
    EmailChange,
}
