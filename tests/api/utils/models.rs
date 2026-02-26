//! Test data models and builders

use family_cloud::hash_password;
use secrecy::SecretBox;
use serde::Serialize;
use uuid::Uuid;

/// Test account with both plain and hashed passwords
#[derive(Debug, Clone, Serialize)]
pub struct TestAccount {
    pub id: Uuid,
    pub root_folder: Option<Uuid>,
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_hash: String,
}

impl TestAccount {
    /// Create account with custom values
    pub fn new(
        id: Uuid,
        username: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let password_str = password.into();
        let password_hash = hash_password(&SecretBox::new(Box::new(password_str.clone())))?;

        Ok(Self {
            id,
            root_folder: None,
            username: username.into(),
            email: email.into(),
            password: password_str,
            password_hash,
        })
    }

    /// Fluent API: Set email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }
    pub fn root_folder(&self) -> Option<Uuid> {
        self.root_folder
    }

    /// Fluent API: Set password and rehash
    pub fn with_password(mut self, password: impl Into<String>) -> anyhow::Result<Self> {
        let password_str = password.into();
        let password_hash = hash_password(&SecretBox::new(Box::new(password_str.clone())))?;

        self.password = password_str;
        self.password_hash = password_hash;
        Ok(self)
    }

    /// Get login credentials
    pub fn credentials(&self) -> (String, String) {
        (self.email.clone(), self.password.clone())
    }
}

impl Default for TestAccount {
    fn default() -> Self {
        let id = Uuid::new_v4();
        let password = id.to_string();
        let password_hash = hash_password(&SecretBox::new(Box::new(password.clone())))
            .expect("Failed to hash default password");

        Self {
            id,
            root_folder: None,
            username: format!("user_{}", id),
            email: format!("{}@test.com", id),
            password,
            password_hash,
        }
    }
}

/// Builder for creating test accounts with fluent API
pub struct AccountBuilder {
    id: Uuid,
    username: String,
    email: String,
    password: String,
}

impl AccountBuilder {
    /// Start building a new test account
    pub fn new() -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            username: format!("user_{}", id),
            email: format!("{}@test.local", id),
            password: id.to_string(),
        }
    }

    /// Set custom username
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set custom email
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// Set custom password
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    /// Set custom ID
    pub fn id(mut self, id: Uuid) -> Self {
        self.id = id;
        self
    }

    /// Build the TestAccount
    pub fn build(self) -> anyhow::Result<TestAccount> {
        TestAccount::new(self.id, self.username, self.email, self.password)
    }
}

impl Default for AccountBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let account = TestAccount::new(
            Uuid::new_v4(),
            "testuser",
            "test@example.com",
            "password123",
        );

        assert!(account.is_ok());
        let acc = account.unwrap();
        assert_eq!(acc.username, "testuser");
        assert_eq!(acc.email, "test@example.com");
        assert_ne!(acc.password, acc.password_hash);
    }

    #[test]
    fn test_account_builder() {
        let account = AccountBuilder::new()
            .username("custom_user")
            .email("custom@test.com")
            .password("custom_pass")
            .build();

        assert!(account.is_ok());
        let acc = account.unwrap();
        assert_eq!(acc.username, "custom_user");
        assert_eq!(acc.email, "custom@test.com");
    }

    #[test]
    fn test_account_fluent_api() {
        let account = TestAccount::default()
            .with_email("newemail@test.com")
            .with_password("newpass");

        assert!(account.is_ok());
        let acc = account.unwrap();
        assert_eq!(acc.email, "newemail@test.com");
        assert_eq!(acc.password, "newpass");
    }

    #[test]
    fn test_credentials() {
        let account = TestAccount::default();
        let (email, password) = account.credentials();
        assert_eq!(email, account.email);
        assert_eq!(password, account.password);
    }
}
