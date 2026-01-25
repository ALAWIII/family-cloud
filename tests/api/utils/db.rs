//! Database utilities for test setup and data management

use sqlx::PgPool;
use uuid::Uuid;

use super::TestAccount;

/// Database helper for test data operations
pub struct TestDatabase;

impl TestDatabase {
    /// Create and insert a verified test account into database
    pub async fn create_verified_account(pool: &PgPool) -> anyhow::Result<TestAccount> {
        let account = TestAccount::default();
        Self::insert_account(pool, &account).await?;
        Ok(account)
    }

    /// Create and insert a custom test account
    pub async fn create_account(
        pool: &PgPool,
        username: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
    ) -> anyhow::Result<TestAccount> {
        let account = TestAccount::new(Uuid::new_v4(), username, email, password)?;
        Self::insert_account(pool, &account).await?;
        Ok(account)
    }

    /// Insert account into database
    pub async fn insert_account(pool: &PgPool, account: &TestAccount) -> anyhow::Result<()> {
        sqlx::query!(
            "INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)",
            account.id,
            account.username,
            account.email,
            account.password_hash
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get account by email
    pub async fn get_account_by_email(
        pool: &PgPool,
        email: &str,
    ) -> anyhow::Result<Option<(Uuid, String, String)>> {
        let record = sqlx::query_as::<_, (Uuid, String, String)>(
            "SELECT id, username, email FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;

        Ok(record)
    }

    /// Delete all test accounts
    pub async fn cleanup_accounts(pool: &PgPool) -> anyhow::Result<u64> {
        let result = sqlx::query!("DELETE FROM users").execute(pool).await?;

        Ok(result.rows_affected())
    }

    /// Check if account exists
    pub async fn account_exists(pool: &PgPool, email: &str) -> anyhow::Result<bool> {
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
                .bind(email)
                .fetch_one(pool)
                .await?;

        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_insertion_query() {
        let account = TestAccount::default();
        // Query structure validation (integration test would execute)
        assert!(!account.email.is_empty());
        assert!(!account.password_hash.is_empty());
    }
}
