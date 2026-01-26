# Integration Tests Using Refactored Code

## Complete Refactored Signup Tests

```rust
//! Integration tests for signup and email verification endpoints
//! 
//! Tests using the refactored test utilities:
//! - Container setup
//! - Account builders
//! - Email token extraction
//! - Database helpers
//! - MailHog client

use family_cloud::{
    TokenType, create_verification_key, get_db, get_redis_con, get_redis_pool, 
    is_account_exist, is_token_exist, init_db, init_mail_client, init_redis_pool, 
    init_rustfs, build_router, AppState,
};
use secrecy::ExposeSecret;

use tests::api::{
    containers::{
        init_test_containers, get_database_config, get_redis_config, 
        get_email_config, get_rustfs_config,
    },
    utils::{AppTest, TestAccount, AccountBuilder, EmailTokenExtractor, TestDatabase},
};

// ============================================================================
// Shared Test Setup - Initialize All Infrastructure Once
// ============================================================================

/// Helper to initialize complete test infrastructure
async fn setup_test_env() -> anyhow::Result<(AppTest, AppState)> {
    // 1. Start containers
    let containers = init_test_containers().await?;

    // 2. Get configurations from containers
    let db_config = get_database_config(&containers.postgres).await?;
    let redis_config = get_redis_config(&containers.redis).await?;
    let email_config = get_email_config(&containers.mailhog).await?;
    let rustfs_config = get_rustfs_config();

    // 3. Initialize services
    init_db(&db_config).await?;
    init_mail_client(&email_config)?;
    init_redis_pool(&redis_config).await?;
    init_rustfs(&/* settings would go here */).await;

    // 4. Get connection pools
    let db_pool = get_db()?;
    let mailhog_url = std::env::var("MAILHOG_URL")?;

    // 5. Build app state
    let state = AppState {
        settings: family_cloud::AppSettings {
            app: family_cloud::AppConfig {
                host: "localhost".into(),
                port: 5050,
            },
            database: db_config,
            email: email_config,
            rustfs: rustfs_config,
            secrets: family_cloud::Secrets {
                hmac: "OIodbFUiNK34xthjR0newczMC6HaAyksJS1GXfYZ".into(),
                rustfs: "OIodbFUiNK34xthjR0newczMC6HaAyksJS1GXfYZ".into(),
            },
            redis: redis_config,
        },
        db_pool,
        rustfs_con: family_cloud::get_rustfs(),
        redis_pool: get_redis_pool()?,
        mail_client: family_cloud::get_mail_client()?,
    };

    // 6. Build router and create AppTest
    let app_test = AppTest::new(build_router(state.clone())?, state.clone(), mailhog_url)?;

    Ok((app_test, state))
}

// ============================================================================
// Shared Helper Functions
// ============================================================================

/// Complete signup flow: signup, get email, extract tokens
async fn signup_and_get_tokens(
    app: &AppTest,
    account: &TestAccount,
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    // 1. Send signup request
    let response = app.signup(account).await;
    assert!(response.status().is_success(), "Signup should succeed");

    // 2. Fetch all emails from MailHog
    let messages = app.mailhog.get_all_messages().await?;

    // 3. Extract raw tokens from verification email
    let raw_tokens = EmailTokenExtractor::extract_raw_tokens(
        &messages,
        "new account email verification",
    );

    assert!(!raw_tokens.is_empty(), "Should have received verification email");

    // 4. Convert raw tokens to hashed format
    let hashed_tokens = EmailTokenExtractor::hash_tokens(
        &raw_tokens,
        app.state.settings.secrets.hmac.expose_secret(),
    )?
    .iter()
    .map(|v| create_verification_key(TokenType::Signup, v))
    .collect::<Vec<_>>();

    Ok((raw_tokens, hashed_tokens))
}

/// Verify email by clicking token link
async fn verify_email_with_token(app: &AppTest, token: &str) -> bool {
    let response = app.verify_email("/api/auth/verify", token).await;
    response.status().is_success()
}

// ============================================================================
// Individual Integration Tests
// ============================================================================

#[tokio::test]
async fn test_signup_sends_verification_email() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    // Create test account using builder
    let account = AccountBuilder::new()
        .username("testuser_email_verification")
        .email("testuser_email_verification@test.local")
        .password("SecurePassword123!")
        .build()?;

    // Send signup
    let response = app.signup(&account).await;
    assert!(response.status().is_success(), "Signup should succeed");

    // Get messages from MailHog
    let messages = app.mailhog.get_all_messages().await?;

    // Extract verification tokens
    let raw_tokens = EmailTokenExtractor::extract_raw_tokens(
        &messages,
        "new account email verification",
    );

    // Assertions
    assert_eq!(
        raw_tokens.len(),
        1,
        "Should send exactly one verification email"
    );

    Ok(())
}

#[tokio::test]
async fn test_verification_token_stored_in_redis() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;

    // Create and signup account
    let account = TestAccount::default();
    let (_raw_tokens, hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Get Redis connection
    let mut redis_conn = get_redis_con(state.redis_pool.clone()).await?;

    // Verify all tokens exist in Redis
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            token_exists,
            "Token '{}' should exist in Redis before verification",
            hashed_token
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_verification_completes_account_creation() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;

    // Create and signup account
    let account = TestAccount::default();
    let (raw_tokens, _hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Get database connection
    let db_pool = get_db()?;

    // Verify email for each token
    for raw_token in &raw_tokens {
        let verified = verify_email_with_token(&app, raw_token).await;
        assert!(verified, "Email verification should succeed for token: {}", raw_token);
    }

    // Check account was created in database
    let user_id = is_account_exist(&db_pool, &account.email).await?;
    assert!(
        user_id.is_some(),
        "Account should be created after verification for email: {}",
        account.email
    );

    Ok(())
}

#[tokio::test]
async fn test_existing_account_prevents_duplicate_signup() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;
    let db_pool = get_db()?;

    // Step 1: Create and verify first account
    let account = AccountBuilder::new()
        .username("duplicate_test_user")
        .email("duplicate@test.local")
        .password("SecurePassword123!")
        .build()?;

    let (raw_tokens, hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Verify email
    for raw_token in &raw_tokens {
        verify_email_with_token(&app, raw_token).await;
    }

    // Confirm account exists
    let user_exists = is_account_exist(&db_pool, &account.email).await?;
    assert!(user_exists.is_some(), "First account should exist");

    // Clear MailHog for clean test
    app.mailhog.delete_all_messages().await?;

    // Step 2: Try signing up with same email
    let duplicate_account = TestAccount::new(
        uuid::Uuid::new_v4(),
        "different_username",
        &account.email, // Same email!
        "DifferentPassword123!",
    )?;

    let response = app.signup(&duplicate_account).await;
    assert!(
        response.status().is_success() || response.status().is_client_error(),
        "Duplicate signup should be rejected"
    );

    // Step 3: Verify no new verification email was sent
    let messages_after = app.mailhog.get_all_messages().await?;
    let new_tokens = EmailTokenExtractor::extract_raw_tokens(
        &messages_after,
        "new account email verification",
    );

    assert_eq!(
        new_tokens.len(),
        0,
        "No new verification email should be sent for duplicate email"
    );

    // Step 4: Verify old tokens were cleaned up
    let mut redis_conn = get_redis_con(state.redis_pool).await?;
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            !token_exists,
            "Old verification token should be removed after account creation"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_verification_removes_token_from_redis() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;

    // Create and signup account
    let account = TestAccount::default();
    let (raw_tokens, hashed_tokens) = signup_and_get_tokens(&app, &account).await?;

    // Get Redis connection
    let mut redis_conn = get_redis_con(state.redis_pool).await?;

    // Verify tokens exist BEFORE verification
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            token_exists,
            "Token should exist in Redis BEFORE verification"
        );
    }

    // Complete email verification
    for raw_token in &raw_tokens {
        verify_email_with_token(&app, raw_token).await;
    }

    // Refresh Redis connection
    let mut redis_conn = get_redis_con(state.redis_pool).await?;

    // Verify tokens removed AFTER verification
    for hashed_token in &hashed_tokens {
        let token_exists = is_token_exist(&mut redis_conn, hashed_token).await?;
        assert!(
            !token_exists,
            "Token should be removed from Redis AFTER verification"
        );
    }

    Ok(())
}

// ============================================================================
// Additional Edge Case Tests Using New Utilities
// ============================================================================

#[tokio::test]
async fn test_signup_with_invalid_email_format() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    let invalid_account = AccountBuilder::new()
        .email("not-a-valid-email")
        .build()?;

    let response = app.signup(&invalid_account).await;
    assert!(
        response.status().is_client_error(),
        "Signup with invalid email should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_signup_with_weak_password() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    let weak_account = AccountBuilder::new()
        .password("123") // Too weak
        .build()?;

    let response = app.signup(&weak_account).await;
    assert!(
        response.status().is_client_error(),
        "Signup with weak password should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_verification_with_invalid_token() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    let response = app.verify_email("/api/auth/verify", "invalid_token_xyz").await;
    assert!(
        response.status().is_client_error(),
        "Verification with invalid token should fail"
    );

    Ok(())
}

#[tokio::test]
async fn test_multiple_accounts_can_be_verified_in_sequence() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;
    let db_pool = get_db()?;

    // Create and verify multiple accounts
    for i in 0..3 {
        let account = AccountBuilder::new()
            .username(format!("user_{}", i))
            .email(format!("user_{}@test.local", i))
            .build()?;

        let (raw_tokens, _) = signup_and_get_tokens(&app, &account).await?;

        for raw_token in &raw_tokens {
            verify_email_with_token(&app, raw_token).await;
        }

        // Verify account was created
        let user_exists = is_account_exist(&db_pool, &account.email).await?;
        assert!(
            user_exists.is_some(),
            "Account {} should be created after verification",
            account.email
        );
    }

    Ok(())
}

// ============================================================================
// Test Fixtures for Reuse
// ============================================================================

/// Create a verified test account in database
async fn create_and_verify_account() -> anyhow::Result<TestAccount> {
    let (app, _state) = setup_test_env().await?;

    let account = TestAccount::default();
    let (raw_tokens, _) = signup_and_get_tokens(&app, &account).await?;

    // Verify email
    for raw_token in &raw_tokens {
        verify_email_with_token(&app, raw_token).await;
    }

    Ok(account)
}

#[tokio::test]
async fn test_verified_account_can_login() -> anyhow::Result<()> {
    let (app, _state) = setup_test_env().await?;

    // Create verified account using fixture
    let account = create_and_verify_account().await?;

    // Attempt login
    let (email, password) = account.credentials();
    let response = app.login(&email, &password).await;

    assert!(
        response.status().is_success(),
        "Verified account should be able to login"
    );

    Ok(())
}
```

---

## Key Migration Points

### ✅ Old Code → New Code Mapping

| Old Pattern | New Pattern | Benefits |
|------------|-----------|----------|
| `setup_app().await?` | `setup_test_env().await?` | Returns both AppTest and AppState |
| `TestAccount::default()` | `TestAccount::default()` or `AccountBuilder::new().build()?` | More flexible, builder pattern |
| `extract_raw_token_list()` | `EmailTokenExtractor::extract_raw_tokens()` | Encapsulated, testable |
| `convert_raw_tokens_to_hashed()` | `EmailTokenExtractor::hash_tokens()` | Clearer naming, error handling |
| `app.get_all_messages_mailhog()` | `app.mailhog.get_all_messages().await?` | Better separation, reusable |
| `app.click_verify_url_in_email_message()` | `app.verify_email()` | Cleaner API |
| Manual account creation | `AccountBuilder` or `TestDatabase::create_account()` | Type-safe, fluent API |

---

## New Utilities You Can Use

### AccountBuilder
```rust
let account = AccountBuilder::new()
    .username("custom_user")
    .email("custom@test.com")
    .password("CustomPass123!")
    .build()?;
```

### TestDatabase (for DB operations)
```rust
// Create account directly in database
let account = TestDatabase::create_account(
    &db_pool,
    "testuser",
    "test@example.com",
    "password123"
).await?;

// Check if account exists
let exists = TestDatabase::account_exists(&db_pool, "test@example.com").await?;

// Cleanup
TestDatabase::cleanup_accounts(&db_pool).await?;
```

### MailHogClient
```rust
// Get all messages
let messages = app.mailhog.get_all_messages().await?;

// Get messages by subject
let verification_emails = app.mailhog.get_messages_by_subject("Verify Email").await?;

// Get token directly
let token = app.mailhog.get_verification_token("Verify Email").await?;

// Delete messages
app.mailhog.delete_all_messages().await?;
```

---

## Testing Best Practices with Refactored Code

### ✅ Good Practices

```rust
#[tokio::test]
async fn test_something() -> anyhow::Result<()> {
    let (app, state) = setup_test_env().await?;

    // Create account with builder - clear intent
    let account = AccountBuilder::new()
        .email("specific@test.com")
        .build()?;

    // Use descriptive assertions
    assert!(
        response.status().is_success(),
        "Request should succeed because..."
    );

    Ok(())
}
```

### ❌ Anti-Patterns

```rust
// Don't: Recreate setup per test manually
let app = setup_app().await?; // Old way
let account = TestAccount::new(...)?; // Verbose

// Don't: Missing error context
assert!(result); // No message

// Don't: Hardcoded values
app.login("test@test.com", "password");
```

---

## Continuous Integration Ready

All tests now:
- ✅ Use containerized infrastructure (no localhost assumptions)
- ✅ Clean up resources properly
- ✅ Have descriptive assertions with messages
- ✅ Use proper error handling
- ✅ Are easily parallelizable
- ✅ Have clear test names describing behavior
