use argon2::{Argon2, Params, PasswordHash};
use secrecy::{ExposeSecret, SecretBox};
use sha3::{self, Digest};
use sqlx::PgPool;

pub(super) async fn login() {}
/// used only on login !!!
struct Credentials {
    pub email: String,
    pub password: SecretBox<String>,
}

async fn validate_credentials(credentials: Credentials, pool: &PgPool) -> Result<(), &str> {
    let row: Option<_> = sqlx::query!(
        "select id ,password_hash from users where username=$1",
        credentials.email
    )
    .fetch_optional(pool)
    .await
    .expect("failed to send to database");
    let (expected_password_hash, user_id) = match row {
        Some(row) => (row.password_hash, row.id),
        None => {
            return Err("failed to retrive credentials ");
        }
    };
    let expected_password_hash =
        PasswordHash::new(&expected_password_hash).expect("failed to hash password");
    let hasher = Argon2::default();
    let password_hash = sha3::Sha3_256::digest(credentials.password.expose_secret().as_bytes());
    Ok(())
}
