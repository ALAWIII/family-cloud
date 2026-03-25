use std::fmt::Debug;

use anyhow::anyhow;
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::Json;
use axum_extra::extract::CookieJar;
use deadpool_redis::Connection;
use jsonwebtoken::{EncodingKey, Header, encode};
use secrecy::{ExposeSecret, SecretBox, SecretString};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use hmac::{Hmac, Mac};
use rand::{TryRngCore, rngs::OsRng as RandOsRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use tracing::{debug, error, info, warn};

use crate::{
    ApiError, Claims, CryptoError, TokenPayload, TokenType, UserTokenPayload,
    delete_token_from_redis,
};
type HmacSha256 = Hmac<Sha256>;

//----------------------------------------------tokens generating, securing and encoding/decoding
/// Generates a cryptographically secure random token of `len` bytes
/// (e.g., 32 bytes = 256 bits) using the OS RNG, returning the raw byte
/// buffer for further encoding or hashing.
pub fn generate_token_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    debug!("Generating {} bytes of random token data", len);
    let mut buf = vec![0u8; len];
    // CryptoError::RngFailed
    RandOsRng
        .try_fill_bytes(&mut buf)
        .inspect_err(|e| error!("RNG failed to generate token bytes: {}", e))?; // trait method
    debug!("Random token bytes generated successfully");
    Ok(buf)
}

/// Encodes raw token bytes into a URL‑safe base64 string (no padding),
/// suitable for use in URLs, cookies, and headers.
pub fn encode_token(token: &[u8]) -> String {
    debug!("Encoding {} bytes to base64url", token.len());
    URL_SAFE_NO_PAD.encode(token)
}

/// Decodes a URL‑safe base64 token string back into raw bytes, returning
/// a `CryptoError::TokenDecode` on malformed input.
pub fn decode_token(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    debug!("Decoding base64url string (len={}) to bytes", encoded.len());
    //CryptoError::TokenDecode
    Ok(URL_SAFE_NO_PAD
        .decode(encoded)
        .inspect_err(|e| error!("Base64 decoding failed: {}", e))?)
}
/// Derives a hex‑encoded HMAC‑SHA256 hash of a token using the provided
/// secret, used as a non‑reversible key for Redis so raw tokens are never
/// stored in plaintext.
pub fn hash_token(token: &[u8], secret: &str) -> Result<String, CryptoError> {
    debug!("Hashing token (len={}) with HMAC-SHA256", token.len());
    //Hmac Invalid length
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .inspect_err(|e| error!("HMAC initialization failed: {}", e))?;
    mac.update(token);
    let tag = mac.finalize().into_bytes();
    debug!("Token hash computed successfully");
    Ok(hex::encode(tag)) // encodes data to hex strings with lowercase chars
}

//------------------------------- generating access token--------------------------
/// Creates a signed JWT access token for the given user payload by:
/// 1. Building `Claims` with user id, username, and `exp` in `seconds`.
/// 2. Encoding with the shared HMAC secret, returning the JWT string or a
///    `CryptoError::Jwt` on failure.
pub fn create_jwt_access_token(
    user: &UserTokenPayload,
    seconds: i64,
    secret_key: SecretString,
) -> Result<String, CryptoError> {
    info!(
        user_id = %user.id,
        user_name = %user.username,
        expiry_seconds = seconds,
        "Creating JWT access token"
    );

    let claims = Claims::new(user.id, user.username.to_string()).with_expiry(seconds);
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.expose_secret().as_bytes()),
    )
    .inspect_err(|e| error!("Failed to generate new JWT access token: {}", e))?)
}

//------------------------------- user password hashing -------------------
/// Hashes a secret‑boxed password using Argon2id with a random salt and
/// returns the encoded hash string suitable for storage in the database.
pub fn hash_password(password: &SecretBox<String>) -> Result<String, CryptoError> {
    debug!("Hashing password with Argon2id");

    let salt = SaltString::generate(&mut OsRng);
    let argon = argon2::Argon2::default();
    let password_hash = argon
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .inspect_err(|e| error!("Password hashing failed: {}", e))?
        .to_string();
    debug!("Password hashed successfully");
    Ok(password_hash)
}

/// Verifies a secret‑boxed password against an Argon2 encoded hash by:
/// 1. Parsing the stored hash format.
/// 2. Returning `Ok(true)` on match, `Ok(false)` on password mismatch
///    only, and `Err(CryptoError::PasswordHash)` on other verification
///    errors.
pub fn verify_password(
    password: &SecretBox<String>,
    password_hash: &str,
) -> Result<bool, CryptoError> {
    debug!("Verifying password against hash");
    let parsed_hash = PasswordHash::new(password_hash)
        .inspect_err(|e| error!("Failed to parse password hash format: {}", e))?; //fails parsing the password into a good formant (corrupted password format)
    let argon = Argon2::default();

    match argon.verify_password(password.expose_secret().as_bytes(), &parsed_hash) {
        Ok(()) => {
            debug!("Password verification successful");
            Ok(true)
        } // Match
        Err(argon2::password_hash::Error::Password) => {
            warn!("Password verification failed - password mismatch");
            Ok(false)
        } // No match
        Err(e) => {
            error!("Password verification error: {}", e);
            Err(CryptoError::PasswordHash(e))
        } // INTERNAL_Error 500
    }
}

//-----------------------
/// Serializes any `Serialize` value to a JSON string, mapping errors into
/// `ApiError::Serialization` and logging failures.
pub fn serialize_content(content: &impl Serialize) -> Result<String, ApiError> {
    debug!("serializing content to json");
    Ok(serde_json::to_string(content)
        .inspect_err(|e| error!("JSON serialization failed: {}", e))?)
}
/// Deserializes a JSON string into type `T`, logging failures and mapping
/// them to `ApiError::Serialization`.
pub fn deserialize_content<T: DeserializeOwned + Debug>(content: &str) -> Result<T, ApiError> {
    debug!("Deserializing JSON content (len={})", content.len());
    Ok(serde_json::from_str(content)
        .inspect_err(|e| error!("JSON deserialization failed: {}", e))?)
}
//----------------------
/// Extracts a refresh token from either the `token` cookie or an optional
/// JSON body `TokenPayload`, returning `ApiError::Unauthorized` if not
/// found in either location.
pub fn extract_refresh_token(
    cookie_jar: &CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<SecretString, ApiError> {
    debug!("Attempting to extract refresh token from cookie or body");
    let token = cookie_jar
        .get("token")
        .map(|cookie| {
            debug!("Token extracted from cookie");
            cookie.value().into()
        })
        .or_else(|| {
            body.map(|t| {
                debug!("Token extracted from request body");
                t.0.token
            })
        })
        .ok_or(ApiError::Unauthorized)
        .inspect_err(|_| warn!("No refresh token found in request"));
    debug!("Refresh token extraction successful");
    token
}
//------------------------
/// Builds a namespaced Redis key for a given token type and token value
/// (e.g., `signup:<hash>`, `refresh:<hash>`), keeping key construction
/// consistent across the codebase.
pub fn create_redis_key(token_type: TokenType, token: &str) -> String {
    format!("{}:{}", token_type, token)
}
/// Validates a file/folder display name by enforcing:
/// 1. Length between 1 and 255 characters.
/// 2. Not equal to `.` or `..`.
/// 3. No trailing dot.
/// 4. No `/`, `\`, null byte, or control characters.
/// Returns `ApiError::BadRequest` with a descriptive message on failure.
pub fn validate_display_name(name: &str) -> Result<(), ApiError> {
    // 1. Length check
    if name.is_empty() || name.len() > 255 {
        return Err(ApiError::BadRequest(anyhow!(
            "Name must be between 1 and 255 characters"
        )));
    }

    // 2. Block "." and ".." only (leading dot is allowed for hidden files)
    if name == "." || name == ".." {
        return Err(ApiError::BadRequest(anyhow!("Name cannot be '.' or '..'")));
    }

    // 3.no trailing dot
    if name.ends_with('.') {
        return Err(ApiError::BadRequest(anyhow!("Name cannot end with a dot")));
    }

    // 4. Forbidden characters: path separators, null byte, control characters
    for c in name.chars() {
        match c {
            '/' => return Err(ApiError::BadRequest(anyhow!("Name cannot contain '/'"))),
            '\\' => return Err(ApiError::BadRequest(anyhow!("Name cannot contain '\\'"))),
            '\0' => {
                return Err(ApiError::BadRequest(anyhow!(
                    "Name cannot contain null byte"
                )));
            }
            c if (c as u32) < 0x20 => {
                return Err(ApiError::BadRequest(anyhow!(
                    "Name cannot contain control characters"
                )));
            }
            _ => {}
        }
    }

    Ok(())
}
//-----------------------
/// Revokes a refresh token by:
/// 1. Decoding the base64url string to bytes and hashing it with HMAC
///    using `hmac_sec`.
/// 2. Building the Redis key for `TokenType::Refresh`.
/// 3. Deleting the corresponding entry from Redis via
///    `delete_token_from_redis`.
pub async fn revoke_refresh_token(
    hmac_sec: &str,
    refresh_token: &str,
    redis_con: &mut Connection,
) -> Result<(), ApiError> {
    info!("decoding and hashing the refresh token for logout");
    let token_bytes = decode_token(refresh_token)?;
    let token_hash = hash_token(&token_bytes, hmac_sec)?;
    let key = create_redis_key(crate::TokenType::Refresh, &token_hash);

    info!("deleting and invalidating the refresh token from redis.");
    delete_token_from_redis(redis_con, &key).await?; // already deleted
    Ok(())
}
