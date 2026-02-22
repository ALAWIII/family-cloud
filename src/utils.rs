use std::fmt::Debug;

use anyhow::anyhow;
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::Json;
use axum_extra::extract::CookieJar;
use jsonwebtoken::{EncodingKey, Header, encode};
use secrecy::{ExposeSecret, SecretBox, SecretString};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use hmac::{Hmac, Mac};
use rand::{TryRngCore, rngs::OsRng as RandOsRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;
use tracing::{debug, error, info, warn};

use crate::{ApiError, Claims, CryptoError, TokenPayload, TokenType, UserTokenPayload};
type HmacSha256 = Hmac<Sha256>;

//----------------------------------------------tokens generating, securing and encoding/decoding
/// accepts number of bytes , len=32 , bits = len*8 = 256-bit token
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

/// URL-safe base64 encode token for transport (cookies, links, headers) to alphenumeric text.
pub fn encode_token(token: &[u8]) -> String {
    debug!("Encoding {} bytes to base64url", token.len());
    URL_SAFE_NO_PAD.encode(token)
}

/// Decode token from URL-safe base64 (incoming from client) to array of bytes.
pub fn decode_token(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    debug!("Decoding base64url string (len={}) to bytes", encoded.len());
    //CryptoError::TokenDecode
    Ok(URL_SAFE_NO_PAD
        .decode(encoded)
        .inspect_err(|e| error!("Base64 decoding failed: {}", e))?)
}

/// accepts a decoded token as bytes and returns a hashed version of it.
/// accepts a token bytes and a global secret  to create a strong hashed token
///
/// the hashed token used to be stored in redis database for account verfication and authentication purposes
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

/// accepts user refresh token and generate new JWT access token , Err(CryptoError::JwtEncode)
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
/// accepts a secured password as secret of string and produce a one way hashed and salted using argon2id
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

/// accepts a raw password from user , and a hashed version of the password (mainly retrived from database)
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

pub fn serialize_content(content: &impl Serialize) -> Result<String, ApiError> {
    debug!("serializing content to json");
    Ok(serde_json::to_string(content)
        .inspect_err(|e| error!("JSON serialization failed: {}", e))?)
}
pub fn deserialize_content<T: DeserializeOwned + Debug>(content: &str) -> Result<T, ApiError> {
    debug!("Deserializing JSON content (len={})", content.len());
    Ok(serde_json::from_str(content)
        .inspect_err(|e| error!("JSON deserialization failed: {}", e))?)
}
//----------------------
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
/// the token maybe Uuid or CSRPNG hashed
pub fn create_redis_key(token_type: TokenType, token: &str) -> String {
    format!("{}:{}", token_type, token)
}

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
