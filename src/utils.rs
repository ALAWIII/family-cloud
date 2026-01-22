use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::Json;
use axum_extra::extract::CookieJar;
use jsonwebtoken::{EncodingKey, Header, encode};
use secrecy::{ExposeSecret, SecretBox};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use hmac::{Hmac, Mac};
use rand::{TryRngCore, rngs::OsRng as RandOsRng};
use serde::{Serialize, de::DeserializeOwned};
use sha2::Sha256;

use crate::{ApiError, Claims, CryptoError, TokenPayload, TokenType, UserTokenPayload};
type HmacSha256 = Hmac<Sha256>;

//----------------------------------------------tokens generating, securing and encoding/decoding
/// accepts number of bytes , len=32 , bits = len*8 = 256-bit token
pub fn generate_token_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; len];
    // CryptoError::RngFailed
    RandOsRng.try_fill_bytes(&mut buf)?; // trait method
    Ok(buf)
}

/// URL-safe base64 encode token for transport (cookies, links, headers) to alphenumeric text.
pub fn encode_token(token: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(token)
}

/// Decode token from URL-safe base64 (incoming from client) to array of bytes.
pub fn decode_token(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    //CryptoError::TokenDecode
    Ok(URL_SAFE_NO_PAD.decode(encoded)?)
}

/// accepts a token bytes and a global secret  to create a strong hashed token
///
/// the hashed token used to be stored in redis database for account verfication and authentication purposes
pub fn hmac_token_hex(token: &[u8], secret: &[u8]) -> Result<String, CryptoError> {
    //Hmac Invalid length
    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(token);
    let tag = mac.finalize().into_bytes();
    Ok(hex::encode(tag)) // encodes data to hex strings with lowercase chars
}
/// accepts a decoded token as bytes and returns a hashed version of it.
pub fn hash_token(token: &[u8]) -> Result<String, CryptoError> {
    let secret = std::env::var("HMAC_SECRET").expect("Failed to load hmac secret");
    hmac_token_hex(token, secret.as_bytes())
}
//------------------------------- generating access token--------------------------

/// creating JWT access token
pub fn create_access_token(
    user: &UserTokenPayload,
    seconds: i64,
    secret_key: SecretBox<String>,
) -> Result<String, CryptoError> {
    let claims = Claims::new(user.id, user.username.to_string()).with_expiry(seconds);
    //CryptoError::JwtEncode
    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret_key.expose_secret().as_bytes()),
    )?)
}

//------------------------------- user password hashing -------------------
/// accepts a secured password as secret of string and produce a one way hashed and salted using argon2id
pub fn hash_password(password: &SecretBox<String>) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = argon2::Argon2::default();
    let password_hash = argon
        .hash_password(password.expose_secret().as_bytes(), &salt)?
        .to_string();
    Ok(password_hash)
}

/// accepts a raw password from user , and a hashed version of the password (mainly retrived from database)
pub fn verify_password(
    password: &SecretBox<String>,
    password_hash: &str,
) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(password_hash)?; //fails parsing the password into a good formant (corrupted password format)
    let argon = Argon2::default();

    match argon.verify_password(password.expose_secret().as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),                                       // Match
        Err(argon2::password_hash::Error::Password) => Ok(false), // No match
        Err(e) => Err(CryptoError::PasswordHash(e)),              // INTERNAL_Error 500
    }
}

//-----------------------

pub fn serialize_content(content: &impl Serialize) -> Result<String, ApiError> {
    Ok(serde_json::to_string(content)?)
}
pub fn deserialize_content<T: DeserializeOwned>(content: &str) -> Result<T, ApiError> {
    Ok(serde_json::from_str(content)?)
}
//----------------------
pub fn extract_refresh_token(
    cookie_jar: &CookieJar,
    body: Option<Json<TokenPayload>>,
) -> Result<SecretBox<String>, ApiError> {
    cookie_jar
        .get("token")
        .map(|cookie| SecretBox::new(Box::new(cookie.value().into())))
        .or_else(|| body.map(|t| t.0.token))
        .ok_or(ApiError::Unauthorized)
}
//------------------------
pub fn create_verification_key(token_type: TokenType, hashed_token: &str) -> String {
    format!("{}:{}", token_type, hashed_token)
}
