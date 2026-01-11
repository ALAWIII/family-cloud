use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{TryRngCore, rngs::OsRng as RandOsRng};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

//----------------------------------------------tokens generating, securing and encoding/decoding
/// accepts number of bytes , len=32 , bits = len*8 = 256-bit token
pub fn generate_token_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    RandOsRng.try_fill_bytes(&mut buf).unwrap(); // trait method
    buf
}

/// URL-safe base64 encode token for transport (cookies, links, headers) to alphenumeric text.
pub fn encode_token(token: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(token)
}

/// Decode token from URL-safe base64 (incoming from client) to array of bytes.
pub fn decode_token(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(encoded)
}

/// accepts a token bytes and a global secret  to create a strong hashed token
///
/// the hashed token used to be stored in redis database for account verfication and authentication purposes
pub fn hmac_token_hex(token: &[u8], secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC can take secret of any length (panic only on zero-length)");
    mac.update(token);
    let tag = mac.finalize().into_bytes();
    hex::encode(tag) // encodes data to hex strings with lowercase chars
}
pub fn hash_token(token: &[u8]) -> String {
    let secret = std::env::var("HMAC_SECRET").expect("Failed to load hmac secret");
    hmac_token_hex(token, secret.as_bytes())
}

//------------------------------- user password hashing -------------------
/// accepts a secured password as secret of string and produce a one way hashed and salted using argon2id
pub fn hash_password(password: &SecretBox<String>) -> Result<String, argon2::password_hash::Error> {
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
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?; //fails parsing the password into a good formant (corrupted password format)
    let argon = Argon2::default();
    Ok(argon
        .verify_password(password.expose_secret().as_bytes(), &parsed_hash)
        .is_ok())
}
