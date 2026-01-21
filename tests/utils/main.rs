use secrecy::SecretBox;

use family_cloud::{
    decode_token, encode_token, generate_token_bytes, hash_password, hmac_token_hex,
    verify_password,
};

#[test]
fn generate_token_test() {
    let token = generate_token_bytes(32).unwrap();
    assert_eq!(token.len(), 32);
}
#[test]
fn encode_decode_token() {
    let token = generate_token_bytes(32).unwrap();
    let encoded = encode_token(&token);
    let decoded = decode_token(&encoded);
    assert!(!encoded.is_empty());
    assert!(decoded.is_ok());
    assert_eq!(decoded.unwrap(), token);
}

#[test]
fn test_hmac_deterministic() {
    let token = b"my_test_token";
    let secret = b"my_secret_key";

    let hash1 = hmac_token_hex(token, secret).unwrap();
    let hash2 = hmac_token_hex(token, secret).unwrap();

    // Same input must produce same output
    assert_eq!(hash1, hash2);
}

#[test]
fn test_hmac_different_tokens_different_hashes() {
    let secret = b"my_secret_key";

    let hash1 = hmac_token_hex(b"token1", secret).unwrap();
    let hash2 = hmac_token_hex(b"token2", secret).unwrap();

    // Different tokens produce different hashes
    assert_ne!(hash1, hash2);
}

#[test]
fn test_hmac_different_secrets_different_hashes() {
    let token = b"my_token";

    let hash1 = hmac_token_hex(token, b"secret1").unwrap();
    let hash2 = hmac_token_hex(token, b"secret2").unwrap();

    // Different secrets produce different hashes
    assert_ne!(hash1, hash2);
}

#[test]
fn test_hmac_known_vector() {
    // RFC 4231 test vector
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";

    let result = hmac_token_hex(data, key).unwrap();

    // Expected HMAC-SHA256 output for this input
    assert_eq!(
        result,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn test_hmac_output_length() {
    let hash = hmac_token_hex(b"any_token", b"any_secret").unwrap();

    // SHA-256 produces 64 hex characters (32 bytes)
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_hash_password() {
    let passwd = SecretBox::new(Box::new("dragon".to_string()));
    let hashed = hash_password(&passwd);
    assert!(hashed.is_ok());
    let v = verify_password(&passwd, &hashed.unwrap());
    assert!(v.is_ok());
    assert!(v.unwrap());
}
