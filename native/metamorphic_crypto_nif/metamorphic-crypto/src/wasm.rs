//! WASM bindings via `wasm-bindgen`.
//!
//! Exposes the same async-style API that `assets/js/crypto/nacl.js` provides,
//! so existing hooks can call into the WASM module as a drop-in replacement.
//!
//! Every function accepts and returns base64 strings (matching the JS convention).
//! Errors are returned as JavaScript exceptions via `JsValue`.

use wasm_bindgen::prelude::*;

use crate::{b64, box_seal, hybrid, kdf, keys, recovery, seal, secretbox};

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derive a 32-byte session key from password + base64-encoded salt.
/// Returns base64-encoded key.
#[wasm_bindgen(js_name = "deriveSessionKey")]
pub fn derive_session_key(password: &str, salt_b64: &str) -> Result<String, JsValue> {
    kdf::derive_session_key(password, salt_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Secretbox (symmetric encryption)
// ---------------------------------------------------------------------------

/// Encrypt a UTF-8 string with a base64 key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptSecretboxString")]
pub fn encrypt_secretbox_string(plaintext: &str, key_b64: &str) -> Result<String, JsValue> {
    secretbox::encrypt_secretbox_string(plaintext, key_b64).map_err(to_js)
}

/// Decrypt base64 ciphertext to a UTF-8 string.
#[wasm_bindgen(js_name = "decryptSecretboxToString")]
pub fn decrypt_secretbox_to_string(ciphertext_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    secretbox::decrypt_secretbox_to_string(ciphertext_b64, key_b64).map_err(to_js)
}

/// Encrypt raw bytes (as base64) with a base64 key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptSecretbox")]
pub fn encrypt_secretbox(plaintext_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    secretbox::encrypt_secretbox(&pt, key_b64).map_err(to_js)
}

/// Decrypt base64 ciphertext, returning plaintext as base64.
#[wasm_bindgen(js_name = "decryptSecretbox")]
pub fn decrypt_secretbox(ciphertext_b64: &str, key_b64: &str) -> Result<String, JsValue> {
    let pt = secretbox::decrypt_secretbox(ciphertext_b64, key_b64).map_err(to_js)?;
    Ok(b64::encode(&pt))
}

// ---------------------------------------------------------------------------
// Box seal (anonymous public-key encryption)
// ---------------------------------------------------------------------------

/// Seal plaintext (base64) to a recipient's public key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "boxSeal")]
pub fn box_seal_wasm(plaintext_b64: &str, public_key_b64: &str) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    box_seal::box_seal(&pt, public_key_b64).map_err(to_js)
}

/// Open a sealed box. Returns base64-encoded plaintext.
#[wasm_bindgen(js_name = "boxSealOpen")]
pub fn box_seal_open(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
) -> Result<String, JsValue> {
    box_seal::box_seal_open(ciphertext_b64, public_key_b64, private_key_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Unified seal/unseal (auto-detects hybrid vs legacy)
// ---------------------------------------------------------------------------

/// Seal plaintext bytes (base64) to a user's key(s). Uses hybrid PQ if pq_pk is provided.
#[wasm_bindgen(js_name = "sealForUser")]
pub fn seal_for_user(
    plaintext_b64: &str,
    public_key_b64: &str,
    pq_public_key_b64: Option<String>,
) -> Result<String, JsValue> {
    let pt = b64::decode(plaintext_b64).map_err(to_js)?;
    seal::seal_for_user(&pt, public_key_b64, pq_public_key_b64.as_deref()).map_err(to_js)
}

/// Unseal ciphertext using the user's keys. Auto-detects format.
/// Returns base64-encoded plaintext.
#[wasm_bindgen(js_name = "unsealFromUser")]
pub fn unseal_from_user(
    ciphertext_b64: &str,
    public_key_b64: &str,
    private_key_b64: &str,
    pq_secret_key_b64: Option<String>,
) -> Result<String, JsValue> {
    seal::unseal_from_user(
        ciphertext_b64,
        public_key_b64,
        private_key_b64,
        pq_secret_key_b64.as_deref(),
    )
    .map_err(to_js)
}

// ---------------------------------------------------------------------------
// Hybrid PQ KEM
// ---------------------------------------------------------------------------

/// Generate a ML-KEM-768 keypair. Returns JSON: `{ publicKey, secretKey }`.
#[wasm_bindgen(js_name = "generateHybridKeyPair")]
pub fn generate_hybrid_keypair() -> JsValue {
    let kp = hybrid::generate_hybrid_keypair();
    // Return as a plain JS object
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.into()).unwrap();
    js_sys::Reflect::set(&obj, &"secretKey".into(), &kp.secret_key.into()).unwrap();
    obj.into()
}

/// Check if a base64 ciphertext is hybrid (v2) format.
#[wasm_bindgen(js_name = "isHybridCiphertext")]
pub fn is_hybrid_ciphertext(ciphertext_b64: &str) -> bool {
    hybrid::is_hybrid_ciphertext(ciphertext_b64)
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a random 32-byte symmetric key (base64).
#[wasm_bindgen(js_name = "generateKey")]
pub fn generate_key() -> String {
    keys::generate_key()
}

/// Generate a random X25519 keypair. Returns JSON: `{ publicKey, privateKey }`.
#[wasm_bindgen(js_name = "generateKeyPair")]
pub fn generate_keypair() -> JsValue {
    let kp = keys::generate_keypair();
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"publicKey".into(), &kp.public_key.into()).unwrap();
    js_sys::Reflect::set(&obj, &"privateKey".into(), &kp.private_key.into()).unwrap();
    obj.into()
}

/// Generate a random 16-byte salt (base64).
#[wasm_bindgen(js_name = "generateSalt")]
pub fn generate_salt() -> String {
    keys::generate_salt()
}

// ---------------------------------------------------------------------------
// Private key encrypt/decrypt
// ---------------------------------------------------------------------------

/// Encrypt a base64 private key with a session key. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptPrivateKey")]
pub fn encrypt_private_key(
    private_key_b64: &str,
    session_key_b64: &str,
) -> Result<String, JsValue> {
    keys::encrypt_private_key(private_key_b64, session_key_b64).map_err(to_js)
}

/// Decrypt an encrypted private key with a session key. Returns base64 private key.
#[wasm_bindgen(js_name = "decryptPrivateKey")]
pub fn decrypt_private_key(ciphertext_b64: &str, session_key_b64: &str) -> Result<String, JsValue> {
    keys::decrypt_private_key(ciphertext_b64, session_key_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Recovery key
// ---------------------------------------------------------------------------

/// Generate a recovery key. Returns JSON: `{ recoveryKey, recoverySecretBase64 }`.
#[wasm_bindgen(js_name = "generateRecoveryKey")]
pub fn generate_recovery_key() -> Result<JsValue, JsValue> {
    let rk = recovery::generate_recovery_key().map_err(to_js)?;
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"recoveryKey".into(), &rk.recovery_key.into()).unwrap();
    js_sys::Reflect::set(
        &obj,
        &"recoverySecretBase64".into(),
        &rk.recovery_secret_b64.into(),
    )
    .unwrap();
    Ok(obj.into())
}

/// Derive the 32-byte secret (base64) from a human-readable recovery key.
#[wasm_bindgen(js_name = "recoveryKeyToSecret")]
pub fn recovery_key_to_secret(recovery_key: &str) -> Result<String, JsValue> {
    recovery::recovery_key_to_secret(recovery_key).map_err(to_js)
}

/// Encrypt private key for recovery backup. Returns base64 ciphertext.
#[wasm_bindgen(js_name = "encryptPrivateKeyForRecovery")]
pub fn encrypt_private_key_for_recovery(
    private_key_b64: &str,
    recovery_secret_b64: &str,
) -> Result<String, JsValue> {
    recovery::encrypt_private_key_for_recovery(private_key_b64, recovery_secret_b64).map_err(to_js)
}

/// Decrypt private key from recovery backup. Returns base64 private key.
#[wasm_bindgen(js_name = "decryptPrivateKeyWithRecovery")]
pub fn decrypt_private_key_with_recovery(
    ciphertext_b64: &str,
    recovery_secret_b64: &str,
) -> Result<String, JsValue> {
    recovery::decrypt_private_key_with_recovery(ciphertext_b64, recovery_secret_b64).map_err(to_js)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Parse the salt (base64) from a key_hash string (`salt$argon2id`).
#[wasm_bindgen(js_name = "parseSaltFromKeyHash")]
pub fn parse_salt_from_key_hash(key_hash: &str) -> Result<String, JsValue> {
    b64::parse_salt_from_key_hash(key_hash)
        .map(|s| s.to_string())
        .map_err(to_js)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a CryptoError into a JsValue (thrown as a JS Error).
fn to_js(e: crate::CryptoError) -> JsValue {
    JsValue::from_str(&e.to_string())
}
