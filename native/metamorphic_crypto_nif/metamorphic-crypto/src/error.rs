//! Error types for the crypto library.

use thiserror::Error;

/// All possible errors from cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Base64 decoding failed.
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Decryption failed (wrong key, corrupted ciphertext, or MAC mismatch).
    #[error("decryption failed: invalid ciphertext or wrong key")]
    Decryption,

    /// A key or salt has the wrong byte length.
    #[error("invalid length: expected {expected} bytes, got {got}")]
    InvalidLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        got: usize,
    },

    /// Ciphertext is too short to contain the expected components.
    #[error("ciphertext too short to be valid")]
    TooShort,

    /// The key_hash string is not in the expected `{salt}$argon2id` format.
    #[error("invalid key_hash format (expected `salt$argon2id`)")]
    InvalidKeyHash,

    /// A recovery key contains characters outside the allowed base32 alphabet.
    #[error("invalid recovery key character")]
    InvalidRecoveryKey,

    /// The Argon2id key derivation failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),

    /// An error in the hybrid PQ KEM layer.
    #[error("hybrid KEM: {0}")]
    Hybrid(String),

    /// Decrypted bytes are not valid UTF-8.
    #[error("UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}
