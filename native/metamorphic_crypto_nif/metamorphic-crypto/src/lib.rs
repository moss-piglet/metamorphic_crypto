//! # metamorphic-crypto
//!
//! Zero-knowledge end-to-end encryption core for the Metamorphic platform.
//!
//! This library implements the cryptographic operations required by all Metamorphic
//! clients (web/WASM, iOS/UniFFI, Android/UniFFI). It produces byte-compatible
//! ciphertext with the existing JavaScript implementation so that data encrypted
//! by one client can be decrypted by any other.
//!
//! ## Security guarantees
//!
//! - All secret key material is [`Zeroize`]-on-drop
//! - No `unsafe` code
//! - Constant-time comparisons via the underlying RustCrypto crates
//! - Randomness sourced directly from the OS CSPRNG ([`getrandom`])
//!
//! ## Ciphertext formats
//!
//! | Format | Layout |
//! |--------|--------|
//! | Secretbox | `nonce (24B) \|\| ciphertext (len + 16B MAC)` |
//! | box_seal | `ephemeral_pk (32B) \|\| box ciphertext` |
//! | Hybrid v2 | `0x02 \|\| ML-KEM-768 ct (1088B) \|\| nonce (24B) \|\| secretbox ct` |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod b64;
pub mod box_seal;
pub mod error;
pub mod hybrid;
pub mod kdf;
pub mod keys;
pub mod recovery;
pub mod seal;
pub mod secretbox;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::CryptoError;

// Re-export the primary public API
pub use b64::parse_salt_from_key_hash;
pub use box_seal::{box_seal, box_seal_open};
pub use hybrid::{
    HybridKeyPair, generate_hybrid_keypair, hybrid_open, hybrid_seal, is_hybrid_ciphertext,
};
pub use kdf::derive_session_key;
pub use keys::{
    KeyPair, decrypt_private_key, encrypt_private_key, generate_key, generate_keypair,
    generate_salt,
};
pub use recovery::{
    RecoveryKey, decrypt_private_key_with_recovery, encrypt_private_key_for_recovery,
    generate_recovery_key, recovery_key_to_secret,
};
pub use seal::{seal_for_user, unseal_from_user};
pub use secretbox::{
    decrypt_secretbox, decrypt_secretbox_to_string, encrypt_secretbox, encrypt_secretbox_string,
};
