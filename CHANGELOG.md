# Changelog

## v0.1.1 (2026-05-12)

- Fix precompiled NIF loading on macOS and Windows
  - Binary inside tar archive was named incorrectly (`libmetamorphic_crypto_nif.dylib`
    instead of the versioned `.so` name that RustlerPrecompiled expects)
  - Users without Rust installed would get `nif_not_loaded` errors

## v0.1.0 (2026-05-11)

- Initial release
- XSalsa20-Poly1305 symmetric encryption (`MetamorphicCrypto.SecretBox`)
- X25519 sealed box public-key encryption (`MetamorphicCrypto.BoxSeal`)
- ML-KEM-768 + X25519 hybrid post-quantum encryption (`MetamorphicCrypto.Hybrid`)
- Unified seal/unseal with auto-format-detection (`MetamorphicCrypto.Seal`)
- Argon2id key derivation (`MetamorphicCrypto.KDF`)
- Key generation utilities (`MetamorphicCrypto.Keys`)
- Human-readable recovery keys (`MetamorphicCrypto.Recovery`)
- Precompiled NIF binaries for all major platforms
