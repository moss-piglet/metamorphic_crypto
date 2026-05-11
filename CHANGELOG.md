# Changelog

## v0.1.0 (2025-XX-XX)

- Initial release
- XSalsa20-Poly1305 symmetric encryption (`MetamorphicCrypto.SecretBox`)
- X25519 sealed box public-key encryption (`MetamorphicCrypto.BoxSeal`)
- ML-KEM-768 + X25519 hybrid post-quantum encryption (`MetamorphicCrypto.Hybrid`)
- Unified seal/unseal with auto-format-detection (`MetamorphicCrypto.Seal`)
- Argon2id key derivation (`MetamorphicCrypto.KDF`)
- Key generation utilities (`MetamorphicCrypto.Keys`)
- Human-readable recovery keys (`MetamorphicCrypto.Recovery`)
- Precompiled NIF binaries for all major platforms
