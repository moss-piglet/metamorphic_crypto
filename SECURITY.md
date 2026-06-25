# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this package, **do not open a public issue**.

Please report it privately via one of:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/moss-piglet/metamorphic_crypto/security/advisories/new)
- **Email**: security@metamorphic.app

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This policy covers the `metamorphic_crypto` Hex package, including:

- The Elixir API (`MetamorphicCrypto.*`)
- The Rust NIF (`native/metamorphic_crypto_nif`) and its bindings
- Precompiled NIF distribution and checksum verification

The underlying cryptography lives in the [`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto)
Rust crate; vulnerabilities in the cryptographic primitives themselves should be
reported there.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Security Design

- Cryptography delegated to the `metamorphic-crypto` crate (`#![forbid(unsafe_code)]`),
  built on the audited [RustCrypto](https://github.com/RustCrypto) project
- ML-KEM-512/768/1024 post-quantum hybrid KEM (FIPS 203)
- Precompiled NIFs are distributed via GitHub Releases and verified at fetch
  time by `rustler_precompiled` against the committed `checksum-*.exs` (SHA-256)
- Release artifacts carry GitHub build-provenance attestations
- CI gates every change on `cargo audit` (RustSec advisories), `clippy -D warnings`,
  and the full Elixir test suite across supported OTP/Elixir versions
