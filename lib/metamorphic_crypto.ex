defmodule MetamorphicCrypto do
  @moduledoc """
  NaCl-compatible encryption for Elixir with post-quantum support.

  `MetamorphicCrypto` provides NaCl-compatible cryptographic primitives powered
  by Rust NIFs with precompiled binaries — no Rust toolchain, no C compiler,
  no system packages required.

  ## Quick Start

      # Generate keys
      key = MetamorphicCrypto.generate_key()
      {public_key, private_key} = MetamorphicCrypto.generate_keypair()

      # Symmetric encryption (XSalsa20-Poly1305)
      {:ok, ciphertext} = MetamorphicCrypto.encrypt("hello", key)
      {:ok, "hello"} = MetamorphicCrypto.decrypt(ciphertext, key)

      # Public-key encryption (X25519 sealed box)
      {:ok, sealed} = MetamorphicCrypto.seal("secret", public_key)
      {:ok, "secret"} = MetamorphicCrypto.unseal(sealed, public_key, private_key)

  ## Modules

  For full control, use the specialized modules directly:

  - `MetamorphicCrypto.SecretBox` — symmetric encryption
  - `MetamorphicCrypto.BoxSeal` — public-key encryption
  - `MetamorphicCrypto.Hybrid` — ML-KEM (512/768/1024) + X25519 post-quantum
  - `MetamorphicCrypto.Seal` — unified seal/unseal (auto-detects format)
  - `MetamorphicCrypto.KDF` — Argon2id key derivation
  - `MetamorphicCrypto.Keys` — key generation and management
  - `MetamorphicCrypto.Hash` — SHA3/SHA2 hashing for public data (fingerprints, safety numbers)
  - `MetamorphicCrypto.Mac` — HMAC-SHA256 keyed message authentication (RFC 2104)
  - `MetamorphicCrypto.Sign` — hybrid ML-DSA + Ed25519 post-quantum signatures
  - `MetamorphicCrypto.Vrf` — ECVRF-Edwards25519-SHA512-TAI verifiable random function (RFC 9381)
  - `MetamorphicCrypto.VrfP256` — ECVRF-P256-SHA256-TAI verifiable random function (RFC 9381)
  - `MetamorphicCrypto.Recovery` — human-readable recovery keys

  ## Wire Format

  All functions accept and return base64-encoded strings. Ciphertext produced
  by this library is byte-compatible with libsodium/NaCl and the
  `metamorphic-crypto` WASM module used in browser clients.
  """

  alias MetamorphicCrypto.{BoxSeal, Hash, Keys, SecretBox, Sign}

  # ─── Convenience API ──────────────────────────────────────────────────────

  @doc """
  Generate a random 32-byte symmetric key (base64-encoded).

  ## Example

      key = MetamorphicCrypto.generate_key()

  """
  @spec generate_key() :: String.t()
  defdelegate generate_key, to: Keys

  @doc """
  Generate an X25519 keypair.

  Returns `{public_key, private_key}` as base64-encoded strings.

  ## Example

      {public_key, private_key} = MetamorphicCrypto.generate_keypair()

  """
  @spec generate_keypair() :: {String.t(), String.t()}
  defdelegate generate_keypair, to: Keys

  @doc """
  Encrypt a UTF-8 string with a symmetric key.

  Uses XSalsa20-Poly1305 (NaCl secretbox). Returns base64-encoded ciphertext.

  ## Example

      key = MetamorphicCrypto.generate_key()
      {:ok, ciphertext} = MetamorphicCrypto.encrypt("hello, world!", key)

  """
  @spec encrypt(plaintext :: String.t(), key :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encrypt(plaintext, key) when is_binary(plaintext) and is_binary(key) do
    SecretBox.encrypt_string(plaintext, key)
  end

  @doc """
  Decrypt a ciphertext back to a UTF-8 string.

  ## Example

      {:ok, "hello, world!"} = MetamorphicCrypto.decrypt(ciphertext, key)

  """
  @spec decrypt(ciphertext :: String.t(), key :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(ciphertext, key) when is_binary(ciphertext) and is_binary(key) do
    SecretBox.decrypt_string(ciphertext, key)
  end

  @doc """
  Encrypt a UTF-8 string to a recipient's public key (anonymous sealed box).

  The sender remains anonymous — only the recipient can decrypt.

  ## Example

      {public_key, _private_key} = MetamorphicCrypto.generate_keypair()
      {:ok, sealed} = MetamorphicCrypto.seal("secret message", public_key)

  """
  @spec seal(plaintext :: String.t(), public_key :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal(plaintext, public_key) when is_binary(plaintext) and is_binary(public_key) do
    BoxSeal.seal(plaintext, public_key)
  end

  @doc """
  Decrypt a sealed box using the recipient's keypair.

  ## Example

      {public_key, private_key} = MetamorphicCrypto.generate_keypair()
      {:ok, sealed} = MetamorphicCrypto.seal("secret", public_key)
      {:ok, "secret"} = MetamorphicCrypto.unseal(sealed, public_key, private_key)

  """
  @spec unseal(ciphertext :: String.t(), public_key :: String.t(), private_key :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def unseal(ciphertext, public_key, private_key)
      when is_binary(ciphertext) and is_binary(public_key) and is_binary(private_key) do
    BoxSeal.open(ciphertext, public_key, private_key)
  end

  @doc """
  SHA3-512 of base64-encoded data (base64 digest out).

  General-purpose digest for **public** data. For key fingerprints, safety
  numbers, and key-transparency-log entries, prefer `sha3_512_with_context/2`.
  See `MetamorphicCrypto.Hash` for the full menu and the "public data only"
  security note.

  ## Example

      {:ok, digest} = MetamorphicCrypto.sha3_512(Base.encode64("abc"))

  """
  @spec sha3_512(data_b64 :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  defdelegate sha3_512(data_b64), to: Hash

  @doc """
  Domain-separated SHA3-512 — recommended for key fingerprints, safety numbers,
  and key-transparency-log entries.

  `context` is a versioned UTF-8 label (e.g. `"mosslet/key-fingerprint/v1"`);
  `data_b64` is the base64-encoded payload. See `MetamorphicCrypto.Hash`.

  ## Example

      {:ok, fp} =
        MetamorphicCrypto.sha3_512_with_context(
          "mosslet/key-fingerprint/v1",
          Base.encode64("public key bytes")
        )

  """
  @spec sha3_512_with_context(context :: String.t(), data_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defdelegate sha3_512_with_context(context, data_b64), to: Hash

  @doc """
  Generate a hybrid ML-DSA + Ed25519 signing keypair (Cat-3 / ML-DSA-65 default).

  Returns `%{public_key: base64, secret_key: base64}`. See
  `MetamorphicCrypto.Sign` for security levels, the wire format, and the recovery
  hook.

  ## Example

      kp = MetamorphicCrypto.generate_signing_keypair()
      kp = MetamorphicCrypto.generate_signing_keypair(:cat5)

  """
  @spec generate_signing_keypair(Sign.level()) :: Sign.keypair()
  defdelegate generate_signing_keypair(level \\ :cat3), to: Sign

  @doc """
  Re-derive the base64 public key from a base64 hybrid signing secret key.

  Deterministic — reproduces the keypair's `public_key` exactly, which is what
  makes recovery-based key regeneration byte-identical. See
  `MetamorphicCrypto.Sign`.
  """
  @spec derive_public_key(secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defdelegate derive_public_key(secret_key_b64), to: Sign

  @doc """
  Sign a `message` binary under a UTF-8 `context` with a base64 hybrid
  `secret_key`.

  Returns `{:ok, signature_b64}`. ML-DSA signing is randomized, so signatures are
  non-reproducible (but verify). See `MetamorphicCrypto.Sign`.

  ## Example

      {:ok, sig} =
        MetamorphicCrypto.sign("log entry", "metamorphic/sign/v1", kp.secret_key)

  """
  @spec sign(message :: binary(), context :: String.t(), secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  defdelegate sign(message, context, secret_key_b64), to: Sign

  @doc """
  Verify a composite `signature` over `message` / `context` against `public_key`.

  Returns `true` only if **both** the Ed25519 and ML-DSA components verify
  (strict AND); `false` otherwise (including malformed input). See
  `MetamorphicCrypto.Sign`.

  ## Example

      true = MetamorphicCrypto.verify("log entry", "metamorphic/sign/v1", sig, kp.public_key)

  """
  @spec verify(
          message :: binary(),
          context :: String.t(),
          signature_b64 :: String.t(),
          public_key_b64 :: String.t()
        ) :: boolean()
  defdelegate verify(message, context, signature_b64, public_key_b64), to: Sign
end
