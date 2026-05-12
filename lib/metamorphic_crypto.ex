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
  - `MetamorphicCrypto.Hybrid` — ML-KEM-768 + X25519 post-quantum
  - `MetamorphicCrypto.Seal` — unified seal/unseal (auto-detects format)
  - `MetamorphicCrypto.KDF` — Argon2id key derivation
  - `MetamorphicCrypto.Keys` — key generation and management
  - `MetamorphicCrypto.Recovery` — human-readable recovery keys

  ## Wire Format

  All functions accept and return base64-encoded strings. Ciphertext produced
  by this library is byte-compatible with libsodium/NaCl and the
  `metamorphic-crypto` WASM module used in browser clients.
  """

  alias MetamorphicCrypto.{BoxSeal, Keys, SecretBox}

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
end
