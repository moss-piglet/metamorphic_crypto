defmodule MetamorphicCrypto.Hybrid do
  @moduledoc """
  ML-KEM + X25519 hybrid post-quantum encryption.

  Provides quantum-resistant key encapsulation by combining:

  - **ML-KEM** (NIST FIPS 203) — lattice-based post-quantum KEM
  - **X25519** — classical elliptic-curve Diffie-Hellman

  ## Security Levels

  | Level | ML-KEM | NIST Category | Equivalent | Version Tag |
  |-------|--------|---------------|------------|-------------|
  | Cat-3 | 768    | 3             | ~AES-192   | `0x02`      |
  | Cat-5 | 1024   | 5             | ~AES-256   | `0x03`      |

  ## Ciphertext formats

      v2 (Cat-3): 0x02 || ML-KEM-768 ct (1088 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct
      v3 (Cat-5): 0x03 || ML-KEM-1024 ct (1568 B) || X25519 eph pk (32 B) || nonce (24 B) || secretbox ct

  ## Key sizes

  | Component | Cat-3 | Cat-5 |
  |-----------|-------|-------|
  | Public key | 1216 bytes | 1600 bytes |
  | Secret key (seed) | 32 bytes | 32 bytes |

  ## Usage

      # Cat-3 (default)
      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("quantum-safe secret", pk)
      {:ok, "quantum-safe secret"} = MetamorphicCrypto.Hybrid.open(ct, sk)

      # Cat-5 (ML-KEM-1024, highest security)
      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair_1024()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal_1024("top secret", pk)
      {:ok, "top secret"} = MetamorphicCrypto.Hybrid.open(ct, sk)

  """

  alias MetamorphicCrypto.Native

  # ─── Cat-3 (ML-KEM-768, default) ─────────────────────────────────────────────

  @doc """
  Generate a hybrid ML-KEM-768 + X25519 keypair (Cat-3, default).

  Returns `{public_key_b64, secret_key_b64}`.

  The public key is 1216 bytes (base64-encoded). The secret key is a 32-byte seed.

  ## Example

      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair()

  """
  @spec generate_keypair() :: {String.t(), String.t()}
  def generate_keypair do
    Native.nif_generate_hybrid_keypair()
  end

  @doc """
  Seal a UTF-8 plaintext string using Cat-3 hybrid post-quantum encryption (ML-KEM-768).

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Example

      {pk, _sk} = MetamorphicCrypto.Hybrid.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("secret data", pk)

  """
  @spec seal(plaintext :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal(plaintext, public_key_b64) when is_binary(plaintext) do
    plaintext_b64 = Base.encode64(plaintext)
    seal_raw(plaintext_b64, public_key_b64)
  end

  @doc """
  Seal raw bytes (as base64) using Cat-3 hybrid post-quantum encryption.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec seal_raw(plaintext_b64 :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_raw(plaintext_b64, public_key_b64) do
    case Native.nif_hybrid_seal(plaintext_b64, public_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  # ─── Cat-5 (ML-KEM-1024) ────────────────────────────────────────────────────

  @doc """
  Generate a hybrid ML-KEM-1024 + X25519 keypair (Cat-5, highest security).

  Returns `{public_key_b64, secret_key_b64}`.

  The public key is 1600 bytes (base64-encoded). The secret key is a 32-byte seed.

  ## Example

      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair_1024()

  """
  @spec generate_keypair_1024() :: {String.t(), String.t()}
  def generate_keypair_1024 do
    Native.nif_generate_hybrid_keypair_1024()
  end

  @doc """
  Seal a UTF-8 plaintext string using Cat-5 hybrid post-quantum encryption (ML-KEM-1024).

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Example

      {pk, _sk} = MetamorphicCrypto.Hybrid.generate_keypair_1024()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal_1024("top secret", pk)

  """
  @spec seal_1024(plaintext :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_1024(plaintext, public_key_b64) when is_binary(plaintext) do
    plaintext_b64 = Base.encode64(plaintext)
    seal_raw_1024(plaintext_b64, public_key_b64)
  end

  @doc """
  Seal raw bytes (as base64) using Cat-5 hybrid post-quantum encryption.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec seal_raw_1024(plaintext_b64 :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_raw_1024(plaintext_b64, public_key_b64) do
    case Native.nif_hybrid_seal_1024(plaintext_b64, public_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  # ─── Open (auto-detects Cat-3 or Cat-5) ─────────────────────────────────────

  @doc """
  Open a hybrid-sealed ciphertext, returning the decrypted UTF-8 string.

  Automatically detects whether the ciphertext is Cat-3 (v2) or Cat-5 (v3)
  based on the version tag byte.

  Returns `{:ok, plaintext}` or `{:error, reason}`.

  ## Example

      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("hello PQ", pk)
      {:ok, "hello PQ"} = MetamorphicCrypto.Hybrid.open(ct, sk)

  """
  @spec open(ciphertext_b64 :: String.t(), secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def open(ciphertext_b64, secret_key_b64) do
    case open_raw(ciphertext_b64, secret_key_b64) do
      {:ok, plaintext_b64} -> {:ok, Base.decode64!(plaintext_b64)}
      error -> error
    end
  end

  @doc """
  Open a hybrid-sealed ciphertext, returning plaintext as base64.

  Automatically detects Cat-3 or Cat-5 from the version tag.

  Returns `{:ok, plaintext_b64}` or `{:error, reason}`.
  """
  @spec open_raw(ciphertext_b64 :: String.t(), secret_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def open_raw(ciphertext_b64, secret_key_b64) do
    case Native.nif_hybrid_open(ciphertext_b64, secret_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  # ─── Utility ─────────────────────────────────────────────────────────────────

  @doc """
  Check if a base64 ciphertext uses the hybrid format (v2 Cat-3 or v3 Cat-5).

  ## Example

      MetamorphicCrypto.Hybrid.hybrid_ciphertext?(ciphertext)
      #=> true

  """
  @spec hybrid_ciphertext?(ciphertext_b64 :: String.t()) :: boolean()
  def hybrid_ciphertext?(ciphertext_b64) do
    Native.nif_is_hybrid_ciphertext(ciphertext_b64)
  end
end
