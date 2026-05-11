defmodule MetamorphicCrypto.Hybrid do
  @moduledoc """
  ML-KEM-768 + X25519 hybrid post-quantum encryption.

  Provides quantum-resistant key encapsulation by combining:

  - **ML-KEM-768** (NIST FIPS 203) — lattice-based post-quantum KEM
  - **X25519** — classical elliptic-curve Diffie-Hellman

  The shared secrets from both KEMs are combined via SHA3-256 to derive the
  final symmetric key, which encrypts the payload with XSalsa20-Poly1305.

  ## Ciphertext format (v2)

      0x02 || ML-KEM-768 ciphertext (1088 bytes) || X25519 ephemeral pk (32 bytes) || nonce (24 bytes) || secretbox ciphertext

  ## Key sizes

  - Public key: 1216 bytes (ML-KEM ek 1184 + X25519 pk 32)
  - Secret key: 32 bytes (root seed, expanded via SHAKE256)

  ## Usage

      {pk, sk} = MetamorphicCrypto.Hybrid.generate_keypair()

      {:ok, ct} = MetamorphicCrypto.Hybrid.seal("quantum-safe secret", pk)
      {:ok, "quantum-safe secret"} = MetamorphicCrypto.Hybrid.open(ct, sk)

  """

  alias MetamorphicCrypto.Native

  @doc """
  Generate a hybrid ML-KEM-768 + X25519 keypair.

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
  Seal a UTF-8 plaintext string using hybrid post-quantum encryption.

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
  Seal raw bytes (as base64) using hybrid post-quantum encryption.

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

  @doc """
  Open a hybrid-sealed ciphertext, returning the decrypted UTF-8 string.

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

  @doc """
  Check if a base64 ciphertext uses the hybrid v2 format.

  ## Example

      MetamorphicCrypto.Hybrid.hybrid_ciphertext?(ciphertext)
      #=> true

  """
  @spec hybrid_ciphertext?(ciphertext_b64 :: String.t()) :: boolean()
  def hybrid_ciphertext?(ciphertext_b64) do
    Native.nif_is_hybrid_ciphertext(ciphertext_b64)
  end
end
