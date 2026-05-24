defmodule MetamorphicCrypto.Seal do
  @moduledoc """
  Unified seal/unseal with automatic format detection.

  This module provides the highest-level encryption API. It automatically
  selects the best available algorithm:

  - If a post-quantum public key is provided, uses **ML-KEM + X25519 hybrid**
  - Otherwise, falls back to **X25519 sealed box** (NaCl-compatible)

  On decryption, the format is auto-detected from the ciphertext header byte,
  so old (legacy) and new (PQ) ciphertexts can coexist seamlessly.

  ## Security Levels

  When sealing with a PQ key, pass `:level` to choose the NIST category:

  - `:cat3` — ML-KEM-768 + X25519 (~AES-192). Default.
  - `:cat5` — ML-KEM-1024 + X25519 (~AES-256).

  Decryption always auto-detects the level from the ciphertext header.

  ## Usage

      # Classical (X25519 only)
      {pk, sk} = MetamorphicCrypto.Keys.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Seal.seal_for_user("data", pk)
      {:ok, "data"} = MetamorphicCrypto.Seal.unseal_from_user(ct, pk, sk)

      # Post-quantum hybrid Cat-3 (default)
      {pq_pk, pq_sk} = MetamorphicCrypto.Hybrid.generate_keypair()
      {:ok, ct} = MetamorphicCrypto.Seal.seal_for_user("data", pk, pq_public_key: pq_pk)
      {:ok, "data"} = MetamorphicCrypto.Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)

      # Post-quantum hybrid Cat-5 (highest security)
      {pq_pk, pq_sk} = MetamorphicCrypto.Hybrid.generate_keypair(:cat5)
      {:ok, ct} = MetamorphicCrypto.Seal.seal_for_user("data", pk, pq_public_key: pq_pk, level: :cat5)
      {:ok, "data"} = MetamorphicCrypto.Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)

  """

  alias MetamorphicCrypto.{BoxSeal, Hybrid, Native}

  @doc """
  Seal plaintext (UTF-8 string) to a user's key(s).

  ## Options

  - `:pq_public_key` — if provided, uses hybrid ML-KEM + X25519 encryption.
    Otherwise uses classical X25519 sealed box.
  - `:level` — `t:MetamorphicCrypto.Hybrid.security_level/0`, either `:cat3`
    (default) or `:cat5`. Only applies when `:pq_public_key` is present.

  ## Examples

      # Classical
      {:ok, ct} = MetamorphicCrypto.Seal.seal_for_user("secret", public_key)

      # Post-quantum Cat-3 (default)
      {:ok, ct} = MetamorphicCrypto.Seal.seal_for_user("secret", public_key, pq_public_key: pq_pk)

      # Post-quantum Cat-5
      {:ok, ct} = MetamorphicCrypto.Seal.seal_for_user("secret", public_key,
        pq_public_key: pq_pk, level: :cat5)

  """
  @spec seal_for_user(plaintext :: String.t(), public_key_b64 :: String.t(), opts :: keyword()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_for_user(plaintext, public_key_b64, opts \\ []) when is_binary(plaintext) do
    plaintext_b64 = Base.encode64(plaintext)
    seal_for_user_raw(plaintext_b64, public_key_b64, opts)
  end

  @doc """
  Seal raw bytes (as base64) to a user's key(s).

  Same as `seal_for_user/3` but accepts pre-encoded base64 plaintext.
  Supports the same options (`:pq_public_key`, `:level`).
  """
  @spec seal_for_user_raw(
          plaintext_b64 :: String.t(),
          public_key_b64 :: String.t(),
          opts :: keyword()
        ) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_for_user_raw(plaintext_b64, public_key_b64, opts \\ []) do
    pq_pk = Keyword.get(opts, :pq_public_key)
    level = Keyword.get(opts, :level, :cat3)

    cond do
      is_nil(pq_pk) or pq_pk == "" ->
        # No PQ key — fall back to classical X25519 sealed box
        BoxSeal.seal_raw(plaintext_b64, public_key_b64)

      level == :cat5 ->
        # Cat-5: use ML-KEM-1024 NIF
        Hybrid.seal_raw(plaintext_b64, pq_pk, :cat5)

      true ->
        # Cat-3 (default): use the existing unified seal NIF
        case Native.nif_seal_for_user(plaintext_b64, public_key_b64, pq_pk) do
          {:error, reason} -> {:error, reason}
          ct -> {:ok, ct}
        end
    end
  end

  @doc """
  Unseal ciphertext using the user's key(s). Auto-detects format.

  ## Options

  - `:pq_secret_key` — the hybrid ML-KEM secret key. Required for decrypting
    hybrid (v2/v3) ciphertexts. Safe to always pass — legacy ciphertexts are
    detected and decrypted with the classical key regardless.

  ## Examples

      # Classical
      {:ok, plaintext} = MetamorphicCrypto.Seal.unseal_from_user(ct, pk, sk)

      # With PQ key available (auto-detects format and level)
      {:ok, plaintext} = MetamorphicCrypto.Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)

  """
  @spec unseal_from_user(
          ciphertext_b64 :: String.t(),
          public_key_b64 :: String.t(),
          private_key_b64 :: String.t(),
          opts :: keyword()
        ) :: {:ok, String.t()} | {:error, String.t()}
  def unseal_from_user(ciphertext_b64, public_key_b64, private_key_b64, opts \\ []) do
    pq_sk = Keyword.get(opts, :pq_secret_key)

    case Native.nif_unseal_from_user(ciphertext_b64, public_key_b64, private_key_b64, pq_sk) do
      {:error, reason} -> {:error, reason}
      plaintext_b64 -> {:ok, Base.decode64!(plaintext_b64)}
    end
  end
end
