defmodule MetamorphicCrypto.BoxSeal do
  @moduledoc """
  X25519 anonymous sealed box (public-key encryption).

  Implements the libsodium `crypto_box_seal` / `crypto_box_seal_open` construction:

  1. Generate an ephemeral X25519 keypair
  2. Derive nonce = `BLAKE2b-24(ephemeral_pk || recipient_pk)`
  3. Encrypt with `crypto_box(msg, nonce, recipient_pk, ephemeral_sk)`
  4. Output: `ephemeral_pk (32 bytes) || box ciphertext (len + 16 byte MAC)`

  The sender remains anonymous — only the recipient can decrypt.

  ## Usage

      {pk, sk} = MetamorphicCrypto.Keys.generate_keypair()

      {:ok, sealed} = MetamorphicCrypto.BoxSeal.seal("secret", pk)
      {:ok, "secret"} = MetamorphicCrypto.BoxSeal.open(sealed, pk, sk)

  """

  alias MetamorphicCrypto.Native

  @doc """
  Seal a UTF-8 plaintext string to a recipient's public key.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Example

      {pk, _sk} = MetamorphicCrypto.Keys.generate_keypair()
      {:ok, sealed} = MetamorphicCrypto.BoxSeal.seal("hello", pk)

  """
  @spec seal(plaintext :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal(plaintext, public_key_b64) when is_binary(plaintext) do
    plaintext_b64 = Base.encode64(plaintext)
    seal_raw(plaintext_b64, public_key_b64)
  end

  @doc """
  Seal raw bytes (as base64) to a recipient's public key.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec seal_raw(plaintext_b64 :: String.t(), public_key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def seal_raw(plaintext_b64, public_key_b64) do
    case Native.nif_box_seal(plaintext_b64, public_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Open a sealed box, returning the decrypted UTF-8 string.

  Returns `{:ok, plaintext}` or `{:error, reason}`.

  ## Example

      {pk, sk} = MetamorphicCrypto.Keys.generate_keypair()
      {:ok, sealed} = MetamorphicCrypto.BoxSeal.seal("secret", pk)
      {:ok, "secret"} = MetamorphicCrypto.BoxSeal.open(sealed, pk, sk)

  """
  @spec open(
          ciphertext_b64 :: String.t(),
          public_key_b64 :: String.t(),
          private_key_b64 :: String.t()
        ) ::
          {:ok, String.t()} | {:error, String.t()}
  def open(ciphertext_b64, public_key_b64, private_key_b64) do
    case open_raw(ciphertext_b64, public_key_b64, private_key_b64) do
      {:ok, plaintext_b64} -> {:ok, Base.decode64!(plaintext_b64)}
      error -> error
    end
  end

  @doc """
  Open a sealed box, returning the plaintext as base64.

  Returns `{:ok, plaintext_b64}` or `{:error, reason}`.
  """
  @spec open_raw(
          ciphertext_b64 :: String.t(),
          public_key_b64 :: String.t(),
          private_key_b64 :: String.t()
        ) ::
          {:ok, String.t()} | {:error, String.t()}
  def open_raw(ciphertext_b64, public_key_b64, private_key_b64) do
    case Native.nif_box_seal_open(ciphertext_b64, public_key_b64, private_key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end
end
