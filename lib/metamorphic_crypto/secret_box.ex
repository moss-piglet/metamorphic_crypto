defmodule MetamorphicCrypto.SecretBox do
  @moduledoc """
  XSalsa20-Poly1305 authenticated symmetric encryption (NaCl `secretbox`).

  Ciphertext layout: `nonce (24 bytes) || ciphertext (plaintext_len + 16 byte MAC)`

  This is the same format produced by libsodium's `crypto_secretbox_easy` with a
  prepended random nonce, making it compatible with existing NaCl implementations.

  ## Usage

      key = MetamorphicCrypto.Keys.generate_key()

      # Encrypt/decrypt UTF-8 strings
      {:ok, ct} = MetamorphicCrypto.SecretBox.encrypt_string("hello", key)
      {:ok, "hello"} = MetamorphicCrypto.SecretBox.decrypt_string(ct, key)

      # Encrypt/decrypt raw bytes (as base64)
      plaintext_b64 = Base.encode64("raw bytes")
      {:ok, ct} = MetamorphicCrypto.SecretBox.encrypt(plaintext_b64, key)
      {:ok, ^plaintext_b64} = MetamorphicCrypto.SecretBox.decrypt(ct, key)

  """

  alias MetamorphicCrypto.Native

  @doc """
  Encrypt raw bytes (passed as base64) with a base64 key.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.
  """
  @spec encrypt(plaintext_b64 :: String.t(), key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encrypt(plaintext_b64, key_b64) do
    case Native.nif_encrypt_secretbox(plaintext_b64, key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Decrypt base64 ciphertext, returning plaintext as base64.

  Returns `{:ok, plaintext_b64}` or `{:error, reason}`.
  """
  @spec decrypt(ciphertext_b64 :: String.t(), key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt(ciphertext_b64, key_b64) do
    case Native.nif_decrypt_secretbox(ciphertext_b64, key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Encrypt a UTF-8 string with a base64 key.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Example

      key = MetamorphicCrypto.Keys.generate_key()
      {:ok, ct} = MetamorphicCrypto.SecretBox.encrypt_string("my secret", key)

  """
  @spec encrypt_string(plaintext :: String.t(), key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encrypt_string(plaintext, key_b64) do
    case Native.nif_encrypt_secretbox_string(plaintext, key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Decrypt base64 ciphertext to a UTF-8 string.

  Returns `{:ok, plaintext}` or `{:error, reason}`.

  ## Example

      {:ok, "my secret"} = MetamorphicCrypto.SecretBox.decrypt_string(ct, key)

  """
  @spec decrypt_string(ciphertext_b64 :: String.t(), key_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt_string(ciphertext_b64, key_b64) do
    case Native.nif_decrypt_secretbox_to_string(ciphertext_b64, key_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Encrypt a UTF-8 string, raising on failure.

  ## Example

      ct = MetamorphicCrypto.SecretBox.encrypt_string!("hello", key)

  """
  @spec encrypt_string!(plaintext :: String.t(), key_b64 :: String.t()) :: String.t()
  def encrypt_string!(plaintext, key_b64) do
    case encrypt_string(plaintext, key_b64) do
      {:ok, ct} -> ct
      {:error, reason} -> raise "encryption failed: #{reason}"
    end
  end

  @doc """
  Decrypt base64 ciphertext to a UTF-8 string, raising on failure.

  ## Example

      "hello" = MetamorphicCrypto.SecretBox.decrypt_string!(ct, key)

  """
  @spec decrypt_string!(ciphertext_b64 :: String.t(), key_b64 :: String.t()) :: String.t()
  def decrypt_string!(ciphertext_b64, key_b64) do
    case decrypt_string(ciphertext_b64, key_b64) do
      {:ok, pt} -> pt
      {:error, reason} -> raise "decryption failed: #{reason}"
    end
  end
end
