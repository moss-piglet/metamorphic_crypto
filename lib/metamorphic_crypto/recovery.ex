defmodule MetamorphicCrypto.Recovery do
  @moduledoc """
  Human-readable recovery keys for private key backup.

  A recovery key is a 64-character string encoded with a custom base32 alphabet
  (no I/O/0/1 to avoid confusion), formatted as 13 hyphen-separated groups:

      ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2-34567-89ABC-DEFGH-JKLMN-PQRST-UVWXY-Z2345-6789

  The recovery key encodes a 32-byte secret which can encrypt/decrypt the user's
  private key as a backup mechanism.

  ## Usage

      # Generate a recovery key for the user to write down
      {:ok, recovery_key, secret} = MetamorphicCrypto.Recovery.generate()

      # Encrypt the user's private key for recovery backup
      {:ok, backup} = MetamorphicCrypto.Recovery.encrypt_private_key(private_key, secret)

      # Later, restore from backup using the recovery key
      {:ok, restored_secret} = MetamorphicCrypto.Recovery.key_to_secret(recovery_key)
      {:ok, private_key} = MetamorphicCrypto.Recovery.decrypt_private_key(backup, restored_secret)

  """

  alias MetamorphicCrypto.Native

  @doc """
  Generate a new recovery key.

  Returns `{:ok, recovery_key, recovery_secret_b64}` where:

  - `recovery_key` is the human-readable string to show the user
  - `recovery_secret_b64` is the 32-byte secret (base64) used for encryption

  ## Example

      {:ok, recovery_key, secret} = MetamorphicCrypto.Recovery.generate()
      # recovery_key => "ABCDE-FGHJK-LMNPQ-..."

  """
  @spec generate() :: {:ok, String.t(), String.t()} | {:error, String.t()}
  def generate do
    case Native.nif_generate_recovery_key() do
      {:error, reason} -> {:error, reason}
      {recovery_key, secret_b64} -> {:ok, recovery_key, secret_b64}
    end
  end

  @doc """
  Re-derive the 32-byte secret from a human-readable recovery key.

  Case-insensitive. Hyphens are stripped automatically.

  Returns `{:ok, secret_b64}` or `{:error, reason}`.

  ## Example

      {:ok, secret} = MetamorphicCrypto.Recovery.key_to_secret("ABCDE-FGHJK-...")

  """
  @spec key_to_secret(recovery_key :: String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def key_to_secret(recovery_key) when is_binary(recovery_key) do
    case Native.nif_recovery_key_to_secret(recovery_key) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Encrypt a private key (base64) with the recovery secret for backup storage.

  Returns `{:ok, ciphertext_b64}` or `{:error, reason}`.

  ## Example

      {:ok, backup} = MetamorphicCrypto.Recovery.encrypt_private_key(private_key_b64, secret)

  """
  @spec encrypt_private_key(private_key_b64 :: String.t(), recovery_secret_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def encrypt_private_key(private_key_b64, recovery_secret_b64) do
    case Native.nif_encrypt_private_key_for_recovery(private_key_b64, recovery_secret_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end

  @doc """
  Decrypt a private key from a recovery backup.

  Returns `{:ok, private_key_b64}` or `{:error, reason}`.

  ## Example

      {:ok, private_key} = MetamorphicCrypto.Recovery.decrypt_private_key(backup, secret)

  """
  @spec decrypt_private_key(ciphertext_b64 :: String.t(), recovery_secret_b64 :: String.t()) ::
          {:ok, String.t()} | {:error, String.t()}
  def decrypt_private_key(ciphertext_b64, recovery_secret_b64) do
    case Native.nif_decrypt_private_key_with_recovery(ciphertext_b64, recovery_secret_b64) do
      {:error, reason} -> {:error, reason}
      result -> {:ok, result}
    end
  end
end
