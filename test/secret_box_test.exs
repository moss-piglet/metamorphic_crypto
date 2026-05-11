defmodule MetamorphicCrypto.SecretBoxTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.{Keys, SecretBox}

  describe "encrypt_string/2 and decrypt_string/2" do
    test "roundtrip" do
      key = Keys.generate_key()
      plaintext = "hello, metamorphic!"

      assert {:ok, ct} = SecretBox.encrypt_string(plaintext, key)
      assert {:ok, ^plaintext} = SecretBox.decrypt_string(ct, key)
    end

    test "handles unicode" do
      key = Keys.generate_key()
      plaintext = "Exercise 3x/week 🏋️"

      assert {:ok, ct} = SecretBox.encrypt_string(plaintext, key)
      assert {:ok, ^plaintext} = SecretBox.decrypt_string(ct, key)
    end

    test "empty plaintext" do
      key = Keys.generate_key()

      assert {:ok, ct} = SecretBox.encrypt_string("", key)
      assert {:ok, ""} = SecretBox.decrypt_string(ct, key)
    end

    test "wrong key fails" do
      k1 = Keys.generate_key()
      k2 = Keys.generate_key()

      {:ok, ct} = SecretBox.encrypt_string("secret", k1)
      assert {:error, _reason} = SecretBox.decrypt_string(ct, k2)
    end

    test "nonces are random (different ciphertext each time)" do
      key = Keys.generate_key()

      {:ok, ct1} = SecretBox.encrypt_string("x", key)
      {:ok, ct2} = SecretBox.encrypt_string("x", key)
      assert ct1 != ct2
    end
  end

  describe "encrypt/2 and decrypt/2 (raw bytes)" do
    test "roundtrip with base64 plaintext" do
      key = Keys.generate_key()
      plaintext_b64 = Base.encode64("raw binary data")

      assert {:ok, ct} = SecretBox.encrypt(plaintext_b64, key)
      assert {:ok, ^plaintext_b64} = SecretBox.decrypt(ct, key)
    end
  end

  describe "bang variants" do
    test "encrypt_string!/2 returns ciphertext" do
      key = Keys.generate_key()
      ct = SecretBox.encrypt_string!("hello", key)
      assert is_binary(ct)
    end

    test "decrypt_string!/2 returns plaintext" do
      key = Keys.generate_key()
      ct = SecretBox.encrypt_string!("hello", key)
      assert "hello" = SecretBox.decrypt_string!(ct, key)
    end

    test "decrypt_string!/2 raises on failure" do
      key = Keys.generate_key()

      assert_raise RuntimeError, ~r/decryption failed/, fn ->
        SecretBox.decrypt_string!("invalid", key)
      end
    end
  end
end
