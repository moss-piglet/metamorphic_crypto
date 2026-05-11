defmodule MetamorphicCrypto.KeysTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Keys

  describe "generate_key/0" do
    test "returns 32-byte base64 key" do
      key = Keys.generate_key()
      assert byte_size(Base.decode64!(key)) == 32
    end

    test "keys are unique" do
      assert Keys.generate_key() != Keys.generate_key()
    end
  end

  describe "generate_keypair/0" do
    test "returns tuple of 32-byte keys" do
      {pk, sk} = Keys.generate_keypair()
      assert byte_size(Base.decode64!(pk)) == 32
      assert byte_size(Base.decode64!(sk)) == 32
    end

    test "keypairs are unique" do
      {pk1, _} = Keys.generate_keypair()
      {pk2, _} = Keys.generate_keypair()
      assert pk1 != pk2
    end
  end

  describe "generate_salt/0" do
    test "returns 16-byte base64 salt" do
      salt = Keys.generate_salt()
      assert byte_size(Base.decode64!(salt)) == 16
    end
  end

  describe "encrypt_private_key/2 and decrypt_private_key/2" do
    test "roundtrip" do
      {_pk, sk} = Keys.generate_keypair()
      session_key = Keys.generate_key()

      assert {:ok, encrypted} = Keys.encrypt_private_key(sk, session_key)
      assert {:ok, ^sk} = Keys.decrypt_private_key(encrypted, session_key)
    end

    test "wrong session key fails" do
      {_pk, sk} = Keys.generate_keypair()
      k1 = Keys.generate_key()
      k2 = Keys.generate_key()

      {:ok, encrypted} = Keys.encrypt_private_key(sk, k1)
      assert {:error, _reason} = Keys.decrypt_private_key(encrypted, k2)
    end
  end
end
