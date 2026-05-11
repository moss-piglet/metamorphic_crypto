defmodule MetamorphicCryptoTest do
  use ExUnit.Case, async: true

  describe "top-level convenience API" do
    test "generate_key/0" do
      key = MetamorphicCrypto.generate_key()
      assert byte_size(Base.decode64!(key)) == 32
    end

    test "generate_keypair/0" do
      {pk, sk} = MetamorphicCrypto.generate_keypair()
      assert byte_size(Base.decode64!(pk)) == 32
      assert byte_size(Base.decode64!(sk)) == 32
    end

    test "encrypt/2 and decrypt/2 roundtrip" do
      key = MetamorphicCrypto.generate_key()

      assert {:ok, ct} = MetamorphicCrypto.encrypt("hello, world!", key)
      assert {:ok, "hello, world!"} = MetamorphicCrypto.decrypt(ct, key)
    end

    test "seal/2 and unseal/3 roundtrip" do
      {pk, sk} = MetamorphicCrypto.generate_keypair()

      assert {:ok, sealed} = MetamorphicCrypto.seal("secret message", pk)
      assert {:ok, "secret message"} = MetamorphicCrypto.unseal(sealed, pk, sk)
    end
  end
end
