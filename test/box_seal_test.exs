defmodule MetamorphicCrypto.BoxSealTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.{BoxSeal, Keys}

  describe "seal/2 and open/3" do
    test "roundtrip with string plaintext" do
      {pk, sk} = Keys.generate_keypair()
      plaintext = "context key material"

      assert {:ok, ct} = BoxSeal.seal(plaintext, pk)
      assert {:ok, ^plaintext} = BoxSeal.open(ct, pk, sk)
    end

    test "wrong key fails" do
      {pk1, _sk1} = Keys.generate_keypair()
      {pk2, sk2} = Keys.generate_keypair()

      {:ok, ct} = BoxSeal.seal("secret", pk1)
      assert {:error, _reason} = BoxSeal.open(ct, pk2, sk2)
    end

    test "nondeterministic (ephemeral keypair)" do
      {pk, _sk} = Keys.generate_keypair()

      {:ok, ct1} = BoxSeal.seal("x", pk)
      {:ok, ct2} = BoxSeal.seal("x", pk)
      assert ct1 != ct2
    end

    test "empty plaintext" do
      {pk, sk} = Keys.generate_keypair()

      assert {:ok, ct} = BoxSeal.seal("", pk)
      assert {:ok, ""} = BoxSeal.open(ct, pk, sk)
    end
  end

  describe "seal_raw/2 and open_raw/3" do
    test "roundtrip with base64 plaintext" do
      {pk, sk} = Keys.generate_keypair()
      plaintext_b64 = Base.encode64("raw bytes")

      assert {:ok, ct} = BoxSeal.seal_raw(plaintext_b64, pk)
      assert {:ok, ^plaintext_b64} = BoxSeal.open_raw(ct, pk, sk)
    end
  end
end
