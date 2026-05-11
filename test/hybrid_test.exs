defmodule MetamorphicCrypto.HybridTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Hybrid

  describe "generate_keypair/0" do
    test "returns tuple of two base64 strings" do
      {pk, sk} = Hybrid.generate_keypair()
      assert is_binary(pk)
      assert is_binary(sk)

      # Public key is 1216 bytes
      assert byte_size(Base.decode64!(pk)) == 1216
      # Secret key is 32 bytes (seed)
      assert byte_size(Base.decode64!(sk)) == 32
    end
  end

  describe "seal/2 and open/2" do
    test "roundtrip" do
      {pk, sk} = Hybrid.generate_keypair()
      plaintext = "quantum-safe secret"

      assert {:ok, ct} = Hybrid.seal(plaintext, pk)
      assert {:ok, ^plaintext} = Hybrid.open(ct, sk)
    end

    test "wrong key fails" do
      {pk1, _sk1} = Hybrid.generate_keypair()
      {_pk2, sk2} = Hybrid.generate_keypair()

      {:ok, ct} = Hybrid.seal("secret", pk1)
      assert {:error, _reason} = Hybrid.open(ct, sk2)
    end

    test "nondeterministic" do
      {pk, _sk} = Hybrid.generate_keypair()

      {:ok, ct1} = Hybrid.seal("x", pk)
      {:ok, ct2} = Hybrid.seal("x", pk)
      assert ct1 != ct2
    end

    test "empty plaintext" do
      {pk, sk} = Hybrid.generate_keypair()

      assert {:ok, ct} = Hybrid.seal("", pk)
      assert {:ok, ""} = Hybrid.open(ct, sk)
    end
  end

  describe "hybrid_ciphertext?/1" do
    test "true for hybrid ciphertext" do
      {pk, _sk} = Hybrid.generate_keypair()
      {:ok, ct} = Hybrid.seal("x", pk)
      assert Hybrid.hybrid_ciphertext?(ct)
    end

    test "false for non-hybrid ciphertext" do
      legacy = Base.encode64(<<0x01, 0x02, 0x03>>)
      refute Hybrid.hybrid_ciphertext?(legacy)
    end
  end
end
