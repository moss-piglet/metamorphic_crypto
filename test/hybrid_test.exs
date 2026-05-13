defmodule MetamorphicCrypto.HybridTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Hybrid

  describe "Cat-3: generate_keypair/0" do
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

  describe "Cat-3: seal/2 and open/2" do
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

  describe "Cat-5: generate_keypair_1024/0" do
    test "returns tuple of two base64 strings" do
      {pk, sk} = Hybrid.generate_keypair_1024()
      assert is_binary(pk)
      assert is_binary(sk)

      # Public key is 1600 bytes (ML-KEM-1024 ek 1568 + X25519 pk 32)
      assert byte_size(Base.decode64!(pk)) == 1600
      # Secret key is 32 bytes (seed)
      assert byte_size(Base.decode64!(sk)) == 32
    end
  end

  describe "Cat-5: seal_1024/2 and open/2" do
    test "roundtrip" do
      {pk, sk} = Hybrid.generate_keypair_1024()
      plaintext = "top secret cat-5 data"

      assert {:ok, ct} = Hybrid.seal_1024(plaintext, pk)
      assert {:ok, ^plaintext} = Hybrid.open(ct, sk)
    end

    test "wrong key fails" do
      {pk1, _sk1} = Hybrid.generate_keypair_1024()
      {_pk2, sk2} = Hybrid.generate_keypair_1024()

      {:ok, ct} = Hybrid.seal_1024("secret", pk1)
      assert {:error, _reason} = Hybrid.open(ct, sk2)
    end

    test "nondeterministic" do
      {pk, _sk} = Hybrid.generate_keypair_1024()

      {:ok, ct1} = Hybrid.seal_1024("x", pk)
      {:ok, ct2} = Hybrid.seal_1024("x", pk)
      assert ct1 != ct2
    end

    test "empty plaintext" do
      {pk, sk} = Hybrid.generate_keypair_1024()

      assert {:ok, ct} = Hybrid.seal_1024("", pk)
      assert {:ok, ""} = Hybrid.open(ct, sk)
    end
  end

  describe "cross-level" do
    test "cat-3 ciphertext cannot be opened with cat-5 key" do
      {pk3, _sk3} = Hybrid.generate_keypair()
      {_pk5, sk5} = Hybrid.generate_keypair_1024()

      {:ok, ct} = Hybrid.seal("test", pk3)
      assert {:error, _reason} = Hybrid.open(ct, sk5)
    end

    test "cat-5 ciphertext cannot be opened with cat-3 key" do
      {_pk3, sk3} = Hybrid.generate_keypair()
      {pk5, _sk5} = Hybrid.generate_keypair_1024()

      {:ok, ct} = Hybrid.seal_1024("test", pk5)
      assert {:error, _reason} = Hybrid.open(ct, sk3)
    end
  end

  describe "hybrid_ciphertext?/1" do
    test "true for Cat-3 hybrid ciphertext" do
      {pk, _sk} = Hybrid.generate_keypair()
      {:ok, ct} = Hybrid.seal("x", pk)
      assert Hybrid.hybrid_ciphertext?(ct)
    end

    test "true for Cat-5 hybrid ciphertext" do
      {pk, _sk} = Hybrid.generate_keypair_1024()
      {:ok, ct} = Hybrid.seal_1024("x", pk)
      assert Hybrid.hybrid_ciphertext?(ct)
    end

    test "false for non-hybrid ciphertext" do
      legacy = Base.encode64(<<0x01, 0x02, 0x03>>)
      refute Hybrid.hybrid_ciphertext?(legacy)
    end
  end
end
