defmodule MetamorphicCrypto.HybridTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.Hybrid

  describe "Cat-1: generate_keypair(:cat1)" do
    test "returns tuple of two base64 strings" do
      {pk, sk} = Hybrid.generate_keypair(:cat1)
      assert is_binary(pk)
      assert is_binary(sk)

      # Public key is 832 bytes (ML-KEM-512 ek 800 + X25519 pk 32)
      assert byte_size(Base.decode64!(pk)) == 832
      # Secret key is 32 bytes (seed)
      assert byte_size(Base.decode64!(sk)) == 32
    end

    test "generate_keypair_512/0 is an alias" do
      {pk, sk} = Hybrid.generate_keypair_512()
      assert byte_size(Base.decode64!(pk)) == 832
      assert byte_size(Base.decode64!(sk)) == 32
    end
  end

  describe "Cat-1: seal/3 with :cat1 and open/2" do
    test "roundtrip" do
      {pk, sk} = Hybrid.generate_keypair(:cat1)
      plaintext = "quantum-safe cat-1 data"

      assert {:ok, ct} = Hybrid.seal(plaintext, pk, :cat1)
      assert {:ok, ^plaintext} = Hybrid.open(ct, sk)
    end

    test "seal_512/2 alias roundtrip" do
      {pk, sk} = Hybrid.generate_keypair(:cat1)
      plaintext = "quantum-safe via seal_512"

      assert {:ok, ct} = Hybrid.seal_512(plaintext, pk)
      assert {:ok, ^plaintext} = Hybrid.open(ct, sk)
    end

    test "version tag is 0x01" do
      {pk, _sk} = Hybrid.generate_keypair(:cat1)
      {:ok, ct} = Hybrid.seal("x", pk, :cat1)
      assert <<0x01, _rest::binary>> = Base.decode64!(ct)
    end

    test "ciphertext size for empty plaintext" do
      {pk, _sk} = Hybrid.generate_keypair(:cat1)
      {:ok, ct} = Hybrid.seal("", pk, :cat1)
      # 0x01 (1) + ML-KEM-512 ct (768) + X25519 eph pk (32) + nonce (24) + MAC (16)
      assert byte_size(Base.decode64!(ct)) == 1 + 768 + 32 + 24 + 16
    end

    test "wrong key fails" do
      {pk1, _sk1} = Hybrid.generate_keypair(:cat1)
      {_pk2, sk2} = Hybrid.generate_keypair(:cat1)

      {:ok, ct} = Hybrid.seal("secret", pk1, :cat1)
      assert {:error, _reason} = Hybrid.open(ct, sk2)
    end

    test "nondeterministic" do
      {pk, _sk} = Hybrid.generate_keypair(:cat1)

      {:ok, ct1} = Hybrid.seal("x", pk, :cat1)
      {:ok, ct2} = Hybrid.seal("x", pk, :cat1)
      assert ct1 != ct2
    end

    test "empty plaintext" do
      {pk, sk} = Hybrid.generate_keypair(:cat1)

      assert {:ok, ct} = Hybrid.seal("", pk, :cat1)
      assert {:ok, ""} = Hybrid.open(ct, sk)
    end
  end

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

  describe "Cat-5: generate_keypair(:cat5)" do
    test "returns tuple of two base64 strings" do
      {pk, sk} = Hybrid.generate_keypair(:cat5)
      assert is_binary(pk)
      assert is_binary(sk)

      # Public key is 1600 bytes (ML-KEM-1024 ek 1568 + X25519 pk 32)
      assert byte_size(Base.decode64!(pk)) == 1600
      # Secret key is 32 bytes (seed)
      assert byte_size(Base.decode64!(sk)) == 32
    end

    test "generate_keypair_1024/0 is an alias" do
      # Just verify it produces correct key sizes
      {pk, sk} = Hybrid.generate_keypair_1024()
      assert byte_size(Base.decode64!(pk)) == 1600
      assert byte_size(Base.decode64!(sk)) == 32
    end
  end

  describe "Cat-5: seal/3 with :cat5 and open/2" do
    test "roundtrip" do
      {pk, sk} = Hybrid.generate_keypair(:cat5)
      plaintext = "top secret cat-5 data"

      assert {:ok, ct} = Hybrid.seal(plaintext, pk, :cat5)
      assert {:ok, ^plaintext} = Hybrid.open(ct, sk)
    end

    test "seal_1024/2 alias roundtrip" do
      {pk, sk} = Hybrid.generate_keypair(:cat5)
      plaintext = "top secret via seal_1024"

      assert {:ok, ct} = Hybrid.seal_1024(plaintext, pk)
      assert {:ok, ^plaintext} = Hybrid.open(ct, sk)
    end

    test "wrong key fails" do
      {pk1, _sk1} = Hybrid.generate_keypair(:cat5)
      {_pk2, sk2} = Hybrid.generate_keypair(:cat5)

      {:ok, ct} = Hybrid.seal("secret", pk1, :cat5)
      assert {:error, _reason} = Hybrid.open(ct, sk2)
    end

    test "nondeterministic" do
      {pk, _sk} = Hybrid.generate_keypair(:cat5)

      {:ok, ct1} = Hybrid.seal("x", pk, :cat5)
      {:ok, ct2} = Hybrid.seal("x", pk, :cat5)
      assert ct1 != ct2
    end

    test "empty plaintext" do
      {pk, sk} = Hybrid.generate_keypair(:cat5)

      assert {:ok, ct} = Hybrid.seal("", pk, :cat5)
      assert {:ok, ""} = Hybrid.open(ct, sk)
    end
  end

  describe "explicit :cat3 level" do
    test "generate_keypair(:cat3) same sizes as default" do
      {pk, sk} = Hybrid.generate_keypair(:cat3)
      assert byte_size(Base.decode64!(pk)) == 1216
      assert byte_size(Base.decode64!(sk)) == 32
    end

    test "seal with explicit :cat3 roundtrips" do
      {pk, sk} = Hybrid.generate_keypair(:cat3)
      assert {:ok, ct} = Hybrid.seal("explicit cat3", pk, :cat3)
      assert {:ok, "explicit cat3"} = Hybrid.open(ct, sk)
    end
  end

  describe "cross-level" do
    test "cat-1 ciphertext cannot be opened with cat-5 key" do
      {pk1, _sk1} = Hybrid.generate_keypair(:cat1)
      {_pk5, sk5} = Hybrid.generate_keypair(:cat5)

      {:ok, ct} = Hybrid.seal("test", pk1, :cat1)
      assert {:error, _reason} = Hybrid.open(ct, sk5)
    end

    test "cat-1 ciphertext cannot be opened with cat-3 key" do
      {pk1, _sk1} = Hybrid.generate_keypair(:cat1)
      {_pk3, sk3} = Hybrid.generate_keypair(:cat3)

      {:ok, ct} = Hybrid.seal("test", pk1, :cat1)
      assert {:error, _reason} = Hybrid.open(ct, sk3)
    end

    test "cat-3 ciphertext cannot be opened with cat-5 key" do
      {pk3, _sk3} = Hybrid.generate_keypair(:cat3)
      {_pk5, sk5} = Hybrid.generate_keypair(:cat5)

      {:ok, ct} = Hybrid.seal("test", pk3, :cat3)
      assert {:error, _reason} = Hybrid.open(ct, sk5)
    end

    test "cat-5 ciphertext cannot be opened with cat-3 key" do
      {_pk3, sk3} = Hybrid.generate_keypair(:cat3)
      {pk5, _sk5} = Hybrid.generate_keypair(:cat5)

      {:ok, ct} = Hybrid.seal("test", pk5, :cat5)
      assert {:error, _reason} = Hybrid.open(ct, sk3)
    end
  end

  describe "hybrid_ciphertext?/1" do
    test "true for Cat-1 hybrid ciphertext" do
      {pk, _sk} = Hybrid.generate_keypair(:cat1)
      {:ok, ct} = Hybrid.seal("x", pk, :cat1)
      assert Hybrid.hybrid_ciphertext?(ct)
    end

    test "true for Cat-3 hybrid ciphertext" do
      {pk, _sk} = Hybrid.generate_keypair()
      {:ok, ct} = Hybrid.seal("x", pk)
      assert Hybrid.hybrid_ciphertext?(ct)
    end

    test "true for Cat-5 hybrid ciphertext" do
      {pk, _sk} = Hybrid.generate_keypair(:cat5)
      {:ok, ct} = Hybrid.seal("x", pk, :cat5)
      assert Hybrid.hybrid_ciphertext?(ct)
    end

    test "false for non-hybrid ciphertext" do
      legacy = Base.encode64(<<0x01, 0x02, 0x03>>)
      refute Hybrid.hybrid_ciphertext?(legacy)
    end

    test "legacy 0x01-prefixed ciphertext is not misdetected as Cat-1" do
      # A short legacy ciphertext that happens to begin with 0x01 must not be
      # mistaken for a Cat-1 (ML-KEM-512) hybrid ciphertext. Detection is
      # length-aware: anything shorter than a full Cat-1 ciphertext is rejected.
      legacy = Base.encode64(<<0x01>> <> :crypto.strong_rand_bytes(100))
      refute Hybrid.hybrid_ciphertext?(legacy)
    end
  end
end
