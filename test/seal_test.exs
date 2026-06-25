defmodule MetamorphicCrypto.SealTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.{Hybrid, Keys, Seal}

  describe "seal_for_user/3 and unseal_from_user/4 — classical" do
    test "roundtrip without PQ key" do
      {pk, sk} = Keys.generate_keypair()
      plaintext = "context key material"

      assert {:ok, ct} = Seal.seal_for_user(plaintext, pk)
      assert {:ok, ^plaintext} = Seal.unseal_from_user(ct, pk, sk)
    end

    test "classical ciphertext is not hybrid" do
      {pk, _sk} = Keys.generate_keypair()
      {:ok, ct} = Seal.seal_for_user("x", pk)
      refute Hybrid.hybrid_ciphertext?(ct)
    end
  end

  describe "seal_for_user/3 and unseal_from_user/4 — hybrid PQ Cat-3" do
    test "roundtrip with PQ keys" do
      {pk, sk} = Keys.generate_keypair()
      {pq_pk, pq_sk} = Hybrid.generate_keypair()
      plaintext = "post-quantum secret"

      assert {:ok, ct} = Seal.seal_for_user(plaintext, pk, pq_public_key: pq_pk)
      assert Hybrid.hybrid_ciphertext?(ct)
      assert {:ok, ^plaintext} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
    end

    test "empty pq_public_key falls back to classical" do
      {pk, sk} = Keys.generate_keypair()

      {:ok, ct} = Seal.seal_for_user("x", pk, pq_public_key: "")
      refute Hybrid.hybrid_ciphertext?(ct)
      assert {:ok, "x"} = Seal.unseal_from_user(ct, pk, sk)
    end
  end

  describe "seal_for_user/3 and unseal_from_user/4 — hybrid PQ Cat-1" do
    test "roundtrip with Cat-1 PQ keys" do
      {pk, sk} = Keys.generate_keypair()
      {pq_pk, pq_sk} = Hybrid.generate_keypair(:cat1)
      plaintext = "cat-1 post-quantum secret"

      assert {:ok, ct} =
               Seal.seal_for_user(plaintext, pk, pq_public_key: pq_pk, level: :cat1)

      assert Hybrid.hybrid_ciphertext?(ct)
      # Cat-1 ciphertexts carry the 0x01 version tag
      assert <<0x01, _rest::binary>> = Base.decode64!(ct)
      assert {:ok, ^plaintext} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
    end

    test "no PQ key falls back to legacy even with :cat1 level" do
      {pk, sk} = Keys.generate_keypair()

      {:ok, ct} = Seal.seal_for_user("x", pk, level: :cat1)
      refute Hybrid.hybrid_ciphertext?(ct)
      assert {:ok, "x"} = Seal.unseal_from_user(ct, pk, sk)
    end

    test "Cat-1 ciphertext cannot be unsealed with a Cat-5 PQ key" do
      {pk, sk} = Keys.generate_keypair()
      {pq_pk, _pq_sk} = Hybrid.generate_keypair(:cat1)
      {_pq_pk5, pq_sk5} = Hybrid.generate_keypair(:cat5)

      {:ok, ct} = Seal.seal_for_user("x", pk, pq_public_key: pq_pk, level: :cat1)
      assert {:error, _reason} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk5)
    end
  end

  describe "seal_for_user/3 and unseal_from_user/4 — hybrid PQ Cat-5" do
    test "roundtrip with Cat-5 PQ keys" do
      {pk, sk} = Keys.generate_keypair()
      {pq_pk, pq_sk} = Hybrid.generate_keypair(:cat5)
      plaintext = "cat-5 post-quantum secret"

      assert {:ok, ct} =
               Seal.seal_for_user(plaintext, pk, pq_public_key: pq_pk, level: :cat5)

      assert Hybrid.hybrid_ciphertext?(ct)
      assert {:ok, ^plaintext} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
    end

    test "explicit :cat3 level matches default" do
      {pk, sk} = Keys.generate_keypair()
      {pq_pk, pq_sk} = Hybrid.generate_keypair(:cat3)
      plaintext = "explicit cat3"

      assert {:ok, ct} =
               Seal.seal_for_user(plaintext, pk, pq_public_key: pq_pk, level: :cat3)

      assert Hybrid.hybrid_ciphertext?(ct)
      assert {:ok, ^plaintext} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
    end

    test "no PQ key falls back to legacy even with :cat5 level" do
      {pk, sk} = Keys.generate_keypair()

      {:ok, ct} = Seal.seal_for_user("x", pk, level: :cat5)
      refute Hybrid.hybrid_ciphertext?(ct)
      assert {:ok, "x"} = Seal.unseal_from_user(ct, pk, sk)
    end
  end

  describe "format auto-detection" do
    test "legacy ciphertext decrypts when PQ key is available" do
      {pk, sk} = Keys.generate_keypair()
      {_pq_pk, pq_sk} = Hybrid.generate_keypair()

      # Seal with classical
      {:ok, ct} = Seal.seal_for_user("old data", pk)
      refute Hybrid.hybrid_ciphertext?(ct)

      # Unseal with PQ key available — should auto-detect legacy format
      assert {:ok, "old data"} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
    end

    test "Cat-1 ciphertext auto-detected by unseal" do
      {pk, sk} = Keys.generate_keypair()
      {pq_pk, pq_sk} = Hybrid.generate_keypair(:cat1)

      {:ok, ct} = Seal.seal_for_user("cat1 data", pk, pq_public_key: pq_pk, level: :cat1)
      assert Hybrid.hybrid_ciphertext?(ct)

      # unseal_from_user auto-detects Cat-1 from the version tag
      assert {:ok, "cat1 data"} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
    end

    test "Cat-5 ciphertext auto-detected by unseal" do
      {pk, sk} = Keys.generate_keypair()
      {pq_pk, pq_sk} = Hybrid.generate_keypair(:cat5)

      {:ok, ct} = Seal.seal_for_user("cat5 data", pk, pq_public_key: pq_pk, level: :cat5)
      assert Hybrid.hybrid_ciphertext?(ct)

      # unseal_from_user auto-detects Cat-5 from the version tag
      assert {:ok, "cat5 data"} = Seal.unseal_from_user(ct, pk, sk, pq_secret_key: pq_sk)
    end
  end
end
