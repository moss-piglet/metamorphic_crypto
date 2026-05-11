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

  describe "seal_for_user/3 and unseal_from_user/4 — hybrid PQ" do
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
  end
end
