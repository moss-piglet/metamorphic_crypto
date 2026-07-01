defmodule MetamorphicCrypto.KDFTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.{KDF, Keys}

  doctest MetamorphicCrypto.KDF, only: [hkdf_sha512: 4, hkdf_sha512_hash_len: 0]

  describe "derive_session_key/2" do
    test "deterministic (same password + salt = same key)" do
      salt = Base.encode64(<<0::128>>)

      assert {:ok, key1} = KDF.derive_session_key("password", salt)
      assert {:ok, key2} = KDF.derive_session_key("password", salt)
      assert key1 == key2
    end

    test "output is 32 bytes" do
      salt = Keys.generate_salt()
      {:ok, key} = KDF.derive_session_key("pw", salt)
      assert byte_size(Base.decode64!(key)) == 32
    end

    test "different passwords produce different keys" do
      salt = Keys.generate_salt()
      {:ok, k1} = KDF.derive_session_key("alpha", salt)
      {:ok, k2} = KDF.derive_session_key("beta", salt)
      assert k1 != k2
    end

    test "different salts produce different keys" do
      s1 = Base.encode64(<<1::128>>)
      s2 = Base.encode64(<<2::128>>)
      {:ok, k1} = KDF.derive_session_key("pw", s1)
      {:ok, k2} = KDF.derive_session_key("pw", s2)
      assert k1 != k2
    end

    test "invalid salt length returns error" do
      short_salt = Base.encode64(<<0::64>>)
      assert {:error, _reason} = KDF.derive_session_key("pw", short_salt)
    end
  end

  describe "derive_session_key!/2" do
    test "returns key on success" do
      salt = Keys.generate_salt()
      key = KDF.derive_session_key!("pw", salt)
      assert is_binary(key)
    end

    test "raises on failure" do
      assert_raise RuntimeError, ~r/key derivation failed/, fn ->
        KDF.derive_session_key!("pw", "bad")
      end
    end
  end

  describe "parse_salt_from_key_hash/1" do
    test "extracts salt from valid hash" do
      assert {:ok, "c2FsdA=="} = KDF.parse_salt_from_key_hash("c2FsdA==$argon2id")
    end

    test "rejects invalid format" do
      assert {:error, _} = KDF.parse_salt_from_key_hash("noseparator")
      assert {:error, _} = KDF.parse_salt_from_key_hash("a$b$c")
    end
  end

  describe "hkdf_sha512_hash_len/0" do
    test "is 64 (a SHA-512 digest)" do
      assert KDF.hkdf_sha512_hash_len() == 64
    end
  end

  describe "hkdf_sha512/4" do
    # LOCKED PARITY VECTOR — RFC 5869 Test Case 1 inputs recomputed with SHA-512
    # (L = 42). Value-for-value identical to the crate's native/WASM KAT and to
    # `@noble/hashes` / WebCrypto HKDF-SHA-512. This is the guarantee that a wrap
    # made in the browser unwraps byte-for-byte identically here.
    test "RFC 5869 Test Case 1, SHA-512, L=42 (base64 in, base64 out)" do
      ikm = Base.encode64(String.duplicate(<<0x0B>>, 22))
      salt = Base.encode64(Enum.into(0..0x0C, <<>>, &<<&1>>))
      info = <<0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9>>

      assert {:ok, okm_b64} = KDF.hkdf_sha512(salt, ikm, info, 42)

      assert Base.decode16!(
               "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
               case: :lower
             ) == Base.decode64!(okm_b64)
    end

    test "produces the requested output length" do
      {:ok, okm} = KDF.hkdf_sha512(Base.encode64("salt"), Base.encode64("ikm"), "info", 32)
      assert byte_size(Base.decode64!(okm)) == 32
    end

    test "empty salt means 'not provided' (RFC 5869 §2.2 = HashLen zero bytes)" do
      ikm = Base.encode64("ikm")
      empty = KDF.hkdf_sha512!("", ikm, "info", 32)
      zeros = KDF.hkdf_sha512!(Base.encode64(<<0::size(64)-unit(8)>>), ikm, "info", 32)
      assert empty == zeros
    end

    test "info provides domain separation" do
      salt = Base.encode64("salt")
      ikm = Base.encode64("ikm")
      {:ok, a} = KDF.hkdf_sha512(salt, ikm, "mosslet/user_key-wrap/v1", 32)
      {:ok, b} = KDF.hkdf_sha512(salt, ikm, "mosslet/user_key-wrap/v2", 32)
      assert a != b
    end

    test "distinct salt / ikm produce distinct output" do
      base = KDF.hkdf_sha512!(Base.encode64("salt"), Base.encode64("ikm"), "info", 32)
      assert base != KDF.hkdf_sha512!(Base.encode64("salt2"), Base.encode64("ikm"), "info", 32)
      assert base != KDF.hkdf_sha512!(Base.encode64("salt"), Base.encode64("ikm2"), "info", 32)
    end

    test "is deterministic" do
      salt = Base.encode64("salt")
      ikm = Base.encode64("ikm")
      assert KDF.hkdf_sha512(salt, ikm, "info", 32) == KDF.hkdf_sha512(salt, ikm, "info", 32)
    end

    test "output length above the RFC maximum returns {:error, _}" do
      salt = Base.encode64("salt")
      ikm = Base.encode64("ikm")
      assert {:ok, _} = KDF.hkdf_sha512(salt, ikm, "info", 255 * 64)
      assert {:error, _} = KDF.hkdf_sha512(salt, ikm, "info", 255 * 64 + 1)
    end

    test "invalid base64 returns {:error, _}" do
      assert {:error, _} = KDF.hkdf_sha512("not valid base64!!!", Base.encode64("ikm"), "i", 32)
    end
  end

  describe "hkdf_sha512!/4" do
    test "returns the OKM directly on success" do
      assert is_binary(KDF.hkdf_sha512!(Base.encode64("salt"), Base.encode64("ikm"), "info", 32))
    end

    test "raises on failure" do
      assert_raise RuntimeError, ~r/HKDF-SHA512 failed/, fn ->
        KDF.hkdf_sha512!("not valid base64!!!", Base.encode64("ikm"), "info", 32)
      end
    end
  end
end
