defmodule MetamorphicCrypto.KDFTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.{KDF, Keys}

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
end
