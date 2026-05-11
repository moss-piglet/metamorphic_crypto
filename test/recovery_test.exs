defmodule MetamorphicCrypto.RecoveryTest do
  use ExUnit.Case, async: true

  alias MetamorphicCrypto.{Keys, Recovery}

  describe "generate/0" do
    test "returns recovery key and secret" do
      assert {:ok, recovery_key, secret} = Recovery.generate()
      assert is_binary(recovery_key)
      assert is_binary(secret)

      # 13 hyphen-separated groups
      groups = String.split(recovery_key, "-")
      assert length(groups) == 13

      # Secret is 32 bytes
      assert byte_size(Base.decode64!(secret)) == 32
    end

    test "recovery key uses valid alphabet (no I/O/0/1)" do
      {:ok, recovery_key, _secret} = Recovery.generate()
      stripped = String.replace(recovery_key, "-", "")
      refute String.contains?(stripped, "I")
      refute String.contains?(stripped, "O")
      refute String.contains?(stripped, "0")
      refute String.contains?(stripped, "1")
    end
  end

  describe "key_to_secret/1" do
    test "roundtrip with generate" do
      {:ok, recovery_key, secret} = Recovery.generate()
      assert {:ok, ^secret} = Recovery.key_to_secret(recovery_key)
    end

    test "case insensitive" do
      {:ok, recovery_key, secret} = Recovery.generate()
      assert {:ok, ^secret} = Recovery.key_to_secret(String.downcase(recovery_key))
    end

    test "invalid characters rejected" do
      assert {:error, _} =
               Recovery.key_to_secret(
                 "IIIII-OOOOO-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-GGGGG-HHHHH-JJJJJ-KKKKK-LLLL"
               )
    end
  end

  describe "encrypt_private_key/2 and decrypt_private_key/2" do
    test "roundtrip" do
      {_pk, sk} = Keys.generate_keypair()
      {:ok, _recovery_key, secret} = Recovery.generate()

      assert {:ok, backup} = Recovery.encrypt_private_key(sk, secret)
      assert {:ok, ^sk} = Recovery.decrypt_private_key(backup, secret)
    end

    test "wrong secret fails" do
      {_pk, sk} = Keys.generate_keypair()
      {:ok, _rk1, secret1} = Recovery.generate()
      {:ok, _rk2, secret2} = Recovery.generate()

      {:ok, backup} = Recovery.encrypt_private_key(sk, secret1)
      assert {:error, _reason} = Recovery.decrypt_private_key(backup, secret2)
    end
  end
end
