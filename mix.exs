defmodule MetamorphicCrypto.MixProject do
  use Mix.Project

  @version "0.1.0"
  @repo_url "https://github.com/moss-piglet/metamorphic_crypto"

  def project do
    [
      app: :metamorphic_crypto,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @repo_url,
      homepage_url: @repo_url,
      docs: docs(),
      aliases: aliases()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp description do
    """
    Zero-knowledge end-to-end encryption for Elixir.

    NaCl-compatible symmetric and public-key encryption, Argon2id key derivation,
    ML-KEM-768 + X25519 hybrid post-quantum encryption, and human-readable
    recovery keys — all powered by Rust NIFs with precompiled binaries.
    """
  end

  defp deps do
    [
      {:rustler, "~> 0.37.3", runtime: false},
      {:rustler_precompiled, "~> 0.8"},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      name: "metamorphic_crypto",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @repo_url,
        "Changelog" => "#{@repo_url}/blob/main/CHANGELOG.md"
      },
      files: ~w[
        lib
        native/metamorphic_crypto_nif/.cargo
        native/metamorphic_crypto_nif/Cargo.toml
        native/metamorphic_crypto_nif/Cargo.lock
        native/metamorphic_crypto_nif/src
        native/metamorphic_crypto_nif/metamorphic-crypto/Cargo.toml
        native/metamorphic_crypto_nif/metamorphic-crypto/src
        checksum-*.exs
        mix.exs
        README.md
        CHANGELOG.md
        LICENSE
        .formatter.exs
      ]
    ]
  end

  defp docs do
    [
      main: "MetamorphicCrypto",
      extras: ["README.md", "CHANGELOG.md"],
      groups_for_modules: [
        "Symmetric Encryption": [MetamorphicCrypto.SecretBox],
        "Public-Key Encryption": [MetamorphicCrypto.BoxSeal],
        "Post-Quantum Hybrid": [MetamorphicCrypto.Hybrid],
        "Unified Seal/Unseal": [MetamorphicCrypto.Seal],
        "Key Management": [MetamorphicCrypto.Keys, MetamorphicCrypto.KDF],
        Recovery: [MetamorphicCrypto.Recovery]
      ]
    ]
  end

  defp aliases do
    [
      fmt: ["format", "cmd cargo fmt --manifest-path native/metamorphic_crypto_nif/Cargo.toml"]
    ]
  end
end
