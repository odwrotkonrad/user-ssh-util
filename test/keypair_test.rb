##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  # KeypairTest drives the real ssh-keygen against a throwaway directory.
  class KeypairTest < Minitest::Test
    include TestSupport

    def setup
      @dir = Pathname.new(Dir.mktmpdir("keypair"))
      @keypair = Keypair.new(CommandRunner.new)
    end

    def teardown = FileUtils.remove_entry(@dir)

    def test_generate_writes_both_halves
      public_path = generate("k")

      assert_path_exists @dir.join("k")
      assert_path_exists public_path
      assert_equal @dir.join("k.pub"), public_path
    end

    def test_generated_key_is_passphraseless_and_usable
      generate("k")

      probe = CommandRunner.new.run("ssh-keygen", "-y", "-P", "", "-f", @dir.join("k").to_s)

      assert_predicate probe, :success?, "a passphraseless key must yield its public half without a prompt"
    end

    def test_public_key_carries_the_requested_algorithm_and_comment
      generate("k", algorithm: "ssh-ed25519", comment: "u@example.com")

      assert_match(/\Assh-ed25519 \S+ u@example\.com\z/, @keypair.public_key(@dir.join("k")))
    end

    def test_ecdsa_generates_at_the_requested_curve
      generate("k", algorithm: "ecdsa-sha2-nistp521")

      assert_match(/\Aecdsa-sha2-nistp521 /, @keypair.public_key(@dir.join("k")))
    end

    def test_generate_creates_missing_directories
      generate("nested/deeper/k")

      assert_path_exists @dir.join("nested", "deeper", "k")
    end

    def test_generate_refuses_to_clobber_an_existing_key
      generate("k")
      original = @keypair.public_key(@dir.join("k"))

      assert_raises(Keypair::ExistsError) { generate("k") }
      assert_equal original, @keypair.public_key(@dir.join("k")), "the existing key must survive a refused generate"
    end

    def test_override_replaces_an_existing_key
      generate("k")
      original = @keypair.public_key(@dir.join("k"))

      generate("k", override: true)

      refute_equal original, @keypair.public_key(@dir.join("k"))
    end

    def test_unsupported_algorithm_is_rejected
      assert_raises(ArgumentError) { generate("k", algorithm: "rsa-but-not-really") }
    end

    def test_move_relocates_both_halves
      generate("k")
      original = @keypair.public_key(@dir.join("k"))

      moved = @keypair.move(from_private: @dir.join("k"), to_private: @dir.join("backup", "20260824", "k"))

      assert_path_exists moved
      assert_path_exists @dir.join("backup", "20260824", "k.pub")
      refute_path_exists @dir.join("k")
      refute_path_exists @dir.join("k.pub")
      assert_equal original, @keypair.public_key(moved), "moving must not alter the key material"
    end

    private

    def generate(name, algorithm: "ssh-ed25519", comment: "u@example.com", override: false)
      @keypair.generate(private_path: @dir.join(name), algorithm: algorithm, comment: comment, override: override)
    end
  end
end
##[<] 🤖🤖
