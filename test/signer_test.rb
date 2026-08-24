##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  # SignerTest drives the real ssh-keygen sign/verify against throwaway keys.
  class SignerTest < Minitest::Test
    include TestSupport

    EMAIL = "u@example.com"

    def setup
      @dir = Pathname.new(Dir.mktmpdir("signer"))
      @keypair = Keypair.new(CommandRunner.new)
      @signer = Signer.new(CommandRunner.new)
    end

    def teardown = FileUtils.remove_entry(@dir)

    def test_a_freshly_generated_key_signs_and_verifies
      assert @signer.usable?(generate("k"), email: EMAIL)
    end

    def test_an_ecdsa_key_signs_and_verifies
      assert @signer.usable?(generate("k", algorithm: "ecdsa-sha2-nistp521"), email: EMAIL)
    end

    def test_the_probe_leaves_nothing_behind
      generate("k")

      @signer.usable?(@dir.join("k"), email: EMAIL)

      assert_equal %w[k k.pub], @dir.children.map { _1.basename.to_s }.sort
    end

    def test_a_missing_private_key_is_not_usable
      generate("k")
      @dir.join("k").delete

      refute @signer.usable?(@dir.join("k"), email: EMAIL)
    end

    # a key whose halves disagree can sign, but the signature verifies against nothing
    def test_a_mismatched_public_half_is_not_usable
      private_path = generate("k")
      other = generate("other")
      FileUtils.cp(@keypair.public_path_for(other).to_s, @keypair.public_path_for(private_path).to_s)

      refute @signer.usable?(private_path, email: EMAIL)
    end

    def test_verification_is_scoped_to_the_signing_identity
      private_path = generate("k")

      assert @signer.usable?(private_path, email: "someone-else@example.com"),
             "the probe writes its own allowed_signers, so any identity it declares must verify"
    end

    private

    def generate(name, algorithm: "ssh-ed25519")
      @keypair.generate(private_path: @dir.join(name), algorithm: algorithm, comment: EMAIL)
      @dir.join(name)
    end
  end
end
##[<] 🤖🤖
