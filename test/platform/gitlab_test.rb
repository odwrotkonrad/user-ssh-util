##[>] 🤖🤖
require_relative "../test_helper"

module UserSshUtil
  module Platform
    class GitlabTest < Minitest::Test
      include TestSupport

      LISTED = <<~JSON
        [{"id":111,"title":"id_access-abc123"},{"id":222,"title":"id_sign-def456"}]
      JSON

      #[why] real glab output: the key carries gitlab's own comment, never the uploaded one
      COMMENTED = <<~JSON
        [{"id":111,"title":"id_access-abc123","key":"ssh-ed25519 AAAA Konrad (gitlab.com)"},
         {"id":222,"title":"id_sign-def456","key":"ssh-ed25519 BBBB Konrad (gitlab.com)"}]
      JSON

      def setup
        @runner = FakeRunner.new
        @gitlab = Gitlab.new(@runner)
      end

      def test_add_uploads_the_public_key_under_the_title
        title = @gitlab.add("/home/u/.ssh/k.pub", "k-abc123")

        assert_equal "k-abc123", title
        assert @runner.ran?(%r{glab ssh-key add /home/u/\.ssh/k\.pub --title k-abc123})
      end

      # glab defaults to auth_and_signing, which grants more than an access key asked for
      def test_add_pins_the_usage_type_for_an_access_key
        @gitlab.add("/home/u/.ssh/k.pub", "k-abc123", key_type: "access")

        assert @runner.ran?(/--usage-type auth$/)
      end

      def test_add_pins_the_usage_type_for_a_signing_key
        @gitlab.add("/home/u/.ssh/k.pub", "k-abc123", key_type: "signing")

        assert @runner.ran?(/--usage-type signing$/)
      end

      def test_add_never_leaves_the_usage_type_to_the_cli_default
        @gitlab.add("/home/u/.ssh/k.pub", "k-abc123")

        assert @runner.ran?(/--usage-type/)
        refute @runner.ran?(/auth_and_signing/)
      end

      def test_delete_resolves_the_title_to_an_id
        @runner.stub(/ssh-key list/, stdout: LISTED)

        @gitlab.delete("id_sign-def456")

        assert @runner.ran?(/glab ssh-key delete 222/)
      end

      def test_delete_asks_for_ids_the_list_hides_by_default
        @runner.stub(/ssh-key list/, stdout: LISTED)

        @gitlab.delete("id_access-abc123")

        assert @runner.ran?(/glab ssh-key list --show-id --output json/)
      end

      def test_delete_raises_when_the_title_is_absent
        @runner.stub(/ssh-key list/, stdout: LISTED)

        error = assert_raises(CommandFailed) { @gitlab.delete("never-published") }

        assert_match(/no gitlab ssh key titled never-published/, error.message)
        refute @runner.ran?(/ssh-key delete/), "an unresolved title must delete nothing"
      end

      # gitlab replaces the uploaded comment with its own, so only algorithm and body can match
      def test_find_by_public_key_matches_despite_a_rewritten_comment
        @runner.stub(/ssh-key list/, stdout: COMMENTED)

        assert_equal "id_access-abc123", @gitlab.find_by_public_key("ssh-ed25519 AAAA u@example.com")
      end

      def test_find_by_public_key_is_nil_when_the_material_is_absent
        @runner.stub(/ssh-key list/, stdout: COMMENTED)

        assert_nil @gitlab.find_by_public_key("ssh-ed25519 ZZZZ u@example.com")
      end

      def test_find_by_public_key_never_matches_on_the_body_of_another_algorithm
        @runner.stub(/ssh-key list/, stdout: COMMENTED)

        assert_nil @gitlab.find_by_public_key("ecdsa-sha2-nistp521 AAAA u@example.com")
      end

      def test_find_by_public_key_survives_an_account_with_no_keys
        @runner.stub(/ssh-key list/, stdout: "")

        assert_nil @gitlab.find_by_public_key("ssh-ed25519 AAAA u@example.com")
      end

      def test_verify_passes_on_a_zero_exit
        assert @gitlab.verify("/home/u/.ssh/k")
      end

      def test_verify_accepts_the_welcome_banner_despite_a_nonzero_exit
        @runner.stub(/^ssh /, stderr: "Welcome to GitLab, @user!", exitstatus: 1)

        assert @gitlab.verify("/home/u/.ssh/k")
      end

      def test_verify_fails_on_a_rejection
        @runner.stub(/^ssh /, stderr: "Permission denied (publickey).", exitstatus: 255)

        refute @gitlab.verify("/home/u/.ssh/k")
      end

      def test_verify_offers_only_the_named_identity
        @gitlab.verify("/home/u/.ssh/k")

        assert @runner.ran?(%r{ssh -F /dev/null -i /home/u/\.ssh/k -o IdentitiesOnly=yes .* -T git@gitlab\.com})
      end

      # IdentitiesOnly drops agent keys but keeps a `Host *` IdentityFile, which would verify
      # the wrong key entirely and pass a rotation whose replacement cannot actually log in
      def test_verify_ignores_the_users_ssh_config
        @gitlab.verify("/home/u/.ssh/k")

        assert @runner.ran?(%r{ssh -F /dev/null }), "a user config must not supply an identity"
      end
    end
  end
end
##[<] 🤖🤖
