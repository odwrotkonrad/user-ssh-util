##[>] 🤖🤖
require_relative "../test_helper"

module UserSshUtil
  module Platform
    class GithubTest < Minitest::Test
      include TestSupport

      #[why] real gh output: title, key, added-at, id, type
      LISTED = "id_access-abc123\tssh-ed25519 AAAA\t2026-08-24T16:05:45Z\t111\tauthentication\n" \
               "id_sign-def456\tssh-ed25519 BBBB\t2026-08-24T16:05:46Z\t222\tsigning\n"

      def setup
        @runner = FakeRunner.new
        @github = Github.new(@runner)
      end

      def test_add_uploads_the_public_key_under_the_title
        title = @github.add("/home/u/.ssh/k.pub", "k-abc123")

        assert_equal "k-abc123", title
        assert @runner.ran?(%r{gh ssh-key add /home/u/\.ssh/k\.pub --title k-abc123})
      end

      # gh defaults to authentication: a signing key added without --type lands in the
      # ssh_signing_keys collection's counterpart and is the wrong kind of key entirely
      def test_add_pins_the_type_for_a_signing_key
        @github.add("/home/u/.ssh/k.pub", "k-abc123", key_type: "signing")

        assert @runner.ran?(/--type signing$/)
      end

      def test_add_pins_the_type_for_an_access_key
        @github.add("/home/u/.ssh/k.pub", "k-abc123", key_type: "access")

        assert @runner.ran?(/--type authentication$/)
      end

      # the id column sits after the added-at column: picking the wrong one sends a date to the API
      def test_delete_sends_a_numeric_id_not_a_timestamp
        @runner.stub(/ssh-key list/, stdout: LISTED)

        @github.delete("id_access-abc123")

        assert @runner.ran?(/gh ssh-key delete 111 --yes/)
        refute @runner.ran?(/delete 2026-/), "a timestamp in the delete path means the wrong column"
      end

      # `gh ssh-key delete` only calls /user/keys, which 404s for a key in the signing collection
      def test_deleting_a_signing_key_goes_through_the_signing_endpoint
        @runner.stub(/ssh-key list/, stdout: LISTED)

        @github.delete("id_sign-def456")

        assert @runner.ran?(%r{gh api -X DELETE /user/ssh_signing_keys/222})
        refute @runner.ran?(/ssh-key delete/), "the plain delete path 404s on a signing key"
      end

      def test_deleting_an_auth_key_uses_the_plain_command
        @runner.stub(/ssh-key list/, stdout: LISTED)

        @github.delete("id_access-abc123")

        assert @runner.ran?(/gh ssh-key delete 111 --yes/)
        refute @runner.ran?(/ssh_signing_keys/)
      end

      def test_delete_never_prompts
        @runner.stub(/ssh-key list/, stdout: LISTED)

        @github.delete("id_access-abc123")

        assert @runner.ran?(/--yes/), "an unattended sync must not stall on a confirmation prompt"
      end

      def test_delete_raises_when_the_title_is_absent
        @runner.stub(/ssh-key list/, stdout: LISTED)

        assert_raises(CommandFailed) { @github.delete("never-published") }
        refute @runner.ran?(/ssh-key delete/)
      end

      def test_find_by_public_key_returns_the_title_already_holding_that_material
        @runner.stub(/ssh-key list/, stdout: LISTED)

        assert_equal "id_sign-def456", @github.find_by_public_key("ssh-ed25519 BBBB u@example.com")
      end

      def test_find_by_public_key_is_nil_when_the_material_is_absent
        @runner.stub(/ssh-key list/, stdout: LISTED)

        assert_nil @github.find_by_public_key("ssh-ed25519 ZZZZ u@example.com")
      end

      def test_find_by_public_key_survives_an_account_with_no_keys
        @runner.stub(/ssh-key list/, stdout: "")

        assert_nil @github.find_by_public_key("ssh-ed25519 AAAA u@example.com")
      end

      def test_verify_accepts_the_greeting_despite_a_nonzero_exit
        @runner.stub(/^ssh /, stderr: "Hi user! You've successfully authenticated.", exitstatus: 1)

        assert @github.verify("/home/u/.ssh/k")
      end

      def test_verify_fails_on_a_rejection
        @runner.stub(/^ssh /, stderr: "Permission denied (publickey).", exitstatus: 255)

        refute @github.verify("/home/u/.ssh/k")
      end

      # IdentitiesOnly drops agent keys but keeps a `Host *` IdentityFile, which would verify
      # the wrong key entirely and pass a rotation whose replacement cannot actually log in
      def test_verify_ignores_the_users_ssh_config
        @github.verify("/home/u/.ssh/k")

        assert @runner.ran?(%r{ssh -F /dev/null -i /home/u/\.ssh/k -o IdentitiesOnly=yes})
      end
    end
  end
end
##[<] 🤖🤖
