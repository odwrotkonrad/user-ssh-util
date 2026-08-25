##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class RotatorTest < Minitest::Test
    include TestSupport

    OLD_PUBLIC = "ssh-ed25519 AAAAOLDMATERIAL u@example.com"

    # UnusableSigner stands in for a key that cannot produce a valid signature.
    class UnusableSigner
      def usable?(_private_path, email:) = false
    end

    # VanishedPlatform stands in for a platform that no longer holds the key state names.
    class VanishedPlatform < FakePlatform
      def delete(title)
        super
        raise CommandFailed, "no ssh key titled #{title}"
      end
    end

    # CrashingPlatform dies instead of deleting, standing in for a connection lost mid-revoke.
    class CrashingPlatform < FakePlatform
      Crash = Class.new(StandardError)

      def delete(_title) = raise(Crash, "connection lost")
    end

    def setup
      @home = Pathname.new(Dir.mktmpdir("rotate"))
      @paths = Paths.new(env: { "HOME" => @home.to_s, "XDG_DATA_HOME" => @home.join("data").to_s })
      @runner = FakeRunner.new
      @keypair = Keypair.new(CommandRunner.new)
      @signer = Signer.new(CommandRunner.new)
      @gitlab = FakePlatform.new("gitlab", host: "gitlab.com")
      @github = FakePlatform.new("github", host: "github.com")
      @registry = Platform::Registry.new(@runner, adapters: { "gitlab" => @gitlab, "github" => @github })
      @reporter = StringIO.new
      @state = State.new({ "k" => key_entry(public_key: OLD_PUBLIC, published_to: { "gitlab" => "k-old" }) },
                         path: @home.join("state.yml"))
      install_live_key
    end

    def teardown = FileUtils.remove_entry(@home)

    def test_the_live_key_is_replaced
      before = @paths.private_key("k").read

      rotate

      refute_equal before, @paths.private_key("k").read
      assert_path_exists @paths.public_key("k")
    end

    def test_the_superseded_keypair_is_archived_not_destroyed
      before = @paths.private_key("k").read

      rotate

      archived = @state.key("k").fetch("archived").first
      assert_path_exists Pathname.new(archived.fetch("private-path"))
      assert_path_exists Pathname.new(archived.fetch("public-path"))
      assert_equal before, Pathname.new(archived.fetch("private-path")).read
    end

    def test_the_replacement_is_published_before_anything_is_revoked
      rotate(revoke_platforms: ["gitlab"])

      assert_equal 1, @gitlab.added.size
      assert_equal ["k-old"], @gitlab.deleted
    end

    def test_each_platform_gets_a_unique_title
      rotate(key: key_spec(publish_to: %w[gitlab github]))

      titles = [@gitlab.added.first.last, @github.added.first.last]

      assert_equal 2, titles.uniq.size, "a shared title would make revocation ambiguous"
      titles.each { assert_match(/\Ak-[0-9a-f]{6}\z/, _1) }
    end

    def test_a_platform_outside_the_revoke_list_keeps_the_old_key
      @state = State.new({ "k" => key_entry(public_key: OLD_PUBLIC, published_to: { "gitlab" => "k-old", "github" => "k-old-gh" }) },
                         path: @home.join("state.yml"))

      rotate(key: key_spec(publish_to: %w[gitlab github]), revoke_platforms: ["gitlab"], keep_published: ["github"])

      assert_equal ["k-old"], @gitlab.deleted
      assert_empty @github.deleted
    end

    def test_a_kept_grant_is_reported_on_stderr
      rotate(keep_published: ["github"])

      assert_match(/stays published on github/, @reporter.string)
    end

    # github grants a signing key no ssh access, so verifying by login would always fail
    def test_a_signing_key_rotates_without_ssh_authentication
      refusing = FakePlatform.new("gitlab", verifies: false)
      @registry = Platform::Registry.new(@runner, adapters: { "gitlab" => refusing })

      rotate(key: key_spec(type: "signing"), revoke_platforms: ["gitlab"])

      assert_equal ["k-old"], refusing.deleted, "a signing rotation must not hinge on ssh login"
    end

    def test_a_signing_key_that_cannot_sign_aborts
      @signer = UnusableSigner.new
      before = @paths.private_key("k").read

      assert_raises(Rotator::VerificationFailed) { rotate(key: key_spec(type: "signing")) }
      assert_equal before, @paths.private_key("k").read, "the live key must survive"
    end

    def test_an_access_key_still_proves_it_can_log_in
      failing = FakePlatform.new("gitlab", verifies: false)
      @registry = Platform::Registry.new(@runner, adapters: { "gitlab" => failing })
      before = @paths.private_key("k").read

      assert_raises(Rotator::VerificationFailed) { rotate(revoke_platforms: ["gitlab"]) }

      assert_empty failing.deleted, "the old key must survive a failed verification"
      assert_equal before, @paths.private_key("k").read, "the live key must be untouched"
    end

    def test_state_records_the_rotation
      rotate

      entry = @state.key("k")

      assert_equal 1, entry.fetch("rotationCounter")
      assert_equal @keypair.public_key(@paths.private_key("k")), entry.fetch("public-key")
      assert_equal FIXED_NOW.utc.iso8601, entry.fetch("lastRotatedAt")
    end

    def test_state_records_the_new_titles
      rotate

      assert_equal [@gitlab.added.first.last], @state.published_to("k").values
    end

    def test_state_is_persisted
      rotate

      assert_equal 1, State.load(@home.join("state.yml")).key("k").fetch("rotationCounter")
    end

    def test_the_agent_reloads_the_new_key
      rotate

      assert @runner.ran?(/ssh-add -D/)
      assert @runner.ran?(%r{ssh-add .*/\.ssh/k$})
    end

    def test_a_signing_key_appends_to_allowed_signers_keeping_the_superseded_key
      @paths.allowed_signers.dirname.mkpath
      @paths.allowed_signers.write("u@example.com #{OLD_PUBLIC}\n")

      rotate(key: key_spec(type: "signing"))

      signers = @paths.allowed_signers.read

      assert_includes signers, "AAAAOLDMATERIAL"
      assert_includes signers, @keypair.public_key(@paths.private_key("k"))
      assert_match(/valid-after="\d{8}"/, signers)
    end

    def test_a_signing_rotation_backs_up_the_previous_files
      @paths.allowed_signers.dirname.mkpath
      @paths.allowed_signers.write("u@example.com #{OLD_PUBLIC}\n")
      @paths.known_hosts.write("gitlab.com ssh-ed25519 AAAAHOST\n")

      rotate(key: key_spec(type: "signing"))

      archived = @state.key("k").fetch("archived").first

      assert_path_exists Pathname.new(archived.fetch("allowed_signers"))
      assert_path_exists Pathname.new(archived.fetch("known_hosts"))
    end

    def test_a_signing_rotation_refreshes_known_hosts
      rotate(key: key_spec(type: "signing"))

      assert @runner.ran?(/ssh-keyscan gitlab\.com/)
    end

    def test_a_refreshed_known_hosts_drops_the_stale_entry_for_that_host
      @paths.known_hosts.write("gitlab.com ssh-ed25519 AAAASTALE\nexample.org ssh-ed25519 AAAAKEEP\n")
      @runner.stub(/ssh-keyscan/, stdout: "gitlab.com ssh-ed25519 AAAAFRESH\n")

      rotate(key: key_spec(type: "signing"))

      refreshed = @paths.known_hosts.read

      refute_includes refreshed, "AAAASTALE"
      assert_includes refreshed, "AAAAFRESH"
      assert_includes refreshed, "AAAAKEEP", "an unrelated host must survive the refresh"
    end

    # a key already gone is the state we wanted: aborting here would strand the rotation half done
    def test_an_already_absent_key_is_a_warning_not_a_failure
      @gitlab = VanishedPlatform.new("gitlab", host: "gitlab.com")
      @registry = Platform::Registry.new(@runner, adapters: { "gitlab" => @gitlab, "github" => @github })

      rotate(revoke_platforms: ["gitlab"])

      assert_match(/already gone from gitlab/, @reporter.string)
      assert_equal 1, @state.key("k").fetch("rotationCounter"), "the rotation must still complete"
    end

    # state naming a title the platform no longer has would fail every retry forever
    def test_state_is_written_after_each_delete_so_a_crash_cannot_wedge_the_retry
      @state = State.new(
        { "k" => key_entry(public_key: OLD_PUBLIC, published_to: { "gitlab" => "k-old", "github" => "k-old-gh" }) },
        path: @home.join("state.yml")
      )
      @github = CrashingPlatform.new("github", host: "github.com")
      @registry = Platform::Registry.new(@runner, adapters: { "gitlab" => @gitlab, "github" => @github })

      assert_raises(CrashingPlatform::Crash) do
        rotate(key: key_spec(publish_to: %w[gitlab github]), revoke_platforms: %w[gitlab github])
      end

      persisted = State.load(@home.join("state.yml"))

      assert_equal ["k-old-gh"], persisted.published_to("k").values,
                   "the deleted gitlab title must be gone from the written state"
    end

    def test_a_plain_key_leaves_allowed_signers_alone
      rotate

      refute_path_exists @paths.allowed_signers
      refute @runner.ran?(/ssh-keyscan/)
    end

    private

    def rotate(key: key_spec, revoke_platforms: [], keep_published: [])
      rotator.call(key, revoke_platforms: revoke_platforms, keep_published: keep_published)
    end

    def rotator
      Rotator.new(
        paths: @paths, state: @state, registry: @registry, keypair: @keypair,
        agent: Agent.new(@runner),
        allowed_signers: AllowedSigners.new(@paths.allowed_signers),
        known_hosts: KnownHosts.new(@paths.known_hosts, @runner),
        signer: @signer,
        clock: fixed_clock, reporter: @reporter
      )
    end

    def key_spec(type: "access", publish_to: ["gitlab"])
      Config::KeySpec.new(
        name: "k", type: type, email: "u@example.com", algorithm: "ssh-ed25519",
        publish_to: publish_to, revoke_platforms: nil
      )
    end

    def install_live_key
      @keypair.generate(private_path: @paths.private_key("k"), algorithm: "ssh-ed25519", comment: "u@example.com")
    end
  end
end
##[<] 🤖🤖
