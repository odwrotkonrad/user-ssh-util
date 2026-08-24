##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class CliTest < Minitest::Test
    include TestSupport

    CONFIG = <<~YML
      defaults:
        email: u@example.com
        algorithm: ssh-ed25519
      keys:
        id_access:
          type: access
          publishTo: [gitlab]
    YML

    def setup
      @home = Pathname.new(Dir.mktmpdir("cli"))
      @config_file = @home.join("config.yml")
      @config_file.write(CONFIG)
      @state_file = @home.join("state.yml")
      @out = StringIO.new
      @reporter = StringIO.new
      @runner = FakeRunner.new(passthrough: ["ssh-keygen"])
    end

    def teardown = FileUtils.remove_entry(@home)

    def test_an_unknown_subcommand_reports_usage
      assert_equal 2, cli_run(%w[frobnicate])
      assert_match(/usage: user-ssh-util/, @reporter.string)
    end

    def test_no_subcommand_reports_usage
      assert_equal 2, cli_run([])
    end

    def test_an_unparsable_flag_reports_usage
      assert_equal 2, cli_run(%w[sync --nonsense])
    end

    def test_a_missing_config_file_is_an_error_not_a_crash
      @config_file.delete

      assert_equal 1, cli_run(%w[sync])
      assert_match(/error:.*config/, @reporter.string)
    end

    def test_an_unparsable_period_is_reported
      @config_file.write("#{CONFIG}rotation:\n  - type: access\n    period: fortnight\n")

      assert_equal 1, cli_run(%w[sync])
      assert_match(/error:.*fortnight/, @reporter.string)
    end

    def test_dry_run_prints_a_plan_and_writes_nothing
      assert_equal 0, cli_run(%w[sync --dry-run])

      assert_match(/create id_access/, @out.string)
      assert_match(/publish id_access to gitlab/, @out.string)
      refute_path_exists @state_file, "a dry run must not write state"
      refute_path_exists @home.join(".ssh", "id_access"), "a dry run must not generate a key"
      refute @runner.ran?(/glab/), "a dry run must not call a platform"
    end

    def test_sync_creates_publishes_and_records
      assert_equal 0, cli_run(%w[sync])

      assert_path_exists @home.join(".ssh", "id_access")
      assert @runner.ran?(/glab ssh-key add/)
      assert_equal ["gitlab"], State.load(@state_file).published_to("id_access").keys
    end

    # regenerating over a hand-made keypair would destroy a key the user may have published already
    def test_sync_adopts_a_keypair_that_predates_state
      hand_made = write_hand_made_key

      assert_equal 0, cli_run(%w[sync])

      assert_equal hand_made, @home.join(".ssh", "id_access.pub").read, "the original material must survive"
      assert_match(/adopted id_access/, @out.string)
      assert_equal ["gitlab"], State.load(@state_file).published_to("id_access").keys
    end

    # state must describe the key that exists, not the one config asked for
    def test_adoption_records_the_algorithm_found_on_disk
      @config_file.write(CONFIG.sub("ssh-ed25519", "ecdsa-sha2-nistp521"))
      write_hand_made_key

      assert_equal 0, cli_run(%w[sync]), @reporter.string

      assert_equal "ssh-ed25519", State.load(@state_file).key("id_access").fetch("algo")
    end

    def test_an_adopted_algorithm_mismatch_is_reported
      @config_file.write(CONFIG.sub("ssh-ed25519", "ecdsa-sha2-nistp521"))
      write_hand_made_key

      cli_run(%w[sync])

      assert_match(/id_access on disk is ssh-ed25519.*declares ecdsa-sha2-nistp521/, @reporter.string)
    end

    def test_a_matching_algorithm_is_not_reported_as_drift
      write_hand_made_key

      cli_run(%w[sync])

      refute_match(/on disk is/, @reporter.string)
    end

    # adoption reads the public half: a lone private key would report success then crash
    def test_a_private_key_with_no_public_half_is_not_adopted
      write_hand_made_key
      @home.join(".ssh", "id_access.pub").delete

      assert_equal 1, cli_run(%w[sync])

      refute_match(/adopted id_access/, @out.string, "a half keypair must not report adoption")
      assert_match(/exists, pass --override/, @reporter.string)
    end

    def test_a_dry_run_names_adoption_rather_than_creation
      write_hand_made_key

      cli_run(%w[sync --dry-run])

      assert_match(/adopt id_access, already on disk/, @out.string)
      refute_match(/create id_access/, @out.string)
    end

    # a duplicate upload would be a second live grant that nothing later revokes
    def test_adoption_records_an_existing_platform_key_instead_of_publishing_a_duplicate
      hand_made = write_hand_made_key
      @runner.stub(/ssh-key list/, stdout: JSON.dump([{ "id" => 9, "title" => "made-by-hand", "key" => hand_made }]))

      cli_run(%w[sync])

      refute @runner.ran?(/glab ssh-key add/), "the key is already on gitlab"
      assert_equal({ "gitlab" => "made-by-hand" }, State.load(@state_file).published_to("id_access"))
    end

    def test_an_adopted_signing_key_enters_allowed_signers
      write_signing_config
      write_hand_made_key("id_sign")

      cli_run(%w[sync])

      assert_includes @home.join(".ssh", "allowed_signers").read, @home.join(".ssh", "id_sign.pub").read.split[1]
    end

    def test_a_second_sync_is_a_no_op
      cli_run(%w[sync])
      calls = @runner.calls.size
      @out.truncate(0)

      assert_equal 0, cli_run(%w[sync])
      assert_equal calls, @runner.calls.size, "a reconciled config must issue no further commands"
      assert_match(/nothing to do/, @out.string)
    end

    def test_a_key_dropped_from_config_is_revoked_by_default
      cli_run(%w[sync])
      @runner.stub(/ssh-key list/, stdout: listed_titles)
      @config_file.write("defaults:\n  email: u@example.com\nkeys: {}\n")

      assert_equal 0, cli_run(%w[sync])
      assert @runner.ran?(/glab ssh-key delete/)
      assert_empty State.load(@state_file).published_to("id_access")
    end

    # only the user can judge a key worthless, so a revoked key is moved aside, never deleted
    def test_a_revoked_key_is_archived_out_of_the_live_ssh_dir
      cli_run(%w[sync])
      before = @home.join(".ssh", "id_access").read
      @runner.stub(/ssh-key list/, stdout: listed_titles)
      @config_file.write("defaults:\n  email: u@example.com\nkeys: {}\n")

      assert_equal 0, cli_run(%w[sync])

      refute_path_exists @home.join(".ssh", "id_access"), "a revoked key must leave the live path"
      archived = State.load(@state_file).key("id_access").fetch("archived").first
      assert_equal before, Pathname.new(archived.fetch("private-path")).read
    end

    def test_a_revoked_signing_key_loses_its_allowed_signers_line
      @config_file.write("defaults:\n  email: u@example.com\n  algorithm: ssh-ed25519\nkeys:\n  id_sign:\n    type: signing\n    publishTo: [gitlab]\n")
      cli_run(%w[sync])
      body = @home.join(".ssh", "id_sign.pub").read.split[1]
      @runner.stub(/ssh-key list/, stdout: listed_titles)
      @config_file.write("defaults:\n  email: u@example.com\nkeys: {}\n")

      assert_equal 0, cli_run(%w[sync]), @reporter.string

      refute_includes @home.join(".ssh", "allowed_signers").read, body
    end

    def test_an_orphan_left_published_keeps_its_live_keypair
      cli_run(%w[sync])
      @config_file.write("revokePlatforms: []\ndefaults:\n  email: u@example.com\nkeys: {}\n")

      cli_run(%w[sync])

      assert_path_exists @home.join(".ssh", "id_access"), "nothing was revoked, so nothing is archived"
    end

    def test_an_explicit_empty_revoke_list_reports_the_orphan_instead
      cli_run(%w[sync])
      @config_file.write("revokePlatforms: []\ndefaults:\n  email: u@example.com\nkeys: {}\n")

      assert_equal 0, cli_run(%w[sync])
      assert_match(/orphan: id_access/, @reporter.string)
      refute @runner.ran?(/ssh-key delete/)
    end

    def test_revoke_flag_opts_the_orphan_into_deletion
      cli_run(%w[sync])
      @config_file.write("defaults:\n  email: u@example.com\nkeys: {}\n")
      @runner.stub(/ssh-key list/, stdout: listed_titles)

      assert_equal 0, cli_run(%w[sync --revoke-platforms=gitlab])
      assert @runner.ran?(/glab ssh-key delete/)
      assert_empty State.load(@state_file).published_to("id_access")
    end

    def test_revoking_moves_the_private_key_aside_rather_than_deleting_it
      cli_run(%w[sync])
      before = @home.join(".ssh", "id_access").read
      @config_file.write("defaults:\n  email: u@example.com\nkeys: {}\n")
      @runner.stub(/ssh-key list/, stdout: listed_titles)

      cli_run(%w[sync --revoke-platforms=gitlab])

      refute_path_exists @home.join(".ssh", "id_access")
      archived = State.load(@state_file).key("id_access").fetch("archived").first
      assert_equal before, Pathname.new(archived.fetch("private-path")).read,
                   "revocation moves a keypair, never destroys it"
    end

    # a created signing key never reached allowed_signers: only rotation wrote the file
    def test_creating_a_signing_key_registers_it_in_allowed_signers
      write_signing_config

      cli_run(%w[sync])

      signers = @home.join(".ssh", "allowed_signers").read

      assert_includes signers, @home.join(".ssh", "id_sign.pub").read.strip
      assert_includes signers, "u@example.com"
    end

    def test_creating_a_signing_key_keeps_existing_signers
      write_signing_config
      @home.join(".ssh").mkpath
      @home.join(".ssh", "allowed_signers").write("other@example.com ssh-ed25519 AAAASTRANGER other\n")

      cli_run(%w[sync])

      assert_includes @home.join(".ssh", "allowed_signers").read, "AAAASTRANGER"
    end

    # re-registering the same key must not append a duplicate entry
    def test_registering_a_signer_is_idempotent
      write_signing_config
      cli_run(%w[sync])
      once = @home.join(".ssh", "allowed_signers").read

      @state_file.delete
      cli_run(%w[sync])

      assert_equal once, @home.join(".ssh", "allowed_signers").read
    end

    def test_creating_an_access_key_leaves_allowed_signers_alone
      cli_run(%w[sync])

      refute_path_exists @home.join(".ssh", "allowed_signers")
    end

    def test_a_signing_key_is_published_with_the_signing_type
      write_signing_config

      cli_run(%w[sync])

      assert @runner.ran?(/glab ssh-key add .* --usage-type signing/)
      assert @runner.ran?(/gh ssh-key add .* --type signing/)
    end

    def test_a_due_key_asks_before_rotating
      make_due

      assert_equal 0, cli_run(%w[sync], prompt: FakePrompt.new(true))

      assert_equal 1, State.load(@state_file).key("id_access").fetch("rotationCounter")
    end

    def test_declining_the_prompt_leaves_the_key_alone
      make_due
      before = @home.join(".ssh", "id_access").read

      assert_equal 0, cli_run(%w[sync], prompt: FakePrompt.new(false))

      assert_equal 0, State.load(@state_file).key("id_access").fetch("rotationCounter")
      assert_equal before, @home.join(".ssh", "id_access").read
      assert_match(/skipped id_access, not confirmed/, @reporter.string)
    end

    def test_declining_revokes_nothing
      make_due

      cli_run(%w[sync], prompt: FakePrompt.new(false))

      refute @runner.ran?(/ssh-key delete/), "a declined rotation must not touch the platform"
    end

    def test_the_prompt_names_what_will_be_revoked
      make_due
      prompt = FakePrompt.new(false)

      cli_run(%w[sync], prompt: prompt)

      assert_match(/rotate id_access\?.*revoked from gitlab/, prompt.questions.first)
    end

    def test_yes_skips_the_prompt
      make_due

      assert_equal 0, cli_run(%w[sync --yes])
      assert_equal 1, State.load(@state_file).key("id_access").fetch("rotationCounter")
    end

    def test_force_rotate_keys_rotates_before_the_period_and_never_asks
      cli_run(%w[sync])
      @runner.stub(/ssh-key list/, stdout: listed_titles)
      prompt = FakePrompt.new(false)

      assert_equal 0, cli_run(%w[sync --force-rotate-keys=id_access], prompt: prompt)

      assert_empty prompt.questions, "naming the key is the confirmation"
      assert_equal 1, State.load(@state_file).key("id_access").fetch("rotationCounter")
    end

    def test_force_rotate_keys_rejects_an_unknown_name
      cli_run(%w[sync])

      assert_equal 2, cli_run(%w[sync --force-rotate-keys=nope])
      assert_match(/--force-rotate-keys names no such key: nope/, @reporter.string)
    end

    def test_force_rotate_keys_accepts_several_names
      write_two_key_config
      cli_run(%w[sync])
      @runner.stub(/ssh-key list/, stdout: listed_titles)

      assert_equal 0, cli_run(%w[sync --force-rotate-keys=id_access,id_other])

      loaded = State.load(@state_file)

      assert_equal 1, loaded.key("id_access").fetch("rotationCounter")
      assert_equal 1, loaded.key("id_other").fetch("rotationCounter")
    end

    def test_rotate_subcommand_never_prompts
      cli_run(%w[sync])
      @runner.stub(/ssh-key list/, stdout: listed_titles)
      prompt = FakePrompt.new(false)

      assert_equal 0, cli_run(%w[rotate id_access], prompt: prompt)

      assert_empty prompt.questions
      assert_equal 1, State.load(@state_file).key("id_access").fetch("rotationCounter")
    end

    def test_a_rotation_revokes_the_old_key_by_default
      cli_run(%w[sync])
      @runner.stub(/ssh-key list/, stdout: listed_titles)

      cli_run(%w[sync --force-rotate-keys=id_access])

      assert @runner.ran?(/glab ssh-key delete/)
    end

    def test_dry_run_marks_which_rotations_will_ask
      make_due

      cli_run(%w[sync --dry-run])

      assert_match(/rotate id_access.*\(asks first\)/, @out.string)
    end

    def test_pwd_resolves_both_paths_beside_the_working_directory
      paths = Paths.new(pwd: true, env: { "HOME" => @home.to_s }, cwd: @home.to_s)

      assert_equal @home.join("user-ssh-util.yml"), paths.config_file
      assert_equal @home.join("user-ssh-util.state.yml"), paths.state_file
    end

    def test_xdg_locations_are_the_default
      paths = Paths.new(env: { "HOME" => "/home/u", "XDG_CONFIG_HOME" => "/c", "XDG_DATA_HOME" => "/d" })

      assert_equal Pathname.new("/c/user-ssh-util/config.yml"), paths.config_file
      assert_equal Pathname.new("/d/user-ssh-util/state.yml"), paths.state_file
    end

    def test_xdg_falls_back_to_the_home_defaults
      paths = Paths.new(env: { "HOME" => "/home/u" })

      assert_equal Pathname.new("/home/u/.config/user-ssh-util/config.yml"), paths.config_file
      assert_equal Pathname.new("/home/u/.local/share/user-ssh-util/state.yml"), paths.state_file
    end

    def test_explicit_paths_beat_pwd
      paths = Paths.new(config_file: "/tmp/c.yml", state_file: "/tmp/s.yml", pwd: true, env: { "HOME" => @home.to_s })

      assert_equal Pathname.new("/tmp/c.yml"), paths.config_file
      assert_equal Pathname.new("/tmp/s.yml"), paths.state_file
    end

    def test_a_state_written_for_another_config_warns_and_continues
      @state_file.write(Psych.dump("configfile" => "/elsewhere/config.yml"))

      assert_equal 0, cli_run(%w[sync --dry-run])
      assert_match(%r{state was written for /elsewhere/config\.yml}, @reporter.string)
    end

    def test_a_matching_configfile_warns_about_nothing
      cli_run(%w[sync])
      @reporter.truncate(0)

      cli_run(%w[sync])

      refute_match(/warning/, @reporter.string)
    end

    def test_status_lists_each_recorded_key
      cli_run(%w[sync])
      @out.truncate(0)

      assert_equal 0, cli_run(%w[status])
      assert_match(/id_access\tssh-ed25519\tpublished on gitlab/, @out.string)
    end

    def test_status_on_an_empty_state_says_so
      assert_equal 0, cli_run(%w[status])
      assert_match(/no keys recorded/, @out.string)
    end

    def test_generate_creates_without_publishing
      assert_equal 0, cli_run(%w[generate id_access])

      assert_path_exists @home.join(".ssh", "id_access")
      refute @runner.ran?(/glab/), "generate must not publish"
    end

    def test_generate_refuses_to_clobber_without_override
      cli_run(%w[generate id_access])

      assert_equal 1, cli_run(%w[generate id_access])
      assert_match(/--override/, @reporter.string)
    end

    def test_generate_override_replaces_the_key
      cli_run(%w[generate id_access])
      before = @home.join(".ssh", "id_access").read

      assert_equal 0, cli_run(%w[generate id_access --override])
      refute_equal before, @home.join(".ssh", "id_access").read
    end

    def test_generate_rejects_a_name_the_config_does_not_declare
      assert_equal 2, cli_run(%w[generate not_declared])
      assert_match(/no key named not_declared/, @reporter.string)
    end

    def test_publish_targets_the_named_platform_only
      cli_run(%w[generate id_access])

      assert_equal 0, cli_run(%w[publish id_access --platform=github])
      assert @runner.ran?(/gh ssh-key add/)
      refute @runner.ran?(/glab ssh-key add/)
    end

    def test_publish_needs_a_key_name
      assert_equal 2, cli_run(%w[publish])
      assert_match(/needs a key name/, @reporter.string)
    end

    def test_remove_deletes_the_recorded_title
      cli_run(%w[sync])
      @runner.stub(/ssh-key list/, stdout: listed_titles)

      assert_equal 0, cli_run(%w[remove id_access --platform=gitlab])
      assert @runner.ran?(/glab ssh-key delete/)
      assert_empty State.load(@state_file).published_to("id_access")
    end

    def test_remove_rejects_a_platform_the_key_was_never_published_to
      cli_run(%w[sync])

      assert_equal 2, cli_run(%w[remove id_access --platform=github])
      assert_match(/not recorded as published on github/, @reporter.string)
    end

    def test_rotate_replaces_a_key_regardless_of_its_period
      cli_run(%w[sync])
      before = @home.join(".ssh", "id_access").read
      @runner.stub(/ssh-key list/, stdout: listed_titles)

      assert_equal 0, cli_run(%w[rotate id_access])

      refute_equal before, @home.join(".ssh", "id_access").read
      assert_equal 1, State.load(@state_file).key("id_access").fetch("rotationCounter")
    end

    private

    # FakePrompt answers every question the same way and records what it was asked.
    class FakePrompt
      attr_reader :questions

      def initialize(answer)
        @answer = answer
        @questions = []
      end

      def confirm?(question)
        @questions << question
        @answer
      end
    end

    # make_due creates the key, then backdates it past the rotation period
    def make_due
      @config_file.write("#{CONFIG}rotation:\n  - type: access\n    period: 1 month\n")
      cli_run(%w[sync])
      @runner.stub(/ssh-key list/, stdout: listed_titles)
      state = @state_file.read.sub(/lastRotatedAt: .*/, "lastRotatedAt: '2020-01-01T00:00:00Z'")
      @state_file.write(state)
    end

    # write_hand_made_key generates a keypair the way a user would, leaving state untouched
    def write_hand_made_key(name = "id_access")
      Keypair.new(CommandRunner.new).generate(
        private_path: @home.join(".ssh", name), algorithm: "ssh-ed25519", comment: "u@example.com"
      )
      @home.join(".ssh", "#{name}.pub").read
    end

    def write_two_key_config
      @config_file.write(<<~YML)
        defaults:
          email: u@example.com
          algorithm: ssh-ed25519
        keys:
          id_access:
            type: access
            publishTo: [gitlab]
          id_other:
            type: access
            publishTo: [gitlab]
      YML
    end

    def write_signing_config
      @config_file.write(<<~YML)
        defaults:
          email: u@example.com
          algorithm: ssh-ed25519
        keys:
          id_sign:
            type: signing
            publishTo: [gitlab, github]
      YML
    end

    def cli_run(argv, prompt: FakePrompt.new(true))
      cli = Cli.new(
        runner: @runner, clock: fixed_clock, prompt: prompt, out: @out, reporter: @reporter,
        env: { "HOME" => @home.to_s, "XDG_CONFIG_HOME" => @home.to_s, "XDG_DATA_HOME" => @home.to_s }
      )
      cli.call(argv + ["--config-file=#{@config_file}", "--state-file=#{@state_file}"])
    end

    # listed_titles echoes back every title state recorded, so any delete can resolve it
    def listed_titles
      loaded = State.load(@state_file)
      entries = loaded.names.flat_map { |name| loaded.published_to(name).values }
      JSON.dump(entries.each_with_index.map { |title, index| { "id" => 100 + index, "title" => title } })
    end
  end
end
##[<] 🤖🤖
