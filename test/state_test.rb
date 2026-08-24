##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class StateTest < Minitest::Test
    include TestSupport

    def setup
      @dir = Pathname.new(Dir.mktmpdir("state"))
      @path = @dir.join("nested", "state.yml")
    end

    def teardown = FileUtils.remove_entry(@dir)

    def test_absent_file_loads_as_empty_state
      loaded = State.load(@path, configfile: "/etc/config.yml")

      assert_empty loaded.names
      assert_equal "/etc/config.yml", loaded.configfile
    end

    def test_write_creates_missing_directories
      recorded = State.new({}, path: @path, configfile: "/etc/config.yml")
      recorded.write

      assert_path_exists @path
    end

    def test_written_state_round_trips
      recorded = State.new({}, path: @path, configfile: "/etc/config.yml")
      record_key(recorded)
      recorded.record_published("k", "gitlab", "k-abc")
      recorded.write

      reloaded = State.load(@path)

      assert_equal({ "gitlab" => "k-abc" }, reloaded.published_to("k"))
      assert_equal "/etc/config.yml", reloaded.configfile
    end

    def test_write_leaves_no_temporary_file_behind
      recorded = State.new({}, path: @path, configfile: "c")
      recorded.write

      assert_equal ["state.yml"], @path.dirname.children.map { _1.basename.to_s }
    end

    def test_write_replaces_the_previous_content_atomically
      recorded = State.new({}, path: @path, configfile: "c")
      record_key(recorded)
      recorded.write
      recorded.record_published("k", "gitlab", "k-abc")
      recorded.write

      assert_equal({ "gitlab" => "k-abc" }, State.load(@path).published_to("k"))
    end

    def test_recorded_key_carries_every_documented_field
      recorded = State.new({}, path: @path)
      record_key(recorded)

      entry = recorded.key("k")

      assert_equal 0, entry.fetch("rotationCounter")
      assert_equal FIXED_NOW.utc.iso8601, entry.fetch("firstCreatedAt")
      assert_equal FIXED_NOW.utc.iso8601, entry.fetch("lastRotatedAt")
      assert_empty entry.fetch("publishedTo")
      assert_empty entry.fetch("archived")
    end

    def test_revoking_drops_only_that_platform
      recorded = State.new({}, path: @path)
      record_key(recorded)
      recorded.record_published("k", "gitlab", "k-abc")
      recorded.record_published("k", "github", "k-def")

      recorded.record_revoked("k", "gitlab")

      assert_equal({ "github" => "k-def" }, recorded.published_to("k"))
    end

    def test_archive_preserves_the_superseded_record
      recorded = State.new({ "k" => key_entry(published_to: { "gitlab" => "k-old" }) }, path: @path)

      recorded.archive("k", backup_private: "/b/k", backup_public: "/b/k.pub")

      archived = recorded.key("k").fetch("archived").first

      assert_equal "/b/k", archived.fetch("private-path")
      assert_equal({ "gitlab" => "k-old" }, archived.fetch("publishedTo"))
    end

    def test_archive_records_signing_backups_when_given
      recorded = State.new({ "k" => key_entry }, path: @path)

      recorded.archive(
        "k", backup_private: "/b/k", backup_public: "/b/k.pub",
        allowed_signers_backup: "/b/allowed_signers", known_hosts_backup: "/b/known_hosts"
      )

      archived = recorded.key("k").fetch("archived").first

      assert_equal "/b/allowed_signers", archived.fetch("allowed_signers")
      assert_equal "/b/known_hosts", archived.fetch("known_hosts")
    end

    def test_archive_omits_signing_backups_for_a_plain_key
      recorded = State.new({ "k" => key_entry }, path: @path)

      recorded.archive("k", backup_private: "/b/k", backup_public: "/b/k.pub")

      refute recorded.key("k").fetch("archived").first.key?("allowed_signers")
    end

    def test_rotation_bumps_the_counter_and_clears_stale_grants
      recorded = State.new({ "k" => key_entry(published_to: { "gitlab" => "k-old" }, counter: 2) }, path: @path)
      later = FIXED_NOW + 3600

      recorded.record_rotated("k", public_key: "ssh-ed25519 NEW c", now: later)

      entry = recorded.key("k")

      assert_equal 3, entry.fetch("rotationCounter")
      assert_equal "ssh-ed25519 NEW c", entry.fetch("public-key")
      assert_equal later.utc.iso8601, entry.fetch("lastRotatedAt")
      assert_empty entry.fetch("publishedTo"), "the old titles must not survive a rotation"
    end

    def test_archived_entries_survive_a_rotation
      recorded = State.new({ "k" => key_entry }, path: @path)
      recorded.archive("k", backup_private: "/b/k", backup_public: "/b/k.pub")
      recorded.record_rotated("k", public_key: "ssh-ed25519 NEW c", now: FIXED_NOW)

      assert_equal 1, recorded.key("k").fetch("archived").size
    end

    # a hand-edited timestamp loses its quotes, so yaml types it as a Time rather than a string
    def test_an_unquoted_timestamp_loads_and_normalizes
      @path.dirname.mkpath
      @path.write(Psych.dump("configfile" => "/c.yml", "k" => key_entry.merge("lastRotatedAt" => Time.utc(2020, 1, 1))))

      entry = State.load(@path).key("k")

      assert_equal "2020-01-01T00:00:00Z", entry.fetch("lastRotatedAt")
      assert_kind_of String, entry.fetch("lastRotatedAt")
    end

    def test_a_hand_edited_state_survives_a_round_trip
      @path.dirname.mkpath
      @path.write("configfile: /c.yml\nk:\n  lastRotatedAt: 2020-01-01T00:00:00Z\n  publishedTo: {}\n  archived: []\n")

      reloaded = State.load(@path)
      reloaded.write

      assert_equal "2020-01-01T00:00:00Z", State.load(@path).key("k").fetch("lastRotatedAt")
    end

    def test_configfile_is_not_mistaken_for_a_key
      recorded = State.new({ "configfile" => "/etc/config.yml", "k" => key_entry })

      assert_equal ["k"], recorded.names
    end

    private

    def record_key(recorded)
      recorded.record_created(
        "k", private_path: "/home/u/.ssh/k", public_path: "/home/u/.ssh/k.pub",
        public_key: "ssh-ed25519 AAAA c", email: "u@example.com",
        algo: "ssh-ed25519", type: "access", now: FIXED_NOW
      )
    end
  end
end
##[<] 🤖🤖
