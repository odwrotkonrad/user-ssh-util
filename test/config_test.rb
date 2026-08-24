##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class ConfigTest < Minitest::Test
    DEFAULTS = { "email" => "u@example.com", "algorithm" => "ssh-ed25519" }.freeze

    def test_defaults_merge_into_every_key
      config = build("keys" => { "id_access" => { "type" => "access" } })
      key = config.keys.fetch("id_access")

      assert_equal "u@example.com", key.email
      assert_equal "ssh-ed25519", key.algorithm
      assert_equal "access", key.type
    end

    def test_per_key_values_override_defaults
      config = build("keys" => { "id_sign" => { "email" => "other@example.com", "algorithm" => "ecdsa-sha2-nistp521" } })
      key = config.keys.fetch("id_sign")

      assert_equal "other@example.com", key.email
      assert_equal "ecdsa-sha2-nistp521", key.algorithm
    end

    def test_type_defaults_to_the_key_name
      config = build("keys" => { "signing" => {} })

      assert_equal "signing", config.keys.fetch("signing").type
    end

    def test_algorithm_falls_back_to_the_library_default
      config = Config.new("defaults" => { "email" => "u@example.com" }, "keys" => { "k" => {} })

      assert_equal Config::DEFAULT_ALGORITHM, config.keys.fetch("k").algorithm
    end

    def test_missing_email_is_rejected
      error = assert_raises(Config::ValidationError) { Config.new("keys" => { "k" => {} }) }

      assert_match(/no email/, error.message)
    end

    def test_keys_mapping_is_required
      assert_raises(Config::ValidationError) { Config.new({}) }
    end

    def test_publish_to_defaults_to_nothing
      config = build("keys" => { "k" => {} })

      assert_empty config.keys.fetch("k").publish_to
    end

    def test_absent_per_key_revoke_list_is_nil_not_empty
      config = build("revokePlatforms" => ["gitlab"], "keys" => { "k" => {} })

      assert_nil config.keys.fetch("k").revoke_platforms, "an unset per-key list must fall through to the top level"
      assert_equal ["gitlab"], config.revoke_platforms
    end

    def test_explicit_empty_per_key_revoke_list_overrides_the_top_level
      config = build("revokePlatforms" => ["gitlab"], "keys" => { "k" => { "revokePlatforms" => [] } })

      assert_empty config.keys.fetch("k").revoke_platforms
    end

    def test_global_rotation_rule_applies_to_its_type
      config = build(
        "rotation" => [{ "type" => "access", "period" => "1 month" }],
        "keys" => { "id_access" => { "type" => "access" }, "id_sign" => { "type" => "signing" } }
      )

      assert_equal 2_592_000, config.rotation_seconds(config.keys.fetch("id_access"))
      assert_nil config.rotation_seconds(config.keys.fetch("id_sign")), "an untyped key must not inherit a rule"
    end

    def test_key_scoped_rule_beats_a_global_rule_of_the_same_type
      config = build(
        "rotation" => [
          { "type" => "access", "period" => "1 year", "scope" => "global" },
          { "type" => "access", "period" => "1 day", "scope" => "id_access" }
        ],
        "keys" => { "id_access" => { "type" => "access" }, "id_other" => { "type" => "access" } }
      )

      assert_equal 86_400, config.rotation_seconds(config.keys.fetch("id_access"))
      assert_equal 31_536_000, config.rotation_seconds(config.keys.fetch("id_other"))
    end

    def test_absent_period_disables_rotation_for_that_rule
      config = build("rotation" => [{ "type" => "access" }], "keys" => { "k" => { "type" => "access" } })

      assert_nil config.rotation_seconds(config.keys.fetch("k"))
    end

    def test_rotation_must_be_a_list
      assert_raises(Config::ValidationError) do
        build("rotation" => { "type" => "access" }, "keys" => { "k" => {} })
      end
    end

    def test_rotation_entry_needs_a_type
      assert_raises(Config::ValidationError) { build("rotation" => [{ "period" => "1 day" }], "keys" => { "k" => {} }) }
    end

    def test_publish_to_must_be_a_list
      assert_raises(Config::ValidationError) { build("keys" => { "k" => { "publishTo" => "gitlab" } }) }
    end

    private

    def build(raw) = Config.new({ "defaults" => DEFAULTS }.merge(raw))
  end
end
##[<] 🤖🤖
