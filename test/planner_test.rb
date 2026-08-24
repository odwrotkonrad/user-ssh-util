##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class PlannerTest < Minitest::Test
    include TestSupport

    BOTH = %w[gitlab github].freeze
    DEFAULTS = { "email" => "u@example.com", "algorithm" => "ssh-ed25519" }.freeze

    def test_undeclared_key_is_created_then_published
      actions = plan(config_with("k" => { "publishTo" => BOTH }), state)

      create, publish = actions

      assert_instance_of Planner::Create, create
      assert_equal "k", create.key.name
      assert_instance_of Planner::Publish, publish
      assert_equal BOTH, publish.platforms
    end

    # generating over a keypair the user already has would destroy a key still published elsewhere
    def test_untracked_key_already_on_disk_is_adopted_not_created
      actions = plan(config_with("k" => { "publishTo" => BOTH }), state, on_disk: ["k"])

      adopt, publish = actions

      assert_instance_of Planner::Adopt, adopt
      assert_equal "k", adopt.key.name
      assert_equal BOTH, publish.platforms
    end

    def test_adoption_needs_the_key_absent_from_state_and_present_on_disk
      recorded = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }) })

      assert_empty plan(config_with("k" => { "publishTo" => ["gitlab"] }), recorded, on_disk: ["k"])
    end

    def test_a_key_on_disk_under_another_name_is_still_created
      actions = plan(config_with("k" => { "publishTo" => ["gitlab"] }), state, on_disk: ["other"])

      assert_instance_of Planner::Create, actions.first
    end

    def test_created_key_without_publish_targets_is_only_created
      actions = plan(config_with("k" => {}), state)

      assert_equal 1, actions.size
      assert_instance_of Planner::Create, actions.first
    end

    def test_reconciled_key_yields_no_actions
      recorded = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }) })

      assert_empty plan(config_with("k" => { "publishTo" => ["gitlab"] }), recorded)
    end

    def test_only_the_missing_platforms_are_published
      recorded = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }) })

      actions = plan(config_with("k" => { "publishTo" => BOTH }), recorded)

      assert_equal ["github"], sole(actions).platforms
    end

    def test_key_past_its_period_rotates
      actions = plan(rotating_config, stale_state)

      assert_instance_of Planner::Rotate, sole(actions)
    end

    def test_key_inside_its_period_does_not_rotate
      recorded = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }, last_rotated_at: FIXED_NOW - 86_400) })

      assert_empty plan(rotating_config, recorded)
    end

    def test_key_exactly_at_its_period_rotates
      due = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }, last_rotated_at: FIXED_NOW - 2_592_000) })

      assert_instance_of Planner::Rotate, sole(plan(rotating_config, due))
    end

    def test_a_forced_key_rotates_before_its_period_elapses
      fresh = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }, last_rotated_at: FIXED_NOW) })

      rotate = sole(plan(rotating_config, fresh, forced_keys: ["k"]))

      assert_instance_of Planner::Rotate, rotate
      assert rotate.forced, "a forced rotation must not ask again"
    end

    def test_a_forced_key_rotates_even_with_no_rotation_rule
      fresh = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }, last_rotated_at: FIXED_NOW) })
      config = config_with("k" => { "type" => "access", "publishTo" => ["gitlab"] })

      assert_instance_of Planner::Rotate, sole(plan(config, fresh, forced_keys: ["k"]))
    end

    def test_forcing_one_key_leaves_the_others_alone
      recorded = state({
        "k" => key_entry(published_to: { "gitlab" => "k-abc" }, last_rotated_at: FIXED_NOW),
        "other" => key_entry(published_to: { "gitlab" => "o-abc" }, last_rotated_at: FIXED_NOW)
      })
      config = config_with(
        "k" => { "type" => "access", "publishTo" => ["gitlab"] },
        "other" => { "type" => "access", "publishTo" => ["gitlab"] }
      )

      rotate = sole(plan(config, recorded, forced_keys: ["k"]))

      assert_equal "k", rotate.key.name
    end

    def test_a_due_key_is_not_marked_forced
      refute sole(plan(rotating_config, stale_state)).forced, "a scheduled rotation must ask first"
    end

    def test_key_with_no_rotation_rule_never_rotates
      recorded = state({ "k" => key_entry(published_to: { "gitlab" => "k-abc" }, last_rotated_at: Time.utc(2000)) })

      assert_empty plan(config_with("k" => { "publishTo" => ["gitlab"] }), recorded)
    end

    # the replacement is published and verified before anything is deleted, so revoking is the safe default
    def test_rotation_revokes_every_published_platform_by_default
      rotate = sole(plan(rotating_config, stale_state))

      assert_equal ["gitlab"], rotate.revoke_platforms
      assert_empty rotate.keep_published
    end

    def test_an_explicit_empty_top_level_list_opts_out_of_revoking
      config = rotating_config(publish_to: BOTH, extra: { "revokePlatforms" => [] })

      rotate = sole(plan(config, stale_state(published_to: both_titles)))

      assert_empty rotate.revoke_platforms
      assert_equal BOTH, rotate.keep_published
    end

    def test_rotation_revokes_only_the_named_platform
      rotate = sole(plan(rotating_config(publish_to: BOTH), stale_state(published_to: both_titles), revoke_override: ["gitlab"]))

      assert_equal ["gitlab"], rotate.revoke_platforms
      assert_equal ["github"], rotate.keep_published
    end

    def test_bare_revoke_flag_covers_every_publish_target
      rotate = sole(plan(rotating_config(publish_to: BOTH), stale_state(published_to: both_titles), revoke_override: :all))

      assert_equal BOTH, rotate.revoke_platforms
      assert_empty rotate.keep_published
    end

    def test_top_level_revoke_list_applies_when_the_key_sets_none
      config = rotating_config(publish_to: BOTH, extra: { "revokePlatforms" => ["gitlab"] })

      rotate = sole(plan(config, stale_state(published_to: both_titles)))

      assert_equal ["gitlab"], rotate.revoke_platforms
    end

    def test_per_key_revoke_list_beats_the_top_level_one
      config = rotating_config(
        publish_to: BOTH,
        key_extra: { "revokePlatforms" => ["github"] },
        extra: { "revokePlatforms" => ["gitlab"] }
      )

      rotate = sole(plan(config, stale_state(published_to: both_titles)))

      assert_equal ["github"], rotate.revoke_platforms
    end

    def test_flag_beats_both_config_scopes
      config = rotating_config(
        publish_to: BOTH,
        key_extra: { "revokePlatforms" => ["github"] },
        extra: { "revokePlatforms" => ["github"] }
      )

      rotate = sole(plan(config, stale_state(published_to: both_titles), revoke_override: ["gitlab"]))

      assert_equal ["gitlab"], rotate.revoke_platforms
    end

    def test_empty_per_key_list_overrides_a_top_level_list
      config = rotating_config(publish_to: BOTH, key_extra: { "revokePlatforms" => [] }, extra: { "revokePlatforms" => BOTH })

      rotate = sole(plan(config, stale_state(published_to: both_titles)))

      assert_empty rotate.revoke_platforms
    end

    def test_a_platform_never_published_is_not_revoked
      config = rotating_config(publish_to: BOTH, extra: { "revokePlatforms" => BOTH })

      rotate = sole(plan(config, stale_state(published_to: { "gitlab" => "k-abc" })))

      assert_equal ["gitlab"], rotate.revoke_platforms
    end

    def test_key_dropped_from_config_is_revoked_everywhere_by_default
      recorded = state({ "gone" => key_entry(published_to: both_titles) })

      revoke = sole(plan(config_with({}), recorded))

      assert_instance_of Planner::Revoke, revoke
      assert_equal "gone", revoke.name
      assert_equal BOTH, revoke.platforms
    end

    def test_an_explicit_empty_list_reports_an_orphan_instead_of_revoking
      recorded = state({ "gone" => key_entry(published_to: both_titles) })
      config = Config.new("defaults" => DEFAULTS, "revokePlatforms" => [], "keys" => {})

      orphan = sole(plan(config, recorded))

      assert_instance_of Planner::OrphanReported, orphan
      assert_equal BOTH, orphan.platforms
    end

    def test_orphan_is_revoked_only_from_the_named_platforms
      recorded = state({ "gone" => key_entry(published_to: both_titles) })

      revoke = sole(plan(config_with({}), recorded, revoke_override: ["gitlab"]))

      assert_instance_of Planner::Revoke, revoke
      assert_equal ["gitlab"], revoke.platforms
    end

    def test_orphan_revocation_honours_the_top_level_config_list
      recorded = state({ "gone" => key_entry(published_to: both_titles) })
      config = Config.new("defaults" => DEFAULTS, "revokePlatforms" => ["github"], "keys" => {})

      revoke = sole(plan(config, recorded))

      assert_equal ["github"], revoke.platforms
    end

    def test_orphan_published_nowhere_is_still_reported
      recorded = state({ "gone" => key_entry(published_to: {}) })

      orphan = sole(plan(config_with({}), recorded, revoke_override: :all))

      assert_instance_of Planner::OrphanReported, orphan
      assert_empty orphan.platforms
    end

    def test_orphans_are_planned_after_declared_keys
      recorded = state({ "gone" => key_entry(published_to: {}) })

      actions = plan(config_with("k" => { "publishTo" => ["gitlab"] }), recorded)

      assert_instance_of Planner::Create, actions.first
      assert_instance_of Planner::OrphanReported, actions.last
    end

    private

    def plan(config, recorded, revoke_override: nil, forced_keys: [], on_disk: [])
      Planner.new(
        config: config, state: recorded, now: FIXED_NOW,
        revoke_override: revoke_override, forced_keys: forced_keys,
        key_exists: ->(name) { on_disk.include?(name) }
      ).call
    end

    def sole(actions)
      assert_equal 1, actions.size, "expected one action, got #{actions.map(&:class).join(', ')}"
      actions.first
    end

    def config_with(keys, extra = {})
      Config.new({ "defaults" => DEFAULTS, "keys" => keys }.merge(extra))
    end

    def rotating_config(publish_to: ["gitlab"], key_extra: {}, extra: {})
      config_with(
        { "k" => { "type" => "access", "publishTo" => publish_to }.merge(key_extra) },
        { "rotation" => [{ "type" => "access", "period" => "1 month" }] }.merge(extra)
      )
    end

    def stale_state(published_to: { "gitlab" => "k-abc" })
      state({ "k" => key_entry(published_to: published_to, last_rotated_at: FIXED_NOW - 2_592_001) })
    end

    def both_titles = { "gitlab" => "k-abc", "github" => "k-def" }
  end
end
##[<] 🤖🤖
