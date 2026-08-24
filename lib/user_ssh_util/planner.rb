##[>] 🤖🤖
require "time"

module UserSshUtil
  # Planner turns config, state and a clock into an ordered action list. Pure: no disk, no network.
  class Planner
    Create = Struct.new(:key, keyword_init: true)
    Adopt = Struct.new(:key, keyword_init: true)
    Publish = Struct.new(:key, :platforms, keyword_init: true)
    Rotate = Struct.new(:key, :revoke_platforms, :keep_published, :forced, keyword_init: true)
    Revoke = Struct.new(:name, :platforms, keyword_init: true)
    OrphanReported = Struct.new(:name, :platforms, keyword_init: true)

    def initialize(config:, state:, now:, revoke_override: nil, forced_keys: [], key_exists: ->(_name) { false })
      @config = config
      @state = state
      @now = now
      @revoke_override = revoke_override
      @forced_keys = forced_keys
      @key_exists = key_exists
    end

    # call returns the ordered actions reconciling state to config.
    def call
      @config.keys.values.flat_map { actions_for(_1) } + orphan_actions
    end

    private

    #[why] a keypair on disk that state never recorded is adopted, not recreated: generating over
    #   it would destroy a key the user still has published somewhere this tool cannot see
    def actions_for(key)
      return [untracked_action(key), publish(key, key.publish_to)].compact unless @state.key?(key.name)

      forced = forced?(key)
      return [rotate(key, forced: forced)] if forced || due_for_rotation?(key)

      [publish(key, key.publish_to - @state.published_to(key.name).keys)].compact
    end

    def untracked_action(key)
      @key_exists.call(key.name) ? Adopt.new(key: key) : Create.new(key: key)
    end

    def forced?(key) = @forced_keys.include?(key.name)

    def publish(key, platforms)
      return nil if platforms.empty?

      Publish.new(key: key, platforms: platforms)
    end

    def rotate(key, forced: false)
      published = @state.published_to(key.name).keys
      revoking = effective_revoke_platforms(key, published)
      Rotate.new(
        key: key,
        revoke_platforms: published & revoking,
        keep_published: published - revoking,
        forced: forced
      )
    end

    def due_for_rotation?(key)
      seconds = @config.rotation_seconds(key)
      return false if seconds.nil?

      last = @state.key(key.name)["lastRotatedAt"]
      return false if last.nil?

      @now - Time.parse(last) >= seconds
    end

    def orphan_actions
      (@state.names - @config.keys.keys).map do |name|
        published = @state.published_to(name).keys
        revoking = published & orphan_revoke_platforms(published)
        next OrphanReported.new(name: name, platforms: published) if revoking.empty?

        Revoke.new(name: name, platforms: revoking)
      end
    end

    #[why] the superseded key is revoked by default: the replacement is published and proven
    #   to authenticate before anything is deleted, so leaving the old grant is the riskier default
    def effective_revoke_platforms(key, published)
      return resolve_override(key.publish_to) if @revoke_override
      return key.revoke_platforms if key.revoke_platforms
      return @config.revoke_platforms if @config.revoke_platforms

      published
    end

    def orphan_revoke_platforms(published)
      return resolve_override(published) if @revoke_override
      return @config.revoke_platforms if @config.revoke_platforms

      published
    end

    def resolve_override(fallback)
      @revoke_override == :all ? fallback : @revoke_override
    end
  end
end
##[<] 🤖🤖
