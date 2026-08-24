##[>] 🤖🤖
require "psych"
require_relative "period"

module UserSshUtil
  # Config is the declared desired state: which keys exist, where they publish, when they rotate.
  class Config
    ValidationError = Class.new(StandardError)

    DEFAULT_ALGORITHM = "ecdsa-sha2-nistp521"
    GLOBAL_SCOPE = "global"

    # KeySpec is one declared key with every default already merged in.
    KeySpec = Struct.new(:name, :type, :email, :algorithm, :publish_to, :revoke_platforms, keyword_init: true)

    attr_reader :keys, :revoke_platforms

    # load reads and validates a config file.
    def self.load(path)
      raise ValidationError, "no config file at #{path}" unless File.exist?(path)

      new(Psych.safe_load_file(path.to_s) || {})
    end

    def initialize(raw)
      raise ValidationError, "config must be a mapping" unless raw.is_a?(Hash)

      #[why] nil when the key is absent, [] when it is present but empty: an explicit empty
      #   list opts out of revoking, an absent one falls through to revoking every grant
      @revoke_platforms = raw.key?("revokePlatforms") ? platform_list(raw["revokePlatforms"], "revokePlatforms") : nil
      @rotation_rules = parse_rotation(raw["rotation"])
      @keys = parse_keys(raw["keys"], raw["defaults"] || {})
    end

    # rotation_seconds is the period for a key, most specific rule first, nil when rotation is off.
    def rotation_seconds(key)
      rule = @rotation_rules.find { _1[:type] == key.type && _1[:scope] == key.name } ||
             @rotation_rules.find { _1[:type] == key.type && _1[:scope] == GLOBAL_SCOPE }
      rule && rule[:seconds]
    end

    private

    def parse_rotation(raw)
      return [] if raw.nil?
      raise ValidationError, "rotation must be a list" unless raw.is_a?(Array)

      raw.map do |entry|
        raise ValidationError, "rotation entry must be a mapping" unless entry.is_a?(Hash)
        raise ValidationError, "rotation entry needs a type" unless entry["type"]

        {
          type: entry["type"].to_s,
          scope: (entry["scope"] || GLOBAL_SCOPE).to_s,
          seconds: Period.seconds(entry["period"])
        }
      end
    end

    def parse_keys(raw, defaults)
      raise ValidationError, "config needs a keys mapping" unless raw.is_a?(Hash)

      raw.map { |name, spec| [name.to_s, key_spec(name.to_s, spec || {}, defaults)] }.to_h
    end

    def key_spec(name, spec, defaults)
      raise ValidationError, "key #{name} must be a mapping" unless spec.is_a?(Hash)

      email = spec["email"] || defaults["email"]
      raise ValidationError, "key #{name} has no email and defaults set none" unless email

      KeySpec.new(
        name: name,
        type: (spec["type"] || name).to_s,
        email: email.to_s,
        algorithm: (spec["algorithm"] || defaults["algorithm"] || DEFAULT_ALGORITHM).to_s,
        publish_to: platform_list(spec["publishTo"], "key #{name} publishTo"),
        revoke_platforms: spec.key?("revokePlatforms") ? platform_list(spec["revokePlatforms"], "key #{name} revokePlatforms") : nil
      )
    end

    def platform_list(raw, label)
      return [] if raw.nil?
      raise ValidationError, "#{label} must be a list" unless raw.is_a?(Array)

      raw.map(&:to_s)
    end
  end
end
##[<] 🤖🤖
