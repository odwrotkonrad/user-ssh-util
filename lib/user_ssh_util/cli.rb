##[>] 🤖🤖
require "optparse"
require_relative "paths"
require_relative "period"
require_relative "config"
require_relative "state"
require_relative "keypair"
require_relative "command_runner"
require_relative "platform/registry"
require_relative "allowed_signers"
require_relative "known_hosts"
require_relative "agent"
require_relative "rotator"
require_relative "signer"
require_relative "prompt"
require_relative "sync"

module UserSshUtil
  # Cli dispatches one subcommand, resolving paths and wiring the collaborators it needs.
  class Cli
    UsageError = Class.new(StandardError)

    SUBCOMMANDS = %w[sync generate publish remove rotate status].freeze

    USAGE = <<~TEXT
      usage: user-ssh-util <command> [options]

        sync      [--config-file=P] [--state-file=P] [--pwd] [--dry-run] [--yes]
                  [--revoke-platforms[=gitlab,github]]
                  [--force-rotate-keys=name,name]
        generate  [name] [--override]
        publish   <name> [--platform=gitlab,github]
        remove    <name> [--platform=gitlab,github]
        rotate    <name>
        status
    TEXT

    Clock = Struct.new(:frozen) do
      def now = frozen || Time.now
    end

    def initialize(runner: CommandRunner.new, clock: Clock.new(nil), env: ENV, prompt: nil,
                   out: $stdout, reporter: $stderr)
      @runner = runner
      @clock = clock
      @env = env
      @prompt = prompt
      @out = out
      @reporter = reporter
    end

    # call runs one subcommand, returning a process exit status.
    def call(argv)
      command = argv.first
      raise UsageError, USAGE unless SUBCOMMANDS.include?(command)

      options = parse(argv.drop(1))
      public_send(command, options)
      0
    rescue UsageError => e
      @reporter.puts(e.message)
      2
    rescue Config::ValidationError, Period::ParseError, CommandFailed, Keypair::ExistsError,
           Rotator::VerificationFailed, Platform::Registry::UnknownPlatform => e
      @reporter.puts("error: #{e.message}")
      1
    end

    # sync reconciles every declared key, rotating whatever is past its period.
    def sync(options)
      config, state = load_pair(options)
      forced = forced_keys(options, config)
      sync_for(options, config, state).call(
        revoke_override: options[:revoke_platforms],
        forced_keys: forced,
        dry_run: options[:dry_run]
      )
    end

    # generate creates one declared keypair without publishing it.
    def generate(options)
      config, state = load_pair(options)
      names = options[:args].empty? ? config.keys.keys : options[:args]
      names.each { generate_one(config, state, options, _1) }
    end

    # publish uploads an existing key to the platforms named, defaulting to its publishTo.
    def publish(options)
      config, state = load_pair(options)
      key = fetch_key(config, require_name(options))
      platforms = options[:platform] || key.publish_to
      sync_for(options, config, state).publish(key, platforms)
    end

    # remove deletes a key from the platforms named, immediately and explicitly.
    def remove(options)
      config, state = load_pair(options)
      name = require_name(options)
      platforms = options[:platform] || state.published_to(name).keys
      platforms.each do |platform|
        title = state.published_to(name)[platform]
        raise UsageError, "#{name} is not recorded as published on #{platform}" unless title

        registry.fetch(platform).delete(title)
        state.record_revoked(name, platform)
        state.write
        @out.puts("removed #{name} from #{platform}")
      end
    end

    # rotate replaces one key now, regardless of its period.
    #
    # Naming the key is the confirmation, so this never prompts.
    def rotate(options)
      config, state = load_pair(options)
      name = require_name(options)
      fetch_key(config, name)
      sync_for(options, config, state).call(revoke_override: options[:revoke_platforms], forced_keys: [name])
    end

    # status prints each recorded key, where it is published and when it last rotated.
    def status(options)
      _config, state = load_pair(options)
      return @out.puts("no keys recorded") if state.names.empty?

      state.names.each { @out.puts(status_line(state, _1)) }
    end

    private

    def status_line(state, name)
      entry = state.key(name)
      where = entry.fetch("publishedTo", {}).keys
      published = where.empty? ? "unpublished" : "published on #{where.join(', ')}"
      "#{name}\t#{entry['algo']}\t#{published}\trotated #{entry['lastRotatedAt']} (#{entry['rotationCounter']}x)"
    end

    def generate_one(config, state, options, name)
      key = fetch_key(config, name)
      private_path = paths(options).private_key(name)
      public_path = keypair.generate(
        private_path: private_path, algorithm: key.algorithm, comment: key.email, override: options[:override]
      )
      state.record_created(
        name, private_path: private_path, public_path: public_path,
        public_key: keypair.public_key(private_path), email: key.email,
        algo: key.algorithm, type: key.type, now: @clock.now
      )
      state.write
      @out.puts("created #{name}")
    end

    def sync_for(options, config, state)
      Sync.new(
        paths: paths(options), config: config, state: state, registry: registry,
        keypair: keypair, rotator: rotator(options, state),
        allowed_signers: AllowedSigners.new(paths(options).allowed_signers),
        clock: @clock, prompt: prompt(options), out: @out, reporter: @reporter
      )
    end

    def prompt(options)
      @prompt || Prompt.new(assume_yes: options[:assume_yes], output: @reporter)
    end

    #[why] a mistyped name would otherwise rotate nothing and report success
    def forced_keys(options, config)
      names = options[:forced_keys] || []
      unknown = names - config.keys.keys
      raise UsageError, "--force-rotate-keys names no such key: #{unknown.join(', ')}" if unknown.any?

      names
    end

    def fetch_key(config, name)
      config.keys.fetch(name) { raise UsageError, "no key named #{name} in config" }
    end

    def require_name(options)
      options[:args].first or raise UsageError, "this command needs a key name"
    end

    def load_pair(options)
      resolved = paths(options)
      config = Config.load(resolved.config_file)
      state = State.load(resolved.state_file, configfile: resolved.config_file)
      warn_on_config_drift(state, resolved)
      state.configfile = resolved.config_file.to_s
      [config, state]
    end

    def warn_on_config_drift(state, resolved)
      return if state.configfile.nil? || state.configfile == resolved.config_file.to_s

      @reporter.puts("warning: state was written for #{state.configfile}, now using #{resolved.config_file}")
    end

    def paths(options)
      @paths ||= Paths.new(
        config_file: options[:config_file], state_file: options[:state_file], pwd: options[:pwd], env: @env
      )
    end

    def registry = @registry ||= Platform::Registry.new(@runner)

    def keypair = @keypair ||= Keypair.new(@runner)

    def rotator(options, state)
      resolved = paths(options)
      Rotator.new(
        paths: resolved, state: state, registry: registry, keypair: keypair,
        agent: Agent.new(@runner),
        allowed_signers: AllowedSigners.new(resolved.allowed_signers),
        known_hosts: KnownHosts.new(resolved.known_hosts, @runner),
        signer: Signer.new(@runner),
        clock: @clock, reporter: @reporter
      )
    end

    def parse(argv)
      options = { args: [] }
      parser = OptionParser.new do |o|
        o.on("--config-file=PATH") { options[:config_file] = _1 }
        o.on("--state-file=PATH") { options[:state_file] = _1 }
        o.on("--pwd") { options[:pwd] = true }
        o.on("--dry-run") { options[:dry_run] = true }
        o.on("--override") { options[:override] = true }
        o.on("--platform=LIST") { options[:platform] = _1.split(",") }
        o.on("--revoke-platforms[=LIST]") { options[:revoke_platforms] = _1 ? _1.split(",") : :all }
        o.on("--force-rotate-keys=LIST") { options[:forced_keys] = _1.split(",") }
        o.on("--yes") { options[:assume_yes] = true }
      end
      options[:args] = parser.parse(argv)
      options
    rescue OptionParser::ParseError => e
      raise UsageError, e.message
    end
  end
end
##[<] 🤖🤖
