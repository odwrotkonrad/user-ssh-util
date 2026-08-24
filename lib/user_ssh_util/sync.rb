##[>] 🤖🤖
require "securerandom"
require "time"
require_relative "planner"
require_relative "prompt"

module UserSshUtil
  # Sync executes the planner's actions against disk and the platforms.
  class Sync
    TITLE_SUFFIX_BYTES = 3

    SIGNING_TYPE = "signing"

    def initialize(paths:, config:, state:, registry:, keypair:, rotator:, allowed_signers:, clock:,
                   prompt: Prompt.new, out: $stdout, reporter: $stderr)
      @paths = paths
      @config = config
      @state = state
      @registry = registry
      @keypair = keypair
      @rotator = rotator
      @allowed_signers = allowed_signers
      @clock = clock
      @prompt = prompt
      @out = out
      @reporter = reporter
    end

    # call plans, then either prints the plan or runs it.
    def call(revoke_override: nil, forced_keys: [], dry_run: false)
      actions = Planner.new(
        config: @config, state: @state, now: @clock.now,
        revoke_override: revoke_override, forced_keys: forced_keys,
        key_exists: ->(name) { adoptable?(name) }
      ).call
      return print_plan(actions) if dry_run

      actions.each { execute(_1) }
      @out.puts("nothing to do") if actions.empty?
      actions
    end

    # publish uploads a key's public half to each platform, recording the title it landed under.
    def publish(key, platforms)
      private_path = @paths.private_key(key.name)
      public_path = @keypair.public_path_for(private_path)
      public_key = @keypair.public_key(private_path)
      platforms.each { publish_one(key, _1, public_path, public_key) }
    end

    private

    #[why] both halves or nothing: adoption reads the public key, so a lone private half would
    #   be reported adopted and then crash. a half-written keypair is regenerated instead
    def adoptable?(name)
      private_path = @paths.private_key(name)
      private_path.exist? && @keypair.public_path_for(private_path).exist?
    end

    #[why] an already-published key is recorded under the title the platform gave it, never
    #   uploaded again: a duplicate would be a second live grant nothing later revokes
    def publish_one(key, platform, public_path, public_key)
      adapter = @registry.fetch(platform)
      existing = adapter.find_by_public_key(public_key)
      title = existing || adapter.add(public_path, mint_title(key.name), key_type: key.type)
      @state.record_published(key.name, platform, title)
      @state.write
      @out.puts(existing ? "adopted #{key.name} on #{platform} as #{title}" : "published #{key.name} to #{platform} as #{title}")
    end

    def execute(action)
      case action
      when Planner::Create then create(action.key)
      when Planner::Adopt then adopt(action.key)
      when Planner::Publish then publish(action.key, action.platforms)
      when Planner::Rotate then rotate(action)
      when Planner::Revoke then revoke(action)
      when Planner::OrphanReported then report_orphan(action)
      end
    end

    def create(key)
      private_path = @paths.private_key(key.name)
      public_path = @keypair.generate(private_path: private_path, algorithm: key.algorithm, comment: key.email)
      @out.puts("created #{key.name}")
      register_signer(key, private_path)

      @state.record_created(
        key.name,
        private_path: private_path,
        public_path: public_path,
        public_key: @keypair.public_key(private_path),
        email: key.email,
        algo: key.algorithm,
        type: key.type,
        now: @clock.now
      )
      @state.write
    end

    #[why] the keypair predates state, so its mtime is the only record of when it first existed
    #[why] the algorithm is read off the key, never taken from config: the file is the truth, and
    #   recording the declared one would have state describe material that is not there
    def adopt(key)
      private_path = @paths.private_key(key.name)
      public_key = @keypair.public_key(private_path)
      @out.puts("adopted #{key.name}")
      register_signer(key, private_path)

      warn_on_algorithm_drift(key, public_key)
      @state.record_created(
        key.name,
        private_path: private_path,
        public_path: @keypair.public_path_for(private_path),
        public_key: public_key,
        email: key.email,
        algo: algorithm_of(public_key),
        type: key.type,
        now: @clock.now
      )
      @state.key(key.name)["firstCreatedAt"] = private_path.mtime.utc.iso8601
      @state.write
    end

    def algorithm_of(public_key) = public_key.to_s.split.first

    #[why] the mismatch is reported, never corrected: rotation would replace the adopted key with
    #   the declared algorithm, and doing that silently is not this command's call to make
    def warn_on_algorithm_drift(key, public_key)
      found = algorithm_of(public_key)
      return if found == key.algorithm

      @reporter.puts(
        "warning: #{key.name} on disk is #{found}, config declares #{key.algorithm}, " \
        "recording #{found}: the next rotation will replace it with #{key.algorithm}"
      )
    end

    #[why] the config no longer declares this key, so its type and material come from state
    def deregister_signer(name, backup)
      entry = @state.key(name)
      return nil unless entry && entry["type"] == SIGNING_TYPE

      removed = @allowed_signers.remove(
        public_key: entry["public-key"], backup_path: backup.join("allowed_signers")
      )
      @out.puts("dropped #{name} from allowed_signers") if removed
      removed
    end

    # register_signer puts a newly created signing key into allowed_signers, where rotation expects it.
    def register_signer(key, private_path)
      return unless key.type == SIGNING_TYPE

      timestamp = @clock.now.utc.strftime("%Y%m%dT%H%M%SZ")
      @allowed_signers.add(
        email: key.email,
        public_key: @keypair.public_key(private_path),
        backup_path: @paths.backup_dir(key.name, timestamp).join("allowed_signers")
      )
      @out.puts("registered #{key.name} in allowed_signers")
    end

    def rotate(action)
      return @reporter.puts("skipped #{action.key.name}, not confirmed") unless confirmed?(action)

      @out.puts("rotating #{action.key.name}")
      @rotator.call(action.key, revoke_platforms: action.revoke_platforms, keep_published: action.keep_published)
    end

    #[why] a forced key was named on the command line, which is the confirmation
    def confirmed?(action)
      return true if action.forced

      @prompt.confirm?("rotate #{action.key.name}? #{describe_revoke(action)}")
    end

    def describe_revoke(action)
      return "nothing will be revoked" if action.revoke_platforms.empty?

      "the old key will be revoked from #{action.revoke_platforms.join(', ')}"
    end

    def revoke(action)
      action.platforms.each do |platform|
        @registry.fetch(platform).delete(@state.published_to(action.name).fetch(platform))
        @state.record_revoked(action.name, platform)
        @state.write
        @out.puts("revoked #{action.name} from #{platform}")
      end
      archive_revoked(action.name)
    end

    #[why] the key is no longer declared anywhere, so leaving it live in ~/.ssh is a grant the
    #   user believes they removed. it is moved, never deleted: only they can judge it worthless
    def archive_revoked(name)
      private_path = @paths.private_key(name)
      return unless private_path.exist?

      timestamp = @clock.now.utc.strftime("%Y%m%dT%H%M%SZ")
      backup = @paths.backup_dir(name, timestamp)
      archived = @keypair.move(from_private: private_path, to_private: backup.join(name))
      signers_backup = deregister_signer(name, backup)

      @state.archive(name, backup_private: archived, backup_public: @keypair.public_path_for(archived),
                           allowed_signers_backup: signers_backup)
      @state.write
      @out.puts("archived #{name} to #{archived}")
    end

    def report_orphan(action)
      where = action.platforms.empty? ? "no platform" : action.platforms.join(", ")
      @reporter.puts("orphan: #{action.name} is in state but not in config, still published on #{where}, nothing removed")
    end

    def print_plan(actions)
      @out.puts("nothing to do") if actions.empty?
      actions.each { @out.puts(describe(_1)) }
      actions
    end

    def describe(action)
      case action
      when Planner::Create then "create #{action.key.name} (#{action.key.algorithm})"
      when Planner::Adopt then "adopt #{action.key.name}, already on disk"
      when Planner::Publish then "publish #{action.key.name} to #{action.platforms.join(', ')}"
      when Planner::Rotate then describe_rotate(action)
      when Planner::Revoke then "revoke #{action.name} from #{action.platforms.join(', ')}"
      when Planner::OrphanReported then "orphan #{action.name} (reported, nothing removed)"
      end
    end

    def describe_rotate(action)
      revoking = action.revoke_platforms.empty? ? "revoking nothing" : "revoking from #{action.revoke_platforms.join(', ')}"
      kept = action.keep_published.empty? ? "" : ", keeping the old key on #{action.keep_published.join(', ')}"
      asks = action.forced ? "" : " (asks first)"
      "rotate #{action.key.name}, #{revoking}#{kept}#{asks}"
    end

    def mint_title(name) = "#{name}-#{SecureRandom.hex(TITLE_SUFFIX_BYTES)}"
  end
end
##[<] 🤖🤖
