##[>] 🤖🤖
require "securerandom"
require "fileutils"
require "time"

module UserSshUtil
  # Rotator replaces one key, ordered so a failure never leaves the user locked out.
  class Rotator
    VerificationFailed = Class.new(StandardError)
    SIGNING_TYPE = "signing"
    TITLE_SUFFIX_BYTES = 3

    def initialize(paths:, state:, registry:, keypair:, agent:, allowed_signers:, known_hosts:, signer:, clock:,
                   reporter: $stderr)
      @paths = paths
      @state = state
      @registry = registry
      @keypair = keypair
      @agent = agent
      @allowed_signers = allowed_signers
      @known_hosts = known_hosts
      @signer = signer
      @clock = clock
      @reporter = reporter
    end

    # call rotates key, revoking only from revoke_platforms and reporting whatever it leaves published.
    def call(key, revoke_platforms:, keep_published:)
      staged = generate_replacement(key, staging_dir(key.name))

      titles = publish_replacement(key, staged)
      verify_replacement(key, staged)
      revoke_superseded(key, revoke_platforms)
      report_kept(key, keep_published)

      archive_superseded(key, staged)
      install(key, staged, titles)
    end

    private

    def generate_replacement(key, workspace)
      staged = workspace.join(key.name)
      @keypair.generate(private_path: staged, algorithm: key.algorithm, comment: key.email, override: true)
      staged
    end

    def publish_replacement(key, staged)
      public_path = @keypair.public_path_for(staged)
      key.publish_to.to_h do |platform|
        [platform, @registry.fetch(platform).add(public_path, mint_title(key.name), key_type: key.type)]
      end
    end

    #[why] a signing key grants no ssh access: github rejects it by design, so proving it can
    #   sign and verify is the only meaningful check. an access key still proves it can log in
    def verify_replacement(key, staged)
      return verify_signing(key, staged) if key.type == SIGNING_TYPE

      key.publish_to.each do |platform|
        next if @registry.fetch(platform).verify(staged)

        raise VerificationFailed, "#{key.name} failed to authenticate against #{platform}, old key untouched"
      end
    end

    def verify_signing(key, staged)
      return if @signer.usable?(staged, email: key.email)

      raise VerificationFailed, "#{key.name} failed to sign and verify, old key untouched"
    end

    #[why] state is written after each delete: a crash mid-loop would otherwise leave state
    #   naming a title the platform no longer has, and every retry would fail on it forever
    def revoke_superseded(key, platforms)
      platforms.each do |platform|
        title = @state.published_to(key.name)[platform]
        next unless title

        delete_if_present(platform, title)
        @state.record_revoked(key.name, platform)
        @state.write
      end
    end

    #[why] an already-absent key is the state we wanted: report it, do not abort the rotation
    def delete_if_present(platform, title)
      @registry.fetch(platform).delete(title)
    rescue CommandFailed => e
      @reporter.puts("warning: #{title} was already gone from #{platform} (#{e.message})")
    end

    def report_kept(key, platforms)
      platforms.each do |platform|
        @reporter.puts("warning: #{key.name} stays published on #{platform}, pass --revoke-platforms=#{platform} to remove it")
      end
    end

    def archive_superseded(key, staged)
      timestamp = @clock.now.utc.strftime("%Y%m%dT%H%M%SZ")
      backup = @paths.backup_dir(key.name, timestamp)
      archived_private = @keypair.move(from_private: @paths.private_key(key.name), to_private: backup.join(key.name))
      signing_backups = swap_signing_files(key, staged, backup)

      @state.archive(
        key.name,
        backup_private: archived_private,
        backup_public: @keypair.public_path_for(archived_private),
        **signing_backups
      )
      @state.write
    end

    def swap_signing_files(key, staged, backup)
      return {} unless key.type == SIGNING_TYPE

      {
        allowed_signers_backup: @allowed_signers.add(
          email: key.email,
          public_key: @keypair.public_key(staged),
          valid_after: @clock.now,
          backup_path: backup.join("allowed_signers")
        ),
        known_hosts_backup: @known_hosts.refresh(hosts: hosts_for(key), backup_path: backup.join("known_hosts"))
      }
    end

    def install(key, staged, titles)
      live = @keypair.move(from_private: staged, to_private: @paths.private_key(key.name))
      @agent.restart(live)

      @state.record_rotated(key.name, public_key: @keypair.public_key(live), now: @clock.now)
      titles.each { |platform, title| @state.record_published(key.name, platform, title) }
      @state.write
    end

    def hosts_for(key) = key.publish_to.map { @registry.fetch(_1).host }

    def staging_dir(name)
      dir = @paths.backups_dir.join("staging", name)
      FileUtils.mkdir_p(dir)
      dir
    end

    def mint_title(name) = "#{name}-#{SecureRandom.hex(TITLE_SUFFIX_BYTES)}"
  end
end
##[<] 🤖🤖
