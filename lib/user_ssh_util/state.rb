##[>] 🤖🤖
require "psych"
require "fileutils"
require "pathname"
require "time"

module UserSshUtil
  # State records what actually exists on disk and on each platform.
  class State
    attr_reader :path
    attr_accessor :configfile

    # load reads a state file, an absent one yielding empty state.
    #
    # Time is permitted because a hand-edited timestamp loses its quotes and parses as one.
    def self.load(path, configfile: nil)
      raw = File.exist?(path.to_s) ? (Psych.safe_load_file(path.to_s, permitted_classes: [Time]) || {}) : {}
      new(normalize_timestamps(raw), path: path, configfile: configfile)
    end

    def self.normalize_timestamps(raw)
      raw.transform_values do |entry|
        next entry unless entry.is_a?(Hash)

        entry.transform_values { _1.is_a?(Time) ? _1.utc.iso8601 : _1 }
      end
    end
    private_class_method :normalize_timestamps

    def initialize(raw = {}, path: nil, configfile: nil)
      @path = path && Pathname.new(path)
      @configfile = raw["configfile"] || configfile&.to_s
      @keys = raw.reject { |name, _| name == "configfile" }
    end

    def key(name) = @keys[name.to_s]

    def key?(name) = @keys.key?(name.to_s)

    def names = @keys.keys

    # published_to maps platform to the unique title recorded for that key.
    def published_to(name) = key(name)&.fetch("publishedTo", nil) || {}

    # record_created stores a freshly generated, not yet published key.
    def record_created(name, private_path:, public_path:, public_key:, email:, algo:, type:, now:)
      @keys[name.to_s] = {
        "private-path" => private_path.to_s,
        "public-path" => public_path.to_s,
        "public-key" => public_key,
        "email" => email,
        "algo" => algo,
        "type" => type,
        "firstCreatedAt" => now.utc.iso8601,
        "lastRotatedAt" => now.utc.iso8601,
        "rotationCounter" => 0,
        "publishedTo" => {},
        "archived" => []
      }
    end

    # record_published notes the title a platform now holds for this key.
    def record_published(name, platform, title)
      @keys.fetch(name.to_s)["publishedTo"][platform.to_s] = title
    end

    # record_revoked drops a platform's grant for this key.
    def record_revoked(name, platform)
      @keys.fetch(name.to_s)["publishedTo"].delete(platform.to_s)
    end

    # archive moves the current key record into archived and installs the replacement.
    def archive(name, backup_private:, backup_public:, allowed_signers_backup: nil, known_hosts_backup: nil)
      entry = @keys.fetch(name.to_s)
      archived = entry.fetch("archived")
      archived << {
        "private-path" => backup_private.to_s,
        "public-path" => backup_public.to_s,
        "public-key" => entry["public-key"],
        "email" => entry["email"],
        "algo" => entry["algo"],
        "type" => entry["type"],
        "firstCreatedAt" => entry["firstCreatedAt"],
        "lastRotatedAt" => entry["lastRotatedAt"],
        "rotationCounter" => entry["rotationCounter"],
        "publishedTo" => entry.fetch("publishedTo").dup,
        "allowed_signers" => allowed_signers_backup&.to_s,
        "known_hosts" => known_hosts_backup&.to_s
      }.compact
    end

    # record_rotated replaces the live key material and bumps the counter.
    def record_rotated(name, public_key:, now:)
      entry = @keys.fetch(name.to_s)
      entry["public-key"] = public_key
      entry["lastRotatedAt"] = now.utc.iso8601
      entry["rotationCounter"] = entry.fetch("rotationCounter", 0) + 1
      entry["publishedTo"] = {}
    end

    def to_h = { "configfile" => @configfile }.merge(@keys)

    # write persists state atomically, so an interrupted run leaves a readable file.
    def write
      FileUtils.mkdir_p(@path.dirname)
      tmp = @path.sub_ext(".yml.tmp#{Process.pid}")
      tmp.write(Psych.dump(to_h))
      File.rename(tmp.to_s, @path.to_s)
    end
  end
end
##[<] 🤖🤖
