##[>] 🤖🤖
require "minitest/autorun"
require "tmpdir"
require "fileutils"
require "psych"
require "time"

require "user_ssh_util"

module UserSshUtil
  module TestSupport
    FIXED_NOW = Time.utc(2026, 8, 24, 12, 0, 0)

    # FakeRunner records every argv and replays canned results.
    #
    # passthrough names the local tools it runs for real, so a test can exercise ssh-keygen
    # against a tmpdir HOME while every platform call stays a double.
    class FakeRunner
      attr_reader :calls

      def initialize(results: {}, passthrough: [])
        @results = results
        @passthrough = passthrough
        @calls = []
      end

      def stub(pattern, stdout: "", stderr: "", exitstatus: 0)
        @results[pattern] = CommandRunner::Result.new(stdout: stdout, stderr: stderr, exitstatus: exitstatus)
        self
      end

      def run(*argv)
        line = argv.map(&:to_s).join(" ")
        @calls << argv.map(&:to_s)
        _, result = @results.find { |pattern, _| line.match?(pattern) }
        return result if result
        return CommandRunner.new.run(*argv) if @passthrough.include?(argv.first.to_s)

        CommandRunner::Result.new(stdout: "", stderr: "", exitstatus: 0)
      end

      def run!(*argv)
        result = run(*argv)
        raise CommandFailed, "#{argv.join(' ')} exited #{result.exitstatus}" unless result.success?

        result
      end

      def ran?(pattern) = @calls.any? { _1.join(" ").match?(pattern) }
    end

    # FakePlatform stands in for a platform adapter, recording what it was asked to do.
    class FakePlatform
      attr_reader :name, :host, :added, :added_types, :deleted

      attr_accessor :existing_titles

      def initialize(name, host: "#{name}.com", verifies: true, existing_titles: {})
        @name = name
        @host = host
        @verifies = verifies
        @existing_titles = existing_titles
        @added = []
        @added_types = []
        @deleted = []
      end

      def find_by_public_key(public_key) = @existing_titles[public_key.to_s.split[1]]

      def add(public_key_path, title, key_type: nil)
        @added << [public_key_path.to_s, title]
        @added_types << key_type
        title
      end

      def delete(title) = @deleted << title

      def verify(_private_path) = @verifies
    end

    Clock = Struct.new(:now)

    module_function

    def fixed_clock(now = FIXED_NOW) = Clock.new(now)

    def config(raw) = Config.new(raw)

    def state(raw = {}, path: nil) = State.new(raw, path: path)

    def key_entry(public_key: "ecdsa-sha2-nistp521 AAAAmaterial comment", published_to: {}, last_rotated_at: FIXED_NOW,
                  algo: "ecdsa-sha2-nistp521", type: "access", counter: 0)
      {
        "private-path" => "/home/u/.ssh/k",
        "public-path" => "/home/u/.ssh/k.pub",
        "public-key" => public_key,
        "email" => "u@example.com",
        "algo" => algo,
        "type" => type,
        "firstCreatedAt" => FIXED_NOW.utc.iso8601,
        "lastRotatedAt" => last_rotated_at.utc.iso8601,
        "rotationCounter" => counter,
        "publishedTo" => published_to,
        "archived" => []
      }
    end
  end
end
##[<] 🤖🤖
