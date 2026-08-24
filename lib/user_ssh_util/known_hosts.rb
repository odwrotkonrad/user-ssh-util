##[>] 🤖🤖
require "fileutils"
require "pathname"

module UserSshUtil
  # KnownHosts refreshes ~/.ssh/known_hosts so a rotation never trips on a stale host key.
  class KnownHosts
    def initialize(path, runner)
      @path = Pathname.new(path)
      @runner = runner
    end

    # refresh backs up the current file, then re-scans each host into it.
    def refresh(hosts:, backup_path:)
      backup = back_up(backup_path)
      scanned = hosts.map { @runner.run!("ssh-keyscan", _1).stdout }.join
      FileUtils.mkdir_p(@path.dirname)
      @path.write(without(hosts) + scanned)
      backup
    end

    private

    def without(hosts)
      return "" unless @path.exist?

      @path.read.lines.reject { |line| hosts.any? { line.start_with?("#{_1} ", "#{_1},") } }.join
    end

    def back_up(backup_path)
      return nil unless @path.exist?

      backup_path = Pathname.new(backup_path)
      FileUtils.mkdir_p(backup_path.dirname)
      FileUtils.cp(@path.to_s, backup_path.to_s)
      backup_path
    end
  end
end
##[<] 🤖🤖
