##[>] 🤖🤖
require "fileutils"
require "pathname"

module UserSshUtil
  # AllowedSigners appends signing keys to ~/.ssh/allowed_signers, stamped with the date they became valid.
  class AllowedSigners
    def initialize(path)
      @path = Pathname.new(path)
    end

    # add appends a public key for email, stamped valid-after, keeping every existing entry.
    def add(email:, public_key:, valid_after:, backup_path:)
      existing = lines
      return nil if existing.any? { signs_with?(_1, public_key) }

      backup = back_up(backup_path)
      write(existing + ["#{email} valid-after=\"#{stamp(valid_after)}\" #{public_key}"])
      backup
    end

    # entries lists the current file's non-empty lines.
    def entries = lines

    private

    def lines
      return [] unless @path.exist?

      @path.read.lines.map(&:chomp).reject { _1.strip.empty? }
    end

    def signs_with?(line, public_key)
      key_body = key_body_of(public_key)
      key_body && line.include?(key_body)
    end

    def key_body_of(public_key) = public_key.to_s.split[1]

    def stamp(valid_after) = valid_after.strftime("%Y%m%d")

    def back_up(backup_path)
      return nil unless @path.exist?

      backup_path = Pathname.new(backup_path)
      FileUtils.mkdir_p(backup_path.dirname)
      FileUtils.cp(@path.to_s, backup_path.to_s)
      backup_path
    end

    def write(entries)
      FileUtils.mkdir_p(@path.dirname)
      @path.write("#{entries.join("\n")}\n")
    end
  end
end
##[<] 🤖🤖
