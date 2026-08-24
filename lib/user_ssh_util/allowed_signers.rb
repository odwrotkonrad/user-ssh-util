##[>] 🤖🤖
require "fileutils"
require "pathname"

module UserSshUtil
  # AllowedSigners keeps ~/.ssh/allowed_signers in step with a rotated signing key.
  class AllowedSigners
    def initialize(path)
      @path = Pathname.new(path)
    end

    # add registers a public key for email, replacing any earlier entry for that same key.
    def add(email:, public_key:, backup_path:)
      swap(email: email, old_public_key: public_key, new_public_key: public_key, backup_path: backup_path)
    end

    # swap drops the superseded public key and adds the replacement, backing up the previous file.
    def swap(email:, old_public_key:, new_public_key:, backup_path:)
      backup = back_up(backup_path)
      kept = lines.reject { signs_with?(_1, old_public_key) }
      write(kept + ["#{email} #{new_public_key}"])
      backup
    end

    # remove drops every entry signing with public_key, backing up the previous file.
    def remove(public_key:, backup_path:)
      return nil unless @path.exist?

      backup = back_up(backup_path)
      write(lines.reject { signs_with?(_1, public_key) })
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
