##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class AllowedSignersTest < Minitest::Test
    include TestSupport

    OLD_KEY = "ssh-ed25519 AAAAOLDMATERIAL u@example.com"
    NEW_KEY = "ssh-ed25519 AAAANEWMATERIAL u@example.com"
    OTHER = "other@example.com ssh-ed25519 AAAAOTHER other@example.com"

    def setup
      @dir = Pathname.new(Dir.mktmpdir("signers"))
      @path = @dir.join(".ssh", "allowed_signers")
      @signers = AllowedSigners.new(@path)
    end

    def teardown = FileUtils.remove_entry(@dir)

    def test_swap_replaces_the_superseded_key
      write_file("u@example.com #{OLD_KEY}")

      swap

      assert_equal ["u@example.com #{NEW_KEY}"], @signers.entries
    end

    def test_swap_leaves_other_signers_untouched
      write_file(OTHER, "u@example.com #{OLD_KEY}")

      swap

      assert_includes @signers.entries, OTHER
      assert_equal 2, @signers.entries.size
    end

    def test_swap_matches_on_key_material_not_the_comment
      write_file("u@example.com ssh-ed25519 AAAAOLDMATERIAL a-different-comment")

      swap

      assert_equal ["u@example.com #{NEW_KEY}"], @signers.entries
    end

    def test_swap_backs_up_the_previous_file
      write_file("u@example.com #{OLD_KEY}")

      backup = swap

      assert_path_exists backup
      assert_equal "u@example.com #{OLD_KEY}\n", backup.read
    end

    def test_swap_creates_the_file_when_none_exists
      backup = swap

      assert_nil backup, "there is no previous file to back up"
      assert_equal ["u@example.com #{NEW_KEY}"], @signers.entries
    end

    def test_swap_writes_a_trailing_newline
      write_file("u@example.com #{OLD_KEY}")

      swap

      assert @path.read.end_with?("\n"), "ssh needs a newline-terminated allowed_signers"
    end

    def test_blank_lines_are_dropped
      write_file("u@example.com #{OLD_KEY}", "", "   ")

      swap

      assert_equal 1, @signers.entries.size
    end

    private

    def swap
      @signers.swap(
        email: "u@example.com", old_public_key: OLD_KEY, new_public_key: NEW_KEY,
        backup_path: @dir.join("backups", "allowed_signers")
      )
    end

    def write_file(*lines)
      FileUtils.mkdir_p(@path.dirname)
      @path.write("#{lines.join("\n")}\n")
    end
  end
end
##[<] 🤖🤖
