##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class AllowedSignersTest < Minitest::Test
    include TestSupport

    OLD_KEY = "ssh-ed25519 AAAAOLDMATERIAL u@example.com"
    NEW_KEY = "ssh-ed25519 AAAANEWMATERIAL u@example.com"
    OTHER = "other@example.com ssh-ed25519 AAAAOTHER other@example.com"
    VALID_AFTER = Time.utc(2026, 8, 25, 13, 30)

    def setup
      @dir = Pathname.new(Dir.mktmpdir("signers"))
      @path = @dir.join(".ssh", "allowed_signers")
      @signers = AllowedSigners.new(@path)
    end

    def teardown = FileUtils.remove_entry(@dir)

    def test_the_superseded_key_is_kept_alongside_the_replacement
      write_file("u@example.com #{OLD_KEY}")

      add

      assert_includes @signers.entries, "u@example.com #{OLD_KEY}"
      assert_includes @signers.entries, %(u@example.com valid-after="20260825" #{NEW_KEY})
    end

    def test_the_written_line_carries_a_quoted_valid_after_stamp
      add

      assert_equal [%(u@example.com valid-after="20260825" #{NEW_KEY})], @signers.entries
    end

    def test_adding_the_same_key_twice_does_not_duplicate_it
      add
      once = @path.read

      add

      assert_equal once, @path.read
      assert_equal 1, @signers.entries.size
    end

    def test_add_leaves_other_signers_untouched
      write_file(OTHER, "u@example.com #{OLD_KEY}")

      add

      assert_includes @signers.entries, OTHER
      assert_equal 3, @signers.entries.size
    end

    def test_a_key_already_present_under_a_different_comment_is_not_re_added
      write_file("u@example.com ssh-ed25519 AAAANEWMATERIAL a-different-comment")

      add

      assert_equal 1, @signers.entries.size
    end

    def test_add_backs_up_the_previous_file
      write_file("u@example.com #{OLD_KEY}")

      backup = add

      assert_path_exists backup
      assert_equal "u@example.com #{OLD_KEY}\n", backup.read
    end

    def test_add_creates_the_file_when_none_exists
      backup = add

      assert_nil backup, "there is no previous file to back up"
      assert_equal [%(u@example.com valid-after="20260825" #{NEW_KEY})], @signers.entries
    end

    def test_add_writes_a_trailing_newline
      write_file("u@example.com #{OLD_KEY}")

      add

      assert @path.read.end_with?("\n"), "ssh needs a newline-terminated allowed_signers"
    end

    def test_blank_lines_are_dropped
      write_file("u@example.com #{OLD_KEY}", "", "   ")

      add

      assert_equal 2, @signers.entries.size
    end

    private

    def add
      @signers.add(
        email: "u@example.com", public_key: NEW_KEY, valid_after: VALID_AFTER,
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
