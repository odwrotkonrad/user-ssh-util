##[>] 🤖🤖
require_relative "test_helper"

module UserSshUtil
  class PromptTest < Minitest::Test
    # Tty stands in for an interactive terminal, which a StringIO is not.
    class Tty < StringIO
      def tty? = true
    end

    def test_yes_confirms
      assert asked("y\n")
      assert asked("yes\n")
    end

    def test_case_and_whitespace_are_ignored
      assert asked("  YES \n")
    end

    def test_anything_else_declines
      refute asked("n\n")
      refute asked("\n")
      refute asked("maybe\n")
    end

    def test_the_question_is_shown
      output = StringIO.new
      Prompt.new(input: Tty.new("y\n"), output: output).confirm?("rotate k?")

      assert_match(/rotate k\? \[y\/N\]/, output.string)
    end

    def test_assume_yes_never_asks
      output = StringIO.new
      prompt = Prompt.new(input: Tty.new(""), output: output, assume_yes: true)

      assert prompt.confirm?("rotate k?")
      assert_empty output.string, "--yes must not print a question it never asks"
    end

    # cron and CI have no terminal: rotating there would act on an unanswerable question
    def test_a_non_tty_declines_without_asking
      output = StringIO.new
      prompt = Prompt.new(input: StringIO.new("y\n"), output: output)

      refute prompt.confirm?("rotate k?")
      assert_empty output.string
    end

    def test_assume_yes_wins_over_a_non_tty
      assert Prompt.new(input: StringIO.new(""), output: StringIO.new, assume_yes: true).confirm?("rotate k?")
    end

    private

    def asked(answer)
      Prompt.new(input: Tty.new(answer), output: StringIO.new).confirm?("rotate k?")
    end
  end
end
##[<] 🤖🤖
