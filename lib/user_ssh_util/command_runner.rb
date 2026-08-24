##[>] 🤖🤖
require "open3"

module UserSshUtil
  # CommandRunner is the single seam every external process passes through.
  class CommandRunner
    Result = Struct.new(:stdout, :stderr, :exitstatus, keyword_init: true) do
      def success? = exitstatus.zero?
    end

    # run executes argv without a shell and captures its output, optionally feeding it stdin.
    def run(*argv, stdin: nil)
      stdout, stderr, status = Open3.capture3(*argv.map(&:to_s), stdin_data: stdin.to_s)
      Result.new(stdout: stdout, stderr: stderr, exitstatus: status.exitstatus || 1)
    end

    # run! executes argv and raises unless it exits zero.
    def run!(*argv, stdin: nil)
      result = run(*argv, stdin: stdin)
      return result if result.success?

      raise CommandFailed, "#{argv.join(' ')} exited #{result.exitstatus}: #{result.stderr.strip}"
    end
  end

  CommandFailed = Class.new(StandardError)
end
##[<] 🤖🤖
