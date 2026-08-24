##[>] 🤖🤖
module UserSshUtil
  # Prompt asks the operator to confirm a destructive step.
  class Prompt
    AFFIRMATIVE = %w[y yes].freeze

    def initialize(input: $stdin, output: $stderr, assume_yes: false)
      @input = input
      @output = output
      @assume_yes = assume_yes
    end

    # confirm? answers a yes/no question, defaulting to no.
    #
    # --yes answers every question. Without a tty there is nobody to ask, so the answer is no:
    # an unattended run must never rotate on a prompt it could not display.
    def confirm?(question)
      return true if @assume_yes
      return false unless interactive?

      @output.print("#{question} [y/N] ")
      AFFIRMATIVE.include?(@input.gets.to_s.strip.downcase)
    end

    # interactive? reports whether there is a terminal to ask.
    def interactive? = @input.respond_to?(:tty?) && @input.tty?
  end
end
##[<] 🤖🤖
