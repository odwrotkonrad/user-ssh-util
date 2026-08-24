##[>] 🤖🤖
module UserSshUtil
  # Period parses a rotation period ("1 month", "2 weeks", "month") into seconds.
  module Period
    UNIT_SECONDS = {
      "day" => 86_400,
      "week" => 604_800,
      "month" => 2_592_000,
      "year" => 31_536_000
    }.freeze

    ParseError = Class.new(StandardError)

    PATTERN = /\A(?:(\d+)\s+)?(day|week|month|year)s?\z/

    module_function

    # seconds converts a period phrase to seconds, nil passing through as "no rotation".
    def seconds(phrase)
      return nil if phrase.nil?

      match = PATTERN.match(phrase.to_s.strip.downcase)
      raise ParseError, "unparsable rotation period: #{phrase.inspect}" unless match

      count = (match[1] || 1).to_i
      raise ParseError, "rotation period must be positive: #{phrase.inspect}" if count.zero?

      count * UNIT_SECONDS.fetch(match[2])
    end
  end
end
##[<] 🤖🤖
