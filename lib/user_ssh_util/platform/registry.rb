##[>] 🤖🤖
require_relative "gitlab"
require_relative "github"

module UserSshUtil
  module Platform
    # Registry maps a configured platform name to its adapter.
    class Registry
      UnknownPlatform = Class.new(StandardError)

      ADAPTERS = { Gitlab::NAME => Gitlab, Github::NAME => Github }.freeze

      def initialize(runner, adapters: nil)
        @adapters = adapters || ADAPTERS.transform_values { _1.new(runner) }
      end

      # fetch returns the adapter for a platform name.
      def fetch(name)
        @adapters.fetch(name.to_s) { raise UnknownPlatform, "unknown platform: #{name}" }
      end

      def names = @adapters.keys
    end
  end
end
##[<] 🤖🤖
