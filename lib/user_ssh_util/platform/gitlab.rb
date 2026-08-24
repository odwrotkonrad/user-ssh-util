##[>] 🤖🤖
require "json"

module UserSshUtil
  module Platform
    # Gitlab publishes and revokes keys through an authenticated glab.
    class Gitlab
      NAME = "gitlab"
      HOST = "gitlab.com"
      WELCOME = /Welcome to GitLab/i
      USAGE_TYPES = { "signing" => "signing", "access" => "auth" }.freeze
      DEFAULT_USAGE_TYPE = "auth"

      def initialize(runner)
        @runner = runner
      end

      def name = NAME

      def host = HOST

      # add publishes a public key file under title, returning the title recorded in state.
      #
      # usage_type is passed explicitly: glab defaults to auth_and_signing, granting more than asked.
      def add(public_key_path, title, key_type: nil)
        usage_type = USAGE_TYPES.fetch(key_type.to_s, DEFAULT_USAGE_TYPE)
        @runner.run!("glab", "ssh-key", "add", public_key_path.to_s, "--title", title, "--usage-type", usage_type)
        title
      end

      # delete removes the key the platform holds under title.
      def delete(title)
        id = key_id(title)
        raise CommandFailed, "no gitlab ssh key titled #{title}" unless id

        @runner.run!("glab", "ssh-key", "delete", id.to_s)
      end

      # find_by_public_key returns the title gitlab already holds for this key material, or nil.
      #
      #[why] gitlab rewrites the trailing comment to its own, so only algorithm and body compare
      def find_by_public_key(public_key)
        body = key_body_of(public_key)
        return nil unless body

        listed.find { key_body_of(_1["key"]) == body }&.fetch("title")
      end

      # verify proves the private key authenticates, the welcome banner counting as success.
      #
      #[why] -F /dev/null: IdentitiesOnly excludes agent keys but never the IdentityFile a
      #   `Host *` block adds, so a user config would let an unrelated key pass this check
      def verify(private_key_path)
        result = @runner.run(
          "ssh", "-F", "/dev/null", "-i", private_key_path.to_s, "-o", "IdentitiesOnly=yes",
          "-o", "StrictHostKeyChecking=accept-new", "-T", "git@#{HOST}"
        )
        result.success? || result.stderr.match?(WELCOME) || result.stdout.match?(WELCOME)
      end

      private

      def key_id(title) = listed.find { _1["title"] == title }&.fetch("id")

      #[why] glab prints nothing at all when the account holds no keys, which is not json
      def listed
        raw = @runner.run!("glab", "ssh-key", "list", "--show-id", "--output", "json").stdout
        raw.strip.empty? ? [] : JSON.parse(raw)
      end

      def key_body_of(public_key)
        algorithm, body = public_key.to_s.split
        body && "#{algorithm} #{body}"
      end
    end
  end
end
##[<] 🤖🤖
