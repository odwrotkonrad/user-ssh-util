##[>] 🤖🤖
module UserSshUtil
  module Platform
    # Github publishes and revokes keys through a gh authenticated with the admin:public_key scope.
    class Github
      NAME = "github"
      HOST = "github.com"
      WELCOME = /successfully authenticated/i
      TITLE_COLUMN = 0
      KEY_COLUMN = 1
      #[why] gh prints title, key, added-at, id, type: the id is the 4th column, not the 3rd
      ID_COLUMN = 3
      TYPE_COLUMN = 4
      SIGNING_TYPE = "signing"
      KEY_TYPES = { "signing" => "signing", "access" => "authentication" }.freeze
      DEFAULT_KEY_TYPE = "authentication"

      def initialize(runner)
        @runner = runner
      end

      def name = NAME

      def host = HOST

      # add publishes a public key file under title, returning the title recorded in state.
      #
      # type is passed explicitly: gh defaults to authentication, and a signing key added
      # without it lands in the wrong collection entirely.
      def add(public_key_path, title, key_type: nil)
        type = KEY_TYPES.fetch(key_type.to_s, DEFAULT_KEY_TYPE)
        @runner.run!("gh", "ssh-key", "add", public_key_path.to_s, "--title", title, "--type", type)
        title
      end

      # delete removes the key the platform holds under title.
      #
      #[why] `gh ssh-key delete` only ever calls /user/keys, so it 404s on a signing key:
      #   those live in /user/ssh_signing_keys and are reachable only through `gh api`
      def delete(title)
        id, type = key_entry(title)
        raise CommandFailed, "no github ssh key titled #{title}" unless id
        return @runner.run!("gh", "api", "-X", "DELETE", "/user/ssh_signing_keys/#{id}") if type == SIGNING_TYPE

        @runner.run!("gh", "ssh-key", "delete", id, "--yes")
      end

      # find_by_public_key returns the title github already holds for this key material, or nil.
      def find_by_public_key(public_key)
        body = key_body_of(public_key)
        return nil unless body

        rows.find { key_body_of(_1[KEY_COLUMN]) == body }&.fetch(TITLE_COLUMN)
      end

      # verify proves the private key authenticates, github's greeting counting as success.
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

      def key_entry(title)
        row = rows.find { _1[TITLE_COLUMN] == title }
        row ? [row[ID_COLUMN], row[TYPE_COLUMN]] : []
      end

      def rows
        @runner.run!("gh", "ssh-key", "list").stdout.lines.map { _1.chomp.split("\t") }
      end

      def key_body_of(public_key)
        algorithm, body = public_key.to_s.split
        body && "#{algorithm} #{body}"
      end
    end
  end
end
##[<] 🤖🤖
