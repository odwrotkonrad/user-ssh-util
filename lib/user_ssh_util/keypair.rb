##[>] 🤖🤖
require "fileutils"
require "pathname"

module UserSshUtil
  # Keypair generates and moves ssh keypairs.
  class Keypair
    ExistsError = Class.new(StandardError)

    ALGORITHM_TYPES = {
      "ecdsa-sha2-nistp521" => { type: "ecdsa", bits: "521" },
      "ecdsa-sha2-nistp384" => { type: "ecdsa", bits: "384" },
      "ecdsa-sha2-nistp256" => { type: "ecdsa", bits: "256" },
      "ssh-ed25519" => { type: "ed25519", bits: nil }
    }.freeze

    def initialize(runner)
      @runner = runner
    end

    # generate writes a passphraseless keypair at private_path, refusing to clobber unless override.
    def generate(private_path:, algorithm:, comment:, override: false)
      private_path = Pathname.new(private_path)
      public_path = public_path_for(private_path)
      raise ExistsError, "#{private_path} exists, pass --override to replace it" if private_path.exist? && !override

      FileUtils.mkdir_p(private_path.dirname)
      FileUtils.rm_f([private_path.to_s, public_path.to_s])
      @runner.run!("ssh-keygen", *keygen_argv(private_path, algorithm, comment))
      public_path
    end

    # public_key reads the public half of a keypair.
    def public_key(private_path) = public_path_for(private_path).read.strip

    # move relocates a keypair, creating the destination directory.
    def move(from_private:, to_private:)
      from_private = Pathname.new(from_private)
      to_private = Pathname.new(to_private)
      FileUtils.mkdir_p(to_private.dirname)
      FileUtils.mv(from_private.to_s, to_private.to_s)
      FileUtils.mv(public_path_for(from_private).to_s, public_path_for(to_private).to_s)
      to_private
    end

    def public_path_for(private_path) = Pathname.new("#{private_path}.pub")

    private

    def keygen_argv(private_path, algorithm, comment)
      spec = ALGORITHM_TYPES.fetch(algorithm) { raise ArgumentError, "unsupported algorithm: #{algorithm}" }
      argv = ["-t", spec[:type]]
      argv += ["-b", spec[:bits]] if spec[:bits]
      argv + ["-C", comment, "-N", "", "-f", private_path.to_s]
    end
  end
end
##[<] 🤖🤖
