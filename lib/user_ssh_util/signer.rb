##[>] 🤖🤖
require "tmpdir"
require "fileutils"
require "pathname"

module UserSshUtil
  # Signer proves a signing key can sign and verify, the way git uses it.
  class Signer
    NAMESPACE = "git"
    PAYLOAD = "user-ssh-util signing probe"

    def initialize(runner)
      @runner = runner
    end

    # usable? signs a throwaway payload with private_path, then verifies it against email.
    def usable?(private_path, email:)
      Dir.mktmpdir("ussh-sign") do |dir|
        workspace = Pathname.new(dir)
        payload = write(workspace.join("payload"), PAYLOAD)
        signers = write(workspace.join("allowed_signers"), "#{email} #{public_key(private_path)}")

        sign(private_path, payload) && verify(payload, signers, email)
      end
    end

    private

    def sign(private_path, payload)
      @runner.run("ssh-keygen", "-Y", "sign", "-f", private_path.to_s, "-n", NAMESPACE, payload.to_s).success?
    end

    def verify(payload, signers, email)
      signature = Pathname.new("#{payload}.sig")
      return false unless signature.exist?

      @runner.run(
        "ssh-keygen", "-Y", "verify", "-f", signers.to_s, "-I", email,
        "-n", NAMESPACE, "-s", signature.to_s, stdin: payload.read
      ).success?
    end

    def public_key(private_path) = Pathname.new("#{private_path}.pub").read.strip

    def write(path, content)
      path.write("#{content}\n")
      path
    end
  end
end
##[<] 🤖🤖
