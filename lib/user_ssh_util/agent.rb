##[>] 🤖🤖
module UserSshUtil
  # Agent reloads ssh-agent so a rotated key is the one offered.
  class Agent
    def initialize(runner)
      @runner = runner
    end

    # restart drops every loaded identity, then adds the named key.
    def restart(private_path)
      @runner.run!("ssh-add", "-D")
      @runner.run!("ssh-add", private_path.to_s)
    end
  end
end
##[<] 🤖🤖
