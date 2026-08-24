##[>] 🤖🤖
require "pathname"

module UserSshUtil
  # Paths resolves every location the tool reads or writes.
  class Paths
    PWD_CONFIG = "user-ssh-util.yml"
    PWD_STATE = "user-ssh-util.state.yml"

    attr_reader :config_file, :state_file

    def initialize(config_file: nil, state_file: nil, pwd: false, env: ENV, cwd: Dir.pwd)
      @env = env
      @cwd = Pathname.new(cwd)
      @pwd = pwd
      @config_file = Pathname.new(config_file || default_config_file).expand_path
      @state_file = Pathname.new(state_file || default_state_file).expand_path
    end

    # ssh_dir is the live key directory, never written by this tool except for allowed_signers.
    def ssh_dir = home.join(".ssh")

    def allowed_signers = ssh_dir.join("allowed_signers")

    def known_hosts = ssh_dir.join("known_hosts")

    def private_key(name) = ssh_dir.join(name)

    def public_key(name) = ssh_dir.join("#{name}.pub")

    # backups_dir holds superseded keypairs and the files replaced beside them.
    def backups_dir = data_home.join("user-ssh-util", "backups")

    def backup_dir(name, timestamp) = backups_dir.join(name, timestamp)

    def home = Pathname.new(@env.fetch("HOME"))

    private

    def default_config_file
      return @cwd.join(PWD_CONFIG) if @pwd

      config_home.join("user-ssh-util", "config.yml")
    end

    def default_state_file
      return @cwd.join(PWD_STATE) if @pwd

      data_home.join("user-ssh-util", "state.yml")
    end

    def config_home
      Pathname.new(@env["XDG_CONFIG_HOME"] || home.join(".config"))
    end

    def data_home
      Pathname.new(@env["XDG_DATA_HOME"] || home.join(".local", "share"))
    end
  end
end
##[<] 🤖🤖
