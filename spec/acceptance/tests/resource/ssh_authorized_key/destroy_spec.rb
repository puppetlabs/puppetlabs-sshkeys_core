require 'spec_helper_acceptance'

RSpec.context 'sshkeys: Destroy' do
  confine :except, platform: ['windows']

  let(:auth_keys) { '~/.ssh/authorized_keys' }
  let(:name) { "pl#{rand(999_999).to_i}" }

  before(:each) do
    posix_agents.each do |agent|
      on(agent, "cp #{auth_keys} /tmp/auth_keys", acceptable_exit_codes: [0, 1])

      on(agent, "echo '' >> #{auth_keys} && echo 'ssh-rsa mykey #{name}' >> #{auth_keys}")
      on(agent, "chown $LOGNAME #{auth_keys}")
    end
  end

  after(:each) do
    posix_agents.each do |agent|
      # (teardown) restore the #{auth_keys} file
      on(agent, "mv /tmp/auth_keys #{auth_keys}", acceptable_exit_codes: [0, 1])
    end
  end

  posix_agents.each do |agent|
    it "#{agent} should delete an entry for an SSH authorized key" do
      args = ['ensure=absent',
              'user=$LOGNAME',
              "type='rsa'",
              "key='mykey'"]
      on(agent, puppet_resource('ssh_authorized_key', name.to_s, args))

      on(agent, "cat #{auth_keys}") do |_res|
        expect(stdout).not_to include(name.to_s)
      end
    end
  end
end
