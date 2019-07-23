require 'spec_helper_acceptance'

RSpec.context 'ssh_authorized_key: Create' do
  test_name 'should create an entry for an SSH authorized key'

  let(:auth_keys) { '~/.ssh/authorized_keys' }
  let(:name) { "pl#{rand(999_999).to_i}" }
  let(:custom_key_directory) { "/etc/ssh_authorized_keys_#{name}" }
  let(:custom_key) { "#{custom_key_directory}/authorized_keys_#{name}" }
  let(:custom_name) { "custom_#{name}" }

  before(:each) do
    posix_agents.each do |agent|
      on(agent, "cp #{auth_keys} /tmp/auth_keys", acceptable_exit_codes: [0, 1])
      on(agent, "rm -f #{auth_keys}")
      on(agent, "mkdir #{custom_key_directory}")
    end
  end

  after(:each) do
    posix_agents.each do |agent|
      # (teardown) restore the #{auth_keys} file
      on(agent, "mv /tmp/auth_keys #{auth_keys}", acceptable_exit_codes: [0, 1])
      on(agent, "rm -rf #{custom_key_directory}")
    end
  end

  posix_agents.each do |agent|
    it "#{agent} should create an entry for an SSH authorized key" do
      args = ['ensure=present',
              'user=$LOGNAME',
              "type='rsa'",
              "key='mykey'"]
      on(agent, puppet_resource('ssh_authorized_key', name.to_s, args))

      on(agent, "cat #{auth_keys}") do |_res|
        fail_test "didn't find the ssh_authorized_key for #{name}" unless stdout.include? name.to_s
      end
    end
    it "#{agent} should create an entry for an SSH authorized key in a custom location" do
      custom_args = ['ensure=present',
                     'user=$LOGNAME',
                     "type='rsa'",
                     "key='mykey'",
                     "target='#{custom_key}'"]

      on(agent, puppet_resource('ssh_authorized_key', custom_name.to_s, custom_args))

      on(agent, "cat #{custom_key}") do |_res|
        fail_test "didn't find the ssh_authorized_key for #{custom_name}" unless stdout.include? name.to_s
      end
    end
  end
end
