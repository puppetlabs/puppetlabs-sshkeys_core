require 'spec_helper_acceptance'

RSpec.context 'sshkeys: Marker (cert-authority / revoked)' do
  let(:keyname) { "pl#{rand(999_999).to_i}" }
  let(:sample_key) { 'how_about_the_key_of_c' }
  let(:ssh_known_hosts) { '/etc/ssh/ssh_known_hosts' }

  before(:each) do
    posix_agents.agents.each do |agent|
      # The 'cp' might fail because the source file doesn't exist
      on(
        agent,
        "cp -fv #{ssh_known_hosts} /tmp/ssh_known_hosts",
        acceptable_exit_codes: [0, 1],
      )
    end
  end

  after(:each) do
    posix_agents.each do |agent|
      rc = on(
        agent,
        '[ -e /tmp/ssh_known_hosts ]',
        accept_all_exit_codes: true,
      )
      if rc.exit_code == 0
        on(
          agent,
          "mv -fv /tmp/ssh_known_hosts #{ssh_known_hosts}",
          accept_all_exit_codes: true,
        )
      else
        on(
          agent,
          "rm -fv #{ssh_known_hosts}",
          accept_all_exit_codes: true,
        )
      end
    end
  end

  posix_agents.each do |agent|
    it "#{agent} writes a cert-authority marker to ssh_known_hosts" do
      on agent, puppet('apply'), stdin: <<MANIFEST
      sshkey { '#{keyname}':
        ensure => 'present',
        type   => 'ssh-rsa',
        key    => '#{sample_key}',
        marker => 'cert-authority',
      }
MANIFEST

      on(agent, "cat #{ssh_known_hosts}") do |res|
        expect(res.stdout).to match(%r{^@cert-authority #{keyname} ssh-rsa #{sample_key}$})
      end
    end

    it "#{agent} writes a revoked marker to ssh_known_hosts" do
      on agent, puppet('apply'), stdin: <<MANIFEST
      sshkey { '#{keyname}':
        ensure => 'present',
        type   => 'ssh-rsa',
        key    => '#{sample_key}',
        marker => 'revoked',
      }
MANIFEST

      on(agent, "cat #{ssh_known_hosts}") do |res|
        expect(res.stdout).to match(%r{^@revoked #{keyname} ssh-rsa #{sample_key}$})
      end
    end

    it "#{agent} is idempotent when the marker already matches" do
      manifest = <<MANIFEST
      sshkey { '#{keyname}':
        ensure => 'present',
        type   => 'ssh-rsa',
        key    => '#{sample_key}',
        marker => 'cert-authority',
      }
MANIFEST

      on(agent, puppet('apply'), stdin: manifest)
      on(agent, puppet('apply', '--detailed-exitcodes'), stdin: manifest, acceptable_exit_codes: [0])
    end

    it "#{agent} adds a marker to an existing plain entry" do
      on(agent, "echo '#{keyname} ssh-rsa #{sample_key}' >> #{ssh_known_hosts}")

      on agent, puppet('apply'), stdin: <<MANIFEST
      sshkey { '#{keyname}':
        ensure => 'present',
        type   => 'ssh-rsa',
        key    => '#{sample_key}',
        marker => 'cert-authority',
      }
MANIFEST

      on(agent, "cat #{ssh_known_hosts}") do |res|
        expect(res.stdout).to match(%r{^@cert-authority #{keyname} ssh-rsa #{sample_key}$})
        expect(res.stdout.scan(%r{#{keyname} ssh-rsa}).length).to eq(1)
      end
    end

    it "#{agent} removes an entry with a marker when ensure => absent" do
      on(agent, "echo '@revoked #{keyname} ssh-rsa #{sample_key}' >> #{ssh_known_hosts}")

      on agent, puppet('apply'), stdin: <<MANIFEST
      sshkey { '#{keyname}':
        ensure => 'absent',
        type   => 'ssh-rsa',
      }
MANIFEST

      on(agent, "cat #{ssh_known_hosts}") do |res|
        expect(res.stdout).not_to include(keyname.to_s)
      end
    end
  end
end
