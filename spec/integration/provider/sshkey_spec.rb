require 'spec_helper'
require 'puppet/file_bucket/dipper'
require 'puppet_spec/files'
require 'puppet_spec/compiler'

describe Puppet::Type.type(:sshkey).provider(:parsed), unless: Puppet.features.microsoft_windows? do
  include PuppetSpec::Files
  include PuppetSpec::Compiler

  let(:sshkey_file) { tmpfile('sshkey_integration_specs') }
  let(:type_under_test) { 'sshkey' }

  before :each do
    # Don't backup to filebucket
    allow_any_instance_of(Puppet::FileBucket::Dipper).to receive(:backup) # rubocop:disable RSpec/AnyInstance
    # We don't want to execute anything
    allow(described_class).to receive(:filetype).and_return Puppet::Util::FileType::FileTypeFlat

    FileUtils.cp(my_fixture('sample'), sshkey_file)
  end

  after :each do
    # sshkey provider class
    described_class.clear
  end

  describe 'when managing a ssh known hosts file it...' do
    let(:host_alias) { 'r0ckdata.com' }
    let(:invalid_type) { 'ssh-er0ck' }
    let(:sshkey_name) { 'kirby.madstop.com' }
    let(:super_unique) { 'my.super.unique.host' }

    it 'creates a new known_hosts file with mode 0644' do
      target   = tmpfile('ssh_known_hosts')
      manifest = "#{type_under_test} { '#{super_unique}':
      ensure => 'present',
      type   => 'rsa',
      key    => 'TESTKEY',
      target => '#{target}' }"
      apply_with_error_check(manifest)
      expect_file_mode(target, '644')
    end

    it 'creates an SSH host key entry (ensure present)' do
      manifest = "#{type_under_test} { '#{super_unique}':
      ensure => 'present',
      type   => 'rsa',
      key    => 'mykey',
      target => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).to match(%r{#{super_unique}.*mykey})
    end

    it 'creates two SSH host key entries with two keys (ensure present)' do
      manifest = "
      #{type_under_test} { '#{super_unique}_rsa':
        ensure => 'present',
        type   => 'rsa',
        name   => '#{super_unique}',
        key    => 'myrsakey',
        target => '#{sshkey_file}', }
      #{type_under_test} { '#{super_unique}_dss':
        ensure => 'present',
        type   => 'ssh-dss',
        name   => '#{super_unique}',
        key    => 'mydsskey',
        target => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).to match(%r{#{super_unique}.*myrsakey})
      expect(File.read(sshkey_file)).to match(%r{#{super_unique}.*mydsskey})
    end

    it 'deletes an entry for an SSH host key' do
      manifest = "#{type_under_test} { '#{sshkey_name}':
      ensure => 'absent',
      type   => 'rsa',
      target => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).not_to match(%r{#{sshkey_name}.*Yqk0=})
    end

    it 'updates an entry for an SSH host key' do
      manifest = "#{type_under_test} { '#{sshkey_name}':
      ensure => 'present',
      type   => 'rsa',
      key    => 'mynewshinykey',
      target => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).to match(%r{#{sshkey_name}.*mynewshinykey})
      expect(File.read(sshkey_file)).not_to match(%r{#{sshkey_name}.*Yqk0=})
    end

    it 'prioritizes the specified type instead of type in the name' do
      manifest = "#{type_under_test} { '#{super_unique}@rsa':
      ensure => 'present',
      type   => 'dsa',
      key    => 'mykey',
      target => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).to match(%r{#{super_unique} ssh-dss.*mykey})
    end

    it 'can parse SSH key type that contains @openssh.com in name' do
      manifest = "#{type_under_test} { '#{super_unique}@sk-ssh-ed25519@openssh.com':
      ensure => 'present',
      key    => 'mykey',
      target => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).to match(%r{#{super_unique} sk-ssh-ed25519@openssh.com.*mykey})
    end

    # test all key types
    types = [
      'ssh-dss',     'dsa',
      'ssh-ed25519', 'ed25519',
      'ssh-rsa',     'rsa',
      'ecdsa-sha2-nistp256',
      'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521',
      'ecdsa-sk', 'sk-ecdsa-sha2-nistp256@openssh.com',
      'ed25519-sk', 'sk-ssh-ed25519@openssh.com'
    ]
    # these types are treated as aliases for sshkey <ahem> type
    #   so they are populated as the *values* below
    aliases = {
      'dsa'        => 'ssh-dss',
      'ed25519'    => 'ssh-ed25519',
      'rsa'        => 'ssh-rsa',
      'ecdsa-sk'   => 'sk-ecdsa-sha2-nistp256@openssh.com',
      'ed25519-sk' => 'sk-ssh-ed25519@openssh.com',
    }
    types.each do |type|
      it "updates an entry with #{type} type" do
        manifest = "#{type_under_test} { '#{sshkey_name}':
        ensure => 'present',
        type   => '#{type}',
        key    => 'mynewshinykey',
        target => '#{sshkey_file}' }"

        apply_with_error_check(manifest)
        if aliases.key?(type)
          full_type = aliases[type]
          expect(File.read(sshkey_file)).to match(%r{#{sshkey_name}.*#{full_type}.*mynew})
        else
          expect(File.read(sshkey_file)).to match(%r{#{sshkey_name}.*#{type}.*mynew})
        end
      end
    end

    # test unknown key type fails
    it 'raises an error with an unknown type' do
      manifest = "#{type_under_test} { '#{sshkey_name}':
      ensure => 'present',
      type   => '#{invalid_type}',
      key    => 'mynewshinykey',
      target => '#{sshkey_file}' }"
      expect {
        apply_compiled_manifest(manifest)
      }.to raise_error(Puppet::ResourceError, %r{Invalid value "#{invalid_type}"})
    end

    # single host_alias
    it 'updates an entry with a single new host_alias' do
      manifest = "#{type_under_test} { '#{sshkey_name}':
      ensure       => 'present',
      type         => 'rsa',
      host_aliases => '#{host_alias}',
      target       => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).to match(%r{#{sshkey_name},#{host_alias}\s})
      expect(File.read(sshkey_file)).not_to match(%r{#{sshkey_name}\s})
    end

    # array host_alias
    it 'updates an entry with multiple new host_aliases' do
      manifest = "#{type_under_test} { '#{sshkey_name}':
      ensure       => 'present',
      type         => 'rsa',
      host_aliases => [ 'r0ckdata.com', 'erict.net' ],
      target       => '#{sshkey_file}' }"
      apply_with_error_check(manifest)
      expect(File.read(sshkey_file)).to match(%r{#{sshkey_name},r0ckdata\.com,erict\.net\s})
      expect(File.read(sshkey_file)).not_to match(%r{#{sshkey_name}\s})
    end

    # puppet resource sshkey
    it 'fetches an entry from resources' do
      resource_app = Puppet::Application[:resource]
      resource_app.preinit
      allow(resource_app.command_line).to receive(:args).and_return([type_under_test, sshkey_name, "target=#{sshkey_file}"])

      expect(resource_app).to receive(:puts) do |args|
        expect(args).to match(%r{#{sshkey_name}})
      end
      resource_app.main
    end
  end

  describe 'cert-authority functionality' do
    let(:provider_class) { described_class }
    let(:type) { Puppet::Type.type(:sshkey) }

    describe 'round-trip conversion' do
      it 'correctly parses and generates cert-authority entries' do
        # Test parsing a cert-authority line
        line = '@cert-authority *.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzwHhxXvIrtfIwrudFqc8yQcIfMudrgpnuh1F3AV6d2BrLgu/yQE7W5UyJMUjfj427sQudRwKW45O0Jsnr33F4mUw+GIMlAAmp9g24/OcrTiB8ZUKIjoPy/cO4coxGi8/NECtRzpD/ZUPFh6OEpyOwJPMb7/EC2Az6Otw4StHdXUYw22zHazBcPFnv6zCgPx1hA7QlQDWTu4YcL0WmTYQCtMUb3FUqrcFtzGDD0ytosgwSd+JyN5vj5UwIABjnNOHPZ62EY1OFixnfqX/+dUwrFSs5tPgBF/KkC6R7tmbUfnBON6RrGEmu+ajOTOLy23qUZB4CQ53V7nyAWhzqSK+hw=='

        # Parse the line
        parsed = provider_class.parse_line(line)
        expect(parsed[:name]).to eq('*.example.com')
        expect(parsed[:type]).to eq('@cert-authority ssh-rsa')
        expect(parsed[:key]).to start_with('AAAAB3NzaC1yc2EA')

        # Test generating back to line format
        generated_line = provider_class.to_line(parsed)
        expect(generated_line).to eq(line)
      end

      it 'handles cert-authority entries with host aliases' do
        line = '@cert-authority *.example.com,*.test.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAzwHhxXvIrtfIwrudFqc8yQcIfMudrgpnuh1F3AV6d2BrLgu/yQE7W5UyJMUjfj427sQudRwKW45O0Jsnr33F4mUw+GIMlAAmp9g24/OcrTiB8ZUKIjoPy/cO4coxGi8/NECtRzpD/ZUPFh6OEpyOwJPMb7/EC2Az6Otw4StHdXUYw22zHazBcPFnv6zCgPx1hA7QlQDWTu4YcL0WmTYQCtMUb3FUqrcFtzGDD0ytosgwSd+JyN5vj5UwIABjnNOHPZ62EY1OFixnfqX/+dUwrFSs5tPgBF/KkC6R7tmbUfnBON6RrGEmu+ajOTOLy23qUZB4CQ53V7nyAWhzqSK+hw=='

        parsed = provider_class.parse_line(line)
        expect(parsed[:name]).to eq('*.example.com')
        expect(parsed[:host_aliases]).to eq(['*.test.com'])
        expect(parsed[:type]).to eq('@cert-authority ssh-rsa')

        # Test generating back
        generated_line = provider_class.to_line(parsed)
        expect(generated_line).to eq(line)
      end
    end

    describe 'resource creation' do
      it 'can create a cert-authority sshkey resource' do
        expect {
          type.new(
            name: '*.example.com',
            type: '@cert-authority ssh-rsa',
            key: 'AAAAB3NzaC1yc2EAAAA'
          )
        }.not_to raise_error
      end

      it 'can create a cert-authority resource with aliases' do
        expect {
          type.new(
            name: '*.example.com',
            type: '@cert-authority rsa', # Test alias
            key: 'AAAAB3NzaC1yc2EAAAA'
          )
        }.not_to raise_error
      end

      it 'aliases cert-authority key types correctly' do
        resource = type.new(
          name: '*.example.com',
          type: '@cert-authority rsa', # Alias
          key: 'AAAAB3NzaC1yc2EAAAA'
        )
        expect(resource[:type]).to eq(:'@cert-authority ssh-rsa')
      end
    end
  end
end
