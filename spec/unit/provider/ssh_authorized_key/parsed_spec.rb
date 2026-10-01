require 'spec_helper'

describe 'ssh_authorized_key parsed provider', unless: Puppet.features.microsoft_windows? do
  let(:type) { Puppet::Type.type(:ssh_authorized_key) }
  let(:target) { '/root/.ssh/authorized_keys' }
  let(:provider) { type.new(name: 'foo@bar', target: target).provider }

  after :each do
    type.provider(:parsed).clear
  end

  describe '#trusted_path' do
    # Fake the /root/.ssh -> /root -> / chain as trusted Pathnames so
    # trusted_path walks it to its `return true` without hitting the real filesystem.
    let(:root_dir)  { instance_double(Pathname, root?: true) }
    let(:root_home) { instance_double(Pathname, root?: false, dirname: root_dir) }
    let(:dot_ssh) do
      instance_double(
        Pathname,
        dirname: root_home,
        symlink?: false,
        world_writable?: false,
        stat: instance_double(File::Stat, uid: Process.euid, mode: 0o755),
      )
    end

    before :each do
      allow(provider).to receive(:target).and_return(target)
      allow(Puppet::FileSystem).to receive(:dir_exist?).with(target).and_return(true)
      allow(Puppet::FileSystem).to receive(:pathname).with(target).and_return(instance_double(Pathname, dirname: dot_ssh))
    end

    it 'returns true when every checked path component is trusted' do
      expect(provider.trusted_path).to eq(true)
    end

    it 'returns false when a path component is world writable' do
      allow(dot_ssh).to receive(:world_writable?).and_return(true)
      expect(provider.trusted_path).to eq(false)
    end
  end
end
