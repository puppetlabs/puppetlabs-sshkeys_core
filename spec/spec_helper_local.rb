dir = File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.unshift File.join(dir, 'lib')

# Container for various Puppet-specific RSpec helpers.
module PuppetSpec
end

require 'puppet_spec/files'

RSpec.configure do |config|
  config.before :each do |_test|
    base = PuppetSpec::Files.tmpdir('tmp_settings')
    Puppet[:vardir] = File.join(base, 'var')
    Puppet[:confdir] = File.join(base, 'etc')
    Puppet[:codedir] = File.join(base, 'code')
    Puppet[:logdir] = "$vardir/log"
    Puppet[:rundir] = "$vardir/run"
    Puppet[:hiera_config] = File.join(base, 'hiera')

    FileUtils.mkdir_p Puppet[:statedir]

    if Puppet.version.to_f >= 7.0
      Puppet[:publicdir] = File.join(base, 'public')
      FileUtils.mkdir_p Puppet[:publicdir]
    end

    Puppet::Test::TestHelper.before_each_test()
  end
end
