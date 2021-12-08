require 'spec_helper'
require 'puppet_spec/files'
require 'puppet_spec/compiler'
require 'puppet/provider/parsedfile'

# parsedfile provider implements prefetch
Puppet::Type.newtype(:prefetchable_test) do
  newparam(:name, isnamevar: true)
end
Puppet::Type.type(:prefetchable_test).provide(:parsed, parent: Puppet::Provider::ParsedFile, filetype: :flat) do
end

describe 'Puppet::Type.type(:user) (integration)', unless: Puppet.features.microsoft_windows? do
  include PuppetSpec::Files
  include PuppetSpec::Compiler

  context 'when set to purge ssh keys from a file' do
    # different UTF-8 widths
    # 1-byte A
    # 2-byte ۿ - http://www.fileformat.info/info/unicode/char/06ff/index.htm - 0xDB 0xBF / 219 191
    # 3-byte ᚠ - http://www.fileformat.info/info/unicode/char/16A0/index.htm - 0xE1 0x9A 0xA0 / 225 154 160
    # 4-byte 𠜎 - http://www.fileformat.info/info/unicode/char/2070E/index.htm - 0xF0 0xA0 0x9C 0x8E / 240 160 156 142
    let(:mixed_utf8) { "A\u06FF\u16A0\u{2070E}" } # Aۿᚠ𠜎

    let(:tempfile) do
      file_containing('user_spec', <<-EOF)
        # comment #{mixed_utf8}
        ssh-rsa KEY-DATA key-name
        ssh-rsa KEY-DATA key name
        EOF
    end
    # must use an existing user, or the generated key resource
    # will fail on account of an invalid user for the key
    # - root should be a safe default
    let(:manifest) { "user { 'root': purge_ssh_keys => '#{tempfile}' }" }

    it 'purges authorized ssh keys' do
      apply_manifest(manifest)
      expect(File.read(tempfile, encoding: Encoding::UTF_8)).not_to match(%r{key-name})
    end

    it 'purges keys with spaces in the comment string' do
      apply_manifest(manifest)
      expect(File.read(tempfile, encoding: Encoding::UTF_8)).not_to match(%r{key name})
    end

    context 'with other prefetching resources evaluated first' do
      let(:provider) { Puppet::Type.type(:prefetchable_test).provider(:parsed) }
      let(:manifest) do
        "
          prefetchable_test { 'test':
            before => User[root]
          }
          user { 'root':
            purge_ssh_keys => '#{tempfile}'
          }
        "
      end

      before(:each) do
        provider.default_target = tmpfile('prefetchable')
      end

      after(:each) do
        provider.clear
      end

      it 'purges authorized ssh keys' do
        apply_manifest(manifest)
        expect(File.read(tempfile, encoding: Encoding::UTF_8)).not_to match(%r{key-name})
      end
    end

    context 'with multiple unnamed keys' do
      let(:tempfile) do
        file_containing('user_spec', <<-EOF)
          # comment #{mixed_utf8}
          ssh-rsa KEY-DATA1
          ssh-rsa KEY-DATA2
          EOF
      end

      it 'purges authorized ssh keys' do
        apply_manifest(manifest)
        expect(File.read(tempfile, encoding: Encoding::UTF_8)).not_to match(%r{KEY-DATA})
      end
    end
  end
end
