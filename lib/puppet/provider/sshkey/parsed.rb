require 'puppet/provider/parsedfile'

Puppet::Type.type(:sshkey).provide(
  :parsed,
  parent: Puppet::Provider::ParsedFile,
  filetype: :flat,
) do
  desc 'Parse and generate host-wide known hosts files for SSH.'

  text_line :comment, match: %r{^#}
  text_line :blank, match: %r{^\s*$}

  record_line :parsed, fields: ['name', 'type', 'key'],
                       post_parse: proc { |hash|
                                     # Check if this is a cert-authority line by looking at the name field
                                     if hash[:name] && hash[:name] == '@cert-authority'
                                       # Re-parse the cert-authority format: @cert-authority hostname keytype key
                                       # The original fields were: name='@cert-authority', type='hostname', key='keytype actualkey'
                                       hostname = hash[:type]
                                       keytype_and_key = hash[:key].split(/\s+/, 2)
                                       if keytype_and_key.length >= 2
                                         keytype = keytype_and_key[0]
                                         actual_key = keytype_and_key[1]
                                         hash[:name] = hostname
                                         hash[:type] = "@cert-authority #{keytype}"
                                         hash[:key] = actual_key
                                       end
                                     end

                                     # Handle host aliases for all entries
                                     if hash[:name]
                                       names = hash[:name].split(',', -1)
                                       hash[:name] = names.shift
                                       hash[:host_aliases] = names
                                     end
                                   },
                       pre_gen: proc { |hash|
                                  if hash[:host_aliases]
                                    hash[:name] = [hash[:name], hash[:host_aliases]].flatten.join(',')
                                    hash.delete(:host_aliases)
                                  end
                                  # Handle cert-authority format
                                  if hash[:type] && hash[:type].to_s.start_with?('@cert-authority ')
                                    # Extract the key type from '@cert-authority ssh-rsa' format
                                    key_type = hash[:type].to_s.sub(/^@cert-authority /, '')
                                    # Reorder fields for cert-authority format: @cert-authority name key_type key
                                    # We need to restructure to have three fields: name="@cert-authority hostname", type="keytype", key=key
                                    hash[:name] = "@cert-authority #{hash[:name]}"
                                    hash[:type] = key_type
                                  end
                                }

  # Make sure to use mode 644 if ssh_known_hosts is newly created
  def self.default_mode
    0o644
  end

  def title
    "#{property_hash[:name]}@#{property_hash[:type]}"
  end

  def self.default_target
    case Facter.value('os.name')
    when 'Darwin'
      # Versions 10.11 and up use /etc/ssh/ssh_known_hosts
      version = Facter.value('os.macosx.version.major')
      if version
        if Puppet::Util::Package.versioncmp(version, '10.11') >= 0
          '/etc/ssh/ssh_known_hosts'
        else
          '/etc/ssh_known_hosts'
        end
      else
        '/etc/ssh_known_hosts'
      end
    else
      '/etc/ssh/ssh_known_hosts'
    end
  end

  def self.resource_for_record(record, resources)
    name = "#{record[:name]}@#{record[:type]}"
    resources[name]
  end
end
