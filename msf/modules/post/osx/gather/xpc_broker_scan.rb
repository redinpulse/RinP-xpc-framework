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
        'Name'         => 'macOS XPC Service Broker Scan',
        'Description'  => %q{
          Scans all known system XPC services via the Mach service broker. Enumerates
          which services are present, reachable, and responsive on the target system.
          Useful for identifying attack surface and available privileged services.
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

    print_status("Scanning system XPC services via broker...")
    data = xpc_exec!('b2', timeout: 60)
    return if data.nil?

    found     = []
    not_found = []

    if data.is_a?(Array)
      data.each do |svc|
        if svc.is_a?(Hash)
          if svc['reachable'] || svc['status'] == 'found'
            found << svc
          else
            not_found << svc
          end
        end
      end
    elsif data.is_a?(Hash)
      data.each do |name, status|
        entry = { 'service' => name, 'status' => status.to_s }
        status.to_s =~ /found|reachable|yes|true/i ? found << entry : not_found << entry
      end
    end

    tbl_found = Rex::Text::Table.new(
      'Header'  => "Reachable XPC Services (#{found.length})",
      'Indent'  => 2,
      'Columns' => ['Service', 'Status']
    )
    found.each do |svc|
      tbl_found << [svc['service'] || svc['name'] || '', svc['status'] || 'found']
    end
    print_line(tbl_found.to_s)

    tbl_missing = Rex::Text::Table.new(
      'Header'  => "Unreachable XPC Services (#{not_found.length})",
      'Indent'  => 2,
      'Columns' => ['Service', 'Status']
    )
    not_found.each do |svc|
      tbl_missing << [svc['service'] || svc['name'] || '', svc['status'] || 'not found']
    end
    print_line(tbl_missing.to_s)

    print_good("Total: #{found.length} found, #{not_found.length} not found")
  end
end
