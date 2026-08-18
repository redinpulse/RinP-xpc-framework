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
        'Name'         => 'macOS XPC Security Tools and Posture Check',
        'Description'  => %q{
          Detects installed security tools (EDR, AV, firewalls) and evaluates the
          overall security posture of the macOS target via the XPC daemon. Checks for
          SIP status, Gatekeeper, FileVault, firewall state, and running security
          processes. Detected EDR/AV products are highlighted in red.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Mr.Gedik'],
        'Platform'     => ['osx'],
        'SessionTypes' => ['meterpreter', 'shell']
      )
    )
  end

  EDR_AV_KEYWORDS = %w[
    crowdstrike falcon sentinel sentinelone carbon carbonblack
    cylance sophos jamf kandji mosyle malwarebytes norton kaspersky
    eset avast avg bitdefender mcafee symantec trendmicro
    littlesnitch lulu blockblock santa osquery endpoint xprotect
  ].freeze

  def run
    unless xpc_client_exists?
      print_error("XPC client not found. Run xpc_daemon_install first.")
      return
    end

    print_status("Checking security tools and posture via XPC daemon...")

    tools_data   = xpc_exec!('e2')
    posture_data = xpc_exec!('e4')

    if tools_data
      print_security_tools(tools_data)
    else
      print_warning("Could not retrieve security tools data")
    end

    if posture_data
      print_security_posture(posture_data)
    else
      print_warning("Could not retrieve security posture data")
    end
  end

  private

  def print_security_tools(data)
    tbl = Rex::Text::Table.new(
      'Header'  => 'Security Tools',
      'Indent'  => 2,
      'Columns' => ['Tool / Process', 'Status', 'Details']
    )

    entries = data.is_a?(Array) ? data : (data.is_a?(Hash) ? data.map { |k, v| { 'name' => k, 'status' => v } } : [])

    entries.each do |entry|
      entry = { 'name' => entry.to_s, 'status' => 'detected' } unless entry.is_a?(Hash)
      name    = entry['name']    || entry['tool']    || ''
      status  = entry['status']  || entry['running'] || ''
      details = entry['details'] || entry['path']    || ''

      is_edr = EDR_AV_KEYWORDS.any? { |kw| name.downcase.include?(kw) || details.downcase.include?(kw) }

      if is_edr && status.to_s =~ /running|detected|found|true|yes/i
        name    = "%red#{name}%clr"
        status  = "%red#{status}%clr"
      end

      tbl << [name, status.to_s, details.to_s[0..80]]
    end

    print_line(tbl.to_s)
  end

  def print_security_posture(data)
    tbl = Rex::Text::Table.new(
      'Header'  => 'Security Posture',
      'Indent'  => 2,
      'Columns' => ['Setting', 'Value']
    )

    if data.is_a?(Hash)
      priority_keys = %w[sip gatekeeper filevault firewall xprotect amfi]
      ordered = priority_keys.select { |k| data.key?(k) }
      remaining = data.keys - ordered
      (ordered + remaining.sort).each do |key|
        value = data[key].to_s
        if key =~ /sip|filevault|firewall|gatekeeper/i && value =~ /disabled|off|false/i
          value = "%grn#{value}%clr"
        end
        tbl << [key, value[0..120]]
      end
    elsif data.is_a?(Array)
      data.each do |entry|
        if entry.is_a?(Hash)
          entry.each { |k, v| tbl << [k, v.to_s[0..120]] }
        end
      end
    end

    print_line(tbl.to_s)
  end
end
