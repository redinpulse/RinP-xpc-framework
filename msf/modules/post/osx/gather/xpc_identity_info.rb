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
        'Name'         => 'macOS XPC Daemon Identity Info',
        'Description'  => %q{
          Retrieves the XPC daemon's identity and code signing information including
          the signing identity, team identifier, entitlements, code directory hash,
          and certificate chain. Useful for verifying the daemon's integrity and
          understanding its privilege level.
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

    print_status("Querying daemon identity and code signing info...")
    data = xpc_exec!('id')
    return if data.nil?

    if data.is_a?(Hash)
      tbl = Rex::Text::Table.new(
        'Header'  => 'XPC Daemon Identity',
        'Indent'  => 2,
        'Columns' => ['Property', 'Value']
      )

      display_order = %w[
        bundle_id signing_id team_id pid uid euid
        code_hash executable entitlements certificates
      ]

      ordered_keys = display_order.select { |k| data.key?(k) }
      remaining    = data.keys - ordered_keys
      (ordered_keys + remaining.sort).each do |key|
        value = data[key]
        value = value.to_json if value.is_a?(Array) || value.is_a?(Hash)
        tbl << [key, value.to_s[0..120]]
      end

      print_line(tbl.to_s)
    else
      print_line(data.to_s)
    end
  end
end
