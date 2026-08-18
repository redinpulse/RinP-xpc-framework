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
        'Name'         => 'macOS XPC Daemon Status',
        'Description'  => %q{
          Performs a health check on the installed XPC daemon. Queries
          launchctl for service state and, if the daemon is running,
          retrieves detailed information via the XPC client. Reports
          daemon status, binary presence, and launchctl service details.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Mr.Gedik'],
        'Platform'     => ['osx'],
        'SessionTypes' => ['shell', 'meterpreter']
      )
    )
  end

  def run
    print_status("Checking XPC daemon status (#{DAEMON_LABEL})...")

    status = xpc_status
    case status
    when :running
      print_good("Daemon status: running")
    when :waiting
      print_warning("Daemon status: waiting (loaded but not active)")
    when :not_running
      print_error("Daemon status: not running")
    end

    # Check binary presence
    if file?(DAEMON_PATH)
      print_good("Daemon binary present at #{DAEMON_PATH}")
    else
      print_error("Daemon binary not found at #{DAEMON_PATH}")
    end

    if file?(PLIST_PATH)
      print_good("LaunchDaemon plist present at #{PLIST_PATH}")
    else
      print_error("LaunchDaemon plist not found at #{PLIST_PATH}")
    end

    if xpc_client_exists?
      print_good("XPC client present at #{CLIENT_PATH}")
    else
      print_warning("XPC client not found at #{CLIENT_PATH}")
    end

    # If running, query daemon info via XPC
    if status == :running
      print_status('Querying daemon info via XPC...')
      info = xpc_exec!('i')
      if info
        xpc_print_table('XPC Daemon Info', info)
      else
        print_warning('Could not retrieve daemon info via XPC client')
      end
    end

    # Print launchctl service details
    print_status('Retrieving launchctl service details...')
    launchctl_out = cmd_exec("launchctl print system/#{DAEMON_LABEL} 2>&1")
    if launchctl_out && !launchctl_out.include?('Could not find service')
      print_line
      print_line('--- launchctl print output ---')
      print_line(launchctl_out)
      print_line('--- end launchctl output ---')
    else
      print_error("Service #{DAEMON_LABEL} not found in launchctl")
    end
  end
end
