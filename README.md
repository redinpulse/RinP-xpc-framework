# RinP-xpc-framework
Red in Pulse post-exploitation tool maintains macOS persistence by leveraging a design weakness in Background Task Management (BTM). It creates a service that blends into the `launchd` lifecycle as a legitimate Apple component, enabling scheduled reconnection after session loss while reducing exposure to signature-based detection.
