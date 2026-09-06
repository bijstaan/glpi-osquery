#!/bin/bash
# Install the GLPI osquery agent on macOS.
#
# Lays down the same versioned tree the self-updater maintains
# (versions/<v> plus a `current` symlink) so an installed-from-archive agent and
# an updated-in-place agent are the identical layout — anything else would mean
# the update path is only ever exercised on machines that have already updated.
#
#   sudo ./install.sh --server https://glpi.example.com --secret <secret> [--ca-cert /path/ca.pem]
set -euo pipefail

ROOT="/usr/local/glpi-osquery-agent"
PLIST_LABEL="com.bijstaan.glpi-osquery-agent"
PLIST="/Library/LaunchDaemons/${PLIST_LABEL}.plist"

if [[ "$(id -u)" != "0" ]]; then
  echo "This installer must run as root (osqueryd needs it to read SMBIOS and disks)." >&2
  exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(cat "${HERE}/VERSION" 2>/dev/null || echo 0.0.0)"

echo "==> installing version ${VERSION}"
install -d "${ROOT}/versions/${VERSION}/bin"
cp "${HERE}/bin/"* "${ROOT}/versions/${VERSION}/bin/"
chmod 0755 "${ROOT}/versions/${VERSION}/bin/"*
printf '%s\n' "$VERSION" > "${ROOT}/versions/${VERSION}/VERSION"

ln -sfn "${ROOT}/versions/${VERSION}" "${ROOT}/current.new"
mv -f "${ROOT}/current.new" "${ROOT}/current"

install -d -m 0750 /var/lib/glpi-osquery-agent
install -d /etc/glpi-osquery-agent

if [[ $# -gt 0 ]]; then
  echo "==> enrolling"
  "${ROOT}/current/bin/glpi-osquery-agent" install "$@"
fi

if [[ ! -f /etc/glpi-osquery-agent/agent.json ]]; then
  cat >&2 <<EOF

Installed, but not enrolled. Run:
  sudo ${ROOT}/current/bin/glpi-osquery-agent install \\
      --server https://glpi.example.com --secret <secret>
  sudo launchctl load -w ${PLIST}
EOF
  exit 0
fi

echo "==> installing the launchd daemon"
cp "${HERE}/${PLIST_LABEL}.plist" "$PLIST"
chown root:wheel "$PLIST"
chmod 0644 "$PLIST"

# bootout first so re-running the installer upgrades cleanly rather than
# failing on an already-loaded label.
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/${PLIST_LABEL}"

echo "==> running"
launchctl print "system/${PLIST_LABEL}" | head -5 || true

cat <<EOF

Installed. Useful commands:
  sudo launchctl print system/${PLIST_LABEL}     # status
  sudo launchctl bootout system ${PLIST}          # stop
  tail -f /var/log/glpi-osquery-agent.log         # logs

Note: on macOS the agent needs Full Disk Access to read some tables. Grant it to
${ROOT}/current/bin/osqueryd in System Settings > Privacy & Security.
EOF
