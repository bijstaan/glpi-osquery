#!/usr/bin/env bash
# Build a .deb from an agent bundle.
#
# The package lays down the same versioned tree the self-updater maintains
# (versions/<v> plus a `current` symlink), so an installed-from-package agent
# and an updated-in-place agent are byte-for-byte the same layout. Anything else
# would mean the update path is only ever exercised on machines that have
# already updated once.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-0.1.0}"
ARCH="${2:-amd64}"
BUNDLE="dist/${VERSION}/glpi-osquery-agent_${VERSION}_linux_${ARCH}.tar.gz"

[[ -f "$BUNDLE" ]] || { echo "missing bundle $BUNDLE — run ./build.sh $VERSION first" >&2; exit 1; }

ROOT="$(mktemp -d)"
PKGDIR="${ROOT}/pkg"

install -d "${PKGDIR}/DEBIAN"
install -d "${PKGDIR}/opt/glpi-osquery-agent/versions/${VERSION}"
install -d "${PKGDIR}/lib/systemd/system"
install -d "${PKGDIR}/etc/glpi-osquery-agent"
install -d "${PKGDIR}/var/lib/glpi-osquery-agent"

tar -xzf "$BUNDLE" -C "${PKGDIR}/opt/glpi-osquery-agent/versions/${VERSION}"
ln -sfn "/opt/glpi-osquery-agent/versions/${VERSION}" "${PKGDIR}/opt/glpi-osquery-agent/current"

install -m 0644 packaging/glpi-osquery-agent.service "${PKGDIR}/lib/systemd/system/"

cat > "${PKGDIR}/DEBIAN/control" <<EOF
Package: glpi-osquery-agent
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: Bijstaan <support@bijstaan.com>
Depends: ca-certificates
Description: GLPI osquery inventory agent
 Supervises a bundled osqueryd that reports inventory to GLPI and answers
 live queries, and keeps itself up to date from the GLPI server.
EOF

cat > "${PKGDIR}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

chmod 0750 /var/lib/glpi-osquery-agent || true

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Only started once configured: without a server URL and enrolment secret
    # the agent would fail on every start and fill the journal with noise.
    if [ -f /etc/glpi-osquery-agent/agent.json ]; then
        systemctl enable --now glpi-osquery-agent.service || true
    else
        echo "glpi-osquery-agent installed. Enroll it with:"
        echo "  glpi-osquery-agent install --server https://glpi.example.com --secret <secret>"
        echo "then: systemctl enable --now glpi-osquery-agent"
    fi
fi
EOF
chmod 0755 "${PKGDIR}/DEBIAN/postinst"

cat > "${PKGDIR}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl disable --now glpi-osquery-agent.service || true
fi
EOF
chmod 0755 "${PKGDIR}/DEBIAN/prerm"

# A convenience symlink so the install subcommand is on PATH.
install -d "${PKGDIR}/usr/bin"
ln -sfn /opt/glpi-osquery-agent/current/bin/glpi-osquery-agent "${PKGDIR}/usr/bin/glpi-osquery-agent"

OUT="dist/${VERSION}/glpi-osquery-agent_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKGDIR" "$OUT" >/dev/null
rm -rf "$ROOT"

echo "$OUT"
sha256sum "$OUT"
