#!/usr/bin/env bash
# Build a macOS .pkg installer from a bundle produced by build.sh.
#
#   ./build-pkg.sh <version> <arch>          # arch: amd64 | arm64 | universal
#
# Must run on macOS: pkgbuild and productbuild are part of the Xcode command
# line tools and have no working equivalent on Linux. The archive built by
# build.sh is the input, so the binaries in the .pkg are byte-identical to the
# ones a self-update would fetch — an installer that compiled its own copy would
# be testing a different artifact to the one the fleet actually runs.
#
# Signing and notarisation are opt-in through the environment:
#
#   INSTALLER_IDENTITY  "Developer ID Installer: Example Ltd (TEAMID)"
#   APP_IDENTITY        "Developer ID Application: Example Ltd (TEAMID)"
#   NOTARY_PROFILE      a notarytool keychain profile name
#
# Without them you get an unsigned .pkg: fine for testing, but Gatekeeper will
# refuse it on any machine that did not build it, so shipping one is not an
# option.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:?usage: build-pkg.sh <version> <arch>}"
ARCH="${2:-universal}"

IDENTIFIER="com.bijstaan.glpi-osquery-agent"
INSTALL_ROOT="/usr/local/glpi-osquery-agent"
DIST="dist/${VERSION}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  cat >&2 <<'EOF'
build-pkg.sh must run on macOS.

pkgbuild/productbuild are Xcode tools with no Linux equivalent, and a .pkg that
is not signed and notarised is refused by Gatekeeper anyway — which needs an
Apple Developer ID that only exists on a Mac keychain. On Linux, ship the
tarball from build.sh with install-macos.sh instead; it lays down the identical
tree.
EOF
  exit 2
fi

# "universal" takes the arm64 bundle: build.sh puts the same universal osqueryd
# in both, and the supervisor is the only per-arch part, so lipo-ing the two
# together is the one real step.
srcarch="$ARCH"
[[ "$ARCH" == "universal" ]] && srcarch="arm64"

archive="${DIST}/glpi-osquery-agent_${VERSION}_darwin_${srcarch}.tar.gz"
[[ -f "$archive" ]] || { echo "missing $archive — run ./build.sh $VERSION darwin/$srcarch" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

root="${work}/root"
mkdir -p "${root}${INSTALL_ROOT}/versions/${VERSION}"
tar -xzf "$archive" -C "${root}${INSTALL_ROOT}/versions/${VERSION}"

if [[ "$ARCH" == "universal" ]]; then
  other="${DIST}/glpi-osquery-agent_${VERSION}_darwin_amd64.tar.gz"
  [[ -f "$other" ]] || { echo "missing $other — needed for a universal build" >&2; exit 1; }
  intel="${work}/intel"
  mkdir -p "$intel"
  tar -xzf "$other" -C "$intel"
  lipo -create \
    "${root}${INSTALL_ROOT}/versions/${VERSION}/bin/glpi-osquery-agent" \
    "${intel}/bin/glpi-osquery-agent" \
    -output "${work}/glpi-osquery-agent.universal"
  mv "${work}/glpi-osquery-agent.universal" \
     "${root}${INSTALL_ROOT}/versions/${VERSION}/bin/glpi-osquery-agent"
  chmod 0755 "${root}${INSTALL_ROOT}/versions/${VERSION}/bin/glpi-osquery-agent"
fi

# `current` is a relative symlink so it survives being laid down under a
# non-standard install root.
ln -s "versions/${VERSION}" "${root}${INSTALL_ROOT}/current"

mkdir -p "${root}/Library/LaunchDaemons"
cp packaging/com.bijstaan.glpi-osquery-agent.plist "${root}/Library/LaunchDaemons/"

if [[ -n "${APP_IDENTITY:-}" ]]; then
  echo "==> signing binaries"
  # Hardened runtime is required for notarisation. osqueryd loads our extension
  # over a socket rather than dlopen-ing it, so no library-validation exception
  # is needed.
  for bin in "${root}${INSTALL_ROOT}/versions/${VERSION}/bin/"*; do
    codesign --force --timestamp --options runtime --sign "$APP_IDENTITY" "$bin"
  done
fi

scripts="${work}/scripts"
mkdir -p "$scripts"

cat > "${scripts}/preinstall" <<'PRE'
#!/bin/bash
# Stop a running agent before its files are replaced underneath it.
launchctl bootout system/com.bijstaan.glpi-osquery-agent 2>/dev/null || true
exit 0
PRE

cat > "${scripts}/postinstall" <<POST
#!/bin/bash
set -e
install -d -m 0750 /var/lib/glpi-osquery-agent
install -d /etc/glpi-osquery-agent

# Only start once enrolled. A daemon that restarts forever because it has no
# server to talk to buries the actual problem in launchd's throttle log, so the
# package installs quietly and waits for the enrolment step instead.
if [[ -f /etc/glpi-osquery-agent/agent.json ]]; then
  launchctl bootstrap system /Library/LaunchDaemons/${IDENTIFIER}.plist
  launchctl enable system/${IDENTIFIER}
else
  echo "Installed. Enrol with:"
  echo "  sudo ${INSTALL_ROOT}/current/bin/glpi-osquery-agent install \\\\"
  echo "      --server https://glpi.example.com --secret <secret>"
  echo "  sudo launchctl bootstrap system /Library/LaunchDaemons/${IDENTIFIER}.plist"
fi
exit 0
POST

chmod 0755 "${scripts}/preinstall" "${scripts}/postinstall"

mkdir -p "$DIST"
component="${work}/component.pkg"
out="${DIST}/glpi-osquery-agent_${VERSION}_${ARCH}.pkg"

# --ownership recommended forces root:wheel regardless of who built the staging
# tree. osqueryd refuses to start when its own binary is owned by anyone else,
# so a .pkg built by an ordinary user would otherwise install an agent that
# cannot run osqueryd.
pkgbuild \
  --root "$root" \
  --ownership recommended \
  --scripts "$scripts" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location / \
  "$component"

if [[ -n "${INSTALLER_IDENTITY:-}" ]]; then
  productbuild --package "$component" --sign "$INSTALLER_IDENTITY" "$out"
else
  echo "warning: no INSTALLER_IDENTITY — producing an unsigned .pkg that Gatekeeper will refuse" >&2
  productbuild --package "$component" "$out"
fi

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  echo "==> notarising"
  xcrun notarytool submit "$out" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$out"
fi

sha="$(shasum -a 256 "$out" | cut -d' ' -f1)"
printf '%s  %s\n' "$sha" "$(basename "$out")" > "${out}.sha256"
printf '    %s\n      sha256 %s\n      size   %s\n' "$out" "$sha" "$(stat -f%z "$out")"
