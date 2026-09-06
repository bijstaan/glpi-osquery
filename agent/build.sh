#!/usr/bin/env bash
# Build agent bundles for every supported platform.
#
# A bundle is one archive containing the supervisor, the pinned osqueryd and —
# on Linux — the EDID extension. Keeping them in a single versioned artifact is
# what makes self-update atomic: `current` points at one directory holding
# binaries that were tested together, rather than a mix that has never run as a
# combination anywhere.
#
#   ./build.sh [version] [os/arch ...]
#   ./build.sh 1.0.0 all
#
# Produces dist/<version>/ archives plus a SHA-256 and size for each, which is
# exactly what the GLPI packages table needs.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-0.1.0}"
shift || true

TARGETS=("${@:-linux/amd64}")
if [[ "${TARGETS[0]}" == "all" ]]; then
  TARGETS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)
fi

OSQUERY_VERSION="${OSQUERY_VERSION:-5.19.0}"
RELEASES="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}"
DIST="dist/${VERSION}"
CACHE="dist/cache"

mkdir -p "$DIST" "$CACHE"

fetch() {
  local url="$1"
  local dest="$2"
  if [[ -f "$dest" ]]; then return; fi
  echo "==> fetching $(basename "$url")" >&2
  curl -fsSL -o "$dest" "$url"
}

# osqueryd, per platform, from osquery's own release assets.
#
# Every platform has a plain archive published alongside the installers, so
# nothing here has to unpack an MSI or a .pkg — which would otherwise need
# tooling that does not exist on a normal Linux build host.
osqueryd_for() {
  local goos="$1"
  local goarch="$2"
  local out="$CACHE/osqueryd-${OSQUERY_VERSION}-${goos}-${goarch}"
  if [[ -x "$out" ]]; then echo "$out"; return; fi

  local tmp
  tmp="$(mktemp -d)"

  case "$goos" in
    linux)
      local deb_arch="$goarch"
      local deb="$CACHE/osquery_${OSQUERY_VERSION}_${deb_arch}.deb"
      fetch "${RELEASES}/osquery_${OSQUERY_VERSION}-1.linux_${deb_arch}.deb" "$deb"
      dpkg-deb -x "$deb" "$tmp"
      cp "$tmp/opt/osquery/bin/osqueryd" "$out"
      ;;

    darwin)
      # One universal binary covers both Intel and Apple silicon.
      local tarball="$CACHE/osqueryd-macos-bare-${OSQUERY_VERSION}.tar.gz"
      fetch "${RELEASES}/osqueryd-macos-bare-${OSQUERY_VERSION}.tar.gz" "$tarball"
      tar -xzf "$tarball" -C "$tmp"
      cp "$tmp/osqueryd" "$out"
      ;;

    windows)
      local win_arch="x86_64"
      [[ "$goarch" == "arm64" ]] && win_arch="arm64"
      local zip="$CACHE/osquery-${OSQUERY_VERSION}.windows_${win_arch}.zip"
      fetch "${RELEASES}/osquery-${OSQUERY_VERSION}.windows_${win_arch}.zip" "$zip"
      unzip -q -o "$zip" -d "$tmp"
      cp "$tmp/osquery-${OSQUERY_VERSION}.windows_${win_arch}/Program Files/osquery/osqueryd/osqueryd.exe" "$out"
      ;;

    *)
      echo "no osqueryd source for $goos" >&2
      rm -rf "$tmp"
      return 1
      ;;
  esac

  chmod 0755 "$out"
  rm -rf "$tmp"
  echo "$out"
}

publish() {
  local archive="$1"
  local sha size
  sha="$(sha256sum "$archive" | cut -d' ' -f1)"
  size="$(stat -c%s "$archive")"
  printf '%s  %s\n' "$sha" "$(basename "$archive")" > "${archive}.sha256"
  printf '    %s\n      sha256 %s\n      size   %s\n' "$archive" "$sha" "$size"
}

for target in "${TARGETS[@]}"; do
  GOOS="${target%%/*}"
  GOARCH="${target##*/}"

  echo "==> building ${GOOS}/${GOARCH} ${VERSION}"

  stage="$(mktemp -d)"
  mkdir -p "$stage/bin"

  ext=""
  [[ "$GOOS" == "windows" ]] && ext=".exe"

  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -trimpath \
    -ldflags "-s -w -X github.com/bijstaan/glpi-osquery-agent/internal/version.Version=${VERSION}" \
    -o "$stage/bin/glpi-osquery-agent${ext}" ./cmd/glpi-osquery-agent

  # The EDID extension only has a job on Linux: osquery has a native display
  # table on macOS and the registry serves Windows.
  if [[ "$GOOS" == "linux" ]]; then
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
      -trimpath -ldflags "-s -w" \
      -o "$stage/bin/glpi-edid.ext" ./cmd/glpi-edid-ext
    chmod 0755 "$stage/bin/glpi-edid.ext"
  fi

  osqueryd="$(osqueryd_for "$GOOS" "$GOARCH")"
  cp "$osqueryd" "$stage/bin/osqueryd${ext}"
  chmod 0755 "$stage/bin/osqueryd${ext}"

  # Platform service definitions and installers travel with the bundle so the
  # same artifact can be laid down by a package or by hand.
  case "$GOOS" in
    linux)
      cp packaging/preflight.sh "$stage/bin/preflight.sh"
      chmod 0755 "$stage/bin/preflight.sh"
      cp packaging/glpi-osquery-agent.service "$stage/"
      ;;
    darwin)
      cp packaging/com.bijstaan.glpi-osquery-agent.plist "$stage/"
      cp packaging/install-macos.sh "$stage/install.sh"
      chmod 0755 "$stage/install.sh"
      ;;
    windows)
      cp packaging/install-windows.ps1 "$stage/install.ps1"
      ;;
  esac

  printf '%s\n' "$VERSION" > "$stage/VERSION"

  # Explicit modes rather than whatever the build host's umask produced. A
  # umask of 002 — the default on Debian/Ubuntu for a user in its own group —
  # yields group-writable directories, and osqueryd will not autoload an
  # extension from a directory anyone but the owner can write to. The symptom
  # is the extension's tables silently missing, with one warning buried in
  # osqueryd's stderr.
  find "$stage" -type d -exec chmod 0755 {} +
  find "$stage" -type f -exec chmod 0644 {} +
  chmod 0755 "$stage/bin/"*

  if [[ "$GOOS" == "windows" ]]; then
    archive="${DIST}/glpi-osquery-agent_${VERSION}_${GOOS}_${GOARCH}.zip"
    rm -f "$archive"
    (cd "$stage" && zip -qr "$OLDPWD/$archive" .)
  else
    archive="${DIST}/glpi-osquery-agent_${VERSION}_${GOOS}_${GOARCH}.tar.gz"
    # Stamped root:root rather than inheriting the build user. osqueryd refuses
    # to start if its own binary — or the directory holding an extension it
    # would autoload — is owned by anyone but the user running it, so an archive
    # carrying a build-host uid produces an agent that unpacks perfectly and
    # then cannot run osqueryd at all.
    tar --owner=0 --group=0 --numeric-owner -czf "$archive" -C "$stage" .
  fi

  rm -rf "$stage"
  publish "$archive"
done

echo
echo "Publish these in GLPI under Setup -> osquery Inventory -> Agent updates."
