#!/usr/bin/env bash
# Rollback guard, run by the service manager BEFORE the agent starts.
#
# This exists because the agent cannot roll itself back from the one failure
# that matters most: a new version so broken it never runs. In that case there
# is no process left to notice the problem, and the machine is left with no
# working agent — which from the server looks identical to a computer that has
# been switched off, with no remote way back.
#
# So the decision is made from outside the binary. Each start attempt increments
# a counter in the staged-update marker; after MAX_ATTEMPTS the `current`
# symlink is pointed back at the previous version and the marker cleared.
#
# The agent clears the marker itself once it has started AND reached the server,
# so a version that runs but cannot work is also caught.
set -euo pipefail

STATE_DIR="${GLPI_OSQUERY_STATE_DIR:-/var/lib/glpi-osquery-agent}"
INSTALL_ROOT="${GLPI_OSQUERY_INSTALL_ROOT:-/opt/glpi-osquery-agent}"
MARKER="${STATE_DIR}/update-pending.json"
MAX_ATTEMPTS=3

log() { echo "glpi-osquery-agent preflight: $*" >&2; }

[[ -f "$MARKER" ]] || exit 0

read_field() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" "$MARKER" | head -1
}

attempts="$(read_field attempts)"
previous="$(read_field previous_version)"
new_version="$(read_field new_version)"
attempts="${attempts:-0}"

if [[ "$attempts" -ge "$MAX_ATTEMPTS" ]]; then
  if [[ -n "$previous" && -d "${INSTALL_ROOT}/versions/${previous}" ]]; then
    log "version ${new_version} failed to start ${attempts} times; rolling back to ${previous}"
    ln -sfn "${INSTALL_ROOT}/versions/${previous}" "${INSTALL_ROOT}/current.new"
    mv -Tf "${INSTALL_ROOT}/current.new" "${INSTALL_ROOT}/current"
    rm -f "$MARKER"
  else
    # Nothing to go back to. Clearing the marker stops an unbootable loop from
    # being retried forever; the failure is visible in the journal and the
    # agent's version will stop advancing on the server, which is the signal an
    # operator needs.
    log "version ${new_version} failed ${attempts} times and there is no previous version to restore"
    rm -f "$MARKER"
  fi
  exit 0
fi

next=$((attempts + 1))
tmp="${MARKER}.tmp"
sed "s/\"attempts\"[[:space:]]*:[[:space:]]*${attempts}/\"attempts\": ${next}/" "$MARKER" > "$tmp"
mv -f "$tmp" "$MARKER"

log "starting staged version ${new_version} (attempt ${next}/${MAX_ATTEMPTS})"
