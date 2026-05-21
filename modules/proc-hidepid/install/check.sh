#!/usr/bin/env bash
# proc-hidepid — check. Read-only.

set -euo pipefail

MODULE="proc-hidepid"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_PROC_HIDEPID_CONFIG:-/etc/selfdef/modules/proc-hidepid.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "noaccess")
case "$PROFILE" in
    noaccess) expected_val="2" ;;
    invisible) expected_val="4" ;;
esac

drift=0
PROC_MOUNT_DST="${SYSTEMD_DIR}/proc.mount"
if [[ ! -f "$PROC_MOUNT_DST" ]]; then
    emit_status "drift" "proc.mount unit missing: $PROC_MOUNT_DST"
    drift=$((drift + 1))
elif ! head -1 "$PROC_MOUNT_DST" | grep -qF "$PROC_MARKER"; then
    emit_status "drift" "proc.mount present but not selfdef-managed"
    drift=$((drift + 1))
fi

# Live mount check.
if awk '$2 == "/proc"' /proc/mounts | grep -qE "hidepid=${expected_val}"; then
    log "live /proc has hidepid=${expected_val} — OK"
else
    actual=$(awk '$2 == "/proc"' /proc/mounts | head -1 | awk '{print $4}')
    emit_status "drift" "live /proc options ($actual) do not include hidepid=${expected_val} — reboot may be pending"
    drift=$((drift + 1))
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "proc-hidepid profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "proc-hidepid profile=$PROFILE no drift"
