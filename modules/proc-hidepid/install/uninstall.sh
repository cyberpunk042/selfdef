#!/usr/bin/env bash
# proc-hidepid — uninstall.
#
# Removes proc.mount unit + daemon-reload. Live /proc keeps the
# hidepid option until reboot (re-mount-without-hidepid removes
# the kernel-side setting).

set -euo pipefail

MODULE="proc-hidepid"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

PROC_MOUNT_DST="${SYSTEMD_DIR}/proc.mount"
removed=0
if [[ -f "$PROC_MOUNT_DST" ]]; then
    if head -1 "$PROC_MOUNT_DST" | grep -qF "$PROC_MARKER"; then
        run "remove proc.mount" -- rm -f "$PROC_MOUNT_DST"
        removed=$((removed + 1))
    else
        log "proc.mount present but NOT selfdef-managed — leaving alone"
    fi
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    # Live remount-without-hidepid (best-effort).
    if mount -o "remount,nosuid,nodev,noexec" /proc 2>/dev/null; then
        log "/proc remounted live without hidepid"
    fi
fi

emit_status "ok" "proc-hidepid removed=$removed (NOTE: kernel /proc state survives until next remount or reboot)"
