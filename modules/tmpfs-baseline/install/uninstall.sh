#!/usr/bin/env bash
# tmpfs-baseline — uninstall.
#
# Removes drop-ins. If tmpfs profile was active + backup exists,
# restores the OS-shipped tmp.mount. systemctl daemon-reload.
# NOTE: live mount options persist until reboot or manual remount.

set -euo pipefail

MODULE="tmpfs-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
for f in "${SYSTEMD_DIR}/tmp.mount.d/50-selfdef.conf" \
         "${SYSTEMD_DIR}/var-tmp.mount.d/50-selfdef.conf"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

# Restore OS-shipped tmp.mount if backup present.
TMP_MOUNT_DST="${SYSTEMD_DIR}/tmp.mount"
TMP_MOUNT_BACKUP="${TMP_MOUNT_DST}.selfdef-backup"
if [[ -f "$TMP_MOUNT_BACKUP" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would restore $TMP_MOUNT_BACKUP → $TMP_MOUNT_DST"
    else
        run "restore OS-shipped tmp.mount" -- mv "$TMP_MOUNT_BACKUP" "$TMP_MOUNT_DST"
        removed=$((removed + 1))
    fi
elif [[ -f "$TMP_MOUNT_DST" ]] && grep -q "selfdef" "$TMP_MOUNT_DST" 2>/dev/null; then
    # No backup — operator never had OS-shipped /etc/systemd/system/
    # tmp.mount before us. Remove ours so the OS-default /usr/lib/
    # systemd/system/tmp.mount takes over on next daemon-reload.
    run "remove selfdef tmp.mount" -- rm -f "$TMP_MOUNT_DST"
    removed=$((removed + 1))
fi

if [[ "$removed" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    log "NOTE: live /tmp + /var/tmp mount options persist with selfdef flags until reboot or manual remount"
fi

emit_status "ok" "tmpfs-baseline removed=$removed"
