#!/usr/bin/env bash
# tmpfs-baseline — apply.
#
# Installs tmp.mount.d/50-selfdef.conf + var-tmp.mount.d/
# 50-selfdef.conf drop-ins. systemctl daemon-reload + remount.
# tmpfs profile additionally REPLACES tmp.mount (gated by
# acknowledge_tmpfs=true).

set -euo pipefail

MODULE="tmpfs-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_TMPFS_BASELINE_CONFIG:-/etc/selfdef/modules/tmpfs-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
SYSTEMD_SRC="${MODULE_DIR}/systemd"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$SYSTEMD_SRC" ]] || die "systemd dir missing: $SYSTEMD_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "noexec")
case "$PROFILE" in
    noexec|tmpfs) ;;
    *) die "profile must be noexec|tmpfs, got '$PROFILE'" ;;
esac

# REFUSE-TO-BRICK: tmpfs profile changes /tmp's backing store.
# Operator must acknowledge that workflows won't break with the
# 25% RAM size cap.
if [[ "$PROFILE" == "tmpfs" ]]; then
    ACK=$(toml_get acknowledge_tmpfs "$CONFIG_FILE" || echo "false")
    if [[ "$ACK" != "true" ]]; then
        die "tmpfs profile re-mounts /tmp as RAM-backed tmpfs (25% RAM size cap); set acknowledge_tmpfs = true in $CONFIG_FILE after confirming no operator workflow needs >25% RAM of /tmp space (large builds, video editing scratch, etc.)"
    fi
fi

install_one() {
    local src="$1" dst="$2" mode="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then return 1; fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $dst"
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    install -m "$mode" "$src" "$dst"
}

changes=0
# noexec drop-ins ALWAYS install (both profiles need them).
install_one "${SYSTEMD_SRC}/noexec-tmp.conf" \
            "${SYSTEMD_DIR}/tmp.mount.d/50-selfdef.conf" \
            "0644" && changes=$((changes + 1)) || true
install_one "${SYSTEMD_SRC}/noexec-var-tmp.conf" \
            "${SYSTEMD_DIR}/var-tmp.mount.d/50-selfdef.conf" \
            "0644" && changes=$((changes + 1)) || true

# tmpfs profile: REPLACE tmp.mount unit entirely with a tmpfs-
# backed version. Backup the OS-shipped (or none) first.
TMP_MOUNT_DST="${SYSTEMD_DIR}/tmp.mount"
TMP_MOUNT_BACKUP="${TMP_MOUNT_DST}.selfdef-backup"
if [[ "$PROFILE" == "tmpfs" ]]; then
    if [[ -f "$TMP_MOUNT_DST" ]] && [[ ! -f "$TMP_MOUNT_BACKUP" ]]; then
        if [[ "$DRY_RUN" != "1" ]]; then
            install -m 0644 "$TMP_MOUNT_DST" "$TMP_MOUNT_BACKUP"
        fi
    fi
    install_one "${SYSTEMD_SRC}/tmpfs-tmp.conf" \
                "$TMP_MOUNT_DST" \
                "0644" && changes=$((changes + 1)) || true
else
    # noexec profile: ensure no leftover tmpfs tmp.mount from a
    # prior tmpfs apply. If a backup exists, restore the original
    # OS-shipped tmp.mount; else remove ours.
    if [[ -f "$TMP_MOUNT_DST" ]] && grep -q "selfdef" "$TMP_MOUNT_DST" 2>/dev/null; then
        if [[ -f "$TMP_MOUNT_BACKUP" ]]; then
            run "restore OS-shipped tmp.mount (profile downgrade)" -- mv "$TMP_MOUNT_BACKUP" "$TMP_MOUNT_DST"
        else
            run "remove selfdef tmp.mount (profile downgrade)" -- rm -f "$TMP_MOUNT_DST"
        fi
        changes=$((changes + 1))
    fi
fi

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    # Remount tmp.mount + var-tmp.mount to pick up the new options
    # WITHOUT requiring reboot. The remount happens via systemctl
    # restart tmp.mount but that breaks anything currently holding
    # an fd open in /tmp. Safer: log notice + recommend reboot.
    log "NOTICE: mount options take effect after reboot. To remount NOW (risks breaking processes with open fds in /tmp):"
    log "  sudo systemctl restart tmp.mount var-tmp.mount"
fi

emit_status "ok" "tmpfs-baseline profile=$PROFILE changes=$changes (reboot or manual remount required)"
