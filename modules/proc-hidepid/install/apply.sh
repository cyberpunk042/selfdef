#!/usr/bin/env bash
# proc-hidepid — apply.
#
# /proc is mounted by initramfs BEFORE systemd takes over; the
# safest re-mount path is via systemd's proc-special handling.
# We write a proc-hidepid.mount unit that re-mounts /proc with
# the chosen hidepid option (remount=,hidepid=N).
#
# Alternative: edit /etc/fstab. We avoid that — fstab changes
# need next-reboot to take effect + are operator-territory.

set -euo pipefail

MODULE="proc-hidepid"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_PROC_HIDEPID_CONFIG:-/etc/selfdef/modules/proc-hidepid.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "noaccess")
case "$PROFILE" in
    noaccess) hidepid_val="2" ;;
    invisible) hidepid_val="4" ;;
    *) die "profile must be noaccess|invisible, got '$PROFILE'" ;;
esac

# REFUSE-TO-BRICK: invisible profile breaks dbus + monitoring.
bypass_gid=""
if [[ "$PROFILE" == "invisible" ]]; then
    ACK=$(toml_get acknowledge_hidepid "$CONFIG_FILE" || echo "false")
    if [[ "$ACK" != "true" ]]; then
        die "invisible profile hides /proc/<pid> entries from non-root users; can break dbus + monitoring daemons; set acknowledge_hidepid = true in $CONFIG_FILE after confirming no operator workflow depends on cross-user /proc enumeration"
    fi
    bypass_gid=$(toml_get bypass_gid "$CONFIG_FILE" || echo "")
fi

# Build mount options.
opts="nosuid,nodev,noexec,hidepid=${hidepid_val}"
if [[ -n "$bypass_gid" ]]; then
    # gid= specifies a group that bypasses hidepid (members can
    # see other users' /proc entries). Operator-pull for monitoring.
    opts="${opts},gid=${bypass_gid}"
fi

# Render proc.mount unit (replacing OS-shipped if any).
PROC_MOUNT_DST="${SYSTEMD_DIR}/proc.mount"
tmp_rendered="$(mktemp)"
# NOTE: do NOT include a `rendered=$(date)` timestamp in the unit
# file — including it defeats the cmp -s idempotency check below
# (the timestamp differs on every apply, forcing an unnecessary
# install + systemctl daemon-reload + /proc remount on every run).
# Same lesson as the dns-shield fix (2026-06-06).
cat > "$tmp_rendered" <<EOF
$PROC_MARKER
# profile=$PROFILE hidepid=$hidepid_val
[Unit]
Description=Proc filesystem with hidepid=$hidepid_val (selfdef)
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
ConditionVirtualization=!container

[Mount]
What=proc
Where=/proc
Type=proc
Options=$opts
EOF

changes=0
if [[ -f "$PROC_MOUNT_DST" ]] && cmp -s "$tmp_rendered" "$PROC_MOUNT_DST"; then
    rm -f "$tmp_rendered"
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $PROC_MOUNT_DST (profile=$PROFILE opts=$opts)"
        rm -f "$tmp_rendered"
    else
        install -m 0644 "$tmp_rendered" "$PROC_MOUNT_DST"
        rm -f "$tmp_rendered"
    fi
    changes=$((changes + 1))
fi

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    # Try live remount; falls back to log a NOTICE if mount busy.
    if mount -o "remount,${opts}" /proc 2>/dev/null; then
        log "/proc remounted live with ${opts}"
    else
        log "NOTICE: /proc live remount failed; takes effect after reboot"
    fi
fi

emit_status "ok" "proc-hidepid profile=$PROFILE opts=$opts changes=$changes"
