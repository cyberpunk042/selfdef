#!/usr/bin/env bash
# tmpfs-baseline — check. Read-only.

set -euo pipefail

MODULE="tmpfs-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_TMPFS_BASELINE_CONFIG:-/etc/selfdef/modules/tmpfs-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "noexec")

drift=0
# Drop-ins must be present.
[[ -f "${SYSTEMD_DIR}/tmp.mount.d/50-selfdef.conf" ]] || { emit_status "drift" "tmp.mount.d/50-selfdef.conf missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/var-tmp.mount.d/50-selfdef.conf" ]] || { emit_status "drift" "var-tmp.mount.d/50-selfdef.conf missing"; drift=$((drift + 1)); }

# Live mount options check.
# /proc/mounts shows the LIVE flags. We want noexec,nosuid,nodev
# on both /tmp + /var/tmp.
for mount_point in /tmp /var/tmp; do
    if ! awk -v mp="$mount_point" '$2 == mp {print $4}' /proc/mounts | grep -q "noexec" 2>/dev/null; then
        emit_status "drift" "live mount $mount_point lacks noexec — reboot or remount required after apply"
        drift=$((drift + 1))
    fi
done

# tmpfs profile: verify /tmp's backing is tmpfs.
if [[ "$PROFILE" == "tmpfs" ]]; then
    if ! awk '$2 == "/tmp" {print $3}' /proc/mounts | grep -q "^tmpfs$"; then
        log "/tmp is NOT tmpfs (reboot may be pending after profile change to tmpfs)"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "tmpfs-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "tmpfs-baseline profile=$PROFILE no drift"
