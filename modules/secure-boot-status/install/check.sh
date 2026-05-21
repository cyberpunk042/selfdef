#!/usr/bin/env bash
# secure-boot-status — check. Read-only.

set -euo pipefail

MODULE="secure-boot-status"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SECURE_BOOT_CONFIG:-/etc/selfdef/modules/secure-boot-status.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "monitor")

drift=0
[[ -x "${LIBEXEC_DIR}/secure-boot-status.sh" ]] || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-secure-boot-status.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-secure-boot-status.timer" ]] || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-secure-boot-status.timer; then
        log "selfdef-secure-boot-status.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-secure-boot -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last status event: $last"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "secure-boot-status profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "secure-boot-status profile=$PROFILE no drift"
