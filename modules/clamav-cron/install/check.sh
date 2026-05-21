#!/usr/bin/env bash
# clamav-cron — check. Read-only.

set -euo pipefail

MODULE="clamav-cron"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_CLAMAV_CRON_CONFIG:-/etc/selfdef/modules/clamav-cron.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "home")

drift=0
[[ -x "${LIBEXEC_DIR}/clamav-scan.sh" ]] || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-clamav-scan.service" ]] || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-clamav-scan.timer" ]] || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

# Best-effort signature DB freshness.
if command -v freshclam >/dev/null 2>&1; then
    # ClamAV DB age in days.
    if [[ -r /var/lib/clamav/daily.cvd ]] || [[ -r /var/lib/clamav/daily.cld ]]; then
        db_file=$(ls -1t /var/lib/clamav/daily.cvd /var/lib/clamav/daily.cld 2>/dev/null | head -1)
        if [[ -n "$db_file" ]]; then
            age_s=$(( $(date +%s) - $(stat -c %Y "$db_file") ))
            age_d=$((age_s / 86400))
            log "clamav signature DB age: ${age_d}d (file: $db_file)"
            if [[ "$age_d" -gt 7 ]]; then
                emit_status "drift" "signature DB ${age_d} days old — freshclam not running?"
                drift=$((drift + 1))
            fi
        fi
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-clamav-scan.timer; then
        log "selfdef-clamav-scan.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-clamav -n 1 --no-pager -o cat 2>/dev/null || echo "")
        if [[ -n "$last" ]]; then
            log "last scan event: $last"
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "clamav-cron profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "clamav-cron profile=$PROFILE no drift"
