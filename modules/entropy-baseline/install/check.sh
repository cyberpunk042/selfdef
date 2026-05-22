#!/usr/bin/env bash
# entropy-baseline — check. Read-only.

set -euo pipefail

MODULE="entropy-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_ENTROPY_CONFIG:-/etc/selfdef/modules/entropy-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "report")

drift=0
[[ -x "${LIBEXEC_DIR}/entropy-baseline.sh" ]]      || { emit_status "drift" "wrapper script missing/not exec"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-entropy.service" ]]  || { emit_status "drift" "service unit missing"; drift=$((drift + 1)); }
[[ -f "${SYSTEMD_DIR}/selfdef-entropy.timer" ]]    || { emit_status "drift" "timer unit missing"; drift=$((drift + 1)); }

if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet selfdef-entropy.timer; then
        log "selfdef-entropy.timer NOT active"
    fi
    if command -v journalctl >/dev/null 2>&1; then
        last=$(journalctl -t selfdef-entropy -n 1 --no-pager -o cat 2>/dev/null || echo "")
        [[ -n "$last" ]] && log "last check event: $last"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "entropy-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "entropy-baseline profile=$PROFILE no drift"
