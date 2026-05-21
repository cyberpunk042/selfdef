#!/usr/bin/env bash
# time-skew-watchdog — apply.
#
# Installs:
#   /usr/local/libexec/selfdef/time-skew-watchdog.sh (the probe script)
#   /etc/systemd/system/selfdef-time-skew-watchdog.service
#   /etc/systemd/system/selfdef-time-skew-watchdog.timer
# + systemctl daemon-reload + enables the timer.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="time-skew-watchdog"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
SYSTEMD_SRC="${MODULE_DIR}/systemd"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
SYSTEMD_DIR="${SELFDEF_SYSTEMD_DIR:-/etc/systemd/system}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -d "$SYSTEMD_SRC" ]] || die "systemd source dir missing: $SYSTEMD_SRC"

mkdir -p "$LIBEXEC_DIR"

install_one() {
    local src="$1"
    local dst="$2"
    local mode="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        return 1   # no change
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $dst (mode $mode)"
        return 0
    fi
    install -m "$mode" "$src" "$dst"
}

changes=0
install_one "${SYSTEMD_SRC}/time-skew-watchdog.sh" \
            "${LIBEXEC_DIR}/time-skew-watchdog.sh" \
            "0755" && changes=$((changes + 1)) || true

install_one "${SYSTEMD_SRC}/selfdef-time-skew-watchdog.service" \
            "${SYSTEMD_DIR}/selfdef-time-skew-watchdog.service" \
            "0644" && changes=$((changes + 1)) || true

install_one "${SYSTEMD_SRC}/selfdef-time-skew-watchdog.timer" \
            "${SYSTEMD_DIR}/selfdef-time-skew-watchdog.timer" \
            "0644" && changes=$((changes + 1)) || true

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]]; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    run "enable + start selfdef-time-skew-watchdog.timer" -- \
        systemctl enable --now selfdef-time-skew-watchdog.timer || true
fi

emit_status "ok" "time-skew-watchdog installed=3 changes=$changes"
