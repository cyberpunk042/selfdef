#!/usr/bin/env bash
# acct-baseline — uninstall.
#
# accton off + disables the OS service + removes the logrotate
# drop-in. Does NOT delete /var/account/ or pacct files
# (operator-collected forensic data preserved).

set -euo pipefail

MODULE="acct-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
LOGROTATE_DIR="${SELFDEF_LOGROTATE_DIR:-/etc/logrotate.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ "$DRY_RUN" != "1" ]] && command -v accton >/dev/null; then
    run "accton off" -- accton off || true
fi

if [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    systemctl disable --now acct 2>/dev/null || true
    systemctl disable --now psacct 2>/dev/null || true
fi

removed=0
if [[ -f "${LOGROTATE_DIR}/selfdef-acct" ]]; then
    run "remove selfdef-acct logrotate" -- rm -f "${LOGROTATE_DIR}/selfdef-acct"
    removed=$((removed + 1))
fi

emit_status "ok" "acct-baseline removed=$removed (NOTE: /var/account/ + pacct files preserved — operator-collected forensic data)"
