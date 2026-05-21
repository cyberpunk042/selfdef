#!/usr/bin/env bash
# dnf-automatic-config — uninstall.

set -euo pipefail

MODULE="dnf-automatic-config"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if [[ ! -f "$DNF_AUTO_CONF" ]]; then
    emit_status "ok" "dnf-automatic.conf already absent"
    exit 0
fi

if ! head -1 "$DNF_AUTO_CONF" | grep -qF "$DNF_AUTO_MARKER"; then
    emit_status "ok" "dnf-automatic.conf present but NOT selfdef-managed — leaving alone"
    exit 0
fi

if [[ -f "$DNF_AUTO_BACKUP" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would restore $DNF_AUTO_BACKUP → $DNF_AUTO_CONF"
    else
        run "restore operator automatic.conf" -- mv "$DNF_AUTO_BACKUP" "$DNF_AUTO_CONF"
    fi
else
    log "no backup at $DNF_AUTO_BACKUP — removing managed automatic.conf"
    [[ "$DRY_RUN" != "1" ]] && rm -f "$DNF_AUTO_CONF"
fi

emit_status "ok" "dnf-automatic-config uninstalled (dnf-automatic.timer NOT stopped — operator manages independently)"
