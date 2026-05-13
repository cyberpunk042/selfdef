#!/usr/bin/env bash
# suricata — uninstall.
#
# Removes the NFQUEUE jump (if present) and stops + disables
# suricata.service. Does NOT purge the Suricata package, /etc/suricata/,
# or any captured eve.json. Dry-run aware.

set -euo pipefail

MODULE="suricata"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"

# shellcheck source=lib.sh
source "${BASH_SOURCE[0]%/*}/lib.sh"

# Uninstall overrides: annotated log prefix + lenient run() that
# tolerates per-step failures.
log() { echo "[suricata:uninstall] $*" >&2; }
run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@" || log "(continuing past failure)"
    fi
}

# Remove the NFQUEUE rule we own, if it's there.
if command -v nft >/dev/null && nft list table inet selfdef_bridge >/dev/null 2>&1; then
    handle=$(nft -a list chain inet selfdef_bridge forward_hook 2>/dev/null \
        | awk '/comment "selfdef-suricata"/ {for(i=1;i<=NF;i++) if($i=="handle") print $(i+1)}')
    if [[ -n "$handle" ]]; then
        run "remove NFQUEUE rule (handle $handle)" \
            -- nft delete rule inet selfdef_bridge forward_hook handle "$handle"
    fi
fi

# Stop + disable the service.
if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet suricata.service; then
        run "stop suricata.service" -- systemctl stop suricata.service
    fi
    if systemctl is-enabled --quiet suricata.service 2>/dev/null; then
        run "disable suricata.service" -- systemctl disable suricata.service
    fi
fi

emit_status "ok" "uninstalled"
