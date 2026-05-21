#!/usr/bin/env bash
# dns-shield — uninstall.
#
# Removes the selfdef-bracketed block from /etc/hosts. Leaves
# everything outside the BEGIN/END markers byte-identical.
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="dns-shield"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
HOSTS_FILE="${SELFDEF_HOSTS_FILE:-/etc/hosts}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

if ! grep -q "^${DNS_SHIELD_BEGIN}$" "$HOSTS_FILE" 2>/dev/null; then
    emit_status "ok" "dns-shield block not present in $HOSTS_FILE (already uninstalled)"
    exit 0
fi

tmp_hosts="$(mktemp)"
awk -v begin="$DNS_SHIELD_BEGIN" -v end="$DNS_SHIELD_END" '
    BEGIN { skip = 0 }
    $0 == begin { skip = 1; next }
    $0 == end   { skip = 0; next }
    skip == 0   { print }
' "$HOSTS_FILE" > "$tmp_hosts"

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would remove dns-shield block from $HOSTS_FILE"
    rm -f "$tmp_hosts"
else
    install -m 0644 "$tmp_hosts" "$HOSTS_FILE"
    rm -f "$tmp_hosts"
fi

emit_status "ok" "dns-shield block removed from $HOSTS_FILE"
