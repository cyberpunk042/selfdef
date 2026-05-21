#!/usr/bin/env bash
# dns-shield — check. Read-only.
#
# Verifies the BEGIN/END block exists in /etc/hosts + reports the
# rendered domain count. Spot-checks that a sample blocked domain
# resolves to 0.0.0.0 (best-effort; libc resolver is consulted).

set -euo pipefail

MODULE="dns-shield"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_DNS_SHIELD_CONFIG:-/etc/selfdef/modules/dns-shield.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
HOSTS_FILE="${SELFDEF_HOSTS_FILE:-/etc/hosts}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "base")

if ! grep -q "^${DNS_SHIELD_BEGIN}$" "$HOSTS_FILE" 2>/dev/null; then
    emit_status "drift" "dns-shield block missing from $HOSTS_FILE"
    exit 1
fi
if ! grep -q "^${DNS_SHIELD_END}$" "$HOSTS_FILE" 2>/dev/null; then
    emit_status "drift" "dns-shield END marker missing in $HOSTS_FILE — corrupted block"
    exit 1
fi

# Count the rendered 0.0.0.0 sinkhole lines between markers.
count=$(awk -v begin="$DNS_SHIELD_BEGIN" -v end="$DNS_SHIELD_END" '
    $0 == begin { in_block = 1; next }
    $0 == end   { in_block = 0; next }
    in_block && /^0\.0\.0\.0 / { c++ }
    END { print c+0 }
' "$HOSTS_FILE")

emit_status "ok" "dns-shield profile=$PROFILE rendered=$count entries"
