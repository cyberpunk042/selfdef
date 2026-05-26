#!/usr/bin/env bash
# firewalld-baseline — check. Read-only.

set -euo pipefail

MODULE="firewalld-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_FIREWALLD_CONFIG:-/etc/selfdef/modules/firewalld-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")

if ! command -v firewall-cmd >/dev/null 2>&1; then
    emit_status "ok" "firewalld-baseline (firewalld unavailable on this host)"
    exit 0
fi

drift=0

default_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "?")
if [[ "$default_zone" != "$SELFDEF_ZONE" ]]; then
    emit_status "drift" "default zone is '$default_zone', expected '$SELFDEF_ZONE'"
    drift=$((drift + 1))
fi

# Target must be DROP or %%REJECT%%.
target=$(firewall-cmd --permanent --zone="$SELFDEF_ZONE" --get-target 2>/dev/null || echo "?")
case "$target" in
    DROP|%%REJECT%%) log "zone $SELFDEF_ZONE target=$target" ;;
    *) emit_status "drift" "zone $SELFDEF_ZONE target='$target', expected DROP or %%REJECT%%"; drift=$((drift + 1)) ;;
esac

# Anti-lockout sanity: ssh must be allowed in the zone.
if ! firewall-cmd --permanent --zone="$SELFDEF_ZONE" --query-service=ssh >/dev/null 2>&1; then
    emit_status "drift" "zone $SELFDEF_ZONE does NOT allow ssh — lockout risk"
    drift=$((drift + 1))
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "firewalld-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "firewalld-baseline profile=$PROFILE zone=$SELFDEF_ZONE default-deny + ssh allowed"
