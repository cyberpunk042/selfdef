#!/usr/bin/env bash
# home-perms-baseline — check. Read-only.

set -euo pipefail

MODULE="home-perms-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_HOMEPERMS_CONFIG:-/etc/selfdef/modules/home-perms-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "group")
case "$PROFILE" in
    group)  WANT=750 ;;
    strict) WANT=700 ;;
    *) WANT=750 ;;
esac

drift=0
checked=0
while IFS=$'\t' read -r dir uid user mode; do
    [[ -z "$dir" ]] && continue
    checked=$((checked + 1))
    # A home looser than the target is drift; stricter is fine.
    if [[ "$mode" =~ ^[0-9]+$ ]] && (( mode > WANT )); then
        emit_status "drift" "$dir mode=$mode looser than target $WANT (user=$user)"
        drift=$((drift + 1))
    fi
done < <(enumerate_homes)

[[ "$checked" -eq 0 ]] && log "no eligible home dirs to check"

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "home-perms-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "home-perms-baseline profile=$PROFILE target=$WANT checked=$checked no drift"
