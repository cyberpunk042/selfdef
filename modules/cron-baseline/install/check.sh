#!/usr/bin/env bash
# cron-baseline — check. Read-only.

set -euo pipefail

MODULE="cron-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_CRON_BASELINE_CONFIG:-/etc/selfdef/modules/cron-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
CRON_ALLOW="${SELFDEF_CRON_ALLOW:-/etc/cron.allow}"
AT_ALLOW="${SELFDEF_AT_ALLOW:-/etc/at.allow}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "root-only")

drift=0
for f in "$CRON_ALLOW" "$AT_ALLOW"; do
    if [[ ! -f "$f" ]]; then
        emit_status "drift" "$f missing — restriction not active"
        drift=$((drift + 1))
    elif ! grep -qxF root "$f" 2>/dev/null; then
        emit_status "drift" "$f does not list root — selfdef-managed file may have been clobbered"
        drift=$((drift + 1))
    fi
done

# operator-list profile: confirm configured users are present.
if [[ "$PROFILE" == "operator-list" ]]; then
    operator_users=$(toml_get operator_users "$CONFIG_FILE" || echo "")
    IFS=',' read -ra extra_users <<< "$operator_users"
    for u in "${extra_users[@]}"; do
        u_trimmed="$(echo "$u" | tr -d ' \t')"
        [[ -z "$u_trimmed" ]] && continue
        if id "$u_trimmed" >/dev/null 2>&1; then
            if ! grep -qxF "$u_trimmed" "$CRON_ALLOW" 2>/dev/null; then
                emit_status "drift" "$u_trimmed configured but not in $CRON_ALLOW"
                drift=$((drift + 1))
            fi
        fi
    done
fi

# Best-effort: count users with active crontabs (operator-readable).
if [[ -d /var/spool/cron/crontabs ]]; then
    n=$(ls -1 /var/spool/cron/crontabs/ 2>/dev/null | wc -l)
    log "users with active crontabs: $n"
elif [[ -d /var/spool/cron ]]; then
    n=$(ls -1 /var/spool/cron/ 2>/dev/null | wc -l)
    log "users with active crontabs: $n"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "cron-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "cron-baseline profile=$PROFILE no drift"
