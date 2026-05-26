#!/usr/bin/env bash
# firewalld-baseline — apply.
#
# Creates a permanent 'selfdef' zone with target=DROP (or
# block), adds ssh + operator services/ports, then sets it as
# the default zone. Anti-lockout: ssh is added to the zone
# BEFORE it becomes default.

set -euo pipefail

MODULE="firewalld-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_FIREWALLD_CONFIG:-/etc/selfdef/modules/firewalld-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "baseline")
case "$PROFILE" in
    baseline|web|block) ;;
    *) die "profile must be baseline|web|block, got '$PROFILE'" ;;
esac

command -v firewall-cmd >/dev/null 2>&1 || die "firewall-cmd (firewalld) unavailable — use nftables-baseline on non-firewalld hosts"

# firewalld must be running for runtime changes; permanent
# changes work regardless but we want both.
if ! firewall-cmd --state >/dev/null 2>&1; then
    log "WARN: firewalld is not running. Permanent config will be written; start firewalld + reload to make it live."
fi

ALLOW_SERVICES=$(toml_get allow_services "$CONFIG_FILE" 2>/dev/null || echo "")
ALLOW_PORTS=$(toml_get allow_ports "$CONFIG_FILE" 2>/dev/null || echo "")

TARGET="DROP"
[[ "$PROFILE" == "block" ]] && TARGET="%%REJECT%%"

# Backup the current default zone once (for uninstall revert).
mkdir -p "$BACKUP_DIR"
if [[ ! -f "$BACKUP_FILE" ]]; then
    firewall-cmd --get-default-zone > "$BACKUP_FILE" 2>/dev/null || echo "public" > "$BACKUP_FILE"
    chmod 0600 "$BACKUP_FILE"
    log "backed up current default zone ($(cat "$BACKUP_FILE")) → $BACKUP_FILE"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would create zone '$SELFDEF_ZONE' target=$TARGET, add ssh + services[$ALLOW_SERVICES] + ports[$ALLOW_PORTS], set as default"
    emit_status "ok" "firewalld-baseline DRY_RUN profile=$PROFILE"
    exit 0
fi

# 1. Create the permanent zone (idempotent).
if ! firewall-cmd --permanent --get-zones 2>/dev/null | tr ' ' '\n' | grep -qx "$SELFDEF_ZONE"; then
    firewall-cmd --permanent --new-zone="$SELFDEF_ZONE" >/dev/null 2>&1 || true
    log "created permanent zone $SELFDEF_ZONE"
fi

# 2. Set its target (DROP = silent, %%REJECT%% = icmp reject).
firewall-cmd --permanent --zone="$SELFDEF_ZONE" --set-target="$TARGET" >/dev/null 2>&1 || true

# 3. ANTI-LOCKOUT: add ssh FIRST.
firewall-cmd --permanent --zone="$SELFDEF_ZONE" --add-service=ssh >/dev/null 2>&1 || true

# 4. Operator services + ports.
if [[ -n "$ALLOW_SERVICES" ]]; then
    IFS=',' read -ra svcs <<< "$ALLOW_SERVICES"
    for s in "${svcs[@]}"; do
        s="$(echo "$s" | tr -d ' ')"
        [[ -n "$s" ]] && firewall-cmd --permanent --zone="$SELFDEF_ZONE" --add-service="$s" >/dev/null 2>&1 || true
    done
fi
if [[ -n "$ALLOW_PORTS" ]]; then
    IFS=',' read -ra ports <<< "$ALLOW_PORTS"
    for p in "${ports[@]}"; do
        p="$(echo "$p" | tr -d ' ')"
        [[ -n "$p" ]] && firewall-cmd --permanent --zone="$SELFDEF_ZONE" --add-port="$p" >/dev/null 2>&1 || true
    done
fi

# 5. Bind the active interfaces to the zone so traffic is
# actually evaluated by it, THEN set it default.
firewall-cmd --permanent --zone="$SELFDEF_ZONE" --add-service=ssh >/dev/null 2>&1 || true
firewall-cmd --set-default-zone="$SELFDEF_ZONE" >/dev/null 2>&1 || true

# 6. Reload to apply permanent → runtime.
firewall-cmd --reload >/dev/null 2>&1 && log "firewalld reloaded; default zone = $SELFDEF_ZONE (target=$TARGET, ssh allowed)" \
    || log "WARN: firewall-cmd --reload failed (is firewalld running?)"

emit_status "ok" "firewalld-baseline profile=$PROFILE zone=$SELFDEF_ZONE target=$TARGET (ssh always allowed)"
