#!/usr/bin/env bash
# home-perms-baseline — apply.

set -euo pipefail

MODULE="home-perms-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_HOMEPERMS_CONFIG:-/etc/selfdef/modules/home-perms-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "group")
case "$PROFILE" in
    group)  WANT=750 ;;
    strict) WANT=700 ;;
    *) die "profile must be group|strict, got '$PROFILE'" ;;
esac

mkdir -p "$BACKUP_DIR"

# Back up current modes once (for uninstall revert).
if [[ ! -f "$BACKUP_FILE" ]]; then
    enumerate_homes > "$BACKUP_FILE" 2>/dev/null || true
    chmod 0600 "$BACKUP_FILE"
    log "backed up current home modes → $BACKUP_FILE"
fi

acted=0; skipped=0
while IFS=$'\t' read -r dir uid user mode; do
    [[ -z "$dir" ]] && continue
    if [[ "$mode" == "$WANT" ]]; then
        skipped=$((skipped + 1))
        continue
    fi
    # Only ever TIGHTEN — never loosen. If the current mode is
    # already stricter than the target (e.g. 700 when target is
    # 750), leave it.
    if [[ "$mode" =~ ^[0-9]+$ ]] && (( mode < WANT )); then
        log "leaving $dir at $mode (already stricter than $WANT)"
        skipped=$((skipped + 1))
        continue
    fi
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would chmod $WANT $dir (was $mode, user=$user)"
        acted=$((acted + 1))
        continue
    fi
    if chmod "$WANT" "$dir" 2>/dev/null; then
        log "chmod $WANT $dir (was $mode, user=$user)"
        acted=$((acted + 1))
    else
        log "WARN: chmod $WANT $dir failed"
    fi
done < <(enumerate_homes)

if [[ "$acted" -eq 0 && "$skipped" -eq 0 ]]; then
    log "no eligible /home/<user> dirs (uid>=1000, non-operator) found"
fi

emit_status "ok" "home-perms-baseline profile=$PROFILE target=$WANT acted=$acted skipped=$skipped"
