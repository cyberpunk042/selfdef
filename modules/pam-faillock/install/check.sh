#!/usr/bin/env bash
# pam-faillock — check. Read-only.

set -euo pipefail

MODULE="pam-faillock"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_PAM_FAILLOCK_CONFIG:-/etc/selfdef/modules/pam-faillock.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "lenient")

drift=0
if [[ ! -f "$FAILLOCK_CONF" ]]; then
    emit_status "drift" "faillock.conf missing: $FAILLOCK_CONF"
    drift=$((drift + 1))
elif ! head -1 "$FAILLOCK_CONF" | grep -qF "$FAILLOCK_MARKER"; then
    emit_status "drift" "faillock.conf present but not selfdef-managed (no header marker)"
    drift=$((drift + 1))
fi

if [[ ! -d "$FAILLOCK_DIR" ]]; then
    emit_status "drift" "faillock dir missing: $FAILLOCK_DIR"
    drift=$((drift + 1))
else
    perms=$(stat -c '%a %u %g' "$FAILLOCK_DIR" 2>/dev/null || echo "")
    if [[ "$perms" != "700 0 0" ]]; then
        emit_status "drift" "faillock dir perms = '$perms' (want '700 0 0')"
        drift=$((drift + 1))
    fi
fi

# PAM wiring check.
pam_files=( /etc/pam.d/common-auth /etc/pam.d/sshd /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/login )
faillock_wired=false
for pf in "${pam_files[@]}"; do
    if [[ -r "$pf" ]] && grep -q "pam_faillock\.so" "$pf"; then
        faillock_wired=true
        break
    fi
done

if [[ "$faillock_wired" == "false" ]]; then
    log "PAM stack does NOT reference pam_faillock.so — config is dormant"
fi

# Best-effort live state — current locked accounts.
if command -v faillock >/dev/null 2>&1; then
    locked=$(faillock --user "$(whoami)" 2>/dev/null | grep -cE '^\s*[0-9]' || echo 0)
    log "current user faillock entries: $locked"
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "pam-faillock profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "pam-faillock profile=$PROFILE pam_wired=$faillock_wired no drift"
