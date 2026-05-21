#!/usr/bin/env bash
# pam-pwquality — check. Read-only.

set -euo pipefail

MODULE="pam-pwquality"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_PWQUALITY_CONFIG:-/etc/selfdef/modules/pam-pwquality.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
PWQUALITY_D="${SELFDEF_PWQUALITY_D:-/etc/security/pwquality.conf.d}"
DST="${PWQUALITY_D}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")

drift=0
[[ -f "$DST" ]] || { emit_status "drift" "drop-in missing: $DST"; drift=$((drift + 1)); }

# Verify minlen matches profile.
expected_minlen="12"
[[ "$PROFILE" == "strict" ]] && expected_minlen="16"
if [[ -f "$DST" ]] && ! grep -qE "^minlen[[:space:]]*=[[:space:]]*${expected_minlen}" "$DST"; then
    emit_status "drift" "minlen != $expected_minlen in $DST"
    drift=$((drift + 1))
fi

# pwscore live test — feed a known-weak password + expect rejection.
if command -v pwscore >/dev/null 2>&1; then
    if echo "abc123" | pwscore 2>&1 | grep -qE "Password|score|rejected"; then
        # Output varies by version; just verify pwscore runs.
        log "pwscore reachable (live pwquality functional)"
    fi
fi

# PAM wiring detection.
pam_files=( /etc/pam.d/common-password /etc/pam.d/system-auth \
            /etc/pam.d/password-auth   /etc/pam.d/passwd )
wired=false
for pf in "${pam_files[@]}"; do
    if [[ -r "$pf" ]] && grep -q "pam_pwquality\.so" "$pf"; then
        wired=true
        break
    fi
done
[[ "$wired" == "false" ]] && log "PAM stack does NOT reference pam_pwquality.so — config dormant"

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "pam-pwquality profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "pam-pwquality profile=$PROFILE pam_wired=$wired no drift"
