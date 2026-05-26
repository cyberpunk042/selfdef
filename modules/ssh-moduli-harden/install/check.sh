#!/usr/bin/env bash
# ssh-moduli-harden — check. Read-only.

set -euo pipefail

MODULE="ssh-moduli-harden"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SSH_MODULI_CONFIG:-/etc/selfdef/modules/ssh-moduli-harden.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "strong")
THRESHOLD=$(profile_threshold "$PROFILE")

if [[ ! -f "$MODULI_FILE" ]]; then
    emit_status "ok" "ssh-moduli-harden ($MODULI_FILE absent — sshd not installed?)"
    exit 0
fi

# Any weak modulus still present = drift.
weak=$(awk -v t="$THRESHOLD" '!/^#/ && NF==5 && $5+0 < t {n++} END{print n+0}' "$MODULI_FILE")
keep=$(count_moduli_ge "$MODULI_FILE" "$THRESHOLD")

log "moduli: $keep >= ${THRESHOLD}-bit, $weak weak (< ${THRESHOLD}-bit)"

if [[ "$weak" -gt 0 ]]; then
    emit_status "drift" "ssh-moduli-harden profile=$PROFILE: $weak weak moduli (< ${THRESHOLD}-bit) still present"
    exit 1
fi
emit_status "ok" "ssh-moduli-harden profile=$PROFILE: no weak moduli (< ${THRESHOLD}-bit)"
