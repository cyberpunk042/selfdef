#!/usr/bin/env bash
# ssh-moduli-harden — apply.
#
# Filters /etc/ssh/moduli to keep only moduli >= the profile
# threshold. Refuse-to-brick: if filtering would leave ZERO
# moduli, abort (an empty moduli file breaks diffie-hellman-
# group-exchange KEX entirely). Backs up the original once.

set -euo pipefail

MODULE="ssh-moduli-harden"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SSH_MODULI_CONFIG:-/etc/selfdef/modules/ssh-moduli-harden.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "strong")
case "$PROFILE" in
    strong|minimum) ;;
    *) die "profile must be strong|minimum, got '$PROFILE'" ;;
esac

THRESHOLD=$(profile_threshold "$PROFILE")

# No moduli file (e.g. server-only ssh not installed, or a
# distro that ships none) → no-op.
if [[ ! -f "$MODULI_FILE" ]]; then
    log "$MODULI_FILE absent — no-op (sshd may not be installed)"
    emit_status "ok" "ssh-moduli-harden no-op (no moduli file)"
    exit 0
fi

keep=$(count_moduli_ge "$MODULI_FILE" "$THRESHOLD")

# Refuse-to-brick: never produce an empty moduli file.
if [[ "$keep" -eq 0 ]]; then
    die "filtering $MODULI_FILE to >= ${THRESHOLD}-bit would leave ZERO moduli (breaks DH-group-exchange KEX). Aborting. Regenerate with 'ssh-keygen -M generate/-M screen' to get strong moduli first."
fi

# Backup the operator's original once.
mkdir -p "$BACKUP_DIR"
if [[ ! -f "$BACKUP_FILE" ]]; then
    cp -a "$MODULI_FILE" "$BACKUP_FILE"
    chmod 0600 "$BACKUP_FILE"
    log "backed up original $MODULI_FILE → $BACKUP_FILE"
fi

if [[ "$DRY_RUN" == "1" ]]; then
    total=$(awk '!/^#/ && NF==5' "$MODULI_FILE" | wc -l | tr -d ' ')
    log "DRY_RUN: would keep $keep of $total moduli (>= ${THRESHOLD}-bit)"
    emit_status "ok" "ssh-moduli-harden DRY_RUN profile=$PROFILE keep=$keep"
    exit 0
fi

tmp="$(mktemp "${MODULI_FILE}.XXXXXX")"
# Preserve comment header + keep only strong moduli lines.
awk -v t="$THRESHOLD" '/^#/ {print; next} NF==5 && $5+0 >= t {print}' "$MODULI_FILE" > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$MODULI_FILE"

new_keep=$(count_moduli_ge "$MODULI_FILE" "$THRESHOLD")
log "filtered $MODULI_FILE — $new_keep moduli >= ${THRESHOLD}-bit retained"

emit_status "ok" "ssh-moduli-harden profile=$PROFILE threshold=${THRESHOLD} retained=$new_keep"
