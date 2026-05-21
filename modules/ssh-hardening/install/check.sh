#!/usr/bin/env bash
# ssh-hardening — check. Read-only.

set -euo pipefail

MODULE="ssh-hardening"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_SSH_HARDENING_CONFIG:-/etc/selfdef/modules/ssh-hardening.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SSHD_DROPIN_DIR="${SELFDEF_SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
DST="${SSHD_DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")

drift=0
if [[ ! -f "$DST" ]]; then
    emit_status "drift" "sshd drop-in missing: $DST"
    drift=$((drift + 1))
fi

# sshd -t parses the full tree.
if command -v sshd >/dev/null 2>&1; then
    if ! sshd -t 2>/dev/null; then
        emit_status "drift" "sshd -t reports config tree DOES NOT parse cleanly"
        drift=$((drift + 1))
    fi
fi

# Verify key invariants in the LIVE config (sshd -T dumps effective
# settings).
if command -v sshd >/dev/null 2>&1; then
    if effective=$(sshd -T 2>/dev/null); then
        for setting in "permitrootlogin no" "passwordauthentication no" "x11forwarding no"; do
            if ! echo "$effective" | grep -qiE "^${setting}$"; then
                emit_status "drift" "live sshd config violates invariant: $setting"
                drift=$((drift + 1))
            fi
        done
    fi
fi

# Service active.
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl is-active --quiet sshd 2>/dev/null && ! systemctl is-active --quiet ssh 2>/dev/null; then
        log "sshd / ssh service NOT active"
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "ssh-hardening profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "ssh-hardening profile=$PROFILE no drift"
