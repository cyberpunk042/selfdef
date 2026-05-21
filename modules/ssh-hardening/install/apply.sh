#!/usr/bin/env bash
# ssh-hardening — apply.
#
# Drops /etc/ssh/sshd_config.d/50-selfdef.conf after sshd -t
# validation. sshd -t parses the FULL config tree (sshd_config
# + ALL sshd_config.d/*) so a broken selfdef drop-in WOULD
# fail validation + we refuse to install.
#
# Paranoid profile additionally requires acknowledge_allowgroups
# flag (AllowGroups ssh is a hard lockout).
#
# Restarts sshd.service via systemctl reload (graceful — existing
# sessions stay alive).

set -euo pipefail

MODULE="ssh-hardening"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_SSH_HARDENING_CONFIG:-/etc/selfdef/modules/ssh-hardening.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
SSHD_DROPIN_DIR="${SELFDEF_SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
DST="${SSHD_DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|paranoid) ;;
    *) die "profile must be standard|paranoid, got '$PROFILE'" ;;
esac

# REFUSE-TO-BRICK: paranoid sets AllowGroups ssh (hard lockout).
if [[ "$PROFILE" == "paranoid" ]]; then
    ACK=$(toml_get selfdef_acknowledge_allowgroups "$CONFIG_FILE" || echo "false")
    if [[ "$ACK" != "true" ]]; then
        die "paranoid profile sets AllowGroups ssh (HARD LOCKOUT for users NOT in 'ssh' group); set selfdef_acknowledge_allowgroups = true in $CONFIG_FILE after confirming your user is in the ssh group (id $(whoami) | grep -q ssh && echo OK)"
    fi
fi

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$SSHD_DROPIN_DIR"

# Stage the drop-in to a temp path inside sshd_config.d so sshd -t
# composes it with the rest of the config tree — full-tree validation.
tmp_stage="${SSHD_DROPIN_DIR}/.50-selfdef.conf.staging.$$"
cp "$src" "$tmp_stage"

# IMPORTANT: rename to a name sshd -t WILL load (50-selfdef.conf.staged)
# IF the OS doesn't load .staged-suffixed files. The safer pattern is:
#   1. Save the EXISTING file (if any) to a backup
#   2. Install the new file
#   3. Run sshd -t
#   4. On failure, restore the backup
backup=""
if [[ -f "$DST" ]]; then
    backup="${DST}.selfdef-rollback.$$"
    cp "$DST" "$backup"
fi
rm -f "$tmp_stage"

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would install $DST + sshd -t validate"
    changes=0
else
    # Idempotency: byte-equal skip.
    if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
        emit_status "ok" "ssh-hardening profile=$PROFILE (no change)"
        [[ -n "$backup" ]] && rm -f "$backup"
        exit 0
    fi
    install -m 0644 "$src" "$DST"
    if ! sshd -t 2>/dev/null; then
        log "sshd -t REJECTED the new config; rolling back"
        if [[ -n "$backup" ]] && [[ -f "$backup" ]]; then
            mv "$backup" "$DST"
        else
            rm -f "$DST"
        fi
        die "sshd -t rejected the rendered config — refused to commit"
    fi
    [[ -n "$backup" ]] && rm -f "$backup"
    changes=1
fi

# Reload sshd (existing sessions stay alive, new connections use
# the new config).
if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    # Service unit name varies: sshd.service (RHEL/CentOS),
    # ssh.service (Debian/Ubuntu). Try both.
    run "reload sshd" -- systemctl reload sshd 2>/dev/null \
        || run "reload ssh" -- systemctl reload ssh 2>/dev/null \
        || run "restart ssh" -- systemctl restart ssh 2>/dev/null \
        || true
fi

emit_status "ok" "ssh-hardening profile=$PROFILE changes=$changes"
