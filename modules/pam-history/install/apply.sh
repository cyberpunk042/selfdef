#!/usr/bin/env bash
# pam-history — apply.
#
# Installs /etc/security/pwhistory.conf with the chosen profile.
# Same DETECT-pam-wiring NOTICE pattern as pam-pwquality +
# pam-faillock — if no /etc/pam.d/* invokes pam_pwhistory.so,
# the config is dormant + we log distro-specific operator step.

set -euo pipefail

MODULE="pam-history"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_PWHISTORY_CONFIG:-/etc/selfdef/modules/pam-history.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|strict) ;;
    *) die "profile must be standard|strict, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

# Backup the operator's existing /etc/security/pwhistory.conf
# (if any) before we replace it. Single-shot backup —
# subsequent applies don't overwrite the original distro
# state.
mkdir -p "$BACKUP_DIR"
if [[ -f "$PWHISTORY_CONF" ]] && [[ ! -f "$BACKUP_FILE" ]]; then
    if ! head -1 "$PWHISTORY_CONF" 2>/dev/null | grep -qF "$HEADER_MARKER"; then
        cp -a "$PWHISTORY_CONF" "$BACKUP_FILE"
        chmod 0600 "$BACKUP_FILE"
        log "backed up operator's distro $PWHISTORY_CONF → $BACKUP_FILE"
    fi
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would render $PWHISTORY_CONF from $src"
    emit_status "ok" "pam-history DRY_RUN profile=$PROFILE"
    exit 0
fi

tmp="$(mktemp "${PWHISTORY_CONF}.XXXXXX")"
{
    echo "$HEADER_MARKER"
    # No render-timestamp — defeats cmp -s idempotency (2026-06-06).
    echo "# profile=$PROFILE"
    cat "$src"
} > "$tmp"
chmod 0644 "$tmp"
# Idempotency: skip rewrite when content unchanged.
if [[ -f "$PWHISTORY_CONF" ]] && cmp -s "$tmp" "$PWHISTORY_CONF"; then
    rm -f "$tmp"
else
    mv -f "$tmp" "$PWHISTORY_CONF"
    log "wrote $PWHISTORY_CONF"
fi

# DETECT-AND-NOTICE: is pam_pwhistory.so actually wired?
wired=$(detect_pam_wiring)
if [[ -z "$wired" ]]; then
    log "NOTICE: pam_pwhistory.so NOT wired into any /etc/pam.d/* — config installed but DORMANT"
    log "  Debian/Ubuntu: sudo pam-auth-update --enable pwhistory  (libpam-modules)"
    log "  Fedora/RHEL:   sudo authselect select sssd with-pwhistory"
    log "  Manual:        edit /etc/pam.d/common-password (Debian) or system-auth (RHEL)"
    log "                 add line: password requisite pam_pwhistory.so"
else
    log "pam_pwhistory.so is wired in: $(echo "$wired" | tr '\n' ' ')"
fi

emit_status "ok" "pam-history profile=$PROFILE wired=$( [[ -n "$wired" ]] && echo true || echo false )"
