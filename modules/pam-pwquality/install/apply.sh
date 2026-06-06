#!/usr/bin/env bash
# pam-pwquality — apply.
#
# Installs /etc/security/pwquality.conf.d/50-selfdef.conf with
# the chosen profile. Same DETECT-pam-wiring pattern as
# pam-faillock — if no /etc/pam.d/* file invokes pam_pwquality.so,
# the config is dormant + we log a NOTICE.

set -euo pipefail

MODULE="pam-pwquality"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_PWQUALITY_CONFIG:-/etc/selfdef/modules/pam-pwquality.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
PWQUALITY_D="${SELFDEF_PWQUALITY_D:-/etc/security/pwquality.conf.d}"
DST="${PWQUALITY_D}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")
case "$PROFILE" in
    standard|strict) ;;
    *) die "profile must be standard|strict, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$PWQUALITY_D"

changes=0
if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $DST"
    else
        install -m 0644 "$src" "$DST"
    fi
    changes=$((changes + 1))
fi

# PAM stack wiring detection (same as pam-faillock).
# SELFDEF_PWQUALITY_PAM_DIR added 2026-06-06 for L2 testability —
# live default unchanged.
_pam_dir="${SELFDEF_PWQUALITY_PAM_DIR:-/etc/pam.d}"
pam_files=( "${_pam_dir}/common-password" "${_pam_dir}/system-auth" \
            "${_pam_dir}/password-auth"   "${_pam_dir}/passwd" )
wired=false
for pf in "${pam_files[@]}"; do
    if [[ -r "$pf" ]] && grep -q "pam_pwquality\.so" "$pf"; then
        wired=true
        break
    fi
done

if [[ "$wired" == "false" ]]; then
    log "NOTICE: pwquality config installed but no /etc/pam.d/* references pam_pwquality.so. Wire via:"
    log "  Debian/Ubuntu: sudo pam-auth-update --enable pwquality"
    log "  Fedora/RHEL:   sudo authselect select sssd with-pwquality"
    log "  OR hand-edit common-password / system-auth to add:"
    log "    password requisite pam_pwquality.so retry=3"
fi

emit_status "ok" "pam-pwquality profile=$PROFILE changes=$changes pam_wired=$wired"
