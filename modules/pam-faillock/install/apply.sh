#!/usr/bin/env bash
# pam-faillock — apply.
#
# REPLACES /etc/security/faillock.conf (no conf.d). On first
# apply, backs up the operator's original to .selfdef-backup.
# Creates /var/lib/faillock with mode 0700 root:root.
#
# Note: this module ONLY ships the faillock.conf — the PAM stack
# itself (/etc/pam.d/system-auth, /etc/pam.d/sshd) must include
# `auth required pam_faillock.so preauth` + `auth [default=die]
# pam_faillock.so authfail` + `account required pam_faillock.so`
# lines for the config to take effect. Most modern distros
# (Fedora 35+, Debian 12+, RHEL 9+) include these lines by
# default; older distros need a `pam-auth-update` or
# `authselect select sssd with-faillock` operator step.
# apply.sh prints a NOTICE if the PAM stack lacks pam_faillock.so.

set -euo pipefail

MODULE="pam-faillock"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_PAM_FAILLOCK_CONFIG:-/etc/selfdef/modules/pam-faillock.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "lenient")
case "$PROFILE" in
    lenient|strict) ;;
    *) die "profile must be lenient|strict, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

# Backup operator's original on first apply.
if [[ -f "$FAILLOCK_CONF" ]] && [[ ! -f "$FAILLOCK_BACKUP" ]]; then
    if ! head -1 "$FAILLOCK_CONF" | grep -qF "$FAILLOCK_MARKER"; then
        if [[ "$DRY_RUN" == "1" ]]; then
            log "DRY_RUN: would back up $FAILLOCK_CONF → $FAILLOCK_BACKUP"
        else
            install -m 0644 "$FAILLOCK_CONF" "$FAILLOCK_BACKUP"
            log "backed up operator faillock.conf → $FAILLOCK_BACKUP"
        fi
    fi
fi

# Render with header marker for uninstall ownership check.
tmp_rendered="$(mktemp)"
{
    echo "$FAILLOCK_MARKER"
    echo "# profile=$PROFILE rendered=$(date -u +%FT%TZ)"
    cat "$src"
} > "$tmp_rendered"

changes=0
if [[ -f "$FAILLOCK_CONF" ]] && cmp -s "$tmp_rendered" "$FAILLOCK_CONF"; then
    rm -f "$tmp_rendered"
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $FAILLOCK_CONF"
        rm -f "$tmp_rendered"
    else
        install -m 0644 "$tmp_rendered" "$FAILLOCK_CONF"
        rm -f "$tmp_rendered"
    fi
    changes=$((changes + 1))
fi

# faillock state dir.
mkdir -p "$FAILLOCK_DIR"
chmod 0700 "$FAILLOCK_DIR"
chown root:root "$FAILLOCK_DIR"

# Check the PAM stack actually invokes pam_faillock.so somewhere.
# If not, the config is dormant — log a NOTICE so the operator
# can run `pam-auth-update` / `authselect` to wire it up.
pam_files=( /etc/pam.d/common-auth /etc/pam.d/sshd /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/login )
faillock_wired=false
for pf in "${pam_files[@]}"; do
    if [[ -r "$pf" ]] && grep -q "pam_faillock\.so" "$pf"; then
        faillock_wired=true
        break
    fi
done

if [[ "$faillock_wired" == "false" ]]; then
    log "NOTICE: faillock.conf installed but no /etc/pam.d/* file references pam_faillock.so. Run:"
    log "  Debian/Ubuntu: sudo pam-auth-update --enable faillock-tally"
    log "  Fedora/RHEL:   sudo authselect select sssd with-faillock"
    log "  or hand-edit /etc/pam.d/common-auth (Debian) or system-auth (RHEL) to add the pam_faillock.so preauth + authfail + account lines."
fi

emit_status "ok" "pam-faillock profile=$PROFILE changes=$changes pam_wired=$faillock_wired"
