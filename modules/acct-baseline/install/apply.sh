#!/usr/bin/env bash
# acct-baseline — apply.
#
# 1. Creates /var/account/ + pacct file with mode 0640 root:root.
# 2. Installs the logrotate drop-in.
# 3. enabled profile: `accton on /var/account/pacct` + enables
#    acct.service (or psacct.service depending on distro).
# 4. disabled profile: `accton off` + leaves logrotate drop-in
#    installed for operator-pull re-enable.

set -euo pipefail

MODULE="acct-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_ACCT_CONFIG:-/etc/selfdef/modules/acct-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
SYSTEMD_SRC="${MODULE_DIR}/systemd"
LOGROTATE_DIR="${SELFDEF_LOGROTATE_DIR:-/etc/logrotate.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "enabled")
case "$PROFILE" in
    enabled|disabled) ;;
    *) die "profile must be enabled|disabled, got '$PROFILE'" ;;
esac

# Ensure the pacct parent dir exists.
# SELFDEF_ACCT_DIR added 2026-06-06 for L2 testability — live
# default unchanged.
ACCT_DIR="${SELFDEF_ACCT_DIR:-/var/account}"
mkdir -p "$ACCT_DIR"
# chown/chmod best-effort: in test envs we may not be root.
chown root:root "$ACCT_DIR" 2>/dev/null || true
chmod 0750 "$ACCT_DIR" 2>/dev/null || true

# Ensure pacct file exists.
if [[ ! -f "$PACCT_FILE" ]] && [[ "$DRY_RUN" != "1" ]]; then
    : > "$PACCT_FILE"
    chown root:root "$PACCT_FILE" 2>/dev/null || true
    chmod 0640 "$PACCT_FILE" 2>/dev/null || true
fi

# Logrotate drop-in.
LOGROTATE_DST="${LOGROTATE_DIR}/selfdef-acct"
changes=0
if [[ -f "$LOGROTATE_DST" ]] && cmp -s "${SYSTEMD_SRC}/selfdef-acct.logrotate" "$LOGROTATE_DST"; then
    :
else
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY_RUN: would install $LOGROTATE_DST"
    else
        install -m 0644 "${SYSTEMD_SRC}/selfdef-acct.logrotate" "$LOGROTATE_DST"
    fi
    changes=$((changes + 1))
fi

# accton on/off + service.
if [[ "$DRY_RUN" != "1" ]]; then
    if [[ "$PROFILE" == "enabled" ]]; then
        run "accton on $PACCT_FILE" -- accton "$PACCT_FILE" || true
        # Enable the OS service (debian: acct; rhel: psacct).
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable --now acct 2>/dev/null \
                || systemctl enable --now psacct 2>/dev/null \
                || true
        fi
    else
        # disabled profile: accton off.
        run "accton off" -- accton off || true
    fi
fi

emit_status "ok" "acct-baseline profile=$PROFILE changes=$changes pacct=$PACCT_FILE"
