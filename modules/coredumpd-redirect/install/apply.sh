#!/usr/bin/env bash
# coredumpd-redirect — apply.
#
# Writes /etc/systemd/coredump.conf.d/50-selfdef.conf with the
# chosen profile + ensures the storage dir
# /var/lib/selfdef/coredumps/ exists with mode 0700 root:root +
# restarts systemd-coredump.socket so the new config takes effect
# on the NEXT crash (existing in-flight coredumps drain naturally).
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="coredumpd-redirect"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_COREDUMPD_CONFIG:-/etc/selfdef/modules/coredumpd-redirect.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${SELFDEF_COREDUMPD_CONFIGS:-${MODULE_DIR}/configs}"
DROPIN_DIR="${SELFDEF_COREDUMPD_DROPIN_DIR:-/etc/systemd/coredump.conf.d}"
DST="${DROPIN_DIR}/50-selfdef.conf"
COREDUMP_DIR="${SELFDEF_COREDUMP_DIR:-/var/lib/selfdef/coredumps}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "config source dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "redirect")
case "$PROFILE" in
    redirect|disabled) ;;
    *) die "profile must be redirect|disabled, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$DROPIN_DIR"

# Ensure the coredump dir exists with strict perms for redirect
# profile. (Disabled profile doesn't need it but we create the dir
# anyway so flipping back to redirect is a no-restart change.)
if [[ "$DRY_RUN" != "1" ]]; then
    mkdir -p "$COREDUMP_DIR"
    chown root:root "$COREDUMP_DIR"
    chmod 0700 "$COREDUMP_DIR"
fi

# Idempotency check.
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

# Restart systemd-coredump.socket so the new config applies to
# subsequent crashes. The socket-activated unit re-reads its conf
# on next activation regardless, but explicit restart guarantees
# zero-stale-state.
if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]]; then
    run "systemctl daemon-reload" -- systemctl daemon-reload || true
    run "restart systemd-coredump.socket" -- systemctl restart systemd-coredump.socket || true
fi

emit_status "ok" "coredumpd-redirect profile=$PROFILE changes=$changes"
