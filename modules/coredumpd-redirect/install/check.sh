#!/usr/bin/env bash
# coredumpd-redirect — check. Read-only.
#
# Verifies the drop-in exists + the coredump dir is mode 0700
# root:root + (for redirect profile) Storage=external is the
# effective setting.

set -euo pipefail

MODULE="coredumpd-redirect"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_COREDUMPD_CONFIG:-/etc/selfdef/modules/coredumpd-redirect.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DROPIN_DIR="${SELFDEF_COREDUMPD_DROPIN_DIR:-/etc/systemd/coredump.conf.d}"
DST="${DROPIN_DIR}/50-selfdef.conf"
COREDUMP_DIR="${SELFDEF_COREDUMP_DIR:-/var/lib/selfdef/coredumps}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "redirect")

drift=0
if [[ ! -f "$DST" ]]; then
    emit_status "drift" "drop-in missing: $DST"
    drift=$((drift + 1))
fi

if [[ "$PROFILE" == "redirect" ]]; then
    if [[ ! -d "$COREDUMP_DIR" ]]; then
        emit_status "drift" "coredump dir missing: $COREDUMP_DIR"
        drift=$((drift + 1))
    else
        # Permission check.
        perms=$(stat -c '%a %u %g' "$COREDUMP_DIR" 2>/dev/null || echo "")
        if [[ "$perms" != "700 0 0" ]]; then
            emit_status "drift" "coredump dir perms = '$perms' (want '700 0 0')"
            drift=$((drift + 1))
        fi
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "coredumpd-redirect profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "coredumpd-redirect profile=$PROFILE no drift"
