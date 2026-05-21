#!/usr/bin/env bash
# chrony-baseline — apply.
#
# Renders /etc/chrony/conf.d/50-selfdef.conf from the chosen
# profile + reloads chronyd via systemctl. Idempotent: re-running
# with the same profile writes byte-identical content.
#
# SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="chrony-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_CHRONY_BASELINE_CONFIG:-/etc/selfdef/modules/chrony-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${SELFDEF_CHRONY_BASELINE_CONFIGS:-${MODULE_DIR}/configs}"
CHRONY_DROPIN_DIR="${SELFDEF_CHRONY_DROPIN_DIR:-/etc/chrony/conf.d}"
DST="${CHRONY_DROPIN_DIR}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "config source dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "pool")
case "$PROFILE" in
    pool|nts) ;;
    *) die "profile must be pool|nts, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

# Ensure the conf.d dir exists. On most chrony installs the OS
# already creates it; declare for fresh installs.
mkdir -p "$CHRONY_DROPIN_DIR"

# Idempotency check.
if [[ -f "$DST" ]] && cmp -s "$src" "$DST"; then
    emit_status "ok" "chrony-baseline profile=$PROFILE (no change)"
    exit 0
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would install $DST + restart chronyd"
else
    install -m 0644 "$src" "$DST"
    if command -v systemctl >/dev/null 2>&1; then
        # `restart` rather than `reload` because chrony's conf.d
        # changes don't all apply via reload (e.g. authselectmode).
        run "restart chronyd" -- systemctl restart chronyd || \
            run "restart chrony" -- systemctl restart chrony || true
    fi
fi

emit_status "ok" "chrony-baseline profile=$PROFILE applied"
