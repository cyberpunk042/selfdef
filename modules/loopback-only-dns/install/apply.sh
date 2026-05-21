#!/usr/bin/env bash
# loopback-only-dns — apply.
#
# Writes /etc/systemd/resolved.conf.d/50-selfdef-loopback.conf +
# restarts systemd-resolved. Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="loopback-only-dns"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_LOOPBACK_DNS_CONFIG:-/etc/selfdef/modules/loopback-only-dns.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
CONFIGS_SRC="${MODULE_DIR}/configs"
DROPIN_DIR="${SELFDEF_RESOLVED_DROPIN_DIR:-/etc/systemd/resolved.conf.d}"
DST="${DROPIN_DIR}/50-selfdef-loopback.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$CONFIGS_SRC" ]] || die "configs dir missing: $CONFIGS_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "loopback")
case "$PROFILE" in
    loopback|disabled-listener) ;;
    *) die "profile must be loopback|disabled-listener, got '$PROFILE'" ;;
esac

src="${CONFIGS_SRC}/${PROFILE}.conf"
[[ -r "$src" ]] || die "profile source missing: $src"

mkdir -p "$DROPIN_DIR"

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

if [[ "$changes" -gt 0 ]] && [[ "$DRY_RUN" != "1" ]] && command -v systemctl >/dev/null; then
    run "systemctl restart systemd-resolved" -- systemctl restart systemd-resolved || true
fi

emit_status "ok" "loopback-only-dns profile=$PROFILE changes=$changes"
