#!/usr/bin/env bash
# polarproxy — check. No state changes. JSON status line on stdout.

set -euo pipefail

MODULE="polarproxy"
# F-2027-027: see bridge-l2/check.sh for rationale.
DRY_RUN=0
CONFIG_FILE="${SELFDEF_POLARPROXY_CONFIG:-/etc/selfdef/modules/polarproxy.toml}"
UNIT_PATH="${SELFDEF_POLARPROXY_UNIT_PATH:-/etc/systemd/system/polarproxy.service}"

# shellcheck source=lib.sh
source "${BASH_SOURCE[0]%/*}/lib.sh"

problems=()

[[ -r "$CONFIG_FILE" ]] || { emit_status "failed" "config not readable: $CONFIG_FILE"; exit 1; }

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "host-tls-mitm")

if [[ ! -r "$UNIT_PATH" ]]; then
    problems+=("systemd unit missing at $UNIT_PATH")
fi

if command -v systemctl >/dev/null; then
    if ! systemctl is-active --quiet polarproxy.service; then
        problems+=("polarproxy.service not active")
    fi
fi

if [[ "$PROFILE" == "host-tls-mitm" ]] && command -v nft >/dev/null; then
    if ! nft list table inet selfdef_polarproxy >/dev/null 2>&1; then
        problems+=("nftables redirect table inet selfdef_polarproxy not loaded")
    fi
fi

if [[ "${#problems[@]}" -eq 0 ]]; then
    emit_status "ok" "polarproxy.service running ($PROFILE)"
    exit 0
else
    msg=$(IFS=';'; printf '%s' "${problems[*]}")
    emit_status "failed" "$msg"
    exit 1
fi
