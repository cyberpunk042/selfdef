#!/usr/bin/env bash
# package-trust-baseline — check. Read-only.

set -euo pipefail

MODULE="package-trust-baseline"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_PKG_TRUST_CONFIG:-/etc/selfdef/modules/package-trust-baseline.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
APT_CONFD="${SELFDEF_APT_CONFD:-/etc/apt/apt.conf.d}"
DST="${APT_CONFD}/50-selfdef-secure"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "standard")

drift=0
[[ -f "$DST" ]] || { emit_status "drift" "drop-in missing: $DST"; drift=$((drift + 1)); }

# apt-config dump must succeed (the WHOLE apt.conf.d tree parses).
if command -v apt-config >/dev/null 2>&1; then
    if ! apt-config dump >/dev/null 2>&1; then
        emit_status "drift" "apt-config dump reports parse failure across apt.conf.d/"
        drift=$((drift + 1))
    fi
fi

# Verify core invariants are present in the effective config.
if command -v apt-config >/dev/null 2>&1; then
    if ! apt-config dump | grep -q 'Acquire::AllowInsecureRepositories "false"'; then
        emit_status "drift" "effective Acquire::AllowInsecureRepositories != false"
        drift=$((drift + 1))
    fi
    if ! apt-config dump | grep -q 'APT::Get::AllowUnauthenticated "false"'; then
        emit_status "drift" "effective APT::Get::AllowUnauthenticated != false"
        drift=$((drift + 1))
    fi
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "package-trust-baseline profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "package-trust-baseline profile=$PROFILE no drift"
