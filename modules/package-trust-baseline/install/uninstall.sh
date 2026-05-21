#!/usr/bin/env bash
# package-trust-baseline — uninstall.

set -euo pipefail

MODULE="package-trust-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
APT_CONFD="${SELFDEF_APT_CONFD:-/etc/apt/apt.conf.d}"
DST="${APT_CONFD}/50-selfdef-secure"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

emit_status "ok" "package-trust-baseline removed=$removed (NOTE: OS-default apt-secure settings return)"
