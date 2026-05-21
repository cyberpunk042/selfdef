#!/usr/bin/env bash
# umask-baseline — uninstall.

set -euo pipefail

MODULE="umask-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
PROFILE_D="${SELFDEF_PROFILE_D:-/etc/profile.d}"
LOGIN_DEFS_D="${SELFDEF_LOGIN_DEFS_D:-/etc/login.defs.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
for f in "${PROFILE_D}/50-selfdef-umask.sh" \
         "${LOGIN_DEFS_D}/50-selfdef-umask.conf"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

emit_status "ok" "umask-baseline removed=$removed (NOTE: current shell keeps existing umask; next shell uses OS-default)"
