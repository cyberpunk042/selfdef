#!/usr/bin/env bash
# pam-pwquality — uninstall.
#
# Removes only the selfdef drop-in. OS-shipped
# /etc/security/pwquality.conf + operator-extension drop-ins
# preserved. PAM stack continues to invoke pam_pwquality.so;
# without our drop-in, OS-default minlen=8 + no class requirement
# returns.

set -euo pipefail

MODULE="pam-pwquality"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
PWQUALITY_D="${SELFDEF_PWQUALITY_D:-/etc/security/pwquality.conf.d}"
DST="${PWQUALITY_D}/50-selfdef.conf"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
if [[ -f "$DST" ]]; then
    run "remove $(basename "$DST")" -- rm -f "$DST"
    removed=$((removed + 1))
fi

emit_status "ok" "pam-pwquality removed=$removed (NOTE: OS-default pwquality may have weaker settings; existing user passwords UNAFFECTED — only new password sets re-evaluated)"
