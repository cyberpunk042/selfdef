#!/usr/bin/env bash
# selinux-baseline — uninstall.
#
# We do NOT auto-flip SELinux back to disabled/permissive on
# uninstall — downgrading MAC enforcement silently is the
# opposite of safe. The operator decides the post-uninstall
# posture explicitly.

set -euo pipefail

MODULE="selinux-baseline"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

LIVE=$(selinux_live_mode)
log "selinux-baseline uninstalled — SELinux left at live=$LIVE (NOT downgraded)."
log "To change posture explicitly: edit $SELINUX_CONFIG + setenforce, or re-apply with a different profile."

emit_status "ok" "selinux-baseline uninstalled (MAC posture preserved at $LIVE)"
