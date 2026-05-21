#!/usr/bin/env bash
# kernel-lockdown — uninstall.
#
# Removes the sysctl drop-ins. Running sysctls stay until reboot
# (kernel state survives drop-in removal); the operator may need
# to manually reverse them with `sysctl key=value` or reboot for
# a clean baseline.
#
# kernel.modules_disabled CANNOT be reversed at runtime by design;
# uninstall just removes the drop-in so the NEXT boot is clean.
#
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="kernel-lockdown"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SYSCTL_DIR="${SELFDEF_SYSCTL_DIR:-/etc/sysctl.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
for f in "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" \
         "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

emit_status "ok" "kernel-lockdown removed=$removed (NOTE: live sysctl state survives; reboot for clean baseline)"
