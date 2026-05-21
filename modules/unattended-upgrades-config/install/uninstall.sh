#!/usr/bin/env bash
# unattended-upgrades-config — uninstall.
#
# Removes the selfdef apt.conf.d drop-ins. Leaves the OS-shipped
# /etc/apt/apt.conf.d/50unattended-upgrades + 20auto-upgrades
# alone. Does NOT stop the apt-daily timers — operator may want
# them to keep running with the OS-default config.

set -euo pipefail

MODULE="unattended-upgrades-config"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
APT_CONFD="${SELFDEF_APT_CONFD:-/etc/apt/apt.conf.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

removed=0
for f in "${APT_CONFD}/50selfdef-unattended-upgrades" \
         "${APT_CONFD}/60selfdef-unattended-reboot" \
         "${APT_CONFD}/20selfdef-periodic"; do
    if [[ -f "$f" ]]; then
        run "remove $(basename "$f")" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

emit_status "ok" "unattended-upgrades-config removed=$removed (apt-daily timers NOT stopped — operator manages OS-default config independently)"
