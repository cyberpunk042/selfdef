#!/usr/bin/env bash
# vpn-bridge — apply (dispatcher).
#
# Selects the active profile from the host config and delegates to
# install/profiles/<profile>.sh's `profile_apply` function. Each
# profile owns its own service / nftables / overlay-specific state;
# the dispatcher only owns the preflight and the structured-status
# contract.
#
# F-2029-004: idempotent + SELFDEF_DRY_RUN=1 aware (delegated to the
# selected profile_apply). Profiles use the shared-lib `run` helper
# which short-circuits on dry-run, and `module_record_file` (SDD-006
# v2) to track every persistent file written so uninstall can
# enumerate them. Re-running apply with the same config + present
# target state is a no-op.
#
# To add a new transport / profile: drop install/profiles/<name>.sh
# defining profile_apply / profile_check / profile_uninstall, list
# the slug under [profiles].available in module.toml, and add a
# defaults file under profiles/<name>.toml. See README § Extending.

set -euo pipefail

MODULE="vpn-bridge"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_VPN_BRIDGE_CONFIG:-/etc/selfdef/modules/vpn-bridge.toml}"
LIB_DIR="${SELFDEF_VPN_BRIDGE_LIB_DIR:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")}"
PROFILES_DIR="${SELFDEF_VPN_BRIDGE_PROFILES_DIR:-${LIB_DIR}/profiles}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config file not readable: $CONFIG_FILE"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "relay-via-server")

# Profiles defined; the script is sourced and `profile_apply` runs.
resolve_profile_script apply
