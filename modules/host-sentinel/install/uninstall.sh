#!/usr/bin/env bash
# host-sentinel — uninstall.
#
# Removes host-sentinel's policy YAMLs from tetragon's policy_dir.
# Leaves the policy_dir itself alone (tetragon owns that).
# Idempotent. SELFDEF_DRY_RUN=1 aware.

set -euo pipefail

MODULE="host-sentinel"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_HOST_SENTINEL_CONFIG:-/etc/selfdef/modules/host-sentinel.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

TG_CFG="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
POLICY_DIR="/etc/tetragon/tetragon.tp.d"
if [[ -r "$TG_CFG" ]]; then
    POLICY_DIR=$(toml_get policy_dir "$TG_CFG" || echo "$POLICY_DIR")
fi

removed=0
for name in "selfdef-host-kmod-watch" "selfdef-host-ld-preload-watch"; do
    f="${POLICY_DIR}/${name}.yaml"
    if [[ -f "$f" ]]; then
        run "remove policy ${name}" -- rm -f "$f"
        removed=$((removed + 1))
    fi
done

emit_status "ok" "host-sentinel removed=$removed"
