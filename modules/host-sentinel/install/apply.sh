#!/usr/bin/env bash
# host-sentinel — apply.
#
# Renders 2 host-scope TracingPolicies into Tetragon's policy_dir:
#   - selfdef-host-kmod-watch
#   - selfdef-host-ld-preload-watch
#
# In the `enforce` profile, ld-preload-watch's matchActions is
# rewritten from `Post` to `Sigkill`. kmod-watch stays Post in
# both profiles (the module is already loaded by the time the
# event fires; killing the loader is closing the barn door).
#
# Idempotent: re-applying with the same profile writes byte-
# identical files. Dry-run aware.

set -euo pipefail

MODULE="host-sentinel"
DRY_RUN="${SELFDEF_DRY_RUN:-0}"
CONFIG_FILE="${SELFDEF_HOST_SENTINEL_CONFIG:-/etc/selfdef/modules/host-sentinel.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
MODULE_DIR="$(dirname "$LIB_DIR")"
POLICIES_SRC="${SELFDEF_HOST_SENTINEL_POLICIES:-${MODULE_DIR}/policies}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
[[ -d "$POLICIES_SRC" ]] || die "policy source dir missing: $POLICIES_SRC"

PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "audit")
case "$PROFILE" in
    audit|enforce) ;;
    *) die "profile must be audit|enforce, got '$PROFILE'" ;;
esac

# Per-policy enable flags (default true so a freshly-installed
# module is fully active). Operator can pin one off via the host
# config without touching this script.
KMOD_ENABLED=$(toml_get        kmod_watch_enabled       "$CONFIG_FILE" || echo "true")
LD_PRELOAD_ENABLED=$(toml_get   ld_preload_watch_enabled "$CONFIG_FILE" || echo "true")

# Pull tetragon's policy_dir from *its* config so we never drift.
TG_CFG="${SELFDEF_TETRAGON_CONFIG:-/etc/selfdef/modules/tetragon.toml}"
POLICY_DIR="/etc/tetragon/tetragon.tp.d"
if [[ -r "$TG_CFG" ]]; then
    POLICY_DIR=$(toml_get policy_dir "$TG_CFG" || echo "$POLICY_DIR")
fi
[[ -d "$POLICY_DIR" ]] || die "tetragon policy_dir missing: $POLICY_DIR (run tetragon module first)"

installed=0
disabled=0
changes=0

render_policy() {
    local name="$1"
    local src="$2"
    local enabled="$3"
    local action="$4"   # Post | Sigkill
    local dst="${POLICY_DIR}/${name}.yaml"

    if [[ "$enabled" != "true" ]]; then
        # Policy disabled — make sure no stale file remains.
        if [[ -f "$dst" ]]; then
            run "remove disabled policy ${name}" -- rm -f "$dst"
            changes=$((changes + 1))
        fi
        disabled=$((disabled + 1))
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    # The source YAML carries `action: Post` literally. enforce profile
    # rewrites it; audit leaves it as-is.
    if [[ "$action" == "Sigkill" ]]; then
        sed 's/- action: Post/- action: Sigkill/' "$src" > "$tmp"
    else
        cp "$src" "$tmp"
    fi

    if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then
        rm -f "$tmp"
    else
        run "install policy ${name} (action=${action})" -- install -m 0644 "$tmp" "$dst"
        rm -f "$tmp"
        changes=$((changes + 1))
    fi
    installed=$((installed + 1))
}

KMOD_ACTION="Post"   # always Post (rationale above)
LD_PRELOAD_ACTION="Post"
if [[ "$PROFILE" == "enforce" ]]; then
    LD_PRELOAD_ACTION="Sigkill"
fi

render_policy "selfdef-host-kmod-watch"        "${POLICIES_SRC}/kmod-watch.yaml"        "$KMOD_ENABLED"       "$KMOD_ACTION"
render_policy "selfdef-host-ld-preload-watch"  "${POLICIES_SRC}/ld-preload-watch.yaml"  "$LD_PRELOAD_ENABLED" "$LD_PRELOAD_ACTION"

emit_status "ok" "host-sentinel profile=$PROFILE installed=$installed disabled=$disabled changes=$changes"
