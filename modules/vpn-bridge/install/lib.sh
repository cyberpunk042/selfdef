# Shared helpers used by apply.sh / check.sh / uninstall.sh and by the
# per-profile scripts under install/profiles/. Sourced, not executed.
#
# Caller must have already set:
#   MODULE        — module slug, "vpn-bridge"
#   DRY_RUN       — 0 | 1
#   CONFIG_FILE   — path to the rendered host config

# shellcheck disable=SC2034   # used by sourcing scripts

log() { echo "[vpn-bridge] $*" >&2; }

emit_status() {
    local status="$1" message="$2"
    printf '{"module":"%s","status":"%s","message":"%s"}\n' \
        "$MODULE" "$status" "${message//\"/\\\"}"
}

die() { emit_status "failed" "$*"; exit 1; }

run() {
    local desc="$1"; shift
    [[ "$1" == "--" ]] && shift
    if [[ "${DRY_RUN:-0}" == "1" ]]; then
        log "DRY-RUN: $desc"
        log "    \$ $*"
    else
        log "$desc"
        "$@"
    fi
}

# Minimal TOML reader. Only handles `key = "value"` and `key = N`.
# Multi-line tables / arrays are not supported (we don't need them).
toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}

# Validate a name that will be interpolated into a shell command —
# basic command-injection defense.
safe_name() {
    local v="$1"
    [[ "$v" =~ ^[a-zA-Z0-9_./:-]+$ ]]
}

# Locate the profile script for the active PROFILE. Caller-set:
#   PROFILE          — value from the config
#   PROFILES_DIR     — defaults to install/profiles/ next to this file
resolve_profile_script() {
    local action="$1"  # apply | check | uninstall
    local profiles_dir="${PROFILES_DIR:-$(dirname "${BASH_SOURCE[0]}")/profiles}"
    local script="${profiles_dir}/${PROFILE}.sh"
    [[ -r "$script" ]] || die "no profile script for '${PROFILE}' at ${script}"
    # shellcheck disable=SC1090
    source "$script"
    # Each profile defines profile_<action>; verify it exists.
    if ! declare -f "profile_${action}" >/dev/null; then
        die "profile '${PROFILE}' does not implement '${action}'"
    fi
    "profile_${action}"
}
