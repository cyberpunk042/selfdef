# Module-specific helpers for bridge-l2. Shared helpers (log,
# emit_status, die, run, toml_get) come from
# /usr/share/selfdef/lib/module-lib.sh.
#
# Caller must have already set:
#   MODULE       — "bridge-l2"
#   DRY_RUN      — 0 | 1
#   CONFIG_FILE  — path to the rendered host config

# shellcheck disable=SC1090,SC2034
SELFDEF_MODULE_LIB_VERSION_REQUIRED=1
# Locate the shared module-lib. Precedence:
#   1. $SELFDEF_MODULE_LIB exported by selfdefctl (workspace
#      runs hit this).
#   2. Workspace-relative path (this lib.sh sits at
#      modules/<slug>/install/lib.sh; the shared lib is at
#      packaging/lib/module-lib.sh). Catches direct script
#      invocations from integration tests + ad-hoc runs.
#   3. Installed system path (.deb-shipped).
if [[ -n "${SELFDEF_MODULE_LIB:-}" && -r "${SELFDEF_MODULE_LIB}" ]]; then
    _selfdef_lib="${SELFDEF_MODULE_LIB}"
elif [[ -r "${BASH_SOURCE[0]%/*}/../../../packaging/lib/module-lib.sh" ]]; then
    _selfdef_lib="${BASH_SOURCE[0]%/*}/../../../packaging/lib/module-lib.sh"
else
    _selfdef_lib="/usr/share/selfdef/lib/module-lib.sh"
fi
# shellcheck disable=SC1090
source "$_selfdef_lib"
unset _selfdef_lib

# bridge-l2-specific helper: read a TOML inline array of strings.
# (The shared lib's toml_get only reads scalars.) Returns
# newline-separated tokens with quotes + whitespace stripped.
toml_get_list() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    if [[ -z "$line" ]]; then return 0; fi
    line="${line#*=}"
    line="${line## }"
    line="${line#\[}"; line="${line%\]}"
    local IFS=','
    for tok in $line; do
        tok="${tok## }"; tok="${tok%% }"
        tok="${tok%\"}"; tok="${tok#\"}"
        [[ -n "$tok" ]] && printf '%s\n' "$tok"
    done
}
