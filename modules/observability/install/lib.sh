# Module-specific helpers for observability. Shared helpers (log,
# emit_status, die, run, toml_get) come from
# /usr/share/selfdef/lib/module-lib.sh.
#
# Caller must have set:
#   MODULE      — "observability"
#   DRY_RUN     — 0 | 1
#   CONFIG_FILE — path to the rendered host config

# F-2027-024: opted into v2 for module_record_file /
# module_render_files / module_clear_manifest. Replaces the
# hand-curated SCRAPE_DST + DASHBOARD_DST duplication between
# apply.sh and uninstall.sh.
# shellcheck disable=SC1090,SC2034
SELFDEF_MODULE_LIB_VERSION_REQUIRED=2
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

# Render the scrape config template by replacing the
# __SELFDEF_SCRAPE_TARGETS__ marker line with one `- "host:port"`
# entry per target in the CSV.
#
#   $1 — template path
#   $2 — destination path
#   $3 — CSV of scrape targets (e.g. "localhost:2112,otherhost:2112")
render_scrape_config() {
    local src="$1" dst="$2" csv="$3"
    [[ -z "$csv" ]] && die "scrape_targets is empty — refusing to render an empty scrape job"
    local block="" t
    IFS=',' read -ra targets <<<"$csv"
    for t in "${targets[@]}"; do
        t="${t## }"; t="${t%% }"
        [[ -z "$t" ]] && continue
        block="${block}          - \"${t}\"\n"
    done
    # Drop the marker comment AND the literal default line beneath it,
    # then splice the operator's targets in their place. Using `awk`
    # so we can match multi-line context without sed flags varying
    # across BSD/GNU.
    awk -v block="${block%\\n}" '
        /__SELFDEF_SCRAPE_TARGETS__/ { skip = 2; print block; next }
        skip > 0                     { skip -= 1; next }
        { print }
    ' "$src" > "$dst"
}

# Render the dashboard JSON template by substituting the
# __SELFDEF_DASHBOARD_UID__ and __SELFDEF_DASHBOARD_TITLE__ markers.
render_dashboard() {
    local src="$1" dst="$2" uid="$3" title="$4"
    local esc_title
    esc_title=$(printf '%s' "$title" | sed 's|"|\\"|g')
    sed -e "s|__SELFDEF_DASHBOARD_UID__|${uid}|" \
        -e "s|__SELFDEF_DASHBOARD_TITLE__|${esc_title}|" \
        "$src" > "$dst"
}
