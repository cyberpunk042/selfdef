# Shared helpers for observability apply / check / uninstall.
# Sourced, not executed. Caller must have set:
#   MODULE      — "observability"
#   DRY_RUN     — 0 | 1
#   CONFIG_FILE — path to the rendered host config

# shellcheck disable=SC2034

log() { echo "[observability] $*" >&2; }

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

toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}

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
