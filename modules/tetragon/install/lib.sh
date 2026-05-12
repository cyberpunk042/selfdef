# Shared helpers used by apply / check / uninstall. Sourced, not executed.
# Caller must have set:
#   MODULE       — "tetragon"
#   DRY_RUN      — 0 | 1
#   CONFIG_FILE  — path to the rendered host config

# shellcheck disable=SC2034  # used by sourcing scripts

log() { echo "[tetragon] $*" >&2; }

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

# Minimal TOML reader — `key = "value"` / `key = N`. The other
# selfdef modules use the same shape; we keep it deliberately small
# so the script doesn't pull a TOML parser dependency.
toml_get() {
    local key="$1" file="$2"
    local line
    line=$(grep -E "^[[:space:]]*${key}[[:space:]]*=" "$file" | head -1 || true)
    [[ -z "$line" ]] && return 1
    line="${line#*=}"; line="${line## }"; line="${line%% #*}"
    line="${line%\"}"; line="${line#\"}"
    printf '%s' "$line"
}

# Render Tetragon's main config to stdout. Inputs come from the host
# config via toml_get; failures fall back to the documented defaults.
#
#   $1 — event_log_path
#   $2 — policy_dir
#   $3 — metrics_address
render_tetragon_config() {
    local event_log="$1" policy_dir="$2" metrics_addr="$3"
    cat <<EOF
# Managed by the selfdef \`tetragon\` module. Do not edit by hand —
# selfdefctl modules apply will overwrite it. Operator-tunable knobs
# live in /etc/selfdef/modules/tetragon.toml.

# Where Tetragon writes its event stream. The selfdef daemon's
# eventstream collector tails this path.
export-filename: "${event_log}"
export-allowlist: ""
export-denylist: ""

# Drop directory for TracingPolicy YAMLs. \`agent-guard\` writes here.
tracing-policy-dir: "${policy_dir}"

# Prometheus exporter. \`observability\` scrapes this.
metrics-server: "${metrics_addr}"

# We default to BTF-only operation (no kernel-header BTF lookup at
# build time). If your kernel ships /sys/kernel/btf/vmlinux, this
# Just Works.
btf: ""

# Process cache size — bumped from the upstream default so that
# short-lived agent processes don't get aged out before their events
# correlate.
process-cache-size: 65536
EOF
}
