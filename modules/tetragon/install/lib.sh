# Module-specific helpers for tetragon. Shared helpers (log,
# emit_status, die, run, toml_get) come from
# /usr/share/selfdef/lib/module-lib.sh (or the workspace path
# selfdefctl exports via SELFDEF_MODULE_LIB).
#
# Caller must have set:
#   MODULE       — "tetragon"
#   DRY_RUN      — 0 | 1
#   CONFIG_FILE  — path to the rendered host config

# F-2027-024: opted into v2 to use module_record_file /
# module_render_files / module_clear_manifest. Replaces the
# hand-curated CONFIG_PATH duplication between apply.sh and
# uninstall.sh. Tetragon's policy_dir / event_log are NOT
# tracked — they're operator-owned drop dirs that long outlive
# this module's installation.
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
