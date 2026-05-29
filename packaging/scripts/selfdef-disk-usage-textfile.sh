#!/bin/bash
# selfdef-disk-usage-textfile — emit Prometheus node_exporter
# textfile gauges for the per-directory disk usage of selfdef-
# relevant filesystem locations.
#
# Surfaces real IPS-host operator visibility: tracks disk usage
# (bytes) for /var/lib/selfdef, /var/log/selfdef, /var/log, and
# /var/lib/node_exporter/textfile_collector. Operators detect
# disk-fill attacks (deliberate log spam, ZFS-no-quota loops,
# logrotate misconfiguration) before they degrade the IPS spine.
#
# Runs every 60s via the companion timer. 10th sibling observer.
# Same atomic write + honest-offline discipline as the 9 siblings.
#
# Disk-fill is a load-bearing IPS hazard: when /var is full, the
# selfdef daemon's append-only audit chain (MS016) cannot extend +
# the cli-mirror + four-watchdog + auth-events observer wrappers
# cannot write their textfiles. The IPS spine silently degrades.
# This observer detects the precursor (rising disk usage) before
# the chain fully wedges.
#
# Honest-offline: when `du` is absent OR target paths are
# inaccessible, emit sentinel gauge.
#
# Environment:
#   SELFDEF_DISK_USAGE_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-disk-usage.prom)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_DISK_USAGE_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-disk-usage.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_disk_usage_textfile_emit_failed Wrapper exited unhealthy (du absent OR target paths inaccessible).\n'
    printf '# TYPE selfdef_disk_usage_textfile_emit_failed gauge\n'
    printf 'selfdef_disk_usage_textfile_emit_failed 1\n'
    printf '# HELP selfdef_disk_usage_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_disk_usage_last_run_unix gauge\n'
    printf 'selfdef_disk_usage_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — du available.
if ! command -v du >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

# Per-path disk usage in bytes (du -sb). Missing paths emit 0
# (honest about absence — distinct from observer-failure sentinel).
get_size() {
  local path="$1"
  if [ -d "$path" ] || [ -f "$path" ]; then
    du -sb "$path" 2>/dev/null | awk '{print $1}'
  else
    echo 0
  fi
}

selfdef_lib_bytes="$(get_size /var/lib/selfdef)"
selfdef_log_bytes="$(get_size /var/log/selfdef)"
var_log_bytes="$(get_size /var/log)"
textfile_collector_bytes="$(get_size /var/lib/node_exporter/textfile_collector)"

# Filesystem-level free space for /var — surfaces the operational
# headroom regardless of any single subtree size.
var_free_bytes="$(df -B1 --output=avail /var 2>/dev/null | tail -1 | tr -d ' ')"
var_used_pct="$(df --output=pcent /var 2>/dev/null | tail -1 | tr -d ' %')"

# Sanitize numeric outputs.
selfdef_lib_bytes="${selfdef_lib_bytes:-0}"
selfdef_log_bytes="${selfdef_log_bytes:-0}"
var_log_bytes="${var_log_bytes:-0}"
textfile_collector_bytes="${textfile_collector_bytes:-0}"
var_free_bytes="${var_free_bytes:-0}"
var_used_pct="${var_used_pct:-0}"

# Build textfile in temp + atomic rename.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_disk_usage_lib_bytes Disk usage of /var/lib/selfdef in bytes.\n'
  printf '# TYPE selfdef_disk_usage_lib_bytes gauge\n'
  printf 'selfdef_disk_usage_lib_bytes %s\n' "$selfdef_lib_bytes"

  printf '# HELP selfdef_disk_usage_log_bytes Disk usage of /var/log/selfdef in bytes.\n'
  printf '# TYPE selfdef_disk_usage_log_bytes gauge\n'
  printf 'selfdef_disk_usage_log_bytes %s\n' "$selfdef_log_bytes"

  printf '# HELP selfdef_disk_usage_var_log_bytes Disk usage of /var/log overall in bytes.\n'
  printf '# TYPE selfdef_disk_usage_var_log_bytes gauge\n'
  printf 'selfdef_disk_usage_var_log_bytes %s\n' "$var_log_bytes"

  printf '# HELP selfdef_disk_usage_textfile_collector_bytes Disk usage of the node_exporter textfile_collector dir.\n'
  printf '# TYPE selfdef_disk_usage_textfile_collector_bytes gauge\n'
  printf 'selfdef_disk_usage_textfile_collector_bytes %s\n' "$textfile_collector_bytes"

  printf '# HELP selfdef_disk_usage_var_free_bytes Free space on /var filesystem in bytes.\n'
  printf '# TYPE selfdef_disk_usage_var_free_bytes gauge\n'
  printf 'selfdef_disk_usage_var_free_bytes %s\n' "$var_free_bytes"

  printf '# HELP selfdef_disk_usage_var_used_percent Filesystem usage percent for /var (0-100).\n'
  printf '# TYPE selfdef_disk_usage_var_used_percent gauge\n'
  printf 'selfdef_disk_usage_var_used_percent %s\n' "$var_used_pct"

  printf '# HELP selfdef_disk_usage_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_disk_usage_last_run_unix gauge\n'
  printf 'selfdef_disk_usage_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_disk_usage_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_disk_usage_textfile_emit_failed gauge\n'
  printf 'selfdef_disk_usage_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
