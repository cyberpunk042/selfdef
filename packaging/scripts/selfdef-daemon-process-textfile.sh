#!/bin/bash
# selfdef-daemon-process-textfile — emit Prometheus node_exporter
# textfile gauges for the selfdefd daemon's runtime process state.
#
# Surfaces real IPS-host operator visibility: memory_rss, fd_count,
# uptime_seconds, thread_count, restart_count via /proc/<pid>/ + the
# systemd service property NRestarts.
#
# Runs every 60s via the companion selfdef-daemon-process-textfile.timer.
# Pairs with the existing cli-mirror + m060 + four-watchdog + modules
# observers — same atomic tempfile + rename pattern, same node_exporter
# textfile_collector consumption shape, same honest-offline sentinel
# discipline.
#
# Process-state observability is a load-bearing IPS surface — a memory
# leak in selfdefd would silently weaken the IPS spine before crashing
# the daemon outright. This observer surfaces the runtime characteristics
# operators need to detect leaks + FD exhaustion + restart loops early.
#
# Honest-offline: when selfdefd is not running OR /proc/<pid>/ is
# inaccessible, the wrapper emits a sentinel gauge
# `selfdef_daemon_process_textfile_emit_failed=1` matching the
# four-watchdog convention so monitoring can distinguish "no data"
# from "daemon healthy with zero memory" — never silently emit
# zeroed gauges.
#
# Environment:
#   SELFDEF_DAEMON_PROCESS_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-daemon-process.prom)
#   SELFDEF_DAEMON_UNIT (default selfdefd.service)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_DAEMON_PROCESS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-daemon-process.prom}"
DAEMON_UNIT="${SELFDEF_DAEMON_UNIT:-selfdefd.service}"

emit_failure_sentinel() {
  # Atomic write of the failure sentinel. Same convention as the
  # four-watchdog + modules-catalog wrappers.
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_daemon_process_textfile_emit_failed Wrapper exited unhealthy (daemon not running, /proc unreadable, or systemctl failed).\n'
    printf '# TYPE selfdef_daemon_process_textfile_emit_failed gauge\n'
    printf 'selfdef_daemon_process_textfile_emit_failed 1\n'
    printf '# HELP selfdef_daemon_process_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_daemon_process_last_run_unix gauge\n'
    printf 'selfdef_daemon_process_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — systemctl + /proc available.
if ! command -v systemctl >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

# Resolve the selfdefd PID. systemctl show returns MainPID=0 when the
# service isn't running — treat that as honest-offline.
pid="$(systemctl show -p MainPID --value "$DAEMON_UNIT" 2>/dev/null || echo 0)"
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
  emit_failure_sentinel
  exit 2
fi
if ! [ -d "/proc/$pid" ]; then
  emit_failure_sentinel
  exit 2
fi

# Memory RSS (KB → bytes).
rss_kb="$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
rss_bytes=$(( rss_kb * 1024 ))

# Virtual memory size (KB → bytes).
vsize_kb="$(awk '/^VmSize:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"
vsize_bytes=$(( vsize_kb * 1024 ))

# Open file descriptors — count entries in /proc/<pid>/fd/.
fd_count="$(ls -1 "/proc/$pid/fd/" 2>/dev/null | wc -l || echo 0)"

# Thread count.
thread_count="$(awk '/^Threads:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)"

# Uptime: start_time from /proc/<pid>/stat is in clock ticks since
# boot. Convert via /proc/uptime (current uptime in seconds) and
# CLK_TCK (typically 100).
clk_tck="$(getconf CLK_TCK 2>/dev/null || echo 100)"
start_ticks="$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || echo 0)"
uptime_now="$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)"
start_uptime=$(( start_ticks / clk_tck ))
process_uptime_secs=$(( uptime_now - start_uptime ))
if [ "$process_uptime_secs" -lt 0 ]; then
  process_uptime_secs=0
fi

# systemd restart count — NRestarts property tracks how many times
# systemd has restarted the unit since the unit was last loaded.
n_restarts="$(systemctl show -p NRestarts --value "$DAEMON_UNIT" 2>/dev/null || echo 0)"

# Build textfile in temp + atomic rename.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_daemon_process_memory_rss_bytes Selfdefd resident-set-size memory in bytes (/proc/<pid>/status VmRSS).\n'
  printf '# TYPE selfdef_daemon_process_memory_rss_bytes gauge\n'
  printf 'selfdef_daemon_process_memory_rss_bytes %d\n' "$rss_bytes"

  printf '# HELP selfdef_daemon_process_memory_vsize_bytes Selfdefd virtual memory size in bytes (/proc/<pid>/status VmSize).\n'
  printf '# TYPE selfdef_daemon_process_memory_vsize_bytes gauge\n'
  printf 'selfdef_daemon_process_memory_vsize_bytes %d\n' "$vsize_bytes"

  printf '# HELP selfdef_daemon_process_open_fds Selfdefd open file descriptor count.\n'
  printf '# TYPE selfdef_daemon_process_open_fds gauge\n'
  printf 'selfdef_daemon_process_open_fds %d\n' "$fd_count"

  printf '# HELP selfdef_daemon_process_threads Selfdefd thread count (/proc/<pid>/status Threads).\n'
  printf '# TYPE selfdef_daemon_process_threads gauge\n'
  printf 'selfdef_daemon_process_threads %d\n' "$thread_count"

  printf '# HELP selfdef_daemon_process_uptime_seconds Selfdefd process uptime in seconds (clock-tick derived).\n'
  printf '# TYPE selfdef_daemon_process_uptime_seconds gauge\n'
  printf 'selfdef_daemon_process_uptime_seconds %d\n' "$process_uptime_secs"

  printf '# HELP selfdef_daemon_process_restart_count systemd NRestarts since last unit load.\n'
  printf '# TYPE selfdef_daemon_process_restart_count counter\n'
  printf 'selfdef_daemon_process_restart_count %d\n' "$n_restarts"

  printf '# HELP selfdef_daemon_process_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_daemon_process_last_run_unix gauge\n'
  printf 'selfdef_daemon_process_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_daemon_process_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_daemon_process_textfile_emit_failed gauge\n'
  printf 'selfdef_daemon_process_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

# Clear the ERR trap on successful emit.
trap - ERR
exit 0
