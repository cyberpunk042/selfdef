#!/bin/bash
# four-watchdog-textfile — emit Prometheus node_exporter textfile gauges
# for the 9 four-watchdog alert classifications.
#
# Calls `selfdefctl alerts --json`, parses the structured response, and
# atomically writes a node_exporter textfile with per-alert severity
# gauges + a worst-severity rollup + a last-run-unix observer-freshness
# gauge.
#
# Runs every 60s via the companion selfdef-four-watchdog-doctor.timer.
# Pairs with the existing selfdef-cli-mirror-doctor and selfdef-m060-
# doctor textfile observers — same 3-tier severity ladder (0=OK / 1=WARN
# / 2=CRITICAL), same atomic tempfile + rename pattern, same
# node_exporter textfile_collector consumption shape.
#
# The four-watchdog set is the IPS spine per SECURITY.md and SDD-004
# §"Four-watchdog set (IPS spine, MS046+MS047+MS044+MS048)" — drift
# detection here is page-worthy: a watchdog reporting CRITICAL means an
# IPS-spine subsystem has stopped enforcing.
#
# Honest-offline: when selfdefd is unreachable OR `selfdefctl alerts`
# fails, the wrapper emits a single sentinel gauge
# `selfdef_four_watchdog_textfile_emit_failed 1` so monitoring can
# distinguish "no data" from "all healthy" — never silently produces
# zeroed-out gauges (would mask a wedged daemon as healthy).
#
# Environment:
#   SELFDEF_FOUR_WATCHDOG_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-four-watchdog.prom)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_FOUR_WATCHDOG_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-four-watchdog.prom}"

# Severity-string → numeric gauge value. Matches the cli-mirror-doctor +
# m060-doctor convention (0/1/2). 'unknown' maps to -1 so monitoring
# can filter for "missing data" without conflating with healthy.
severity_to_int() {
  case "$1" in
    ok)        echo 0 ;;
    warn)      echo 1 ;;
    critical)  echo 2 ;;
    unknown)   echo -1 ;;
    *)         echo -1 ;;
  esac
}

emit_failure_sentinel() {
  # Write a sentinel textfile so Prometheus can distinguish "wrapper
  # exited unhealthy" from "no data". An atomic tempfile + rename is
  # used here too — node_exporter never sees a half-written file.
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_four_watchdog_textfile_emit_failed Wrapper exited unhealthy (selfdefctl failure, daemon unreachable, or no JSON).\n'
    printf '# TYPE selfdef_four_watchdog_textfile_emit_failed gauge\n'
    printf 'selfdef_four_watchdog_textfile_emit_failed 1\n'
    printf '# HELP selfdef_four_watchdog_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_four_watchdog_last_run_unix gauge\n'
    printf 'selfdef_four_watchdog_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

# Trap any unexpected exit so monitoring sees the failure sentinel
# rather than a stale textfile from the previous successful run.
trap 'emit_failure_sentinel' ERR

# Probe — selfdefctl alerts --json returns { worst, alerts: [...] }.
# Use `selfdefctl` from $PATH (matches sibling -doctor service convention).
if ! command -v selfdefctl >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

json="$(selfdefctl alerts --json 2>/dev/null)" || {
  emit_failure_sentinel
  exit 2
}

# Validate envelope shape — refuse to emit zeroed gauges from a
# malformed response.
if ! echo "$json" | jq -e '.worst and (.alerts|type=="array")' >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

worst_str="$(echo "$json" | jq -r '.worst')"
worst_int="$(severity_to_int "$worst_str")"

# Build the textfile in a temp file then atomically rename — node_exporter
# never sees a half-written file.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_four_watchdog_worst_severity Aggregate worst severity across the 9 four-watchdog alert classifications (0=OK, 1=WARN, 2=CRITICAL, -1=UNKNOWN).\n'
  printf '# TYPE selfdef_four_watchdog_worst_severity gauge\n'
  printf 'selfdef_four_watchdog_worst_severity %s\n' "$worst_int"

  printf '# HELP selfdef_four_watchdog_severity Per-alert severity classification (0=OK, 1=WARN, 2=CRITICAL, -1=UNKNOWN).\n'
  printf '# TYPE selfdef_four_watchdog_severity gauge\n'

  # One gauge per alert row. Labels: name + ms + series so Grafana can
  # group / filter across the milestone families. Sorted by alert name
  # for deterministic textfile diffs across runs.
  echo "$json" | jq -r '.alerts | sort_by(.name)[] | "\(.name)\t\(.ms)\t\(.series)\t\(.state)"' \
    | while IFS=$'\t' read -r name ms series state; do
      sev="$(severity_to_int "$state")"
      printf 'selfdef_four_watchdog_severity{alert="%s",ms="%s",series="%s"} %s\n' \
        "$name" "$ms" "$series" "$sev"
    done

  printf '# HELP selfdef_four_watchdog_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_four_watchdog_last_run_unix gauge\n'
  printf 'selfdef_four_watchdog_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_four_watchdog_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_four_watchdog_textfile_emit_failed gauge\n'
  printf 'selfdef_four_watchdog_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

# Clear the ERR trap on successful emit so we don't double-emit a
# sentinel on script exit.
trap - ERR

# Exit code mirrors the worst severity ladder so systemd
# SuccessExitStatus= can treat WARN/CRITICAL as wrapper-success-with-data
# rather than wrapper-failure. The textfile carries the actual severity.
case "$worst_str" in
  ok|unknown) exit 0 ;;
  warn)       exit 1 ;;
  critical)   exit 2 ;;
  *)          exit 2 ;;
esac
