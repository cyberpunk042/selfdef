#!/bin/bash
# selfdef-quarantine-textfile — emit Prometheus node_exporter
# textfile gauges for the SDD-066 process-quarantine state.
#
# Surfaces real IPS-host operator visibility for the SDD-066
# process-quarantine action layer (selfdef-process-quarantine-
# backend at selfdef commit aa1cdef):
#   - is selfdef.slice/quarantine-*.scope present in cgroupv2?
#   - how many processes are currently frozen?
#   - what's the soonest auto-release Unix timestamp?
#
# Pairs with blockset observer (19th sibling, SDD-065 enforcement
# axis) at the operator-action-state axis: blockset surfaces
# IP-block state; this surfaces process-freeze state.
#
# Runs every 60s via the companion timer. 20th sibling observer.
#
# Honest-offline: when /sys/fs/cgroup/selfdef.slice is absent
# (selfdefd hasn't bootstrapped its slice yet) emit zero with
# selfdef_quarantine_slice_present=0 sentinel.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_QUARANTINE_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-quarantine.prom}"
SLICE_PATH="${SELFDEF_QUARANTINE_SLICE_PATH:-/sys/fs/cgroup/selfdef.slice}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_quarantine_textfile_emit_failed Wrapper exited unhealthy.\n'
    printf '# TYPE selfdef_quarantine_textfile_emit_failed gauge\n'
    printf 'selfdef_quarantine_textfile_emit_failed 1\n'
    printf '# HELP selfdef_quarantine_last_run_unix Wall-clock seconds of last wrapper invocation.\n'
    printf '# TYPE selfdef_quarantine_last_run_unix gauge\n'
    printf 'selfdef_quarantine_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

slice_present=0
quarantine_active_count=0
quarantine_frozen_count=0
quarantine_oldest_expiry_unix=0

if [ -d "$SLICE_PATH" ]; then
  slice_present=1
  # Iterate quarantine-*.scope entries.
  for scope in "$SLICE_PATH"/quarantine-*.scope; do
    [ -d "$scope" ] || continue
    quarantine_active_count=$(( quarantine_active_count + 1 ))
    # Check freeze state via cgroup.freeze (0=running, 1=frozen).
    freeze_file="$scope/cgroup.freeze"
    if [ -r "$freeze_file" ]; then
      freeze_val="$(cat "$freeze_file" 2>/dev/null || echo 0)"
      if [ "$freeze_val" = "1" ]; then
        quarantine_frozen_count=$(( quarantine_frozen_count + 1 ))
      fi
    fi
  done

  # Soonest auto-release: parse companion systemd timer state via
  # `systemctl list-timers selfdef-quarantine-*.timer --no-legend`
  # if available. The "NEXT" column is iso8601-ish; convert to
  # epoch via date.
  if command -v systemctl >/dev/null 2>&1; then
    smallest_epoch=0
    while read -r next _; do
      [ -z "$next" ] && continue
      [ "$next" = "n/a" ] && continue
      epoch="$(date -d "$next" +%s 2>/dev/null || echo 0)"
      if [ "$epoch" -gt 0 ]; then
        if [ "$smallest_epoch" -eq 0 ] || [ "$epoch" -lt "$smallest_epoch" ]; then
          smallest_epoch="$epoch"
        fi
      fi
    done < <(systemctl list-timers 'selfdef-quarantine-*.timer' --no-legend --no-pager 2>/dev/null | awk '{print $1, $2, $3, $4}')
    quarantine_oldest_expiry_unix="$smallest_epoch"
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_quarantine_slice_present 1 if /sys/fs/cgroup/selfdef.slice exists (selfdefd bootstrapped).\n'
  printf '# TYPE selfdef_quarantine_slice_present gauge\n'
  printf 'selfdef_quarantine_slice_present %d\n' "$slice_present"

  printf '# HELP selfdef_quarantine_active_count Total quarantine-*.scope entries under selfdef.slice.\n'
  printf '# TYPE selfdef_quarantine_active_count gauge\n'
  printf 'selfdef_quarantine_active_count %d\n' "$quarantine_active_count"

  printf '# HELP selfdef_quarantine_frozen_count Subset of active where cgroup.freeze == 1.\n'
  printf '# TYPE selfdef_quarantine_frozen_count gauge\n'
  printf 'selfdef_quarantine_frozen_count %d\n' "$quarantine_frozen_count"

  printf '# HELP selfdef_quarantine_oldest_expiry_unix Unix timestamp of the soonest auto-release timer (0 if none).\n'
  printf '# TYPE selfdef_quarantine_oldest_expiry_unix gauge\n'
  printf 'selfdef_quarantine_oldest_expiry_unix %d\n' "$quarantine_oldest_expiry_unix"

  printf '# HELP selfdef_quarantine_last_run_unix Wall-clock seconds of last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_quarantine_last_run_unix gauge\n'
  printf 'selfdef_quarantine_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_quarantine_textfile_emit_failed Wrapper exited unhealthy (0 on successful emit).\n'
  printf '# TYPE selfdef_quarantine_textfile_emit_failed gauge\n'
  printf 'selfdef_quarantine_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
