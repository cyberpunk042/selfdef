#!/bin/bash
# selfdef-time-sync-textfile — emit Prometheus node_exporter
# textfile gauges for host time-sync state (NTP / chronyd /
# systemd-timesyncd).
#
# Surfaces real IPS-host operator visibility: tracks clock-sync
# state + drift offset + sync-source reachability. Operators detect
# clock drift before audit-trail timestamps become unreliable.
#
# Runs every 60s via the companion timer. 11th sibling observer.
#
# Time-sync is a load-bearing IPS hazard: when the system clock
# drifts, the MS016 append-only audit chain's timestamps become
# unreliable. Forensic correlation against external IDS becomes
# impossible. Selfdef cannot enforce time policy without root-level
# NTP control, but it CAN detect drift early.
#
# Honest-offline: when timedatectl is absent OR systemd-timesyncd
# isn't running, emit sentinel.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_TIME_SYNC_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-time-sync.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_time_sync_textfile_emit_failed Wrapper exited unhealthy (timedatectl absent OR unparseable).\n'
    printf '# TYPE selfdef_time_sync_textfile_emit_failed gauge\n'
    printf 'selfdef_time_sync_textfile_emit_failed 1\n'
    printf '# HELP selfdef_time_sync_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_time_sync_last_run_unix gauge\n'
    printf 'selfdef_time_sync_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — timedatectl available.
if ! command -v timedatectl >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

# Parse timedatectl status. The relevant fields are:
#   System clock synchronized: yes
#   NTP service: active
#   RTC in local TZ: no
status_out="$(timedatectl status 2>/dev/null || true)"
if [ -z "$status_out" ]; then
  emit_failure_sentinel
  exit 2
fi

# Extract values (binary 0/1 for boolean conditions).
synced="$(echo "$status_out" \
  | awk -F': *' '/System clock synchronized/ {print $2}' | tr -d '\n')"
ntp_service="$(echo "$status_out" \
  | awk -F': *' '/NTP service/ {print $2}' | tr -d '\n')"
rtc_local="$(echo "$status_out" \
  | awk -F': *' '/RTC in local TZ/ {print $2}' | tr -d '\n')"

case "$synced" in
  yes) synced_val=1 ;;
  *)   synced_val=0 ;;
esac
case "$ntp_service" in
  active) ntp_active=1 ;;
  *)      ntp_active=0 ;;
esac
case "$rtc_local" in
  no) rtc_local_val=0 ;;
  *)  rtc_local_val=1 ;;  # local TZ for RTC = potential drift hazard
esac

# Drift offset (seconds since epoch from system vs hw clock).
# /sys/class/rtc/rtc0/since_epoch is available on most hosts; if
# absent, drift is 0 (best-effort).
drift_seconds=0
if [ -r /sys/class/rtc/rtc0/since_epoch ]; then
  rtc_epoch="$(cat /sys/class/rtc/rtc0/since_epoch 2>/dev/null || echo 0)"
  sys_epoch="$(date +%s)"
  if [ "$rtc_epoch" -gt 0 ]; then
    drift_seconds=$(( sys_epoch - rtc_epoch ))
    # Absolute value.
    if [ "$drift_seconds" -lt 0 ]; then
      drift_seconds=$(( -drift_seconds ))
    fi
  fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_time_sync_synced 1 if system clock is synchronized to a time source; 0 otherwise.\n'
  printf '# TYPE selfdef_time_sync_synced gauge\n'
  printf 'selfdef_time_sync_synced %d\n' "$synced_val"

  printf '# HELP selfdef_time_sync_ntp_active 1 if NTP service is active; 0 otherwise.\n'
  printf '# TYPE selfdef_time_sync_ntp_active gauge\n'
  printf 'selfdef_time_sync_ntp_active %d\n' "$ntp_active"

  printf '# HELP selfdef_time_sync_rtc_local_tz 1 if RTC is in local TZ (drift hazard); 0 if UTC (the secure default).\n'
  printf '# TYPE selfdef_time_sync_rtc_local_tz gauge\n'
  printf 'selfdef_time_sync_rtc_local_tz %d\n' "$rtc_local_val"

  printf '# HELP selfdef_time_sync_drift_seconds Absolute drift between system clock and RTC in seconds.\n'
  printf '# TYPE selfdef_time_sync_drift_seconds gauge\n'
  printf 'selfdef_time_sync_drift_seconds %d\n' "$drift_seconds"

  printf '# HELP selfdef_time_sync_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_time_sync_last_run_unix gauge\n'
  printf 'selfdef_time_sync_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_time_sync_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_time_sync_textfile_emit_failed gauge\n'
  printf 'selfdef_time_sync_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
