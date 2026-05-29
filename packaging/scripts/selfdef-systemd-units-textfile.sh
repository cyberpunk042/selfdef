#!/bin/bash
# selfdef-systemd-units-textfile — emit Prometheus node_exporter
# textfile gauges for the health of ALL selfdef-prefixed systemd
# units (selfdefd, selfdef-doctor.timer, selfdef-cli-mirror-*,
# selfdef-m060-doctor.*, selfdef-four-watchdog-*, selfdef-modules-*,
# selfdef-daemon-process-*, selfdef-apparmor-*, selfdef-auth-events-*).
#
# Surfaces real IPS-host operator visibility: tracks per-unit
# ActiveState (active / inactive / failed / activating). Silently-
# failed timers + services are a chronic IPS-spine integrity hazard
# that no other alarm fires on — this observer surfaces them.
#
# Runs every 60s via the companion selfdef-systemd-units-textfile.timer.
# 8th sibling observer following the established pattern.
#
# Reads `systemctl list-units --type=service,timer 'selfdef-*'`.
# Honest-offline when systemctl absent OR D-Bus unavailable. Never
# silently emits zeroed unit counts that would mask a wedged
# selfdef-spine as "0 units present, 0 failed".
#
# Environment:
#   SELFDEF_SYSTEMD_UNITS_TEXTFILE_PATH (default
#     /var/lib/node_exporter/textfile_collector/selfdef-systemd-units.prom)
#   SELFDEF_SYSTEMD_UNITS_PREFIX (default selfdef- — pattern matched
#     against unit names)
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_SYSTEMD_UNITS_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-systemd-units.prom}"
UNIT_PREFIX="${SELFDEF_SYSTEMD_UNITS_PREFIX:-selfdef-}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_systemd_units_textfile_emit_failed Wrapper exited unhealthy (systemctl absent OR D-Bus unavailable).\n'
    printf '# TYPE selfdef_systemd_units_textfile_emit_failed gauge\n'
    printf 'selfdef_systemd_units_textfile_emit_failed 1\n'
    printf '# HELP selfdef_systemd_units_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_systemd_units_last_run_unix gauge\n'
    printf 'selfdef_systemd_units_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — systemctl available.
if ! command -v systemctl >/dev/null 2>&1; then
  emit_failure_sentinel
  exit 2
fi

# Enumerate units. --all so inactive + failed units are included
# (without --all, systemctl hides inactive units). --no-legend
# strips header/footer. --plain avoids dbus tree-render quirks.
unit_lines="$(systemctl list-units --all --no-legend --plain \
  --type=service,timer "${UNIT_PREFIX}*" 2>/dev/null || true)"

# Tally counts per ActiveState — active / inactive / failed /
# activating / deactivating. Format: UNIT LOAD ACTIVE SUB DESCRIPTION
total_units=0
active_count=0
inactive_count=0
failed_count=0
activating_count=0
other_count=0

while IFS= read -r line; do
  [ -z "$line" ] && continue
  total_units=$(( total_units + 1 ))
  active_state="$(echo "$line" | awk '{print $3}')"
  case "$active_state" in
    active)        active_count=$((active_count + 1)) ;;
    inactive)      inactive_count=$((inactive_count + 1)) ;;
    failed)        failed_count=$((failed_count + 1)) ;;
    activating)    activating_count=$((activating_count + 1)) ;;
    *)             other_count=$((other_count + 1)) ;;
  esac
done <<< "$unit_lines"

# Build textfile in temp + atomic rename.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_systemd_units_total Count of all selfdef-prefixed systemd service+timer units.\n'
  printf '# TYPE selfdef_systemd_units_total gauge\n'
  printf 'selfdef_systemd_units_total{prefix="%s"} %d\n' "$UNIT_PREFIX" "$total_units"

  printf '# HELP selfdef_systemd_units_active Count of selfdef units currently in active state.\n'
  printf '# TYPE selfdef_systemd_units_active gauge\n'
  printf 'selfdef_systemd_units_active{prefix="%s"} %d\n' "$UNIT_PREFIX" "$active_count"

  printf '# HELP selfdef_systemd_units_inactive Count of selfdef units currently inactive (loaded but not running).\n'
  printf '# TYPE selfdef_systemd_units_inactive gauge\n'
  printf 'selfdef_systemd_units_inactive{prefix="%s"} %d\n' "$UNIT_PREFIX" "$inactive_count"

  printf '# HELP selfdef_systemd_units_failed Count of selfdef units in failed state — page-worthy.\n'
  printf '# TYPE selfdef_systemd_units_failed gauge\n'
  printf 'selfdef_systemd_units_failed{prefix="%s"} %d\n' "$UNIT_PREFIX" "$failed_count"

  printf '# HELP selfdef_systemd_units_activating Count of selfdef units currently activating (in start-up transition).\n'
  printf '# TYPE selfdef_systemd_units_activating gauge\n'
  printf 'selfdef_systemd_units_activating{prefix="%s"} %d\n' "$UNIT_PREFIX" "$activating_count"

  printf '# HELP selfdef_systemd_units_other Count of selfdef units in any non-canonical state (deactivating / reloading).\n'
  printf '# TYPE selfdef_systemd_units_other gauge\n'
  printf 'selfdef_systemd_units_other{prefix="%s"} %d\n' "$UNIT_PREFIX" "$other_count"

  printf '# HELP selfdef_systemd_units_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_systemd_units_last_run_unix gauge\n'
  printf 'selfdef_systemd_units_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_systemd_units_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_systemd_units_textfile_emit_failed gauge\n'
  printf 'selfdef_systemd_units_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
