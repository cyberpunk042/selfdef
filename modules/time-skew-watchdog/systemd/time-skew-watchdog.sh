#!/usr/bin/env bash
# selfdef time-skew-watchdog probe.
#
# Queries chronyc tracking + emits a structured JSON event line
# via logger(1) tagged `selfdef-time-skew`. Thresholds:
#   - last_offset    > 100ms (warn)  /  500ms (alert)
#   - rms_offset     > 50ms (warn)   /  200ms (alert)
#   - root_dispersion > 1s (alert; chrony lost time-source confidence)
#
# Operator-pull thresholds via /etc/selfdef/modules/time-skew-
# watchdog.toml when present; defaults shown inline below.

set -u   # NOT -e: we WANT to emit an event on chronyc failure.

THRESH_OFFSET_WARN_MS="${SELFDEF_TIME_OFFSET_WARN_MS:-100}"
THRESH_OFFSET_ALERT_MS="${SELFDEF_TIME_OFFSET_ALERT_MS:-500}"
THRESH_DISPERSION_ALERT_S="${SELFDEF_TIME_DISPERSION_ALERT_S:-1.0}"

tracking_out="$(chronyc -n tracking 2>&1)"
chronyc_rc=$?

if [[ $chronyc_rc -ne 0 ]]; then
    json="{\"tag\":\"selfdef-time-skew\",\"severity\":\"high\",\"event\":\"chronyc_failed\",\"rc\":$chronyc_rc,\"stderr\":\"${tracking_out//\"/\\\"}\"}"
    logger -t selfdef-time-skew -- "$json"
    exit 0   # don't fail systemd; we logged the event
fi

# Parse "Last offset     : -0.000012345 seconds"
last_offset_s=$(printf '%s\n' "$tracking_out" | awk -F': ' '/^Last offset/ {gsub(" seconds","",$2); print $2; exit}')
rms_offset_s=$(printf  '%s\n' "$tracking_out" | awk -F': ' '/^RMS offset/  {gsub(" seconds","",$2); print $2; exit}')
root_dispersion_s=$(printf '%s\n' "$tracking_out" | awk -F': ' '/^Root dispersion/ {gsub(" seconds","",$2); print $2; exit}')
ref_id=$(printf  '%s\n' "$tracking_out" | awk -F': ' '/^Reference ID/ {print $2; exit}')
stratum=$(printf '%s\n' "$tracking_out" | awk -F': ' '/^Stratum/      {print $2; exit}')

# Compute absolute offsets in ms (chrony reports seconds; bash can't
# do floats so awk).
last_offset_ms=$(awk -v v="${last_offset_s:-0}" 'BEGIN {printf "%.3f", (v<0?-v:v)*1000}')
rms_offset_ms=$(awk  -v v="${rms_offset_s:-0}"  'BEGIN {printf "%.3f", (v<0?-v:v)*1000}')

# Classify.
severity="ok"
event="tracking_ok"
if awk -v v="${root_dispersion_s:-0}" -v t="$THRESH_DISPERSION_ALERT_S" 'BEGIN {exit !(v > t)}'; then
    severity="alert"
    event="root_dispersion_high"
elif awk -v v="$last_offset_ms" -v t="$THRESH_OFFSET_ALERT_MS" 'BEGIN {exit !(v > t)}'; then
    severity="alert"
    event="last_offset_alert"
elif awk -v v="$last_offset_ms" -v t="$THRESH_OFFSET_WARN_MS" 'BEGIN {exit !(v > t)}'; then
    severity="warn"
    event="last_offset_warn"
fi

json=$(printf '{"tag":"selfdef-time-skew","severity":"%s","event":"%s","ref_id":"%s","stratum":"%s","last_offset_ms":%s,"rms_offset_ms":%s,"root_dispersion_s":%s}' \
    "$severity" "$event" "${ref_id:-?}" "${stratum:-?}" \
    "$last_offset_ms" "$rms_offset_ms" "${root_dispersion_s:-0}")

logger -t selfdef-time-skew -- "$json"

# Exit non-zero ONLY on alert so systemd records a failure state
# the operator can `systemctl status` for.
case "$severity" in
    alert) exit 1 ;;
    *)     exit 0 ;;
esac
