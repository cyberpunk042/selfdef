#!/usr/bin/env bash
# selfdef systemd-unit-watchdog — daily + boot delta of the
# enabled systemd service/socket unit set vs a learned
# baseline.
#
# Records (each line: unit<TAB>state<TAB>fragmenthash):
#   every enabled .service + .socket unit, with the sha256 of
#   its FragmentPath so a CHANGED ExecStart / new unit shows.
#
# A new enabled service that runs ExecStart=/tmp/.x, or a
# changed ExecStart on an existing unit, is T1543.002
# systemd-service persistence. (Timers are covered by
# cron-job-watchdog; this covers services + sockets.)
#
# Severity:
#   ok    → no delta
#   warn  → unit removed/disabled
#   alert → unit added/enabled OR ExecStart hash changed

set -u

PROFILE="${SELFDEF_SYSDUNIT_PROFILE:-report}"
BASELINE="${SELFDEF_SYSDUNIT_BASELINE:-/var/lib/selfdef/systemd-units-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

if command -v systemctl >/dev/null 2>&1; then
    # Enabled service + socket unit files.
    systemctl list-unit-files --type=service,socket --state=enabled --no-legend 2>/dev/null \
      | awk '{print $1}' | while IFS= read -r unit; do
            [[ -z "$unit" ]] && continue
            frag=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null || echo "")
            if [[ -n "$frag" && -f "$frag" ]]; then
                h=$(sha256sum "$frag" 2>/dev/null | awk '{print $1}')
                printf '%s\tenabled\t%s\n' "$unit" "${h:0:32}"
            else
                printf '%s\tenabled\ttransient\n' "$unit"
            fi
        done
fi

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-systemd-units -- "$(printf '{"tag":"selfdef-systemd-units","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="no_delta"
if (( n_added > 0 )); then
    severity="alert"; event="unit_added_or_changed"
elif (( n_removed > 0 )); then
    severity="warn"; event="unit_removed_or_disabled"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1}' | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-systemd-units","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$added_sample" "$removed_sample")
logger -t selfdef-systemd-units -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r u s h; do [[ -n "$u" ]] && logger -t selfdef-systemd-units-detail -- "ADDED ${u} ${s} ${h}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r u s h; do [[ -n "$u" ]] && logger -t selfdef-systemd-units-detail -- "REMOVED ${u} ${s} ${h}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
