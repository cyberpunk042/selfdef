#!/usr/bin/env bash
# selfdef cron-job-watchdog — daily delta of every scheduled-
# task surface vs a learned baseline.
#
# Surfaces enumerated (each line: source<TAB>identity<TAB>sha256):
#   - /var/spool/cron/crontabs/*  (Debian) + /var/spool/cron/* (RHEL)
#   - /etc/crontab
#   - /etc/cron.d/*
#   - /etc/cron.{hourly,daily,weekly,monthly}/*
#   - systemd timers (systemctl list-timers + unit file hashes)
#
# First run baselines; subsequent runs diff. A NEW scheduled
# job (or a CHANGED one — hash differs) is the canonical
# T1053 persistence indicator.
#
# Severity:
#   ok    → no delta
#   warn  → 1..2 added/changed
#   alert → 3+ added/changed

set -u

PROFILE="${SELFDEF_CRONJOBS_PROFILE:-report}"
BASELINE="${SELFDEF_CRONJOBS_BASELINE:-/var/lib/selfdef/cron-jobs-baseline.tsv}"
# SELFDEF_CRONJOBS_SPOOL_DIRS + SELFDEF_CRONJOBS_ETC_CRONTAB +
# SELFDEF_CRONJOBS_CRON_DIRS added 2026-06-06 for L2 delta-
# testability. Live defaults unchanged. systemctl calls are
# mocked via PATH override in tests.
_default_spool_dirs="/var/spool/cron/crontabs /var/spool/cron"
SPOOL_DIRS="${SELFDEF_CRONJOBS_SPOOL_DIRS:-${_default_spool_dirs}}"
ETC_CRONTAB="${SELFDEF_CRONJOBS_ETC_CRONTAB:-/etc/crontab}"
_default_cron_dirs="/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"
CRON_DIRS="${SELFDEF_CRONJOBS_CRON_DIRS:-${_default_cron_dirs}}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

emit_file() {
    # source, path -> "source<TAB>path<TAB>sha256"
    local source="$1" path="$2"
    [[ -f "$path" && -r "$path" ]] || return 0
    local h
    h=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
    printf '%s\t%s\t%s\n' "$source" "$path" "$h" >> "$current"
}

# User crontabs (Debian + RHEL locations).
for spool in ${SPOOL_DIRS}; do
    [[ -d "$spool" ]] || continue
    for f in "$spool"/*; do
        [[ -e "$f" ]] || continue
        emit_file "user-crontab" "$f"
    done
done

# System crontab + cron.d + periodic dirs.
emit_file "etc-crontab" "${ETC_CRONTAB}"
for d in ${CRON_DIRS}; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do
        [[ -f "$f" ]] || continue
        emit_file "cron-dir" "$f"
    done
done

# systemd timers: enumerate enabled timers + hash their unit
# files so a changed OnCalendar / ExecStart is caught.
if command -v systemctl >/dev/null 2>&1; then
    while read -r unit; do
        [[ -z "$unit" ]] && continue
        # locate the unit file path
        upath=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null || echo "")
        if [[ -n "$upath" && -f "$upath" ]]; then
            emit_file "systemd-timer" "$upath"
        else
            # timer with no fragment (transient) — record name only
            printf '%s\t%s\t%s\n' "systemd-timer" "$unit" "transient" >> "$current"
        fi
    done < <(systemctl list-unit-files --type=timer --state=enabled --no-legend 2>/dev/null | awk '{print $1}')
fi

sort -u "$current" -o "$current" 2>/dev/null || true
{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"

cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    json=$(printf '{"tag":"selfdef-cron-jobs","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")
    logger -t selfdef-cron-jobs -- "$json"
    exit 0
fi

# Added/changed = lines in current not in baseline (the sha256
# in the identity tuple makes a content change look like an
# add+remove pair on the same path).
added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))

n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="no_delta"
if (( n_added > 0 )); then
    if (( n_added >= 3 )); then
        severity="alert"; event="mass_new_jobs"
    else
        severity="warn"; event="new_job"
    fi
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-cron-jobs","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$added_sample" "$removed_sample")
logger -t selfdef-cron-jobs -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r s p h; do [[ -n "$s" ]] && logger -t selfdef-cron-jobs-detail -- "ADDED ${s} ${p}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r s p h; do [[ -n "$s" ]] && logger -t selfdef-cron-jobs-detail -- "REMOVED ${s} ${p}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
