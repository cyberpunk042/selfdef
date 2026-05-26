#!/usr/bin/env bash
# selfdef crontab-allow-watchdog — daily + boot delta of the
# who-may-schedule roster vs a learned baseline.
#
# Records (each line: file<TAB>entry):
#   /etc/cron.allow  /etc/cron.deny  /etc/at.allow  /etc/at.deny
# one user per line. On a deny-by-default host (cron.allow exists,
# only listed users may use cron), an attacker who appends their
# account to cron.allow grants themselves scheduling-persistence
# capability — without yet creating a job (so cron-job-watchdog
# stays quiet until they do). This catches the capability grant.
#
# Severity:
#   ok    → no delta
#   warn  → a roster file changed
#   alert → a user ADDED to cron.allow / at.allow (capability
#           grant) OR a user REMOVED from cron.deny / at.deny
#           (also a grant — removing from deny permits them)

set -u

PROFILE="${SELFDEF_CRONALLOW_PROFILE:-report}"
BASELINE="${SELFDEF_CRONALLOW_BASELINE:-/var/lib/selfdef/crontab-allow-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    [[ -f "$f" && -r "$f" ]] || continue
    grep -vE '^\s*(#|$)' "$f" 2>/dev/null | sed 's/[[:space:]]//g' | while IFS= read -r u; do
        [[ -n "$u" ]] && printf '%s\t%s\n' "$f" "$u"
    done
done | sort -u > "$current"

cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-crontab-allow -- "$(printf '{"tag":"selfdef-crontab-allow","severity":"ok","event":"baseline_initial","profile":"%s","entries":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# A capability GRANT = added to *.allow OR removed from *.deny.
grant_add=$(printf '%s' "$added"     | grep -cE '/(cron|at)\.allow' || true)
grant_rmdeny=$(printf '%s' "$removed" | grep -cE '/(cron|at)\.deny'  || true)
grants=$((grant_add + grant_rmdeny))

severity="ok"; event="no_delta"
if (( grants > 0 )); then
    severity="alert"; event="schedule_capability_granted"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="schedule_roster_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-crontab-allow","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"grants":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$grants" "$added_sample" "$removed_sample")
logger -t selfdef-crontab-allow -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r f u; do [[ -n "$f" ]] && logger -t selfdef-crontab-allow-detail -- "ADDED ${f} ${u}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r f u; do [[ -n "$f" ]] && logger -t selfdef-crontab-allow-detail -- "REMOVED ${f} ${u}"; done

# Refresh baseline so a confirmed-legit change becomes trusted.
cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 || n_removed > 0 )); then
    exit 1
fi
exit 0
