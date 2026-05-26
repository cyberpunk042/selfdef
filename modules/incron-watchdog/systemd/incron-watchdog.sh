#!/usr/bin/env bash
# selfdef incron-watchdog — boot + daily delta of the incron tables
# vs a learned baseline + ownership + command scan.
#
# incron is cron-for-inotify. Each table line:
#   <path> <event_mask> <command>
# runs the command (as the table's owner — root for the system and
# root tables) when the named inotify event fires on the watched
# path. Tables:
#   /etc/incron.d/*        (system)
#   /var/spool/incron/*    (per-user; root's is .../root)
# A planted line watching a commonly-touched file with a malicious
# command is file-event-triggered code execution / persistence
# (T1546) that an attacker can fire on demand by touching the
# watched path. This is the inotify-event exec surface — distinct
# from cron (time), login/network/power/boot, and at-jobs.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>          — hash of each table
#   own:<path>:<owner:mode>      — owner + mode
#   line:<path>:<watch>:<cmd>    — each incron entry's command
#
# Severity:
#   ok    → no delta
#   warn  → a table / line added / changed / removed
#   alert → a table world-writable/non-root, OR a command program
#           under /tmp /var/tmp /dev/shm /home or with an injection
#           pattern

set -u

PROFILE="${SELFDEF_INCRON_PROFILE:-report}"
BASELINE="${SELFDEF_INCRON_BASELINE:-/var/lib/selfdef/incron-baseline.tsv}"
if [[ -n "${SELFDEF_INCRON_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_INCRON_DIRS}"
else
    DIRS=(/etc/incron.d /var/spool/incron)
fi

# SDD-061 D-6: consume the shared scan helpers (the single source of
# truth for the injection-pattern set + the writable-location policy)
# instead of a per-module copy. Co-shipped by the .deb at
# /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a
# real misconfiguration that would leave the watchdog scanning with a
# divergent/absent set, so we fail loud with a structured finding
# rather than silently degrade.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-incron -- '{"tag":"selfdef-incron","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-incron -- '{"tag":"selfdef-incron","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

is_writable() { selfdef_is_writable_path "$1"; }

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-incron -- '{"tag":"selfdef-incron","severity":"ok","event":"no_incron","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    owner=$(stat -L -c '%U' "$f" 2>/dev/null || echo '?')
    mode=$(stat -L -c '%a' "$f" 2>/dev/null || echo '?')
    printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
    base="$(basename "$f")"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("${base}:world-writable($mode)")
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("${base}:owned-by-$owner")
    fi
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        read -r wpath _mask cmd <<< "$line"
        [[ -z "$cmd" ]] && continue
        printf 'line\t%s\t%s:%s\n' "$f" "$wpath" "$cmd" >> "$current"
        prog="${cmd%%[[:space:]]*}"
        if is_writable "$prog"; then
            suspicious+=("${base}:cmd-writable($prog)")
        fi
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$cmd" | grep -qE "$pat"; then
                suspicious+=("${base}:cmd:$pat")
            fi
        done
    done < "$f"
done

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if (( ${#suspicious[@]} > 0 )); then
    mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)
fi

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp_str=$(IFS='|'; echo "${suspicious[*]:-}")
    sev="ok"; [[ ${#suspicious[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-incron -- "$(printf '{"tag":"selfdef-incron","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="incron_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="incron_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="incron_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-incron","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-incron -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-incron-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-incron-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
