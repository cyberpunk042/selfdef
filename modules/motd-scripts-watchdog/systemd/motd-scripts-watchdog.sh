#!/usr/bin/env bash
# selfdef motd-scripts-watchdog — boot + daily delta of the
# dynamic MOTD script dir vs a learned baseline.
#
# pam_motd runs the scripts in /etc/update-motd.d/ AS ROOT on
# every interactive login (SSH + console) to build the dynamic
# message-of-the-day. A script added or tampered here is reliable
# root-exec persistence that fires on each login and is easy to
# overlook (it looks like cosmetic banner config):
#
#   cp /tmp/p /etc/update-motd.d/99-evil; chmod +x ...
#   → runs as root on the next login
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<script>:<sha12>    — hash of each motd script
#   own:<script>:<owner:mode>— owner + mode (non-root / world-
#                              writable = hijackable)
#   susp:<script>:<pattern>  — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a script added / changed / removed
#   alert → a script world-writable or non-root-owned, OR
#           containing a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_MOTD_PROFILE:-report}"
BASELINE="${SELFDEF_MOTD_BASELINE:-/var/lib/selfdef/motd-scripts-baseline.tsv}"
DIRS="${SELFDEF_MOTD_DIRS:-/etc/update-motd.d}"

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-motd-scripts -- '{"tag":"selfdef-motd-scripts","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-motd-scripts -- '{"tag":"selfdef-motd-scripts","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

have=0
for d in $DIRS; do [[ -d "$d" ]] && { have=1; break; }; done
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-motd-scripts -- '{"tag":"selfdef-motd-scripts","severity":"ok","event":"no_motd_dir","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for d in $DIRS; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do
        [[ -f "$f" ]] || continue
        h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
        printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
        owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
        mode=$(stat -c '%a' "$f" 2>/dev/null || echo '?')
        printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
        if [[ "$mode" =~ [2367]$ ]]; then
            suspicious+=("$(basename "$f"):world-writable($mode)")
        elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
            suspicious+=("$(basename "$f"):owned-by-$owner")
        fi
        scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$scan" | grep -qE "$pat"; then
                printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
                suspicious+=("$(basename "$f"):$pat")
            fi
        done
    done
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
    logger -t selfdef-motd-scripts -- "$(printf '{"tag":"selfdef-motd-scripts","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="motd_scripts_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="motd_scripts_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="motd_scripts_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-motd-scripts","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-motd-scripts -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-motd-scripts-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-motd-scripts-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
