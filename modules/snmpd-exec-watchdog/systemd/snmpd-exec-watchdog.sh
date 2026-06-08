#!/usr/bin/env bash
# selfdef snmpd-exec-watchdog — boot + daily delta of the Net-SNMP
# daemon command directives vs a learned baseline + ownership +
# command scan.
#
# snmpd runs the program named in these directives AS ITS DAEMON
# USER (frequently root) and exposes the output as an SNMP OID:
#   exec [OID] NAME PROG ARGS
#   extend [OID] NAME PROG ARGS      extend-sh ...
#   pass MIBOID PROG                 pass_persist MIBOID PROG
#   sh NAME SHELL-COMMAND
# from /etc/snmp/snmpd.conf + /etc/snmp/snmpd.conf.d/*.conf. The
# command is REMOTELY TRIGGERABLE: anyone who can query the agent
# (default community 'public', or a known community) fires it. A
# planted `extend evil /tmp/x` (or exec/pass to a writable/attacker
# program) is remote-triggered command execution / persistence
# (T1546 / T1059). This is the SNMP-query-triggered exec surface.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>           — hash of each config
#   own:<path>:<owner:mode>       — owner + mode
#   cmd:<path>:<directive>:<rest> — each exec/extend/pass command
#
# Severity:
#   ok    → no delta
#   warn  → a config / directive added / changed / removed
#   alert → a config world-writable/non-root, OR a command program
#           under /tmp /var/tmp /dev/shm /home or with an injection
#           pattern

set -u

PROFILE="${SELFDEF_SNMPD_PROFILE:-report}"
BASELINE="${SELFDEF_SNMPD_BASELINE:-/var/lib/selfdef/snmpd-exec-baseline.tsv}"
if [[ -n "${SELFDEF_SNMPD_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_SNMPD_DIRS}"
else
    DIRS=(/etc/snmp/snmpd.conf.d)
fi
if [[ -n "${SELFDEF_SNMPD_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_SNMPD_FILES}"
else
    EXTRA_FILES=(/etc/snmp/snmpd.conf)
fi

DIRECTIVES='exec|extend|extend-sh|pass|pass_persist|sh'

# SDD-061 D-6: consume the shared scan helpers (the single source of
# truth for the injection-pattern set + the writable-location policy)
# instead of a per-module copy. The library is co-shipped by the selfdef
# package at /usr/share/selfdef/lib/module-lib.sh; in a workspace
# selfdefctl exports SELFDEF_MODULE_LIB. A missing or pre-v3 library is a
# real misconfiguration that would otherwise leave the watchdog scanning
# with a divergent/absent pattern set, so we fail loud with a structured
# finding rather than silently degrade.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-snmpd-exec -- '{"tag":"selfdef-snmpd-exec","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-snmpd-exec -- '{"tag":"selfdef-snmpd-exec","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-snmpd-exec -- '{"tag":"selfdef-snmpd-exec","severity":"ok","event":"no_snmpd","profile":"'"$PROFILE"'"}'
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
    elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
        suspicious+=("${base}:owned-by-$owner")
    fi
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        read -r directive rest <<< "$line"
        [[ -z "$rest" ]] && continue
        printf 'cmd\t%s\t%s:%s\n' "$f" "$directive" "$rest" >> "$current"
        # any absolute path token in the command portion under a
        # writable location is suspicious (the program / a script arg)
        while read -r p; do
            [[ -z "$p" ]] && continue
            if selfdef_is_writable_path "$p"; then
                suspicious+=("${base}:${directive}-writable($p)")
            fi
        done < <(printf '%s\n' "$rest" | grep -oE '/[^[:space:]]+')
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$rest" | grep -qE "$pat"; then
                suspicious+=("${base}:${directive}:$pat")
            fi
        done
    done < <(grep -iE "^[[:space:]]*(${DIRECTIVES})[[:space:]]+" "$f" 2>/dev/null || true)
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
    logger -t selfdef-snmpd-exec -- "$(printf '{"tag":"selfdef-snmpd-exec","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="snmpd_exec_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="snmpd_exec_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="snmpd_exec_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-snmpd-exec","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-snmpd-exec -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-snmpd-exec-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-snmpd-exec-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
