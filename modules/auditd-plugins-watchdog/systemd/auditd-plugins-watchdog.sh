#!/usr/bin/env bash
# selfdef auditd-plugins-watchdog — boot + daily delta of the auditd
# dispatcher-plugin configs vs a learned baseline + ownership +
# plugin-path scan.
#
# auditd launches each active plugin's `path =` program AS ROOT and
# feeds it the live audit event stream:
#   /etc/audit/plugins.d/*.conf      (current)
#   /etc/audisp/plugins.d/*.conf     (legacy audisp)
# A planted plugin (active = yes, path = /tmp/evil) is root-exec
# persistence driven by audit activity (T1546), and it sits inside
# the audit pipeline where it can suppress/tamper with the very
# events that would reveal it (T1562.001 impair defenses). Distinct
# from audit-config-watchdog (auditd.conf + audit.rules content).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each .conf
#   own:<path>:<owner:mode>  — owner + mode
#   path:<path>:<prog>       — the plugin `path =` program
#   active:<path>:<value>    — the plugin `active =` flag
#
# Severity:
#   ok    → no delta
#   warn  → a plugin / key added / changed / removed
#   alert → a .conf world-writable/non-root, OR a plugin path under
#           /tmp /var/tmp /dev/shm /home or relative-with-slash

set -u

PROFILE="${SELFDEF_AUDITPLUG_PROFILE:-report}"
BASELINE="${SELFDEF_AUDITPLUG_BASELINE:-/var/lib/selfdef/auditd-plugins-baseline.tsv}"

# SDD-061 D-6: consume the shared writable-location policy
# (selfdef_is_writable_path) from module-lib instead of a per-module copy.
# Co-shipped by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl
# exports SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a
# real misconfiguration that would leave the watchdog scanning with a
# divergent policy, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-audit-plugins -- '{"tag":"selfdef-audit-plugins","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-audit-plugins -- '{"tag":"selfdef-audit-plugins","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
if [[ -n "${SELFDEF_AUDITPLUG_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_AUDITPLUG_DIRS}"
else
    DIRS=(/etc/audit/plugins.d /etc/audisp/plugins.d)
fi

flag_path() {
    local p="$1"
    if selfdef_is_writable_path "$p"; then echo "writable"
    elif [[ "$p" == */* && "$p" != /* ]]; then echo "relative"; fi
}

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-audit-plugins -- '{"tag":"selfdef-audit-plugins","severity":"ok","event":"no_audit_plugins","profile":"'"$PROFILE"'"}'
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
        [[ "$line" =~ ^[[:space:]]*[#\;] ]] && continue
        key="${line%%=*}"; key="$(printf '%s' "$key" | tr -d '[:space:]' | tr 'A-Z' 'a-z')"
        val="${line#*=}"
        val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
        [[ -z "$val" ]] && continue
        case "$key" in
            path)
                printf 'path\t%s\t%s\n' "$f" "$val" >> "$current"
                r=$(flag_path "$val"); [[ -n "$r" ]] && suspicious+=("${base}:plugin-path-${r}($val)")
                ;;
            active)
                printf 'active\t%s\t%s\n' "$f" "$val" >> "$current"
                ;;
        esac
    done < <(grep -iE '^[[:space:]]*(path|active)[[:space:]]*=' "$f" 2>/dev/null || true)
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
    logger -t selfdef-audit-plugins -- "$(printf '{"tag":"selfdef-audit-plugins","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="audit_plugins_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="audit_plugins_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="audit_plugins_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-audit-plugins","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-audit-plugins -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-audit-plugins-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-audit-plugins-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
