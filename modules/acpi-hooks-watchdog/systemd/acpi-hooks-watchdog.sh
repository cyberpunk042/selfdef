#!/usr/bin/env bash
# selfdef acpi-hooks-watchdog — boot + daily delta of the acpid
# event-binding + action-script surface vs a learned baseline +
# ownership + suspicious-pattern scan.
#
# acpid runs the bound action AS ROOT on each ACPI hardware event
# (power button, lid open/close, AC adapter plug/unplug, thermal):
#   /etc/acpi/events/*   — event bindings (event=<regex>; action=<cmd>)
#   /etc/acpi/actions/*  — action scripts the bindings invoke
#   /etc/acpi/*.sh       — top-level handlers (handler.sh, powerbtn.sh,
#                          lid.sh, …)
# A dropped action script — or a new event binding whose action=
# points at attacker code — self-triggers on routine hardware
# activity without operator action. A rogue script/binding is
# root-exec-on-hardware-event persistence (T1546). acpid is a
# SEPARATE daemon from systemd-logind, so this is distinct from
# systemd-power-hooks-watchdog (systemd system-sleep/system-shutdown).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each file
#   own:<path>:<owner:mode> — owner + mode
#   susp:<path>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a file added / changed / removed
#   alert → a file world-writable or non-root-owned, OR containing a
#           suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_ACPI_PROFILE:-report}"
BASELINE="${SELFDEF_ACPI_BASELINE:-/var/lib/selfdef/acpi-hooks-baseline.tsv}"
if [[ -n "${SELFDEF_ACPI_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_ACPI_DIRS}"
else
    DIRS=(/etc/acpi/events /etc/acpi/actions)
fi
if [[ -n "${SELFDEF_ACPI_GLOB:-}" ]]; then
    read -r -a TOP_GLOB <<< "${SELFDEF_ACPI_GLOB}"
else
    TOP_GLOB=(/etc/acpi/*.sh)
fi

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-acpi-hooks -- '{"tag":"selfdef-acpi-hooks","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-acpi-hooks -- '{"tag":"selfdef-acpi-hooks","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)
# Module-specific patterns beyond the shared set (preserved verbatim):
PATTERNS+=(
    'action[[:space:]]*=[[:space:]]*"?/(tmp|var/tmp|dev/shm|home)/'
)

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${TOP_GLOB[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-acpi-hooks -- '{"tag":"selfdef-acpi-hooks","severity":"ok","event":"no_acpi_hooks","profile":"'"$PROFILE"'"}'
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
    rel="${f#/etc/acpi/}"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("${rel}:world-writable($mode)")
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("${rel}:owned-by-$owner")
    fi
    scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$scan" | grep -qE "$pat"; then
            printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
            suspicious+=("${rel}:$pat")
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
    logger -t selfdef-acpi-hooks -- "$(printf '{"tag":"selfdef-acpi-hooks","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="acpi_hooks_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="acpi_hooks_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="acpi_hooks_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-acpi-hooks","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-acpi-hooks -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-acpi-hooks-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-acpi-hooks-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
