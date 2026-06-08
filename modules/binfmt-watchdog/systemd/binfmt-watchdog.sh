#!/usr/bin/env bash
# selfdef binfmt-watchdog — boot + daily delta of the binfmt_misc
# interpreter registrations vs a learned baseline + ownership +
# interpreter-path scan.
#
# systemd-binfmt applies these at boot:
#   /etc/binfmt.d/*.conf   (admin)
#   /run/binfmt.d/*.conf   (runtime)
# Each line registers an INTERPRETER the kernel invokes whenever a
# file matching a magic-byte signature (type M) or filename
# extension (type E) is executed. Line format (first char is the
# field delimiter, usually ':'):
#   :name:type:offset:magic:mask:INTERPRETER:flags
# A planted registration whose INTERPRETER is an attacker payload is
# execution-flow hijack + persistence — every run of a matching file
# type runs the payload (T1546 event-triggered / T1574 hijack
# execution flow). The 'C' flag runs the interpreter with the
# target's (possibly setuid) credentials.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each .conf
#   own:<path>:<owner:mode>  — owner + mode
#   intr:<path>:<interpreter>— each registered interpreter path
#
# Severity:
#   ok    → no delta
#   warn  → a registration added / changed / removed
#   alert → a .conf world-writable/non-root, OR an interpreter under
#           /tmp /var/tmp /dev/shm /home, OR a non-absolute interpreter

set -u

PROFILE="${SELFDEF_BINFMT_PROFILE:-report}"
BASELINE="${SELFDEF_BINFMT_BASELINE:-/var/lib/selfdef/binfmt-baseline.tsv}"
if [[ -n "${SELFDEF_BINFMT_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_BINFMT_DIRS}"
else
    DIRS=(/etc/binfmt.d /run/binfmt.d)
fi

# SDD-061 D-6: consume the shared writable-location policy
# (selfdef_is_writable_path) instead of a per-module copy. The library is
# co-shipped by the selfdef package at /usr/share/selfdef/lib/module-lib.sh;
# in a workspace selfdefctl exports SELFDEF_MODULE_LIB. A missing or pre-v3
# library is a real misconfiguration that would otherwise leave the watchdog
# scanning with a divergent policy, so we fail loud with a structured
# finding rather than silently degrade.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-binfmt -- '{"tag":"selfdef-binfmt","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-binfmt -- '{"tag":"selfdef-binfmt","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-binfmt -- '{"tag":"selfdef-binfmt","severity":"ok","event":"no_binfmt","profile":"'"$PROFILE"'"}'
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
    # Parse each registration line; first char of the line is the
    # field delimiter, interpreter is the 7th field (leading delim
    # makes field 1 empty).
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        delim="${line:0:1}"
        [[ -n "$delim" ]] || continue
        IFS="$delim" read -r -a parts <<< "$line"
        interp="${parts[6]:-}"
        [[ -z "$interp" ]] && continue
        printf 'intr\t%s\t%s\n' "$f" "$interp" >> "$current"
        if selfdef_is_writable_path "$interp"; then
            suspicious+=("${base}:interp-in-writable($interp)")
        elif [[ "$interp" != /* ]]; then
            suspicious+=("${base}:interp-not-absolute($interp)")
        fi
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
    logger -t selfdef-binfmt -- "$(printf '{"tag":"selfdef-binfmt","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="binfmt_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="binfmt_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="binfmt_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-binfmt","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-binfmt -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-binfmt-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-binfmt-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
