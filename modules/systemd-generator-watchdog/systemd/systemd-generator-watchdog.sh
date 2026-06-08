#!/usr/bin/env bash
# selfdef systemd-generator-watchdog — boot + daily delta of the
# admin/local/runtime systemd generator dirs vs a learned baseline.
#
# systemd "generators" are small executables that systemd runs AS
# ROOT very EARLY in boot (before any unit is started) to
# synthesize units on the fly. A binary or script dropped into a
# generator dir therefore runs as root at the earliest point of
# boot — a stealthy persistence + privilege vector that runs
# before most monitoring is up and is easy to overlook next to
# units/timers:
#
#   cp /tmp/g /etc/systemd/system-generators/00-evil; chmod +x ...
#   → executed as root on the next boot, before multi-user.target
#
# Watched (admin / local / runtime — attacker-writable):
#   /etc/systemd/{system,user}-generators
#   /usr/local/lib/systemd/{system,user}-generators
#   /run/systemd/{system,user}-generators
# NOT /usr/lib/systemd/system-generators (package-managed;
# integrity-sentinel covers package content) — mirrors the
# udev-rules / modprobe decisions.
#
# These dirs are normally EMPTY, so any new generator is
# high-signal.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<gen>:<sha12>      — hash of each generator
#   own:<gen>:<owner:mode>  — owner + mode
#   susp:<gen>:<pattern>    — suspicious exec pattern (if a script)
#
# Severity:
#   ok    → no delta
#   warn  → a generator changed or removed
#   alert → a NEW generator, OR one world-writable / non-root, OR
#           one containing a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_SDGEN_PROFILE:-report}"
BASELINE="${SELFDEF_SDGEN_BASELINE:-/var/lib/selfdef/systemd-generator-baseline.tsv}"
if [[ -n "${SELFDEF_SDGEN_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_SDGEN_DIRS}"
else
    DIRS=(
        /etc/systemd/system-generators /etc/systemd/user-generators
        /usr/local/lib/systemd/system-generators /usr/local/lib/systemd/user-generators
        /run/systemd/system-generators /run/systemd/user-generators
    )
fi

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-systemd-generator -- '{"tag":"selfdef-systemd-generator","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-systemd-generator -- '{"tag":"selfdef-systemd-generator","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)
# Module-specific patterns beyond the shared set (preserved verbatim):
PATTERNS+=(
    '(^|[;&|][[:space:]]*)/(tmp|var/tmp|dev/shm)/'
)

have=0
for d in "${DIRS[@]}"; do [[ -d "$d" ]] && { have=1; break; }; done
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-systemd-generator -- '{"tag":"selfdef-systemd-generator","severity":"ok","event":"no_generator_dirs","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for d in "${DIRS[@]}"; do
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
        # Pattern-scan text generators (binaries won't match; the
        # presence/ownership/new checks cover those).
        if grep -Iq . "$f" 2>/dev/null; then
            scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
            for pat in "${PATTERNS[@]}"; do
                if printf '%s\n' "$scan" | grep -qE "$pat"; then
                    printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
                    suspicious+=("$(basename "$f"):$pat")
                fi
            done
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
    logger -t selfdef-systemd-generator -- "$(printf '{"tag":"selfdef-systemd-generator","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
# A NEW generator (root-at-early-boot exec appearing) is high-signal
# on its own — these dirs are normally empty. "New" = a file PATH
# absent from the baseline; a content change (same path, new hash)
# is remove-old + add-new in comm, so compare PATH sets, not records,
# or a benign edit would mis-classify as new.
base_paths=$(grep '^file' "$BASELINE" 2>/dev/null | cut -f2 | sort -u)
cur_paths=$(grep '^file' "$current"  2>/dev/null | cut -f2 | sort -u)
new_paths=$(comm -23 <(printf '%s\n' "$cur_paths") <(printf '%s\n' "$base_paths") | grep -c . || true)

severity="ok"; event="systemd_generator_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="systemd_generator_suspicious"
elif (( new_paths > 0 )); then
    severity="alert"; event="systemd_generator_new"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="systemd_generator_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-systemd-generator","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-systemd-generator -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-systemd-generator-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-systemd-generator-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
