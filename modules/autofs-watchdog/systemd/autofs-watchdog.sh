#!/usr/bin/env bash
# selfdef autofs-watchdog — boot + daily delta of the autofs master
# maps vs a learned baseline + ownership + program-map scan.
#
# autofs runs a `program:` map (or any executable map file) AS ROOT
# to generate mount entries when the corresponding autofs mountpoint
# is accessed. Master maps:
#   /etc/auto.master
#   /etc/auto.master.d/*.autofs
# Each line: <mountpoint> <map> [options]. The <map> may be:
#   program:/path/to/script   — autofs execs the script (program map)
#   /path/to/mapfile          — a map file; if it is EXECUTABLE,
#                               autofs treats it as a program map too
#   yp:/ldap:/file:/...       — network/file maps (no local exec)
# A planted program: map (or a writable executable map file) is
# mount-access-triggered root code execution (T1546), fired on
# demand by anyone who can stat/cd the mountpoint. This is the
# mount-access exec trigger class.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>              — hash of each master map
#   own:<path>:<owner:mode>          — owner + mode
#   map:<path>:<mountpoint>:<map>    — each master-map entry
#
# Severity:
#   ok    → no delta
#   warn  → a master map / entry added / changed / removed
#   alert → a master map world-writable/non-root, a program:/map path
#           under /tmp /var/tmp /dev/shm /home, or an executable map
#           file that is itself world-writable/non-root

set -u

PROFILE="${SELFDEF_AUTOFS_PROFILE:-report}"
BASELINE="${SELFDEF_AUTOFS_BASELINE:-/var/lib/selfdef/autofs-baseline.tsv}"
if [[ -n "${SELFDEF_AUTOFS_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_AUTOFS_DIRS}"
else
    DIRS=(/etc/auto.master.d)
fi
if [[ -n "${SELFDEF_AUTOFS_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_AUTOFS_FILES}"
else
    EXTRA_FILES=(/etc/auto.master)
fi

is_writable_path() { [[ "$1" =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; }

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.autofs "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done
if (( ${#files[@]} > 0 )); then
    mapfile -t files < <(printf '%s\n' "${files[@]}" | sort -u)
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-autofs -- '{"tag":"selfdef-autofs","severity":"ok","event":"no_autofs","profile":"'"$PROFILE"'"}'
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
        read -r mountpoint map _rest <<< "$line"
        [[ -z "$map" ]] && continue
        printf 'map\t%s\t%s:%s\n' "$f" "$mountpoint" "$map" >> "$current"
        if [[ "$map" == program:* ]]; then
            prog="${map#program:}"
            if is_writable_path "$prog"; then
                suspicious+=("${base}:program-map-writable($prog)")
            elif [[ "$prog" == */* && "$prog" != /* ]]; then
                suspicious+=("${base}:program-map-relative($prog)")
            fi
        elif [[ "$map" == /* ]]; then
            if is_writable_path "$map"; then
                suspicious+=("${base}:map-writable-path($map)")
            fi
            # an executable map file is itself run as root (program map)
            if [[ -x "$map" ]]; then
                mmode=$(stat -L -c '%a' "$map" 2>/dev/null || echo '?')
                mowner=$(stat -L -c '%U' "$map" 2>/dev/null || echo '?')
                if [[ "$mmode" =~ [2367]$ ]]; then
                    suspicious+=("${base}:exec-map-world-writable($map:$mmode)")
                elif [[ "$mowner" != "root" && "$mowner" != "?" ]]; then
                    suspicious+=("${base}:exec-map-non-root($map:$mowner)")
                fi
            fi
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
    logger -t selfdef-autofs -- "$(printf '{"tag":"selfdef-autofs","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="autofs_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="autofs_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="autofs_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-autofs","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-autofs -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-autofs-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-autofs-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
