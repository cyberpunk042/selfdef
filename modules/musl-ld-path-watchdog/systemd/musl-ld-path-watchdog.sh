#!/usr/bin/env bash
# selfdef musl-ld-path-watchdog — boot + daily delta of the musl
# dynamic-linker library path file(s) vs a learned baseline +
# ownership + path-entry scan.
#
# On musl-libc systems (Alpine — the most common container base):
#   /etc/ld-musl-<arch>.path   (e.g. /etc/ld-musl-x86_64.path)
# is the ENTIRE library search path the musl loader uses (the musl
# analog of glibc's /etc/ld.so.conf). Entries are separated by
# newline or ':'. A prepended writable directory makes the loader
# resolve shared libraries from there first, hijacking libc/library
# loads for EVERY dynamically-linked binary — a near-total code
# execution foothold (T1574.006 dynamic linker hijacking). Distinct
# from ld-so-conf-watchdog (glibc) and ld-preload-watchdog
# (LD_PRELOAD / ld.so.preload).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each path file
#   own:<path>:<owner:mode> — owner + mode
#   dir:<path>:<libdir>     — each library search directory
#
# Severity:
#   ok    → no delta
#   warn  → a path file / entry added / changed / removed
#   alert → a path file world-writable/non-root, OR a library dir
#           under /tmp /var/tmp /dev/shm /home

set -u

PROFILE="${SELFDEF_MUSL_PROFILE:-report}"
BASELINE="${SELFDEF_MUSL_BASELINE:-/var/lib/selfdef/musl-ld-path-baseline.tsv}"
if [[ -n "${SELFDEF_MUSL_FILES:-}" ]]; then
    read -r -a FILES <<< "${SELFDEF_MUSL_FILES}"
else
    FILES=(/etc/ld-musl-*.path)
fi

files=()
for f in "${FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-musl-ld-path -- '{"tag":"selfdef-musl-ld-path","severity":"ok","event":"no_musl_path","profile":"'"$PROFILE"'"}'
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
    # Entries are newline- or colon-separated library dirs.
    while IFS= read -r dir; do
        [[ -z "$dir" || "$dir" =~ ^[[:space:]]*# ]] && continue
        dir="${dir#"${dir%%[![:space:]]*}"}"; dir="${dir%"${dir##*[![:space:]]}"}"
        [[ -z "$dir" ]] && continue
        printf 'dir\t%s\t%s\n' "$f" "$dir" >> "$current"
        if [[ "$dir" =~ ^/(tmp|var/tmp|dev/shm|home)/ || "$dir" =~ ^/(tmp|var/tmp|dev/shm|home)$ ]]; then
            suspicious+=("${base}:libdir-writable($dir)")
        fi
    done < <(tr ':' '\n' < "$f" 2>/dev/null)
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
    logger -t selfdef-musl-ld-path -- "$(printf '{"tag":"selfdef-musl-ld-path","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="musl_path_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="musl_path_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="musl_path_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-musl-ld-path","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-musl-ld-path -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-musl-ld-path-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-musl-ld-path-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
