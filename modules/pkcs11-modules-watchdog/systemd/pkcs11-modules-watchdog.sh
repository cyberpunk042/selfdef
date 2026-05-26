#!/usr/bin/env bash
# selfdef pkcs11-modules-watchdog — boot + daily delta of the p11-kit
# PKCS#11 module configs vs a learned baseline + ownership +
# module-path scan.
#
# Every p11-kit consumer (GnuPG/gpgsm, ssh-agent/ssh with PKCS#11,
# NSS-using browsers, libp11) loads the shared object named in each
#   /etc/pkcs11/modules/*.module
# file's `module:` line. A planted .module with
#   module: /tmp/evil.so
# loads attacker code into a broad set of security-sensitive, often
# credential-handling processes whenever they enumerate PKCS#11
# modules (T1574 hijack execution flow). Distinct from
# ld-preload-watchdog (LD_PRELOAD/ld.so.preload) and
# ld-so-conf-watchdog (linker search path).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each .module
#   own:<path>:<owner:mode> — owner + mode
#   mod:<path>:<so>         — the module: shared-object path
#
# Severity:
#   ok    → no delta
#   warn  → a .module / module: added / changed / removed
#   alert → a .module world-writable/non-root, OR a module: path under
#           /tmp /var/tmp /dev/shm /home or a relative (non-absolute)
#           module: path

set -u

PROFILE="${SELFDEF_PKCS11_PROFILE:-report}"
BASELINE="${SELFDEF_PKCS11_BASELINE:-/var/lib/selfdef/pkcs11-modules-baseline.tsv}"
if [[ -n "${SELFDEF_PKCS11_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_PKCS11_DIRS}"
else
    DIRS=(/etc/pkcs11/modules)
fi

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.module "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
# de-dup (the two globs overlap on *.module)
if (( ${#files[@]} > 0 )); then
    mapfile -t files < <(printf '%s\n' "${files[@]}" | sort -u)
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-pkcs11-modules -- '{"tag":"selfdef-pkcs11-modules","severity":"ok","event":"no_pkcs11_modules","profile":"'"$PROFILE"'"}'
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
    # module: <path-or-basename>  (the .so loaded by every consumer)
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        so="${line#*:}"
        so="${so#"${so%%[![:space:]]*}"}"; so="${so%"${so##*[![:space:]]}"}"
        [[ -z "$so" ]] && continue
        printf 'mod\t%s\t%s\n' "$f" "$so" >> "$current"
        if [[ "$so" =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; then
            suspicious+=("${base}:module-writable($so)")
        elif [[ "$so" == */* && "$so" != /* ]]; then
            suspicious+=("${base}:module-relative-path($so)")
        fi
    done < <(grep -iE '^[[:space:]]*module[[:space:]]*:' "$f" 2>/dev/null || true)
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
    logger -t selfdef-pkcs11-modules -- "$(printf '{"tag":"selfdef-pkcs11-modules","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="pkcs11_modules_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="pkcs11_modules_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="pkcs11_modules_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-pkcs11-modules","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-pkcs11-modules -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-pkcs11-modules-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-pkcs11-modules-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
