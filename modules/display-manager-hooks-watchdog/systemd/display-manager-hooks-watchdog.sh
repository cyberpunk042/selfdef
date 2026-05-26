#!/usr/bin/env bash
# selfdef display-manager-hooks-watchdog — boot + daily delta of the
# display-manager ROOT-context login-hook scripts vs a learned
# baseline + ownership + suspicious-pattern scan.
#
# The display manager runs these AS ROOT around every graphical
# login:
#   gdm  — /etc/gdm3/{Init,PreSession,PostSession,PostLogin}/* and the
#          /etc/gdm/* equivalents (RHEL). Init runs before the
#          greeter; PreSession before the user session; PostLogin
#          after auth; PostSession at logout. All as root.
#   sddm — /usr/share/sddm/scripts/Xsetup (before greeter) and Xstop
#          (after session), /etc/sddm/scripts/*. Run as root.
# A dropped/tampered script is root-context GUI-login exec
# persistence (T1037/T1546). Distinct from xsession-watchdog (the
# USER-context X session pipeline) and xdg-autostart-watchdog
# (post-startup user .desktop autostart) — this is the privileged
# DM-side surface.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each script
#   own:<path>:<owner:mode> — owner + mode
#   susp:<path>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a script added / changed / removed
#   alert → a script world-writable or non-root-owned, OR containing
#           a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_DMHOOK_PROFILE:-report}"
BASELINE="${SELFDEF_DMHOOK_BASELINE:-/var/lib/selfdef/display-manager-hooks-baseline.tsv}"
if [[ -n "${SELFDEF_DMHOOK_DIRS:-}" ]]; then
    read -r -a RAW_DIRS <<< "${SELFDEF_DMHOOK_DIRS}"
else
    RAW_DIRS=(
        /etc/gdm3/Init /etc/gdm3/PreSession /etc/gdm3/PostSession /etc/gdm3/PostLogin
        /etc/gdm/Init  /etc/gdm/PreSession  /etc/gdm/PostSession  /etc/gdm/PostLogin
        /etc/sddm/scripts
    )
fi
if [[ -n "${SELFDEF_DMHOOK_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_DMHOOK_FILES}"
else
    EXTRA_FILES=(
        /usr/share/sddm/scripts/Xsetup /usr/share/sddm/scripts/Xstop
    )
fi

# De-duplicate dirs by resolved real path (gdm3 -> gdm symlinks exist).
declare -A seen=()
DIRS=()
for d in "${RAW_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    rp=$(readlink -f "$d" 2>/dev/null || echo "$d")
    [[ -n "${seen[$rp]:-}" ]] && continue
    seen[$rp]=1
    DIRS+=("$rp")
done

# SDD-061 D-6: consume the shared scan helpers (the single source of
# truth for the injection-pattern set + the writable-location policy)
# instead of a per-module copy. Co-shipped by the .deb at
# /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a
# real misconfiguration that would leave the watchdog scanning with a
# divergent/absent set, so we fail loud with a structured finding
# rather than silently degrade.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-dm-hooks -- '{"tag":"selfdef-dm-hooks","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-dm-hooks -- '{"tag":"selfdef-dm-hooks","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

files=()
for d in "${DIRS[@]}"; do
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-dm-hooks -- '{"tag":"selfdef-dm-hooks","severity":"ok","event":"no_dm_hooks","profile":"'"$PROFILE"'"}'
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
    rel="${f#/etc/}"; rel="${rel#/usr/share/}"
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
    logger -t selfdef-dm-hooks -- "$(printf '{"tag":"selfdef-dm-hooks","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="dm_hooks_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="dm_hooks_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="dm_hooks_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-dm-hooks","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-dm-hooks -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dm-hooks-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dm-hooks-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
