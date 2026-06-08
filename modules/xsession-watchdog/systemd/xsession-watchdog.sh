#!/usr/bin/env bash
# selfdef xsession-watchdog — boot + daily delta of the X11
# session-init scripts vs a learned baseline + ownership +
# suspicious-pattern scan.
#
# These run on every graphical login, during session startup, as
# the logging-in user (root for a root login):
#   /etc/X11/Xsession.d/*            (Debian X session pipeline)
#   /etc/X11/xinit/xinitrc.d/*       (xinit/startx)
#   /etc/X11/xinit/{xinitrc,Xclients}
#   /root/.xsession ~/.xprofile ~/.xinitrc ~/.Xsession
# A dropped/tampered script is GUI-login exec persistence
# (T1037/T1546) — distinct from xdg-autostart (.desktop entries
# launched AFTER the session is up).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<script>:<sha12>     — hash of each script
#   own:<script>:<owner:mode> — owner + mode
#   susp:<script>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a script added / changed / removed
#   alert → a script world-writable or non-root-owned, OR
#           containing a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_XSESSION_PROFILE:-report}"
BASELINE="${SELFDEF_XSESSION_BASELINE:-/var/lib/selfdef/xsession-baseline.tsv}"
if [[ -n "${SELFDEF_XSESSION_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_XSESSION_DIRS}"
else
    DIRS=(/etc/X11/Xsession.d /etc/X11/xinit/xinitrc.d)
fi
if [[ -n "${SELFDEF_XSESSION_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_XSESSION_FILES}"
else
    EXTRA_FILES=(
        /etc/X11/xinit/xinitrc /etc/X11/xinit/Xclients /etc/X11/Xsession
        /root/.xsession /root/.Xsession /root/.xprofile /root/.xinitrc
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
    logger -t selfdef-xsession -- '{"tag":"selfdef-xsession","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-xsession -- '{"tag":"selfdef-xsession","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)
# Module-specific patterns beyond the shared set (preserved verbatim):
PATTERNS+=(
    '(^|[;&|][[:space:]]*)/(tmp|var/tmp|dev/shm)/'
)

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-xsession -- '{"tag":"selfdef-xsession","severity":"ok","event":"no_xsession","profile":"'"$PROFILE"'"}'
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
    logger -t selfdef-xsession -- "$(printf '{"tag":"selfdef-xsession","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="xsession_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="xsession_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="xsession_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-xsession","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-xsession -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xsession-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-xsession-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
