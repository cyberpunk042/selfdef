#!/usr/bin/env bash
# selfdef resolvconf-hooks-watchdog — boot + daily delta of the
# resolvconf/openresolv update-hook dirs vs a learned baseline +
# ownership + suspicious-pattern scan.
#
# resolvconf runs every script in these dirs AS ROOT each time
# /etc/resolv.conf is regenerated:
#   /etc/resolvconf/update.d/*        (run on every resolvconf update)
#   /etc/resolvconf/update-libc.d/*   (run after libc resolver update)
# Regeneration happens on every DNS/network change — interface
# up/down, DHCP lease, VPN connect — so a dropped script
# self-triggers on routine network activity without operator action.
# A rogue script is root-exec-on-network-event persistence (T1546).
# Distinct from dns-resolver-watchdog (which watches resolv.conf
# CONTENT/nameservers, not the update scripts that regenerate it).
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

PROFILE="${SELFDEF_RESOLVCONF_PROFILE:-report}"
BASELINE="${SELFDEF_RESOLVCONF_BASELINE:-/var/lib/selfdef/resolvconf-hooks-baseline.tsv}"
if [[ -n "${SELFDEF_RESOLVCONF_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_RESOLVCONF_DIRS}"
else
    DIRS=(
        /etc/resolvconf/update.d
        /etc/resolvconf/update-libc.d
    )
fi

PATTERNS=(
    'curl[^|;&]*\|[[:space:]]*(ba)?sh' 'wget[^|;&]*\|[[:space:]]*(ba)?sh'
    '/dev/tcp/' '/dev/udp/' 'nc[[:space:]]+.*-e' 'ncat[[:space:]]+.*-e'
    'bash[[:space:]]+-i' 'base64[[:space:]]+-d' 'base64[[:space:]]+--decode'
    'eval[[:space:]]*[`$]' 'python[0-9]*[[:space:]]+-c' 'perl[[:space:]]+-e'
    'mkfifo' 'setsid'
    '(^|[;&|][[:space:]]*)/(tmp|var/tmp|dev/shm|home)/'
)

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-resolvconf-hooks -- '{"tag":"selfdef-resolvconf-hooks","severity":"ok","event":"no_resolvconf_hooks","profile":"'"$PROFILE"'"}'
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
    rel="${f#/etc/resolvconf/}"
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
    logger -t selfdef-resolvconf-hooks -- "$(printf '{"tag":"selfdef-resolvconf-hooks","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="resolvconf_hooks_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="resolvconf_hooks_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="resolvconf_hooks_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-resolvconf-hooks","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-resolvconf-hooks -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-resolvconf-hooks-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-resolvconf-hooks-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
