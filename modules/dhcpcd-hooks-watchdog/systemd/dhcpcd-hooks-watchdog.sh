#!/usr/bin/env bash
# selfdef dhcpcd-hooks-watchdog — boot + daily delta of the dhcpcd
# hook surface vs a learned baseline + ownership + suspicious-pattern
# scan.
#
# dhcpcd runs every hook AS ROOT on each lease event
# (PREINIT/CARRIER/BOUND/RENEW/REBIND/REBOOT/EXPIRE/NOCARRIER/...):
#   /lib/dhcpcd/dhcpcd-hooks/*       (distro-shipped)
#   /usr/lib/dhcpcd/dhcpcd-hooks/*   (distro-shipped, newer layout)
#   /etc/dhcpcd/dhcpcd-hooks/*       (admin)
#   /etc/dhcpcd.enter-hook           (single-file enter hook)
#   /etc/dhcpcd.exit-hook            (single-file exit hook)
# RENEW fires automatically on a timer, so a dropped hook
# self-triggers without operator action. dhcpcd is the DEFAULT DHCP
# client on Alpine/Arch/Gentoo/Raspberry Pi OS, where the ISC
# dhclient-hooks-watchdog no-ops; this fills that gap. A rogue hook
# is root-exec-on-network-event persistence (T1546). Distinct from
# dhclient-hooks-watchdog (ISC isc-dhcp-client) and
# network-dispatcher-watchdog (NM/ifupdown/ppp/networkd).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each hook
#   own:<path>:<owner:mode> — owner + mode
#   susp:<path>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a hook added / changed / removed
#   alert → a hook world-writable or non-root-owned, OR containing a
#           suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_DHCPCD_PROFILE:-report}"
BASELINE="${SELFDEF_DHCPCD_BASELINE:-/var/lib/selfdef/dhcpcd-hooks-baseline.tsv}"
if [[ -n "${SELFDEF_DHCPCD_DIRS:-}" ]]; then
    read -r -a RAW_DIRS <<< "${SELFDEF_DHCPCD_DIRS}"
else
    RAW_DIRS=(
        /lib/dhcpcd/dhcpcd-hooks
        /usr/lib/dhcpcd/dhcpcd-hooks
        /etc/dhcpcd/dhcpcd-hooks
    )
fi
if [[ -n "${SELFDEF_DHCPCD_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_DHCPCD_FILES}"
else
    EXTRA_FILES=(/etc/dhcpcd.enter-hook /etc/dhcpcd.exit-hook)
fi

# De-duplicate dirs by resolved real path (/lib -> /usr/lib symlink).
declare -A seen=()
DIRS=()
for d in "${RAW_DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    rp=$(readlink -f "$d" 2>/dev/null || echo "$d")
    [[ -n "${seen[$rp]:-}" ]] && continue
    seen[$rp]=1
    DIRS+=("$rp")
done

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
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-dhcpcd-hooks -- '{"tag":"selfdef-dhcpcd-hooks","severity":"ok","event":"no_dhcpcd_hooks","profile":"'"$PROFILE"'"}'
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
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("$(basename "$f"):world-writable($mode)")
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
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
    logger -t selfdef-dhcpcd-hooks -- "$(printf '{"tag":"selfdef-dhcpcd-hooks","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="dhcpcd_hooks_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="dhcpcd_hooks_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="dhcpcd_hooks_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-dhcpcd-hooks","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-dhcpcd-hooks -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dhcpcd-hooks-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dhcpcd-hooks-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
