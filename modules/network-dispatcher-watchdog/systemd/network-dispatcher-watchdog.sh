#!/usr/bin/env bash
# selfdef network-dispatcher-watchdog — boot + daily delta of the
# network-event dispatcher script dirs vs a learned baseline.
#
# NetworkManager, systemd-networkd-dispatcher, ifupdown, and ppp
# all run scripts AS ROOT when a network event fires — interface
# up/down, DHCP renew, VPN connect, connectivity change. These
# events happen at every boot and every network transition, so a
# script dropped into one of these dirs is reliable root-exec
# persistence (T1546) that is easy to miss next to cron/systemd.
#
#   cp /tmp/p /etc/NetworkManager/dispatcher.d/99-evil; chmod +x ...
#   → runs as root on the next interface-up (i.e. next boot)
#
# Watched dirs (root-exec on network event):
#   /etc/NetworkManager/dispatcher.d{,/pre-up.d,/pre-down.d}
#   /etc/networkd-dispatcher/*.d
#   /etc/network/if-{pre-,post-,}{up,down}.d   (ifupdown)
#   /etc/ppp/ip-up.d  /etc/ppp/ip-down.d  /etc/ppp/ipv6-{up,down}.d
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<script>:<sha12>    — hash of each script
#   own:<script>:<owner:mode> — owner + mode (non-root or
#                               world-writable = hijackable)
#   susp:<script>:<pattern>  — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a script added / changed / removed
#   alert → a script that is world-writable or non-root-owned, OR
#           contains a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_NETDISP_PROFILE:-report}"
BASELINE="${SELFDEF_NETDISP_BASELINE:-/var/lib/selfdef/network-dispatcher-baseline.tsv}"

if [[ -n "${SELFDEF_NETDISP_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_NETDISP_DIRS}"
else
    DIRS=(
        /etc/NetworkManager/dispatcher.d
        /etc/NetworkManager/dispatcher.d/pre-up.d
        /etc/NetworkManager/dispatcher.d/pre-down.d
        /etc/network/if-up.d /etc/network/if-pre-up.d
        /etc/network/if-down.d /etc/network/if-post-down.d
        /etc/ppp/ip-up.d /etc/ppp/ip-down.d
        /etc/ppp/ipv6-up.d /etc/ppp/ipv6-down.d
    )
    # networkd-dispatcher state dirs (routable.d, dormant.d, …)
    if [[ -d /etc/networkd-dispatcher ]]; then
        for sd in /etc/networkd-dispatcher/*.d; do
            [[ -d "$sd" ]] && DIRS+=("$sd")
        done
    fi
fi

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-network-dispatcher -- '{"tag":"selfdef-network-dispatcher","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-network-dispatcher -- '{"tag":"selfdef-network-dispatcher","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

# Any watched dir exists?
have_dir=0
for d in "${DIRS[@]}"; do [[ -d "$d" ]] && { have_dir=1; break; }; done
if [[ "$have_dir" -eq 0 ]]; then
    logger -t selfdef-network-dispatcher -- '{"tag":"selfdef-network-dispatcher","severity":"ok","event":"no_dispatcher_dirs","profile":"'"$PROFILE"'"}'
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
        # Hijackable: world-writable (mode last digit 2,3,6,7) or
        # not owned by root.
        if [[ "$mode" =~ [2367]$ ]]; then
            suspicious+=("$(basename "$f"):world-writable($mode)")
        elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
            suspicious+=("$(basename "$f"):owned-by-$owner")
        fi
        # Suspicious content (comment lines stripped).
        scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$scan" | grep -qE "$pat"; then
                printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
                suspicious+=("$(basename "$f"):$pat")
            fi
        done
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
    logger -t selfdef-network-dispatcher -- "$(printf '{"tag":"selfdef-network-dispatcher","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="network_dispatcher_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="network_dispatcher_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="network_dispatcher_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-network-dispatcher","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-network-dispatcher -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-network-dispatcher-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-network-dispatcher-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
