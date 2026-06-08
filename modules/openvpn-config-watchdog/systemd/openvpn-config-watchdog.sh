#!/usr/bin/env bash
# selfdef openvpn-config-watchdog — boot + daily delta of the
# OpenVPN configs vs a learned baseline + ownership + script-directive
# + key-exposure scan.
#
# OpenVPN runs these directives' command AS ROOT (gated by
# script-security) on connect / route / auth events:
#   up down route-up route-pre-down ipchange client-connect
#   client-disconnect learn-address tls-verify auth-user-pass-verify
# A planted script directive is root-exec-on-VPN-event persistence
# (T1546). Because .conf/.ovpn files may carry inline <key> /
# <tls-crypt> material or a `secret` directive, a world-readable
# config is private-key exposure (T1552.001). The OpenVPN sibling of
# wireguard-config-watchdog. Distinct from vpn-bridge (functional).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>            — hash of each config
#   own:<path>:<owner:mode>        — owner + mode
#   scr:<path>:<directive>:<cmd>   — each script directive
#
# Severity:
#   ok    → no delta
#   warn  → a config / script directive added / changed / removed
#   alert → a config world-writable/non-root, world-readable with
#           inline key material, OR a script command under /tmp
#           /var/tmp /dev/shm /home or with an injection pattern

set -u

PROFILE="${SELFDEF_OPENVPN_PROFILE:-report}"
BASELINE="${SELFDEF_OPENVPN_BASELINE:-/var/lib/selfdef/openvpn-config-baseline.tsv}"
if [[ -n "${SELFDEF_OPENVPN_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_OPENVPN_DIRS}"
else
    DIRS=(/etc/openvpn /etc/openvpn/client /etc/openvpn/server)
fi

SCRIPT_DIRECTIVES='up|down|route-up|route-pre-down|ipchange|client-connect|client-disconnect|learn-address|tls-verify|auth-user-pass-verify'

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
    logger -t selfdef-openvpn -- '{"tag":"selfdef-openvpn","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-openvpn -- '{"tag":"selfdef-openvpn","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

# De-duplicate dirs by resolved real path.
declare -A seen=()
RDIRS=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    rp=$(readlink -f "$d" 2>/dev/null || echo "$d")
    [[ -n "${seen[$rp]:-}" ]] && continue
    seen[$rp]=1
    RDIRS+=("$rp")
done

files=()
for d in "${RDIRS[@]}"; do
    for f in "$d"/*.conf "$d"/*.ovpn; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-openvpn -- '{"tag":"selfdef-openvpn","severity":"ok","event":"no_openvpn","profile":"'"$PROFILE"'"}'
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
    # Key exposure: others-readable config that carries inline key
    # material or a `secret` static-key directive.
    if [[ "$mode" =~ [4567]$ ]] && grep -qiE '^[[:space:]]*<(key|tls-crypt|tls-auth)>|^[[:space:]]*secret[[:space:]]' "$f" 2>/dev/null; then
        suspicious+=("${base}:world-readable-key($mode)")
    fi
    # Script directives run as root.
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*[#\;] ]] && continue
        read -r directive cmd <<< "$line"
        [[ -z "$cmd" ]] && continue
        # strip a single layer of surrounding quotes for the path test
        cmd_unq="$cmd"
        cmd_unq="${cmd_unq#\"}"; cmd_unq="${cmd_unq#\'}"
        printf 'scr\t%s\t%s:%s\n' "$f" "$directive" "$cmd" >> "$current"
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$cmd_unq" | grep -qE "$pat"; then
                suspicious+=("${base}:${directive}:$pat")
            fi
        done
    done < <(grep -iE "^[[:space:]]*(${SCRIPT_DIRECTIVES})[[:space:]]+[^[:space:]]" "$f" 2>/dev/null || true)
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
    logger -t selfdef-openvpn -- "$(printf '{"tag":"selfdef-openvpn","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="openvpn_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="openvpn_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="openvpn_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-openvpn","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-openvpn -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-openvpn-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-openvpn-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
