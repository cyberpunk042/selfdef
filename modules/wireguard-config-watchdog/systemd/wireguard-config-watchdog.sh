#!/usr/bin/env bash
# selfdef wireguard-config-watchdog — boot + daily delta of the
# WireGuard configs vs a learned baseline + ownership + hook-command
# + key-exposure scan.
#
# wg-quick runs these directives in each /etc/wireguard/*.conf AS
# ROOT when the tunnel is brought up/down:
#   PostUp = <cmd>   PreUp = <cmd>   PostDown = <cmd>   PreDown = <cmd>
# A planted hook is root-exec-on-tunnel-event persistence (T1546).
# Because each .conf holds the interface [Interface] PrivateKey, a
# world-readable .conf is private-key exposure (T1552.001). Two
# concerns, one file set. Distinct from vpn-bridge (the functional
# multi-instance VPN module): this is the detection watchdog over the
# on-disk configs.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>            — hash of each .conf
#   own:<path>:<owner:mode>        — owner + mode
#   hook:<path>:<directive>:<cmd>  — each PostUp/PreUp/PostDown/PreDown
#
# Severity:
#   ok    → no delta
#   warn  → a config / hook added / changed / removed
#   alert → a .conf world-writable/non-root, OR world-readable (key
#           exposure), OR a hook command under /tmp /var/tmp /dev/shm
#           /home or with an injection pattern

set -u

PROFILE="${SELFDEF_WIREGUARD_PROFILE:-report}"
BASELINE="${SELFDEF_WIREGUARD_BASELINE:-/var/lib/selfdef/wireguard-config-baseline.tsv}"
if [[ -n "${SELFDEF_WIREGUARD_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_WIREGUARD_DIRS}"
else
    DIRS=(/etc/wireguard)
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
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-wireguard -- '{"tag":"selfdef-wireguard","severity":"ok","event":"no_wireguard","profile":"'"$PROFILE"'"}'
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
    # PrivateKey exposure: WireGuard configs hold the [Interface]
    # private key; others-readable (mode last digit has the read bit)
    # is a confidentiality finding.
    if [[ "$mode" =~ [4567]$ ]] && grep -qiE '^[[:space:]]*PrivateKey[[:space:]]*=' "$f" 2>/dev/null; then
        suspicious+=("${base}:world-readable-privatekey($mode)")
    fi
    # PostUp/PreUp/PostDown/PreDown hook commands run as root.
    while IFS= read -r line; do
        local_dir="${line%%=*}"
        cmd="${line#*=}"
        # trim leading space from cmd
        cmd="${cmd#"${cmd%%[![:space:]]*}"}"
        dir_trim="$(printf '%s' "$local_dir" | tr -d '[:space:]')"
        [[ -z "$cmd" ]] && continue
        printf 'hook\t%s\t%s:%s\n' "$f" "$dir_trim" "$cmd" >> "$current"
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$cmd" | grep -qE "$pat"; then
                suspicious+=("${base}:${dir_trim}:$pat")
            fi
        done
    done < <(grep -iE '^[[:space:]]*(PostUp|PreUp|PostDown|PreDown)[[:space:]]*=' "$f" 2>/dev/null || true)
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
    logger -t selfdef-wireguard -- "$(printf '{"tag":"selfdef-wireguard","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="wireguard_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="wireguard_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="wireguard_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-wireguard","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-wireguard -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-wireguard-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-wireguard-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
