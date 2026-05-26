#!/usr/bin/env bash
# selfdef dhcpd-exec-watchdog — boot + daily delta of the ISC DHCP
# SERVER config vs a learned baseline + ownership + execute()-scan.
#
# dhcpd evaluates `execute("/path", "arg", ...)` statements (usually
# inside `on commit { }` / `on release { }` / `on expiry { }` event
# blocks) and runs the named program AS THE dhcpd USER (often root)
# on the corresponding DHCP lease event. Config:
#   /etc/dhcp/dhcpd.conf  /etc/dhcp/dhcpd6.conf  /etc/dhcpd.conf
#   /etc/dhcp/dhcpd.conf.d/*
# A planted execute() pointing at a writable/attacker program is
# lease-event-triggered root command execution / persistence
# (T1546), fired by any client obtaining/renewing/releasing a lease.
# Distinct from dhclient-hooks-watchdog and dhcpcd-hooks-watchdog
# (the DHCP CLIENTS): this is the DHCP SERVER execute() surface.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each config
#   own:<path>:<owner:mode>  — owner + mode
#   exec:<path>:<prog>       — each execute() program
#
# Severity:
#   ok    → no delta
#   warn  → a config / execute() added / changed / removed
#   alert → a config world-writable/non-root, OR an execute() program
#           under /tmp /var/tmp /dev/shm /home, relative-with-slash,
#           or with an injection pattern in the call

set -u

PROFILE="${SELFDEF_DHCPD_PROFILE:-report}"
BASELINE="${SELFDEF_DHCPD_BASELINE:-/var/lib/selfdef/dhcpd-exec-baseline.tsv}"
if [[ -n "${SELFDEF_DHCPD_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_DHCPD_DIRS}"
else
    DIRS=(/etc/dhcp/dhcpd.conf.d)
fi
if [[ -n "${SELFDEF_DHCPD_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_DHCPD_FILES}"
else
    EXTRA_FILES=(/etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd6.conf /etc/dhcpd.conf)
fi

PATTERNS=(
    'curl[^|;&]*\|[[:space:]]*(ba)?sh' 'wget[^|;&]*\|[[:space:]]*(ba)?sh'
    '/dev/tcp/' '/dev/udp/' 'nc[[:space:]]+.*-e' 'ncat[[:space:]]+.*-e'
    'bash[[:space:]]+-i' 'base64[[:space:]]+-d' 'base64[[:space:]]+--decode'
    'eval[[:space:]]*[`$]' 'python[0-9]*[[:space:]]+-c' 'perl[[:space:]]+-e'
    'mkfifo' 'setsid'
)

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-dhcpd-exec -- '{"tag":"selfdef-dhcpd-exec","severity":"ok","event":"no_dhcpd","profile":"'"$PROFILE"'"}'
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
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        # first quoted string after execute( is the program
        prog=$(printf '%s' "$line" | sed -E 's/.*execute[[:space:]]*\([[:space:]]*"([^"]*)".*/\1/I')
        [[ "$prog" == "$line" || -z "$prog" ]] && continue
        printf 'exec\t%s\t%s\n' "$f" "$prog" >> "$current"
        if [[ "$prog" =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; then
            suspicious+=("${base}:execute-writable($prog)")
        elif [[ "$prog" == */* && "$prog" != /* ]]; then
            suspicious+=("${base}:execute-relative($prog)")
        fi
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$line" | grep -qE "$pat"; then
                suspicious+=("${base}:execute:$pat")
            fi
        done
    done < <(grep -iE 'execute[[:space:]]*\(' "$f" 2>/dev/null || true)
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
    logger -t selfdef-dhcpd-exec -- "$(printf '{"tag":"selfdef-dhcpd-exec","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="dhcpd_exec_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="dhcpd_exec_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="dhcpd_exec_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-dhcpd-exec","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-dhcpd-exec -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dhcpd-exec-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-dhcpd-exec-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
