#!/usr/bin/env bash
# selfdef hosts-allow-watchdog — boot + daily delta of the
# tcpwrappers access files vs a learned baseline + ownership +
# spawn/twist-command scan.
#
# A libwrap-linked daemon (vsftpd, some sshd builds, rpcbind, …)
# evaluates these rules on each connection:
#   /etc/hosts.allow
#   /etc/hosts.deny
# A rule's optional `spawn <cmd>` or `twist <cmd>` shell command
# runs AS ROOT when the rule matches — so a planted
#   ALL: ALL: spawn /tmp/x
# is root-exec-on-network-connection persistence (T1546), triggered
# remotely by simply connecting to any wrapped service. Distinct from
# hosts-file-watchdog (/etc/hosts resolution) and access-conf-watchdog
# (PAM /etc/security/access.conf).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>           — hash of each file
#   own:<path>:<owner:mode>       — owner + mode
#   exec:<path>:<spawn|twist>:<cmd> — each spawn/twist command
#
# Severity:
#   ok    → no delta
#   warn  → a rule / file added / changed / removed
#   alert → a file world-writable/non-root, OR a spawn/twist command
#           under /tmp /var/tmp /dev/shm /home or with an injection
#           pattern

set -u

PROFILE="${SELFDEF_HOSTSALLOW_PROFILE:-report}"
BASELINE="${SELFDEF_HOSTSALLOW_BASELINE:-/var/lib/selfdef/hosts-allow-baseline.tsv}"
if [[ -n "${SELFDEF_HOSTSALLOW_FILES:-}" ]]; then
    read -r -a FILES <<< "${SELFDEF_HOSTSALLOW_FILES}"
else
    FILES=(/etc/hosts.allow /etc/hosts.deny)
fi

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
    logger -t selfdef-hosts-allow -- '{"tag":"selfdef-hosts-allow","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-hosts-allow -- '{"tag":"selfdef-hosts-allow","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

files=()
for f in "${FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-hosts-allow -- '{"tag":"selfdef-hosts-allow","severity":"ok","event":"no_hosts_allow","profile":"'"$PROFILE"'"}'
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
    # spawn/twist directives run a shell command as root on a match.
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        kw="spawn"
        printf '%s' "$line" | grep -qiE '\btwist\b' && kw="twist"
        cmd=$(printf '%s' "$line" | sed -E "s/.*\\b(spawn|twist)\\b[[:space:]]+//I")
        [[ -z "$cmd" ]] && continue
        printf 'exec\t%s\t%s:%s\n' "$f" "$kw" "$cmd" >> "$current"
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$cmd" | grep -qE "$pat"; then
                suspicious+=("${base}:${kw}:$pat")
            fi
        done
    done < <(grep -iE '\b(spawn|twist)\b' "$f" 2>/dev/null || true)
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
    logger -t selfdef-hosts-allow -- "$(printf '{"tag":"selfdef-hosts-allow","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="hosts_allow_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="hosts_allow_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="hosts_allow_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-hosts-allow","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-hosts-allow -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-hosts-allow-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-hosts-allow-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
