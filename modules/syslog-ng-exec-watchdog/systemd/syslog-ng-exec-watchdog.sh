#!/usr/bin/env bash
# selfdef syslog-ng-exec-watchdog — boot + daily delta of the
# syslog-ng config's program() destinations vs a learned baseline.
#
# A syslog-ng program() destination runs a program AS ROOT, fed by
# matching log messages — the syslog-ng sibling of rsyslog omprog:
#
#   destination d_evil { program("/tmp/.payload"); };   # root on log event
#
# A rogue program() is root-exec-on-log-event persistence (T1546),
# triggered by causing a matching log line.
#
# Records (each line: kind<TAB>conf<TAB>value):
#   file:<conf>:<sha12>      — hash of each syslog-ng config
#   own:<conf>:<owner:mode>  — owner + mode
#   program:<conf>:<prog>    — each program() destination (first tok)
#
# Severity:
#   ok    → no delta
#   warn  → a config / program() added, removed, or changed
#   alert → a program under /tmp /home /dev/shm, world-writable, or
#           bare/relative; an injection pattern; or a
#           world-writable/non-root config

set -u

PROFILE="${SELFDEF_SYSLOGNG_PROFILE:-report}"
BASELINE="${SELFDEF_SYSLOGNG_BASELINE:-/var/lib/selfdef/syslog-ng-exec-baseline.tsv}"
CONF="${SELFDEF_SYSLOGNG_FILE:-/etc/syslog-ng/syslog-ng.conf}"
CONFD="${SELFDEF_SYSLOGNG_D:-/etc/syslog-ng/conf.d}"

PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo'

is_suspicious_prog() {
    local p="$1"
    case "$p" in
        /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        "") return 1 ;;
        ./*|../*|*/*) return 0 ;;
        *) return 0 ;;   # bare program for a syslog-ng dest is abnormal
    esac
}

files=()
[[ -f "$CONF" ]] && files+=("$CONF")
if [[ -d "$CONFD" ]]; then
    for f in "$CONFD"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-syslog-ng-exec -- '{"tag":"selfdef-syslog-ng-exec","severity":"ok","event":"no_syslog_ng","profile":"'"$PROFILE"'"}'
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
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("$(basename "$f"):owned-by-$owner")
    fi
    # program("...") destinations
    while IFS= read -r m; do
        val=$(printf '%s' "$m" | sed -E 's/.*program[[:space:]]*\([[:space:]]*"//; s/".*//')
        prog="${val%% *}"
        [[ -z "$prog" ]] && continue
        printf 'program\t%s\t%s\n' "$(basename "$f")" "$prog" >> "$current"
        is_suspicious_prog "$prog" && suspicious+=("$(basename "$f"):program=>${prog}")
        printf '%s\n' "$val" | grep -qE "$PATTERNS" && suspicious+=("$(basename "$f"):program-payload")
    done < <(grep -oiE 'program[[:space:]]*\([[:space:]]*"[^"]*"' "$f" 2>/dev/null)
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
    logger -t selfdef-syslog-ng-exec -- "$(printf '{"tag":"selfdef-syslog-ng-exec","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="syslog_ng_exec_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="syslog_ng_exec_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="syslog_ng_exec_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-syslog-ng-exec","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-syslog-ng-exec -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-syslog-ng-exec-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-syslog-ng-exec-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
