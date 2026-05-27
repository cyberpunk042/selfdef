#!/usr/bin/env bash
# selfdef rsyslog-exec-watchdog — boot + daily delta of the rsyslog
# config's program-exec actions vs a learned baseline.
#
# rsyslog can run a program AS ROOT on a matching log message:
#   legacy:  *.*  ^/path/program;template     # shell-exec action
#   modern:  action(type="omprog" binary="/path/program ...")
#
# A rogue exec action is root-exec-on-log-event persistence: the
# attacker triggers it by causing a matching log line (T1546).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<conf>:<sha12>      — hash of each rsyslog config
#   own:<conf>:<owner:mode>  — owner + mode
#   exec:<conf>:<prog>       — each exec action's program (first token)
#
# Severity:
#   ok    → no delta
#   warn  → a config / exec action added, removed, or changed
#   alert → an exec program under /tmp /home /dev/shm, world-
#           writable, or bare/relative; an injection pattern; or a
#           world-writable/non-root config

set -u

PROFILE="${SELFDEF_RSYSLOG_PROFILE:-report}"
BASELINE="${SELFDEF_RSYSLOG_BASELINE:-/var/lib/selfdef/rsyslog-exec-baseline.tsv}"
CONF="${SELFDEF_RSYSLOG_FILE:-/etc/rsyslog.conf}"
CONFD="${SELFDEF_RSYSLOG_D:-/etc/rsyslog.d}"

PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo'

# SDD-063: consume the shared writable-location policy from module-lib.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-rsyslog-exec -- '{"tag":"selfdef-rsyslog-exec","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-rsyslog-exec -- '{"tag":"selfdef-rsyslog-exec","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

is_suspicious_prog() {
    local p="$1"
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        ""|%*) return 1 ;;
        ./*|../*|*/*) return 0 ;;
        *) return 0 ;;   # a bare program for an rsyslog exec action is
                         # abnormal (legit ones use absolute paths)
    esac
}

files=()
[[ -f "$CONF" ]] && files+=("$CONF")
if [[ -d "$CONFD" ]]; then
    for f in "$CONFD"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-rsyslog-exec -- '{"tag":"selfdef-rsyslog-exec","severity":"ok","event":"no_rsyslog","profile":"'"$PROFILE"'"}'
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
    # modern omprog: binary="/path ..."
    while IFS= read -r m; do
        val=$(printf '%s' "$m" | sed -E 's/.*binary[[:space:]]*=[[:space:]]*"//; s/".*//')
        prog="${val%% *}"
        [[ -z "$prog" ]] && continue
        printf 'exec\t%s\t%s\n' "$(basename "$f")" "$prog" >> "$current"
        is_suspicious_prog "$prog" && suspicious+=("$(basename "$f"):omprog=>${prog}")
        printf '%s\n' "$val" | grep -qE "$PATTERNS" && suspicious+=("$(basename "$f"):omprog-payload")
    done < <(grep -iE 'binary[[:space:]]*=[[:space:]]*"' "$f" 2>/dev/null)
    # legacy caret action: <selector> ^program;template
    while IFS= read -r m; do
        prog=$(printf '%s' "$m" | grep -oE '\^[^;[:space:]]+' | head -1 | sed 's/^\^//')
        [[ -z "$prog" ]] && continue
        printf 'exec\t%s\t%s\n' "$(basename "$f")" "$prog" >> "$current"
        is_suspicious_prog "$prog" && suspicious+=("$(basename "$f"):caret=>${prog}")
    done < <(grep -E '[[:space:]]\^[^[:space:]]' "$f" 2>/dev/null | grep -vE '^[[:space:]]*#')
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
    logger -t selfdef-rsyslog-exec -- "$(printf '{"tag":"selfdef-rsyslog-exec","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="rsyslog_exec_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="rsyslog_exec_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="rsyslog_exec_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-rsyslog-exec","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-rsyslog-exec -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-rsyslog-exec-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-rsyslog-exec-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
