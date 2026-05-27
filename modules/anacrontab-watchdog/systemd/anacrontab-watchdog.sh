#!/usr/bin/env bash
# selfdef anacrontab-watchdog — boot + daily delta of /etc/anacrontab
# vs a learned baseline + ownership + command scan.
#
# anacron is the catch-up scheduler that runs jobs missed while the
# host was off; its job commands run AS ROOT. Job line format:
#
#   period  delay  job-identifier  command...
#   1       5      cron.daily      run-parts /etc/cron.daily
#   7       25     evil            /tmp/.payload          # root, on catch-up
#
# A rogue job line (or a tampered command on an existing one) is
# root-exec persistence (T1053.003) that cron-job-watchdog (which
# covers crontab / cron.d / cron.{daily,weekly,…}) does not see.
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<path>:<sha12>     — hash of anacrontab
#   own:<path>:<owner:mode> — owner + mode
#   job:<job-id>:<cmd0>     — each job's command (first token)
#   susp:<path>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a job / env / file change
#   alert → a job command under /tmp /home /dev/shm, world-writable,
#           or bare/relative; an injection pattern; or a
#           world-writable/non-root anacrontab

set -u

PROFILE="${SELFDEF_ANACRON_PROFILE:-report}"
BASELINE="${SELFDEF_ANACRON_BASELINE:-/var/lib/selfdef/anacrontab-baseline.tsv}"
ANACRONTAB="${SELFDEF_ANACRON_FILE:-/etc/anacrontab}"

# SDD-063: consume the shared writable-location policy from module-lib
# instead of a per-module case statement. Co-shipped by the .deb at
# /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports SELFDEF_MODULE_LIB
# in a workspace. A missing or pre-v4 library is a real misconfiguration that
# would leave the watchdog scanning with a divergent policy, so we fail loud.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-anacrontab -- '{"tag":"selfdef-anacrontab","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-anacrontab -- '{"tag":"selfdef-anacrontab","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo'

is_suspicious_cmd() {
    local p="$1"
    # at/under a writable root → shared policy (selfdef_is_writable_dir)
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        ""|@*) return 1 ;;
        ./*|../*|*/*) return 0 ;;   # relative path with slash
        *) return 1 ;;             # bare command (run-parts, nice, …) — normal
    esac
}

if [[ ! -f "$ANACRONTAB" ]]; then
    logger -t selfdef-anacrontab -- '{"tag":"selfdef-anacrontab","severity":"ok","event":"no_anacrontab","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

h=$(sha256sum "$ANACRONTAB" 2>/dev/null | awk '{print substr($1,1,12)}')
printf 'file\t%s\t%s\n' "$ANACRONTAB" "$h" >> "$current"
owner=$(stat -c '%U' "$ANACRONTAB" 2>/dev/null || echo '?')
mode=$(stat -c '%a' "$ANACRONTAB" 2>/dev/null || echo '?')
printf 'own\t%s\t%s\n' "$ANACRONTAB" "${owner}:${mode}" >> "$current"
if [[ "$mode" =~ [2367]$ ]]; then
    suspicious+=("anacrontab:world-writable($mode)")
elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
    suspicious+=("anacrontab:owned-by-$owner")
fi

while IFS= read -r line; do
    line="${line%%#*}"
    read -r -a F <<< "$line"
    [[ ${#F[@]} -eq 0 ]] && continue
    # env-var assignment line (e.g. PATH=..., RANDOM_DELAY=...)
    if [[ "${F[0]}" == *=* ]]; then
        printf 'env\t%s\t%s\n' "${F[0]%%=*}" "${F[0]#*=}" >> "$current"
        continue
    fi
    # job line: period delay job-id command...
    [[ ${#F[@]} -lt 4 ]] && continue
    jobid="${F[2]}"; cmd0="${F[3]}"
    printf 'job\t%s\t%s\n' "$jobid" "$cmd0" >> "$current"
    is_suspicious_cmd "$cmd0" && suspicious+=("${jobid}:cmd=>${cmd0}")
done < "$ANACRONTAB"

scan=$(grep -vE '^[[:space:]]*#' "$ANACRONTAB" 2>/dev/null || true)
if printf '%s\n' "$scan" | grep -qE "$PATTERNS"; then
    printf 'susp\t%s\t%s\n' "$(basename "$ANACRONTAB")" "injection" >> "$current"
    suspicious+=("anacrontab:injection-pattern")
fi

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
    logger -t selfdef-anacrontab -- "$(printf '{"tag":"selfdef-anacrontab","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="anacrontab_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="anacrontab_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="anacrontab_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-anacrontab","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-anacrontab -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-anacrontab-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-anacrontab-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
