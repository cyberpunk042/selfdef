#!/usr/bin/env bash
# selfdef at-jobs-watchdog — boot + daily delta of the at/batch
# job spool + access lists vs a learned baseline.
#
# atd runs each spooled job AS ITS OWNER at the scheduled time.
# `at` jobs are the scheduler-persistence sibling of cron, and
# cron-job-watchdog does not see them. The high-signal cases:
#   - a job body that RE-SUBMITS itself (`at`/`batch` inside the
#     job) — a self-perpetuating loop that survives its own run;
#   - a job body containing a reverse shell / fetch-pipe-shell /
#     tmp payload;
#   - a job owned by an unexpected (non-root, non-service) user.
#
# Watched:
#   /var/spool/cron/atjobs   (Debian/Ubuntu)
#   /var/spool/at  /var/spool/at/spool  /var/spool/atjobs (RHEL/other)
#   /etc/at.allow  /etc/at.deny         (who may use at)
#
# Records (each line: kind<TAB>path<TAB>value):
#   job:<path>:<sha12>      — hash of each spooled job
#   own:<path>:<owner>      — submitting user (the job runs as)
#   susp:<path>:<pattern>   — suspicious pattern / self-resubmit
#   acl:<file>:<sha12>      — hash of at.allow / at.deny
#
# Severity:
#   ok    → no delta
#   warn  → a job / acl added, removed, or changed
#   alert → a job body with a suspicious pattern OR a self-
#           resubmitting at/batch call

set -u

PROFILE="${SELFDEF_ATJOBS_PROFILE:-report}"
BASELINE="${SELFDEF_ATJOBS_BASELINE:-/var/lib/selfdef/at-jobs-baseline.tsv}"
SPOOLS="${SELFDEF_ATJOBS_SPOOLS:-/var/spool/cron/atjobs /var/spool/at /var/spool/at/spool /var/spool/atjobs}"
ACLS="${SELFDEF_ATJOBS_ACLS:-/etc/at.allow /etc/at.deny}"

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-at-jobs -- '{"tag":"selfdef-at-jobs","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-at-jobs -- '{"tag":"selfdef-at-jobs","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)
# Module-specific patterns beyond the shared set (preserved verbatim):
PATTERNS+=(
    '(^|[;&|][[:space:]]*)/(tmp|var/tmp|dev/shm)/'
    '(^|[;&|`$(][[:space:]]*)(at|batch)[[:space:]]'
)

have=0
for d in $SPOOLS; do [[ -d "$d" ]] && { have=1; break; }; done
for a in $ACLS; do [[ -f "$a" ]] && have=1; done
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-at-jobs -- '{"tag":"selfdef-at-jobs","severity":"ok","event":"no_at_spool","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for d in $SPOOLS; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do
        [[ -f "$f" ]] || continue
        # atd lockfiles / metadata: skip the spool's own bookkeeping.
        case "$(basename "$f")" in .SEQ|.lockfile) continue ;; esac
        h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
        printf 'job\t%s\t%s\n' "$f" "$h" >> "$current"
        owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
        printf 'own\t%s\t%s\n' "$f" "$owner" >> "$current"
        scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
        for pat in "${PATTERNS[@]}"; do
            if printf '%s\n' "$scan" | grep -qE "$pat"; then
                printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
                suspicious+=("$(basename "$f"):$pat")
            fi
        done
    done
done

for a in $ACLS; do
    [[ -f "$a" ]] || continue
    h=$(sha256sum "$a" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'acl\t%s\t%s\n' "$a" "$h" >> "$current"
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
    logger -t selfdef-at-jobs -- "$(printf '{"tag":"selfdef-at-jobs","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="at_jobs_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="at_jobs_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="at_jobs_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-at-jobs","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-at-jobs -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-at-jobs-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-at-jobs-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
