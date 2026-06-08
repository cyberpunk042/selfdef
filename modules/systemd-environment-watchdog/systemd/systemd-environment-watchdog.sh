#!/usr/bin/env bash
# selfdef systemd-environment-watchdog — boot + daily delta of the
# systemd manager environment config vs a learned baseline +
# ownership + env-injection scan.
#
# In /etc/systemd/system.conf (+ system.conf.d/*.conf) and the
# user-manager /etc/systemd/user.conf[.d]:
#   DefaultEnvironment=KEY=VAL ...   sets env for EVERY service the
#                                    manager spawns.
#   ManagerEnvironment=KEY=VAL ...   sets env for the manager (PID 1).
# A planted DefaultEnvironment=LD_PRELOAD=/tmp/evil.so (or LD_AUDIT /
# LD_LIBRARY_PATH to a writable dir) injects attacker code into the
# address space of every service on the host — a near-total,
# persistent code-execution foothold (T1574.006). Distinct from
# ld-preload-watchdog (/etc/ld.so.preload + shell/pam env files).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>            — hash of each config
#   own:<path>:<owner:mode>        — owner + mode
#   env:<path>:<directive>:<pair>  — each KEY=VAL env pair
#
# Severity:
#   ok    → no delta
#   warn  → a config / env pair added / changed / removed
#   alert → a config world-writable/non-root, OR a DefaultEnvironment/
#           ManagerEnvironment that sets LD_PRELOAD/LD_AUDIT/
#           LD_LIBRARY_PATH, OR an env value path under /tmp /var/tmp
#           /dev/shm /home

set -u

PROFILE="${SELFDEF_SYSTEMDENV_PROFILE:-report}"
BASELINE="${SELFDEF_SYSTEMDENV_BASELINE:-/var/lib/selfdef/systemd-environment-baseline.tsv}"
if [[ -n "${SELFDEF_SYSTEMDENV_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_SYSTEMDENV_DIRS}"
else
    DIRS=(/etc/systemd/system.conf.d /etc/systemd/user.conf.d)
fi
if [[ -n "${SELFDEF_SYSTEMDENV_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_SYSTEMDENV_FILES}"
else
    EXTRA_FILES=(/etc/systemd/system.conf /etc/systemd/user.conf)
fi

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-systemd-env -- '{"tag":"selfdef-systemd-env","severity":"ok","event":"no_systemd_env","profile":"'"$PROFILE"'"}'
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
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*[#\;] ]] && continue
        directive="${line%%=*}"; directive="$(printf '%s' "$directive" | tr -d '[:space:]')"
        val="${line#*=}"
        val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
        [[ -z "$val" ]] && continue
        # strip surrounding quotes from the whole value for scanning
        scanval="${val//\"/}"
        # library-injection env vars have no legit place in the manager env
        if printf '%s\n' "$scanval" | grep -qE '(^|[[:space:]])(LD_PRELOAD|LD_AUDIT|LD_LIBRARY_PATH)='; then
            inj=$(printf '%s\n' "$scanval" | grep -oE '(LD_PRELOAD|LD_AUDIT|LD_LIBRARY_PATH)=[^[:space:]]*' | head -1)
            suspicious+=("${base}:${directive}-ld-injection($inj)")
        fi
        if printf '%s\n' "$scanval" | grep -qE '=/(tmp|var/tmp|dev/shm|home)/'; then
            suspicious+=("${base}:${directive}-writable-value")
        fi
        # record each whitespace-separated KEY=VAL pair
        for pair in $scanval; do
            [[ "$pair" == *=* ]] || continue
            printf 'env\t%s\t%s:%s\n' "$f" "$directive" "$pair" >> "$current"
        done
    done < <(grep -iE '^[[:space:]]*(DefaultEnvironment|ManagerEnvironment)[[:space:]]*=' "$f" 2>/dev/null || true)
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
    logger -t selfdef-systemd-env -- "$(printf '{"tag":"selfdef-systemd-env","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="systemd_env_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="systemd_env_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="systemd_env_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-systemd-env","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-systemd-env -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-systemd-env-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-systemd-env-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
