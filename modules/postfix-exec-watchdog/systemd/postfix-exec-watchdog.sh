#!/usr/bin/env bash
# selfdef postfix-exec-watchdog — boot + daily delta of the Postfix
# command-execution config vs a learned baseline + ownership +
# command scan.
#
# Postfix runs external programs from:
#   /etc/postfix/master.cf  — pipe/spawn services: the `argv=<prog>`
#                             token names the external program run as
#                             the service's user (often root or a
#                             mail user) when mail of that class flows.
#   /etc/postfix/main.cf    — *_command directives (mailbox_command,
#                             …) run a program on delivery.
# A planted pipe/spawn argv=, or a *_command, pointing at a writable
# /attacker program is mail-triggered code execution (T1546). The
# attacker can deliver on demand by sending a matching message.
# Distinct from mta-loopback-detect (loopback-only listening posture).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>          — hash of each config
#   own:<path>:<owner:mode>      — owner + mode
#   argv:<path>:<prog>           — a master.cf pipe/spawn argv= program
#   cmd:<path>:<directive>:<val> — a main.cf *_command directive
#
# Severity:
#   ok    → no delta
#   warn  → a config / command added / changed / removed
#   alert → a config world-writable/non-root, OR an argv=/command
#           program under /tmp /var/tmp /dev/shm /home or with an
#           injection pattern

set -u

PROFILE="${SELFDEF_POSTFIX_PROFILE:-report}"
BASELINE="${SELFDEF_POSTFIX_BASELINE:-/var/lib/selfdef/postfix-exec-baseline.tsv}"
MASTER="${SELFDEF_POSTFIX_MASTER:-/etc/postfix/master.cf}"
MAIN="${SELFDEF_POSTFIX_MAIN:-/etc/postfix/main.cf}"

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
    logger -t selfdef-postfix-exec -- '{"tag":"selfdef-postfix-exec","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-postfix-exec -- '{"tag":"selfdef-postfix-exec","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

is_writable_path() { selfdef_is_writable_path "$1"; }

files=()
[[ -f "$MASTER" ]] && files+=("$MASTER")
[[ -f "$MAIN" ]] && files+=("$MAIN")

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-postfix-exec -- '{"tag":"selfdef-postfix-exec","severity":"ok","event":"no_postfix","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

scan_patterns() {
    local text="$1" label="$2" base="$3" pat
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$text" | grep -qE "$pat"; then
            suspicious+=("${base}:${label}:$pat")
        fi
    done
}

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

    if [[ "$f" == "$MASTER" ]]; then
        # pipe/spawn services: argv=<prog> names the external program.
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            # extract every argv=<token>
            while read -r prog; do
                [[ -z "$prog" ]] && continue
                printf 'argv\t%s\t%s\n' "$f" "$prog" >> "$current"
                if is_writable_path "$prog"; then
                    suspicious+=("${base}:argv-writable($prog)")
                fi
            done < <(printf '%s\n' "$line" | grep -oiE 'argv=[^[:space:]]+' | sed -E 's/^argv=//I')
            scan_patterns "$line" "master" "$base"
        done < "$f"
    else
        # main.cf: *_command directives run a program on delivery.
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            directive="${line%%=*}"; directive="$(printf '%s' "$directive" | tr -d '[:space:]')"
            val="${line#*=}"
            val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
            [[ -z "$val" ]] && continue
            printf 'cmd\t%s\t%s:%s\n' "$f" "$directive" "$val" >> "$current"
            # first token of the value is the program
            prog="${val%%[[:space:]]*}"
            if is_writable_path "$prog"; then
                suspicious+=("${base}:${directive}-writable($prog)")
            fi
            scan_patterns "$val" "$directive" "$base"
        done < <(grep -iE '^[[:space:]]*[a-z0-9_]*command[[:space:]]*=' "$f" 2>/dev/null || true)
    fi
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
    logger -t selfdef-postfix-exec -- "$(printf '{"tag":"selfdef-postfix-exec","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="postfix_exec_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="postfix_exec_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="postfix_exec_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-postfix-exec","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-postfix-exec -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-postfix-exec-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-postfix-exec-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
