#!/usr/bin/env bash
# selfdef sudoers-defaults-watchdog — boot + daily delta of the
# sudoers Defaults directives vs a learned baseline.
#
# sudoers-integrity-watchdog tracks the GRANT set and deliberately
# excludes Defaults. But the Defaults tunables are a privesc
# surface in their own right:
#
#   Defaults secure_path="/usr/bin:/tmp"      # sudo finds a trojan in /tmp
#   Defaults env_keep += "LD_PRELOAD"         # LD_PRELOAD into the root cmd
#   Defaults !env_reset                       # ALL env survives into sudo
#
# Each lets an unprivileged sudo-capable user escalate. sudo-tune
# SETS hardened Defaults; this DETECTS tampering.
#
# Records (each line: kind<TAB>key<TAB>value):
#   default:<param>:<value>  — each Defaults parameter
#   file:<path>:<sha12>      — hash of each sudoers file
#
# Severity:
#   ok    → no delta
#   warn  → any Defaults parameter added / removed / changed
#   alert → a NEWLY-ADDED dangerous Default:
#           - secure_path with a writable/tmp/home/relative element
#           - env_keep/env_check/env_delete += of a dangerous var
#             (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, PYTHONPATH,
#              PERL5LIB, RUBYLIB, BASH_ENV, ENV, IFS, PS4)
#           - !env_reset

set -u

PROFILE="${SELFDEF_SUDODEF_PROFILE:-report}"
BASELINE="${SELFDEF_SUDODEF_BASELINE:-/var/lib/selfdef/sudoers-defaults-baseline.tsv}"
SUDOERS="${SELFDEF_SUDODEF_FILE:-/etc/sudoers}"
SUDOERSD="${SELFDEF_SUDODEF_D:-/etc/sudoers.d}"

DANGER_VARS=" LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PERL5LIB RUBYLIB BASH_ENV ENV IFS PS4 "

files=()
[[ -f "$SUDOERS" ]] && files+=("$SUDOERS")
if [[ -d "$SUDOERSD" ]]; then
    for f in "$SUDOERSD"/*; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-sudoers-defaults -- '{"tag":"selfdef-sudoers-defaults","severity":"ok","event":"no_sudoers","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

# Is a secure_path value dangerous (writable / tmp / home / relative
# element)?
secure_path_bad() {
    local v="$1" elem
    v="${v#\"}"; v="${v%\"}"
    IFS=':' read -r -a _parts <<< "$v"
    for elem in "${_parts[@]}"; do
        case "$elem" in
            ""|.|..) return 0 ;;
            /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
            /*) [[ -d "$elem" && "$(stat -L -c '%a' "$elem" 2>/dev/null)" =~ [2367]$ ]] && return 0 ;;
            *) return 0 ;;  # relative element on sudo's PATH
        esac
    done
    return 1
}

scan_dangerous() {  # full Defaults directive text -> echoes a tag if dangerous
    local d="$1"
    case "$d" in
        *secure_path*=*)
            local val="${d#*=}"
            secure_path_bad "$val" && echo "secure_path:${val}"
            ;;
    esac
    case "$d" in
        *env_keep*|*env_check*|*env_delete*)
            local v
            for v in $DANGER_VARS; do
                [[ "$d" == *"$v"* ]] && echo "env:${v}"
            done
            ;;
    esac
    case "$d" in
        *'!env_reset'*) echo "!env_reset" ;;
    esac
}

declare -a baseline_susp=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    while IFS= read -r line; do
        line="${line%%#*}"
        [[ "$line" =~ ^[[:space:]]*Defaults ]] || continue
        # Strip the leading "Defaults[:@>!spec]" keyword, keep params.
        params="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*Defaults[^[:space:]]*[[:space:]]+//')"
        # Normalize whitespace.
        params="$(printf '%s' "$params" | tr -s '[:space:]' ' ' | sed -e 's/^ //' -e 's/ $//')"
        [[ -z "$params" ]] && continue
        printf 'default\t%s\n' "$params" >> "$current"
        while IFS= read -r tag; do
            [[ -n "$tag" ]] && baseline_susp+=("$tag")
        done < <(scan_dangerous "$params")
    done < "$f"
done

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp=()
    (( ${#baseline_susp[@]} > 0 )) && mapfile -t susp < <(printf '%s\n' "${baseline_susp[@]}" | sort -u)
    susp_str=$(IFS='|'; echo "${susp[*]:-}")
    sev="ok"; [[ ${#susp[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-sudoers-defaults -- "$(printf '{"tag":"selfdef-sudoers-defaults","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Dangerous detection only on NEWLY-ADDED Defaults lines.
declare -a suspicious=()
while IFS= read -r aline; do
    [[ "$aline" == default$'\t'* ]] || continue
    params="${aline#default$'\t'}"
    while IFS= read -r tag; do
        [[ -n "$tag" ]] && suspicious+=("$tag")
    done < <(scan_dangerous "$params")
done <<< "$added"
(( ${#suspicious[@]} > 0 )) && mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)

severity="ok"; event="sudoers_defaults_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="sudoers_defaults_dangerous"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="sudoers_defaults_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-sudoers-defaults","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-sudoers-defaults -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k v; do [[ -n "$k" ]] && logger -t selfdef-sudoers-defaults-detail -- "ADDED ${k} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k v; do [[ -n "$k" ]] && logger -t selfdef-sudoers-defaults-detail -- "REMOVED ${k} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
