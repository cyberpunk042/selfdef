#!/usr/bin/env bash
# selfdef rhosts-watchdog — boot + daily delta of the rsh/rlogin
# trust files vs a learned baseline.
#
# /etc/hosts.equiv and per-user ~/.rhosts (+ the ssh equivalents
# ~/.shosts and /etc/ssh/shosts.equiv) declare hosts (and users)
# trusted for PASSWORDLESS rlogin/rsh/rcp. A wildcard entry is a
# classic trusted-relationship backdoor (T1199):
#
#   +              # any host may rlogin (as the matching user)
#   + +            # any host AND any user — total passwordless access
#   +@netgroup     # any host in the netgroup
#
# On a modern host these files are normally ABSENT; root's
# ~/.rhosts existing at all is almost always a backdoor.
#
# Watched: /etc/hosts.equiv /root/.rhosts /root/.shosts
#          /etc/ssh/shosts.equiv
#
# Records (each line: kind<TAB>file<TAB>entry):
#   file:<path>:<sha12>     — hash of each trust file
#   own:<path>:<owner:mode> — owner + mode
#   trust:<path>:<entry>    — each normalized trust entry
#
# Severity:
#   ok    → no delta
#   warn  → a trust entry / file added, removed, or changed
#   alert → a `+` wildcard entry; a world-writable / non-root trust
#           file; or the presence of root's ~/.rhosts/.shosts

set -u

PROFILE="${SELFDEF_RHOSTS_PROFILE:-report}"
BASELINE="${SELFDEF_RHOSTS_BASELINE:-/var/lib/selfdef/rhosts-baseline.tsv}"
if [[ -n "${SELFDEF_RHOSTS_FILES:-}" ]]; then
    read -r -a FILES <<< "${SELFDEF_RHOSTS_FILES}"
else
    FILES=(/etc/hosts.equiv /root/.rhosts /root/.shosts /etc/ssh/shosts.equiv)
fi

files=()
for f in "${FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-rhosts -- '{"tag":"selfdef-rhosts","severity":"ok","event":"no_rhosts_files","profile":"'"$PROFILE"'"}'
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
    # A per-user .rhosts/.shosts existing at all is high-signal.
    case "$f" in
        */.rhosts|*/.shosts) suspicious+=("$(basename "$(dirname "$f")")/$(basename "$f"):present") ;;
    esac
    while IFS= read -r line; do
        line="${line%%#*}"
        entry="$(printf '%s' "$line" | tr -s '[:space:]' ' ' | sed -e 's/^ //' -e 's/ $//')"
        [[ -z "$entry" ]] && continue
        printf 'trust\t%s\t%s\n' "$(basename "$f")" "$entry" >> "$current"
        # A `+` token anywhere = wildcard trust.
        case " $entry " in
            *" + "*|"+ "*|*" +"|"+") suspicious+=("$(basename "$f"):wildcard(${entry})") ;;
            "+"*) suspicious+=("$(basename "$f"):wildcard(${entry})") ;;
        esac
    done < "$f"
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
    logger -t selfdef-rhosts -- "$(printf '{"tag":"selfdef-rhosts","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="rhosts_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="rhosts_trust_backdoor"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="rhosts_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-rhosts","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-rhosts -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-rhosts-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-rhosts-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
