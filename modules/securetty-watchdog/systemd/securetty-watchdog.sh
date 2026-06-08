#!/usr/bin/env bash
# selfdef securetty-watchdog — boot + daily delta of /etc/securetty
# (the root-login TTY allowlist) vs a learned baseline.
#
# pam_securetty.so permits DIRECT root login only on the TTYs listed
# in /etc/securetty. The file traditionally lists physical consoles
# (tty1..tty63, ttyS0, hvc0, …). Two attacker moves widen root login:
#
#   echo 'pts/0' >> /etc/securetty     # root login on a network pty
#   rm /etc/securetty                  # fail-open: root permitted
#                                      #   on ALL ttys (historic glibc
#                                      #   pam_securetty behaviour)
#
# Records (each line: kind<TAB>key<TAB>value):
#   tty:<name>            — each permitted TTY
#   file:<path>:<sha12>   — hash of /etc/securetty
#   own:<path>:<owner:mode> — owner + mode
#
# Severity:
#   ok    → no delta
#   warn  → a TTY added / removed, or file changed
#   alert → a NEWLY-ADDED pts/network TTY; a world-writable/non-root
#           file; or the file was REMOVED since baseline (fail-open)

set -u

PROFILE="${SELFDEF_SECURETTY_PROFILE:-report}"
BASELINE="${SELFDEF_SECURETTY_BASELINE:-/var/lib/selfdef/securetty-baseline.tsv}"
SECURETTY="${SELFDEF_SECURETTY_FILE:-/etc/securetty}"

# A newly-permitted pts/* (pseudo-terminal) or a network-ish tty is the
# widening signature — securetty should list only physical consoles.
is_network_tty() {
    case "$1" in
        pts/*|pts|*:*|ttyp*|ptyp*|ttyS[0-9]*)
            # ttyS* (serial) is legit on many hosts; only pts/network ptys
            # are the high-signal widen. Treat serial as benign.
            case "$1" in ttyS[0-9]*) return 1 ;; esac
            return 0 ;;
        *) return 1 ;;
    esac
}

if [[ ! -f "$SECURETTY" ]]; then
    # File absent. If we had a baseline, that's a REMOVAL (fail-open) — but
    # without a baseline we can't tell absent-by-default from removed; the
    # delta logic below handles removal. On a true first-scan with no file,
    # report no_securetty.
    if [[ ! -f "$BASELINE" ]]; then
        logger -t selfdef-securetty -- '{"tag":"selfdef-securetty","severity":"ok","event":"no_securetty","profile":"'"$PROFILE"'"}'
        exit 0
    fi
    # Baseline exists but file gone → fail-open removal.
    logger -t selfdef-securetty -- "$(printf '{"tag":"selfdef-securetty","severity":"alert","event":"securetty_removed","profile":"%s","suspicious":"file_removed_fail_open"}' "$PROFILE")"
    : > "$BASELINE"  # reset baseline so re-creation is a clean delta
    [[ "$PROFILE" == "enforce" ]] && exit 1
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

h=$(sha256sum "$SECURETTY" 2>/dev/null | awk '{print substr($1,1,12)}')
printf 'file\t%s\t%s\n' "$SECURETTY" "$h" >> "$current"
owner=$(stat -c '%U' "$SECURETTY" 2>/dev/null || echo '?')
mode=$(stat -c '%a' "$SECURETTY" 2>/dev/null || echo '?')
printf 'own\t%s\t%s\n' "$SECURETTY" "${owner}:${mode}" >> "$current"
if [[ "$mode" =~ [2367]$ ]]; then
    suspicious+=("securetty:world-writable($mode)")
elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
    suspicious+=("securetty:owned-by-$owner")
fi

while IFS= read -r line; do
    line="${line%%#*}"
    tty="$(printf '%s' "$line" | tr -d '[:space:]')"
    [[ -z "$tty" ]] && continue
    printf 'tty\t%s\n' "$tty" >> "$current"
done < "$SECURETTY"

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp_str=$(IFS='|'; echo "${suspicious[*]:-}")
    sev="ok"; [[ ${#suspicious[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-securetty -- "$(printf '{"tag":"selfdef-securetty","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# A newly-ADDED network/pts tty is the widen signature.
while IFS= read -r aline; do
    [[ "$aline" == tty$'\t'* ]] || continue
    t="${aline#tty$'\t'}"
    is_network_tty "$t" && suspicious+=("added-network-tty:${t}")
done <<< "$added"
(( ${#suspicious[@]} > 0 )) && mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)

severity="ok"; event="securetty_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="securetty_widened"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="securetty_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-securetty","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-securetty -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k v; do [[ -n "$k" ]] && logger -t selfdef-securetty-detail -- "ADDED ${k} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k v; do [[ -n "$k" ]] && logger -t selfdef-securetty-detail -- "REMOVED ${k} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
