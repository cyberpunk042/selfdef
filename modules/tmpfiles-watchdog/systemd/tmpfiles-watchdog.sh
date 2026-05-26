#!/usr/bin/env bash
# selfdef tmpfiles-watchdog — boot + daily delta of the
# systemd-tmpfiles declarations vs a learned baseline + ownership +
# semantic scan.
#
# systemd-tmpfiles-setup runs these AS ROOT at boot (and the
# systemd-tmpfiles-clean timer runs daily):
#   /etc/tmpfiles.d/*.conf   (admin)
#   /run/tmpfiles.d/*.conf   (runtime)
# Line format (whitespace-separated):
#   Type Path Mode User Group Age Argument
# Each line creates/sets a file (f/F/w), dir (d/D), symlink (L/L+),
# fifo (p), device node (c/b), or COPIES a file into place (C), with
# an explicit Mode. A planted entry can mint a SETUID-root file, a
# world-writable dir in a PATH location, a symlink hijack, or copy
# an attacker file over a trusted one — idempotently re-applied at
# every boot (T1546 / T1574 / T1548). Distinct from the boot-time
# creation peers sysusers (accounts), modules-load (kernel modules),
# binfmt (interpreters): this is the FILE creation surface.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>            — hash of each .conf
#   own:<path>:<owner:mode>        — owner + mode
#   ent:<path>:<type>:<tgt>:<mode> — each declaration entry
#
# Severity:
#   ok    → no delta
#   warn  → an entry added / changed / removed
#   alert → a .conf world-writable/non-root, OR an entry whose Mode
#           sets the SETUID bit (rare/suspicious; legit setgid 2755
#           and sticky 1777 are NOT flagged)

set -u

PROFILE="${SELFDEF_TMPFILES_PROFILE:-report}"
BASELINE="${SELFDEF_TMPFILES_BASELINE:-/var/lib/selfdef/tmpfiles-baseline.tsv}"
if [[ -n "${SELFDEF_TMPFILES_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_TMPFILES_DIRS}"
else
    DIRS=(/etc/tmpfiles.d /run/tmpfiles.d)
fi

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-tmpfiles -- '{"tag":"selfdef-tmpfiles","severity":"ok","event":"no_tmpfiles","profile":"'"$PROFILE"'"}'
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
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        read -r typ tgt fmode _rest <<< "$line"
        [[ -z "$typ" ]] && continue
        printf 'ent\t%s\t%s:%s:%s\n' "$f" "$typ" "${tgt:--}" "${fmode:--}" >> "$current"
        # SETUID-bit mode: strip a leading '~' (mask) and quotes, then
        # a 4-digit mode whose high digit has the suid (4) bit set.
        m="${fmode#\~}"; m="${m//\"/}"
        if [[ "$m" =~ ^[4567][0-7][0-7][0-7]$ ]]; then
            suspicious+=("${base}:setuid-mode(${typ} ${tgt:--} ${fmode})")
        fi
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
    logger -t selfdef-tmpfiles -- "$(printf '{"tag":"selfdef-tmpfiles","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="tmpfiles_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="tmpfiles_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="tmpfiles_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-tmpfiles","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-tmpfiles -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-tmpfiles-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-tmpfiles-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
