#!/usr/bin/env bash
# selfdef sudoers-integrity-watchdog — daily + boot delta of
# the sudo grant set vs a learned baseline.
#
# Parses /etc/sudoers + /etc/sudoers.d/* into normalized rule
# lines (user/group specs, NOT comments/Defaults-noise), so a
# NEW grant is surfaced. NOPASSWD + ALL=(ALL) adds are flagged
# as dangerous (instant priv-esc persistence).
#
# Severity:
#   ok    → no delta
#   warn  → rule removed (operator cleanup) OR a non-dangerous
#           rule added
#   alert → a NOPASSWD or ALL=(ALL[:ALL]) rule added

set -u

PROFILE="${SELFDEF_SUDOERS_PROFILE:-report}"
BASELINE="${SELFDEF_SUDOERS_BASELINE:-/var/lib/selfdef/sudoers-integrity-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

emit_rules() {  # file
    local file="$1"
    [[ -f "$file" && -r "$file" ]] || return 0
    # Keep only rule lines: contain '=' and an ALL/(...) target,
    # i.e. "<who> <host>=(<runas>) <cmds>". Drop comments,
    # blank lines, and Defaults lines (we track GRANTS, not
    # tunables — sudo-tune owns Defaults).
    grep -vE '^\s*(#|$|Defaults)' "$file" 2>/dev/null \
      | grep -E '=' \
      | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' \
      | while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            printf '%s\t%s\n' "$(basename "$file")" "$rule"
        done
}

emit_rules /etc/sudoers
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] && emit_rules "$f"
    done
fi

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-sudoers-integrity -- "$(printf '{"tag":"selfdef-sudoers-integrity","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
# Dangerous = NOPASSWD or a blanket ALL=(ALL...) ALL grant.
n_dangerous=$(printf '%s' "$added" | grep -ciE 'NOPASSWD|=\(ALL(:ALL)?\)[[:space:]]*ALL' || true)

severity="ok"; event="no_delta"
if (( n_dangerous > 0 )); then
    severity="alert"; event="dangerous_sudo_grant_added"
elif (( n_added > 0 )); then
    severity="warn"; event="sudo_grant_added"
elif (( n_removed > 0 )); then
    severity="warn"; event="sudo_grant_removed"
fi

added_sample=$(printf '%s' "$added"   | head -8 | tr '\n' '|' | sed 's/\t/:/g')
removed_sample=$(printf '%s' "$removed" | head -8 | tr '\n' '|' | sed 's/\t/:/g')

json=$(printf '{"tag":"selfdef-sudoers-integrity","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"dangerous":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$n_dangerous" "$added_sample" "$removed_sample")
logger -t selfdef-sudoers-integrity -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r f r; do [[ -n "$f" ]] && logger -t selfdef-sudoers-integrity-detail -- "ADDED ${f}: ${r}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r f r; do [[ -n "$f" ]] && logger -t selfdef-sudoers-integrity-detail -- "REMOVED ${f}: ${r}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
