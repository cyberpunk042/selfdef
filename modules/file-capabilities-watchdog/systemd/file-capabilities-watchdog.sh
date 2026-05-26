#!/usr/bin/env bash
# selfdef file-capabilities-watchdog — daily + boot delta of
# file capabilities vs a learned baseline.
#
# File capabilities (set via setcap, stored in the security.
# capability xattr) are the modern, fine-grained alternative
# to the setuid bit. A binary with cap_setuid+ep is
# root-equivalent; cap_dac_override+ep bypasses all file
# permission checks; cap_net_raw+ep allows packet crafting.
# The setuid-bit scan (suid-sgid-watchdog) does NOT see
# these — capabilities live in a separate xattr.
#
# Severity:
#   ok    → no delta
#   warn  → 1..2 added/changed capability binaries
#   alert → 3+ added OR any added binary with a "dangerous"
#           capability (setuid/setgid/dac_override/dac_read_
#           search/sys_admin/sys_ptrace/sys_module)

set -u

PROFILE="${SELFDEF_FILECAPS_PROFILE:-report}"
BASELINE="${SELFDEF_FILECAPS_BASELINE:-/var/lib/selfdef/file-capabilities-baseline.tsv}"
ROOTS="${SELFDEF_FILECAPS_ROOTS:-/usr /bin /sbin /opt /var}"

PRUNE_PATHS=(
    "/var/lib/docker/overlay2" "/var/lib/containerd"
    "/var/lib/containers/storage" "/var/lib/lxd/storage-pools"
    "/var/lib/snapd/snaps" "/proc" "/sys"
)
prune_expr=()
for p in "${PRUNE_PATHS[@]}"; do
    [[ -d "$p" ]] || continue
    prune_expr+=(-path "$p" -prune -o)
done

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# Walk the roots; getcap on each regular file. getcap -r is
# convenient but noisy on errors; we drive find for prune
# control. Output: "path capabilities".
# shellcheck disable=SC2086
for root in $ROOTS; do
    [[ -d "$root" ]] || continue
    find "$root" -xdev "${prune_expr[@]}" -type f -print 2>/dev/null
done | while IFS= read -r f; do
    caps=$(getcap "$f" 2>/dev/null)
    [[ -n "$caps" ]] && echo "$caps"
done | sed 's/ = / /' | sort -u > "$current"

cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    json=$(printf '{"tag":"selfdef-file-caps","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")
    logger -t selfdef-file-caps -- "$json"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))

n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Dangerous-capability detection on added entries.
n_dangerous=$(printf '%s' "$added" | grep -ciE 'cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_sys_module' || true)

severity="ok"; event="no_delta"
if (( n_dangerous > 0 )); then
    severity="alert"; event="dangerous_capability_added"
elif (( n_added >= 3 )); then
    severity="alert"; event="mass_capability_added"
elif (( n_added > 0 )); then
    severity="warn"; event="capability_added"
fi

added_sample=$(printf '%s' "$added"   | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-file-caps","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"dangerous":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$n_dangerous" "$added_sample" "$removed_sample")
logger -t selfdef-file-caps -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS= read -r l; do [[ -n "$l" ]] && logger -t selfdef-file-caps-detail -- "ADDED ${l}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS= read -r l; do [[ -n "$l" ]] && logger -t selfdef-file-caps-detail -- "REMOVED ${l}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
