#!/usr/bin/env bash
# selfdef world-writable-watchdog — daily scan for files with
# perm 0002 (world-writable) outside the safe whitelist.
#
# The whitelist covers paths where world-writable is INTENDED
# (sticky-bit shared scratch): /tmp /var/tmp /dev/shm /run/lock
# plus the system dconf state dirs.
#
# Emits one JSON event tagged 'selfdef-world-writable' with
# count + sample. Per-path detail goes to
# 'selfdef-world-writable-detail'.
#
# Severity ladder:
#   ok    → 0 findings
#   warn  → 1..25 findings
#   alert → 26+ findings

set -u

PROFILE="${SELFDEF_WORLDWRITE_PROFILE:-report}"
ROOTS="${SELFDEF_WORLDWRITE_ROOTS:-/etc /home /opt /root /srv /usr /var}"

# Safe paths (legitimate world-writable use, sticky-bit dirs).
PRUNE_PATHS=(
    "/tmp"
    "/var/tmp"
    "/dev/shm"
    "/run/lock"
    "/var/lib/docker/overlay2"
    "/var/lib/containerd"
    "/var/lib/containers/storage"
    "/var/lib/lxd/storage-pools"
    "/var/lib/snapd/snaps"
    "/proc"
    "/sys"
)

prune_expr=()
for p in "${PRUNE_PATHS[@]}"; do
    [[ -d "$p" ]] || continue
    prune_expr+=(-path "$p" -prune -o)
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# -perm -0002 = world-writable bit set. -type f restricts to
# regular files (sticky-bit dirs are legitimate-by-design and
# excluded by the path prune list above; non-sticky dirs WITH
# world-writable are caught via -type d below).
#
# We accept both files + dirs in the scan; sticky-bit dirs in
# the safe-list are pruned upstream so they don't reach this
# check.
# shellcheck disable=SC2086
for root in $ROOTS; do
    [[ -d "$root" ]] || continue
    # Files: any world-writable.
    find "$root" -xdev "${prune_expr[@]}" -type f -perm -0002 -print 2>/dev/null
    # Dirs: world-writable WITHOUT sticky bit (sticky dirs are
    # legitimate shared scratch; non-sticky world-writable dirs
    # are usually a misconfiguration).
    find "$root" -xdev "${prune_expr[@]}" -type d -perm -0002 ! -perm -1000 -print 2>/dev/null
done > "$tmp"

count=$(wc -l < "$tmp" | tr -d ' ')

severity="ok"
event="no_findings"
if (( count > 0 )) && (( count <= 25 )); then
    severity="warn"; event="world_writable_found"
elif (( count > 25 )); then
    severity="alert"; event="bulk_world_writable"
fi

sample=$(head -10 "$tmp" | tr '\n' '|' | sed 's/"/\\"/g')

json=$(printf '{"tag":"selfdef-world-writable","severity":"%s","event":"%s","profile":"%s","finding_count":%d,"scan_roots":"%s","sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$count" "$ROOTS" "$sample")
logger -t selfdef-world-writable -- "$json"

if (( count > 0 )); then
    head -c 65536 "$tmp" | while IFS= read -r line; do
        logger -t selfdef-world-writable-detail -- "$line"
    done
fi

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
