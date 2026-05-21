#!/usr/bin/env bash
# selfdef unowned-files-watchdog — periodic scan for files
# whose uid or gid does not resolve to a /etc/passwd or
# /etc/group entry.
#
# Emits one JSON event tagged 'selfdef-unowned-files' with the
# count + a sample of paths. Per-finding detail goes to the
# 'selfdef-unowned-files-detail' tag for forensic drill-down.
#
# Severity ladder:
#   ok    → 0 unowned
#   warn  → 1..50 unowned
#   alert → 51+ unowned   (typical of a bulk uid-deletion event
#                          — usually a real incident)

set -u

PROFILE="${SELFDEF_UNOWNED_PROFILE:-report}"

# Scan roots — operator may override via SELFDEF_UNOWNED_ROOTS
# (space-separated). Defaults exclude /proc /sys /dev /run +
# common bind-mount sources to keep the scan bounded.
ROOTS="${SELFDEF_UNOWNED_ROOTS:-/etc /home /opt /root /srv /usr /var}"

# Path-prune patterns — common churn paths that produce false-
# positives (containerd overlay snapshots use anonymous uids
# inside, etc.).
PRUNE_PATHS=(
    "/var/lib/docker/overlay2"
    "/var/lib/containerd"
    "/var/lib/containers/storage"
    "/var/lib/lxd/storage-pools"
    "/var/lib/snapd/snaps"
    "/var/cache/apt/archives"
)

# Build the prune expression.
prune_expr=()
for p in "${PRUNE_PATHS[@]}"; do
    [[ -d "$p" ]] || continue
    prune_expr+=(-path "$p" -prune -o)
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# shellcheck disable=SC2086
for root in $ROOTS; do
    [[ -d "$root" ]] || continue
    find "$root" -xdev "${prune_expr[@]}" \( -nouser -o -nogroup \) -print 2>/dev/null
done > "$tmp"

count=$(wc -l < "$tmp" | tr -d ' ')

severity="ok"
event="no_unowned"
if (( count > 0 )) && (( count <= 50 )); then
    severity="warn"; event="unowned_found"
elif (( count > 50 )); then
    severity="alert"; event="bulk_unowned"
fi

# Sample first 10 paths for the main event.
sample=$(head -10 "$tmp" | tr '\n' '|' | sed 's/"/\\"/g')

json=$(printf '{"tag":"selfdef-unowned-files","severity":"%s","event":"%s","profile":"%s","unowned_count":%d,"scan_roots":"%s","sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$count" "$ROOTS" "$sample")
logger -t selfdef-unowned-files -- "$json"

# Full per-path detail.
if (( count > 0 )); then
    head -c 65536 "$tmp" | while IFS= read -r line; do
        logger -t selfdef-unowned-files-detail -- "$line"
    done
fi

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
