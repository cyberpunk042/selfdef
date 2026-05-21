#!/usr/bin/env bash
# selfdef suid-sgid-watchdog — daily inventory + delta of
# every setuid OR setgid executable on the host.
#
# First run: write baseline TSV (path<TAB>mode<TAB>uid<TAB>gid<TAB>sha256)
#            to /var/lib/selfdef/suid-sgid-baseline.tsv. Emit
#            'baseline_initial' event with the count.
# Subsequent runs: compute current inventory, diff against
#            baseline. Emit per-class events for added /
#            removed / perm-changed / hash-changed sets.
#
# Severity:
#   ok    → no delta
#   warn  → 1..3 added or perm-changed OR any hash-changed
#   alert → 4+ added or perm-changed (bulk install attack)
#
# The baseline is not auto-updated. Operator-pull rotation:
#   sudo systemctl start selfdef-suid-sgid.service --rotate
# OR remove the baseline file and the next scan re-baselines
# (logged as 'baseline_initial').

set -u

PROFILE="${SELFDEF_SUIDSGID_PROFILE:-report}"
ROOTS="${SELFDEF_SUIDSGID_ROOTS:-/usr /bin /sbin /opt /var}"
BASELINE="${SELFDEF_SUIDSGID_BASELINE:-/var/lib/selfdef/suid-sgid-baseline.tsv}"

PRUNE_PATHS=(
    "/var/lib/docker/overlay2"
    "/var/lib/containerd"
    "/var/lib/containers/storage"
    "/var/lib/lxd/storage-pools"
    "/var/lib/snapd/snaps"
    "/proc" "/sys"
)
prune_expr=()
for p in "${PRUNE_PATHS[@]}"; do
    [[ -d "$p" ]] || continue
    prune_expr+=(-path "$p" -prune -o)
done

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# Build current inventory. -perm /6000 catches u+s OR g+s.
# Sort for stable diff.
# shellcheck disable=SC2086
for root in $ROOTS; do
    [[ -d "$root" ]] || continue
    find "$root" -xdev "${prune_expr[@]}" -type f -perm /6000 -print 2>/dev/null
done | sort -u | while IFS= read -r f; do
    [[ -r "$f" ]] || continue
    mode=$(stat -c '%a' "$f" 2>/dev/null || echo "?")
    uid=$(stat -c '%U' "$f" 2>/dev/null || echo "?")
    gid=$(stat -c '%G' "$f" 2>/dev/null || echo "?")
    hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}' || echo "?")
    printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$mode" "$uid" "$gid" "$hash"
done > "$current"

cur_count=$(wc -l < "$current" | tr -d ' ')

# First run: write baseline + emit baseline_initial.
if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    json=$(printf '{"tag":"selfdef-suid-sgid","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")
    logger -t selfdef-suid-sgid -- "$json"
    exit 0
fi

# Delta against baseline.
#  added       : in current, not in baseline (by path)
#  removed     : in baseline, not in current
#  perm_change : path in both, mode/uid/gid differs
#  hash_change : path in both, mode/uid/gid identical, sha256 differs
added=$(  comm -23 <(awk -F'\t' '{print $1}' "$current"  | sort -u) <(awk -F'\t' '{print $1}' "$BASELINE" | sort -u))
removed=$(comm -13 <(awk -F'\t' '{print $1}' "$current"  | sort -u) <(awk -F'\t' '{print $1}' "$BASELINE" | sort -u))

n_added=$(  printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Path-overlap deltas.
overlap_tmp="$(mktemp)"; trap 'rm -f "$current" "$overlap_tmp"' EXIT
join -t $'\t' -j 1 \
    <(sort -t $'\t' -k1,1 "$BASELINE") \
    <(sort -t $'\t' -k1,1 "$current") > "$overlap_tmp" 2>/dev/null || true

# overlap_tmp columns: path  bmode buid bgid bhash  cmode cuid cgid chash
n_perm_change=0
n_hash_change=0
perm_sample=()
hash_sample=()
while IFS=$'\t' read -r path bmode buid bgid bhash cmode cuid cgid chash; do
    if [[ "$bmode" != "$cmode" || "$buid" != "$cuid" || "$bgid" != "$cgid" ]]; then
        n_perm_change=$((n_perm_change + 1))
        (( ${#perm_sample[@]} < 5 )) && perm_sample+=("${path}:${bmode}→${cmode}/${buid}→${cuid}/${bgid}→${cgid}")
    elif [[ "$bhash" != "$chash" ]]; then
        n_hash_change=$((n_hash_change + 1))
        (( ${#hash_sample[@]} < 5 )) && hash_sample+=("${path}:${bhash:0:12}→${chash:0:12}")
    fi
done < "$overlap_tmp"

# Severity classification.
severity="ok"; event="no_delta"
if (( n_added > 0 || n_perm_change > 0 )); then
    if (( n_added + n_perm_change >= 4 )); then
        severity="alert"; event="bulk_delta"
    else
        severity="warn"; event="suid_drift"
    fi
elif (( n_hash_change > 0 )); then
    severity="warn"; event="suid_hash_drift"
fi

added_sample=$(printf '%s' "$added"   | head -5 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | head -5 | tr '\n' '|')
perm_sample_str=$(IFS='|'; echo "${perm_sample[*]:-}")
hash_sample_str=$(IFS='|'; echo "${hash_sample[*]:-}")

json=$(printf '{"tag":"selfdef-suid-sgid","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"perm_change":%d,"hash_change":%d,"added_sample":"%s","removed_sample":"%s","perm_sample":"%s","hash_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$n_perm_change" "$n_hash_change" \
    "$added_sample" "$removed_sample" "$perm_sample_str" "$hash_sample_str")
logger -t selfdef-suid-sgid -- "$json"

# Per-finding detail.
[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS= read -r p; do [[ -n "$p" ]] && logger -t selfdef-suid-sgid-detail -- "ADDED ${p}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS= read -r p; do [[ -n "$p" ]] && logger -t selfdef-suid-sgid-detail -- "REMOVED ${p}"; done
for p in "${perm_sample[@]}"; do logger -t selfdef-suid-sgid-detail -- "PERM ${p}"; done
for p in "${hash_sample[@]}"; do logger -t selfdef-suid-sgid-detail -- "HASH ${p}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added + n_perm_change > 0 )); then
    exit 1
fi
exit 0
