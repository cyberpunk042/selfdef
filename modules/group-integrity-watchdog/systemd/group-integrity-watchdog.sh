#!/usr/bin/env bash
# selfdef group-integrity-watchdog — daily + boot delta of
# /etc/group membership vs a learned baseline.
#
# Many groups confer root-equivalent power WITHOUT being in
# the sudo/wheel roster that account-watchdog tracks:
#   docker / lxd / podman → spawn a container mounting / as
#       root → trivially root the host (the canonical one).
#   disk     → raw read/write of block devices → read /etc/
#       shadow off the raw fs, or patch a binary.
#   shadow   → read /etc/shadow (password hashes).
#   kvm / libvirt → VM escape surface.
#   adm / systemd-journal → read all logs (info disclosure).
#   video / render → GPU/DRM access.
# Adding an attacker's account to any of these is privilege
# escalation / persistence that the passwd+sudo view misses.
#
# Records (each line: group<TAB>member). Membership = both the
# group-file member list AND users whose PRIMARY gid is the
# group (those don't appear in the group member field).
#
# Severity:
#   ok    → no delta
#   warn  → membership change in a non-privileged group
#   alert → a member ADDED to a privileged (denylist) group

set -u

PROFILE="${SELFDEF_GROUPINT_PROFILE:-report}"
BASELINE="${SELFDEF_GROUPINT_BASELINE:-/var/lib/selfdef/group-integrity-baseline.tsv}"
# SELFDEF_GROUPINT_GROUP_FILE + SELFDEF_GROUPINT_PASSWD_FILE added
# 2026-06-06 for L2 delta-testability. Live defaults unchanged.
GROUP_FILE="${SELFDEF_GROUPINT_GROUP_FILE:-/etc/group}"
PASSWD_FILE="${SELFDEF_GROUPINT_PASSWD_FILE:-/etc/passwd}"

# Root-equivalent / high-value groups.
PRIV_GROUPS="docker lxd podman disk shadow kvm libvirt libvirtd adm systemd-journal video render sudo wheel root"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# group-file member lists.
while IFS=: read -r gname _ gid members; do
    [[ -z "$gname" ]] && continue
    if [[ -n "$members" ]]; then
        IFS=',' read -ra arr <<< "$members"
        for m in "${arr[@]}"; do
            [[ -n "$m" ]] && printf '%s\t%s\n' "$gname" "$m" >> "$current"
        done
    fi
done < "$GROUP_FILE"

# primary-gid members (user's primary group from passwd).
while IFS=: read -r uname _ _ pgid _; do
    [[ -z "$uname" ]] && continue
    gname=$(awk -F: -v g="$pgid" '$3==g{print $1; exit}' "$GROUP_FILE" 2>/dev/null)
    [[ -n "$gname" ]] && printf '%s\t%s\n' "$gname" "$uname" >> "$current"
done < "$PASSWD_FILE"

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-group-integrity -- "$(printf '{"tag":"selfdef-group-integrity","severity":"ok","event":"baseline_initial","profile":"%s","entries":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Added entries whose group is in the privileged denylist.
n_priv=0
priv_sample=()
if [[ -n "$added" ]]; then
    while IFS=$'\t' read -r g m; do
        [[ -z "$g" ]] && continue
        for pg in $PRIV_GROUPS; do
            if [[ "$g" == "$pg" ]]; then
                n_priv=$((n_priv + 1))
                (( ${#priv_sample[@]} < 6 )) && priv_sample+=("${g}:${m}")
                break
            fi
        done
    done <<< "$added"
fi

severity="ok"; event="no_delta"
if (( n_priv > 0 )); then
    severity="alert"; event="privileged_group_member_added"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="group_membership_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
priv_str=$(IFS='|'; echo "${priv_sample[*]:-}")

json=$(printf '{"tag":"selfdef-group-integrity","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"priv_added":%d,"priv_sample":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$n_priv" "$priv_str" "$added_sample" "$removed_sample")
logger -t selfdef-group-integrity -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r g m; do [[ -n "$g" ]] && logger -t selfdef-group-integrity-detail -- "ADDED ${g} ${m}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r g m; do [[ -n "$g" ]] && logger -t selfdef-group-integrity-detail -- "REMOVED ${g} ${m}"; done

# Refresh baseline so a confirmed-legit change becomes trusted.
cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 || n_removed > 0 )); then
    exit 1
fi
exit 0
