#!/usr/bin/env bash
# selfdef account-watchdog — daily delta of the account
# surface vs a learned baseline.
#
# Records (each line: class<TAB>identity):
#   user:<name>:<uid>:<gid>:<shell>     — every /etc/passwd entry
#   uid0:<name>                          — every uid=0 account
#   sudo:<name>                          — members of sudo/wheel/admin
#
# First run baselines; subsequent runs diff. A NEW account,
# a NEW uid=0, or a NEW sudo member is high-signal.
#
# Severity:
#   ok    → no delta
#   warn  → new user (non-privileged)
#   alert → new uid=0 OR new sudo member (privilege persistence)

set -u

PROFILE="${SELFDEF_ACCOUNTS_PROFILE:-report}"
BASELINE="${SELFDEF_ACCOUNTS_BASELINE:-/var/lib/selfdef/accounts-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# Every passwd entry: name:uid:gid:shell (skip the gecos +
# home + password fields — they churn).
while IFS=: read -r name _ uid gid _ _ shell; do
    [[ -z "$name" ]] && continue
    printf 'user\t%s:%s:%s:%s\n' "$name" "$uid" "$gid" "$shell" >> "$current"
    # uid=0 set.
    if [[ "$uid" == "0" ]]; then
        printf 'uid0\t%s\n' "$name" >> "$current"
    fi
done < /etc/passwd

# sudo / wheel / admin group membership (the privilege roster).
for grp in sudo wheel admin; do
    members=$(getent group "$grp" 2>/dev/null | awk -F: '{print $4}')
    [[ -z "$members" ]] && continue
    IFS=',' read -ra arr <<< "$members"
    for m in "${arr[@]}"; do
        [[ -n "$m" ]] && printf 'sudo\t%s\n' "$m" >> "$current"
    done
done
# Also: any passwd-primary-gid member of a sudo group.
for grp in sudo wheel admin; do
    gid=$(getent group "$grp" 2>/dev/null | awk -F: '{print $3}')
    [[ -z "$gid" ]] && continue
    while IFS=: read -r name _ _ pgid _; do
        [[ "$pgid" == "$gid" ]] && printf 'sudo\t%s\n' "$name" >> "$current"
    done < /etc/passwd
done

sort -u "$current" -o "$current" 2>/dev/null || { sort -u "$current" > "${current}.s" && mv "${current}.s" "$current"; }
# Re-sort defensively (some busybox sort lacks -o).
{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"

cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    json=$(printf '{"tag":"selfdef-accounts","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")
    logger -t selfdef-accounts -- "$json"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))

n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
n_new_uid0=$(printf '%s' "$added" | grep -c '^uid0' || true)
n_new_sudo=$(printf '%s' "$added" | grep -c '^sudo' || true)

severity="ok"; event="no_delta"
if (( n_new_uid0 > 0 || n_new_sudo > 0 )); then
    severity="alert"; event="new_privileged_account"
elif (( n_added > 0 )); then
    severity="warn"; event="new_account"
fi

added_sample=$(printf '%s' "$added"   | head -10 | tr '\n' '|' | sed 's/\t/:/g')
removed_sample=$(printf '%s' "$removed" | head -10 | tr '\n' '|' | sed 's/\t/:/g')

json=$(printf '{"tag":"selfdef-accounts","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"new_uid0":%d,"new_sudo":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$n_new_uid0" "$n_new_sudo" \
    "$added_sample" "$removed_sample")
logger -t selfdef-accounts -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r c id; do [[ -n "$c" ]] && logger -t selfdef-accounts-detail -- "ADDED ${c} ${id}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r c id; do [[ -n "$c" ]] && logger -t selfdef-accounts-detail -- "REMOVED ${c} ${id}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
