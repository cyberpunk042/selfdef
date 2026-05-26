#!/usr/bin/env bash
# selfdef ssh-authkeys-watchdog — daily + boot delta of every
# SSH authorized_keys across the host vs a learned baseline.
#
# Each authorized key is the credential for passwordless SSH
# access AS that user. An attacker who appends their public
# key to ~root/.ssh/authorized_keys has persistent root SSH
# that survives password changes + most other remediation.
# This is MITRE T1098.004 — the single most common Linux
# backdoor-access persistence technique.
#
# Records (each line: user<TAB>file<TAB>keyfingerprint):
#   - per-user ~/.ssh/authorized_keys + authorized_keys2
#     (home dirs from /etc/passwd)
#   - /etc/ssh/authorized_keys.d/* (if used)
# Key identity = the base64 key body's sha256 (comment-
# independent, so renaming the comment doesn't mask a key).
#
# Severity:
#   ok    → no delta
#   warn  → a key REMOVED (operator cleanup) only
#   alert → a key ADDED (the persistence signature)

set -u

PROFILE="${SELFDEF_AUTHKEYS_PROFILE:-report}"
BASELINE="${SELFDEF_AUTHKEYS_BASELINE:-/var/lib/selfdef/ssh-authkeys-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

emit_keys() {  # user  file
    local user="$1" file="$2"
    [[ -f "$file" && -r "$file" ]] || return 0
    # Each non-comment line: [options] type base64 [comment].
    # Hash the base64 body (field that starts with the key
    # blob) so options/comment changes don't mask the key and
    # cosmetic edits don't create false adds.
    while IFS= read -r line; do
        line="${line%%$'\r'}"
        [[ -z "$line" || "${line#\#}" != "$line" ]] && continue
        # Extract the longest base64-looking token (the key body).
        local body
        body=$(echo "$line" | grep -oE 'AAAA[A-Za-z0-9+/=]+' | head -1)
        [[ -z "$body" ]] && continue
        local fp
        fp=$(printf '%s' "$body" | sha256sum | awk '{print $1}')
        printf '%s\t%s\t%s\n' "$user" "$file" "${fp:0:32}"
    done < "$file"
}

# Per-user home authorized_keys.
while IFS=: read -r user _ uid _ _ home _; do
    [[ -z "$home" || ! -d "$home" ]] && continue
    emit_keys "$user" "${home}/.ssh/authorized_keys"
    emit_keys "$user" "${home}/.ssh/authorized_keys2"
done < /etc/passwd

# Central authorized_keys.d (if sshd_config points there).
if [[ -d /etc/ssh/authorized_keys.d ]]; then
    for f in /etc/ssh/authorized_keys.d/*; do
        [[ -f "$f" ]] && emit_keys "central:$(basename "$f")" "$f"
    done
fi

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-ssh-authkeys -- "$(printf '{"tag":"selfdef-ssh-authkeys","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="no_delta"
if (( n_added > 0 )); then
    severity="alert"; event="authorized_key_added"
elif (( n_removed > 0 )); then
    severity="warn"; event="authorized_key_removed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$3}' | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-ssh-authkeys","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$added_sample" "$removed_sample")
logger -t selfdef-ssh-authkeys -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r u f fp; do [[ -n "$u" ]] && logger -t selfdef-ssh-authkeys-detail -- "ADDED user=${u} file=${f} fp=${fp}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r u f fp; do [[ -n "$u" ]] && logger -t selfdef-ssh-authkeys-detail -- "REMOVED user=${u} file=${f} fp=${fp}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
