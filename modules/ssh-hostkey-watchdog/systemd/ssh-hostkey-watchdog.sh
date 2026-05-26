#!/usr/bin/env bash
# selfdef ssh-hostkey-watchdog — boot + daily delta of the SSH
# host-key fingerprints vs a learned baseline.
#
# The host key is the server's cryptographic IDENTITY — what
# clients verify (and TOFU-pin on first connect) to know they're
# talking to the right box. If it changes:
#   - MITM prep: an attacker who swapped the key can intercept
#     clients that auto-accept the new fingerprint.
#   - Unauthorized reinstall / re-image of the host.
#   - Key theft → operator rotated (legit) OR attacker rotated.
# Legit host keys NEVER change on a stable host. A change is
# always operator-explainable-or-incident.
#
# Records (each line: keyfile<TAB>type<TAB>sha256-fingerprint).
#
# Severity:
#   ok    → no delta
#   warn  → a host key REMOVED (key-type retired) or ADDED (new
#           key-type enabled — e.g. ed25519 added)
#   alert → an EXISTING key-type's fingerprint CHANGED (identity
#           swap — the MITM/reinstall signature)

set -u

PROFILE="${SELFDEF_HOSTKEY_PROFILE:-report}"
BASELINE="${SELFDEF_HOSTKEY_BASELINE:-/var/lib/selfdef/ssh-hostkey-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

for pub in /etc/ssh/ssh_host_*_key.pub; do
    [[ -f "$pub" ]] || continue
    # ssh-keygen -lf prints: <bits> SHA256:<fp> <comment> (<TYPE>)
    line=$(ssh-keygen -lf "$pub" 2>/dev/null) || continue
    fp=$(echo "$line" | awk '{print $2}')
    type=$(echo "$line" | grep -oE '\([A-Z0-9-]+\)$' | tr -d '()')
    [[ -z "$type" ]] && type=$(basename "$pub" | sed -E 's/ssh_host_(.*)_key.pub/\1/')
    printf '%s\t%s\t%s\n' "$(basename "$pub")" "$type" "$fp"
done | sort -u > "$current"

cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-ssh-hostkey -- "$(printf '{"tag":"selfdef-ssh-hostkey","severity":"ok","event":"baseline_initial","profile":"%s","host_keys":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# A CHANGED key = same keyfile present in both added + removed
# (the fp differs). That's the high-severity identity-swap.
changed=0
changed_sample=()
if [[ -n "$added" && -n "$removed" ]]; then
    while IFS=$'\t' read -r kf ty fp; do
        [[ -z "$kf" ]] && continue
        if printf '%s' "$removed" | grep -qF "$(printf '%s\t' "$kf")"; then
            changed=$((changed + 1))
            (( ${#changed_sample[@]} < 6 )) && changed_sample+=("${kf}:${ty}")
        fi
    done <<< "$added"
fi

severity="ok"; event="hostkeys_intact"
if (( changed > 0 )); then
    severity="alert"; event="hostkey_changed"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="hostkey_set_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -6 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -6 | tr '\n' '|')
changed_str=$(IFS='|'; echo "${changed_sample[*]:-}")

json=$(printf '{"tag":"selfdef-ssh-hostkey","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"changed":%d,"changed_sample":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$changed" "$changed_str" "$added_sample" "$removed_sample")
logger -t selfdef-ssh-hostkey -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r kf ty fp; do [[ -n "$kf" ]] && logger -t selfdef-ssh-hostkey-detail -- "NOW ${kf} ${ty} ${fp}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r kf ty fp; do [[ -n "$kf" ]] && logger -t selfdef-ssh-hostkey-detail -- "WAS ${kf} ${ty} ${fp}"; done

# Refresh baseline so a confirmed-legit rotation becomes trusted.
cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
