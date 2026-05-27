#!/usr/bin/env bash
# selfdef pam-config-watchdog — daily + boot delta of the PAM
# configuration vs a learned baseline.
#
# Two surfaces:
#   1. /etc/pam.d/* config LINES (the auth stack). A new
#      "auth sufficient pam_evil.so" line that accepts a magic
#      password is the classic PAM backdoor.
#   2. The on-disk pam_*.so MODULE set + hashes (the security/
#      pam lib dir). A replaced pam_unix.so (patched to log
#      passwords / accept a backdoor) changes its hash.
#
# Records (each line: kind<TAB>id<TAB>detail):
#   pamline:<file>:<rule>      (rule = type+control+module, args dropped)
#   pammod:<path>:<sha256-12>
#
# Severity:
#   ok    → no delta
#   warn  → line/module removed
#   alert → line added OR module added/hash-changed

set -u

PROFILE="${SELFDEF_PAMCFG_PROFILE:-report}"
BASELINE="${SELFDEF_PAMCFG_BASELINE:-/var/lib/selfdef/pam-config-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# 1. /etc/pam.d config lines (normalized: type control module,
#    args dropped so tuning args don't create churn but a NEW
#    module or control change shows).
if [[ -d /etc/pam.d ]]; then
    for f in /etc/pam.d/*; do
        [[ -f "$f" ]] || continue
        grep -vE '^\s*(#|$|@include)' "$f" 2>/dev/null \
          | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' \
          | awk '{print $1" "$2" "$3}' \
          | while IFS= read -r rule; do
                [[ -z "$rule" ]] && continue
                printf 'pamline\t%s\t%s\n' "$(basename "$f")" "$rule" >> "$current"
            done
    done
fi

# 2. pam_*.so module hashes from the standard lib dirs.
for d in /lib/x86_64-linux-gnu/security /lib64/security \
         /usr/lib/x86_64-linux-gnu/security /usr/lib64/security \
         /lib/security /usr/lib/security; do
    [[ -d "$d" ]] || continue
    for so in "$d"/pam_*.so; do
        [[ -f "$so" ]] || continue
        h=$(sha256sum "$so" 2>/dev/null | awk '{print $1}')
        printf 'pammod\t%s\t%s\n' "$so" "${h:0:12}" >> "$current"
    done
done

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-pam-config -- "$(printf '{"tag":"selfdef-pam-config","severity":"ok","event":"baseline_initial","profile":"%s","baseline_count":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="no_delta"
if (( n_added > 0 )); then
    severity="alert"; event="pam_config_changed"
elif (( n_removed > 0 )); then
    severity="warn"; event="pam_config_removed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-pam-config","severity":"%s","event":"%s","profile":"%s","baseline_count":%d,"current_count":%d,"added":%d,"removed":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" \
    "$(wc -l < "$BASELINE" | tr -d ' ')" "$cur_count" \
    "$n_added" "$n_removed" "$added_sample" "$removed_sample")
logger -t selfdef-pam-config -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k id d; do [[ -n "$k" ]] && logger -t selfdef-pam-config-detail -- "ADDED ${k} ${id} ${d}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k id d; do [[ -n "$k" ]] && logger -t selfdef-pam-config-detail -- "REMOVED ${k} ${id} ${d}"; done

if [[ "$PROFILE" == "enforce" ]] && (( n_added > 0 )); then
    exit 1
fi
exit 0
