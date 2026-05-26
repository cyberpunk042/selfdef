#!/usr/bin/env bash
# selfdef selfdef-self-integrity — the meta-watchdog. Hashes
# selfdef's own trust root + alerts on tampering.
#
# Every delta-watchdog (account/cron/suid/file-caps/listeners/
# kernel-modules/dns/ssh-authkeys/sudoers/systemd-units/pam/
# logfile/audit-config) trusts its baseline in /var/lib/selfdef.
# An attacker who learns this can edit a baseline to ADD their
# backdoor's signature — so the watchdog sees "no delta" + stays
# silent. This module hashes those baselines + the wrapper
# scripts that produce them + the module configs, and surfaces
# any change. It is the answer to "who watches the watchers".
#
# Tracked trust-root artifacts (each line: kind<TAB>path<TAB>sha):
#   baseline:/var/lib/selfdef/*.tsv         (every watchdog baseline)
#   wrapper:/usr/local/libexec/selfdef/*.sh (the detection scripts)
#   config:/etc/selfdef/modules/*.toml      (per-module profile)
#
# A CHANGE to a baseline outside a selfdef re-baseline, or to a
# wrapper script (someone patched the detector to lie), or to a
# config (someone flipped enforce->report to silence alerts) is
# the tamper signature.
#
# Severity:
#   ok    → no change since last manifest
#   warn  → a config .toml changed (could be legit profile switch)
#   alert → a baseline .tsv or wrapper .sh changed/removed/added
#           outside an expected window (detector tamper)

set -u

PROFILE="${SELFDEF_SELFINT_PROFILE:-report}"
MANIFEST="${SELFDEF_SELFINT_MANIFEST:-/var/lib/selfdef/self-integrity-manifest.tsv}"
STATE_DIR="${SELFDEF_STATE_DIR:-/var/lib/selfdef}"
LIBEXEC_DIR="${SELFDEF_LIBEXEC_DIR:-/usr/local/libexec/selfdef}"
MODULE_CONF_DIR="/etc/selfdef/modules"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# baselines (exclude our own manifest to avoid self-reference).
for f in "$STATE_DIR"/*.tsv; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$MANIFEST" ]] && continue
    printf 'baseline\t%s\t%s\n' "$f" "$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,16)}')"
done

# wrapper scripts (exclude THIS script to avoid self-reference
# churn on its own legitimate updates).
for f in "$LIBEXEC_DIR"/*.sh; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "selfdef-self-integrity.sh" ]] && continue
    printf 'wrapper\t%s\t%s\n' "$f" "$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,16)}')"
done

# module configs.
if [[ -d "$MODULE_CONF_DIR" ]]; then
    for f in "$MODULE_CONF_DIR"/*.toml; do
        [[ -f "$f" ]] || continue
        printf 'config\t%s\t%s\n' "$f" "$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,16)}')"
    done
fi

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$MANIFEST" ]]; then
    mkdir -p "$(dirname "$MANIFEST")"
    cp "$current" "$MANIFEST"
    chmod 0600 "$MANIFEST"
    logger -t selfdef-self-integrity -- "$(printf '{"tag":"selfdef-self-integrity","severity":"ok","event":"manifest_initial","profile":"%s","tracked":%d}' "$PROFILE" "$cur_count")"
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$MANIFEST"))
removed=$(comm -13 "$current" <(sort -u "$MANIFEST"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
# How many of the changes touch baselines or wrappers (the
# high-severity classes)?
n_critical=$(printf '%s\n%s' "$added" "$removed" | grep -cE '^(baseline|wrapper)' || true)

severity="ok"; event="trust_root_intact"
if (( n_critical > 0 )); then
    severity="alert"; event="trust_root_tampered"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="config_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')

json=$(printf '{"tag":"selfdef-self-integrity","severity":"%s","event":"%s","profile":"%s","tracked":%d,"added":%d,"removed":%d,"critical":%d,"added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$cur_count" "$n_added" "$n_removed" "$n_critical" "$added_sample" "$removed_sample")
logger -t selfdef-self-integrity -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p h; do [[ -n "$k" ]] && logger -t selfdef-self-integrity-detail -- "CHANGED ${k} ${p}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p h; do [[ -n "$k" ]] && logger -t selfdef-self-integrity-detail -- "WAS ${k} ${p}"; done

# Refresh manifest so a confirmed-legit change (operator re-
# baseline, profile switch, module update) becomes the new
# trusted state on the next run. The alert for THIS run already
# fired — the operator investigates, then it's the baseline.
cp "$current" "$MANIFEST" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
