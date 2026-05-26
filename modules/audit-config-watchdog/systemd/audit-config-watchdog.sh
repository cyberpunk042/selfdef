#!/usr/bin/env bash
# selfdef audit-config-watchdog — daily + boot delta of the
# Linux audit subsystem state.
#
# Captures:
#   rules:<count>           — number of loaded auditctl rules
#   enabled:<0|1|2>         — auditctl -s enabled flag (2=locked)
#   auditd:<active|...>     — systemctl is-active auditd
#   conf:<file>:<sha256-12> — /etc/audit/auditd.conf + rules.d/*
#
# An attacker blinding the host runs `auditctl -D` (flush all
# rules), `systemctl stop auditd`, or `auditctl -e 0` (disable).
# All show as a delta: rule count drops to ~0, enabled flips,
# or auditd goes inactive. That's T1562.001 Impair Defenses.
#
# Severity:
#   ok    → no delta
#   warn  → conf-file change OR rule count changed but >0
#   alert → rules dropped to 0 / huge drop, auditd disabled,
#           or enabled flag turned off

set -u

PROFILE="${SELFDEF_AUDITCFG_PROFILE:-report}"
BASELINE="${SELFDEF_AUDITCFG_BASELINE:-/var/lib/selfdef/audit-config-baseline.tsv}"

current="$(mktemp)"
trap 'rm -f "$current"' EXIT

# Loaded rule count + enabled flag (auditctl needs root; runs
# as root via the unit).
rule_count=0
enabled="?"
if command -v auditctl >/dev/null 2>&1; then
    rule_count=$(auditctl -l 2>/dev/null | grep -vc '^No rules$' || echo 0)
    # auditctl -l prints "No rules" (1 line) when empty → normalize.
    auditctl -l 2>/dev/null | grep -q '^No rules$' && rule_count=0
    enabled=$(auditctl -s 2>/dev/null | awk '/^enabled/{print $2; exit}')
    [[ -z "$enabled" ]] && enabled="?"
fi
printf 'rules\t%s\n' "$rule_count" >> "$current"
printf 'enabled\t%s\n' "$enabled" >> "$current"

# auditd service state.
adstate="unknown"
if command -v systemctl >/dev/null 2>&1; then
    adstate=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
fi
printf 'auditd\t%s\n' "$adstate" >> "$current"

# Config file hashes.
for f in /etc/audit/auditd.conf /etc/audit/audit.rules; do
    [[ -f "$f" ]] && printf 'conf\t%s\t%s\n' "$f" "$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')" >> "$current"
done
if [[ -d /etc/audit/rules.d ]]; then
    for f in /etc/audit/rules.d/*; do
        [[ -f "$f" ]] && printf 'conf\t%s\t%s\n' "$f" "$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')" >> "$current"
    done
fi

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    logger -t selfdef-audit-config -- "$(printf '{"tag":"selfdef-audit-config","severity":"ok","event":"baseline_initial","profile":"%s","rule_count":%s,"auditd":"%s"}' "$PROFILE" "$rule_count" "$adstate")"
    exit 0
fi

# Pull baseline values for the key signals.
base_rules=$(awk -F'\t' '$1=="rules"{print $2}' "$BASELINE" | head -1)
base_enabled=$(awk -F'\t' '$1=="enabled"{print $2}' "$BASELINE" | head -1)
base_auditd=$(awk -F'\t' '$1=="auditd"{print $2}' "$BASELINE" | head -1)
conf_changes=$(comm -13 <(grep '^conf' "$BASELINE" | sort -u) <(grep '^conf' "$current" | sort -u) | grep -c . || true)

severity="ok"; event="audit_intact"
reasons=()

# auditd turned off?
if [[ "$base_auditd" == "active" && "$adstate" != "active" ]]; then
    severity="alert"; event="auditd_disabled"; reasons+=("auditd:${base_auditd}->${adstate}")
fi
# enabled flag flipped off?
if [[ "$base_enabled" =~ ^[12]$ && "$enabled" == "0" ]]; then
    severity="alert"; event="audit_disabled_flag"; reasons+=("enabled:${base_enabled}->${enabled}")
fi
# rule count collapsed?
if [[ "$base_rules" =~ ^[0-9]+$ && "$rule_count" =~ ^[0-9]+$ ]]; then
    if (( rule_count == 0 && base_rules > 0 )); then
        severity="alert"; event="audit_rules_flushed"; reasons+=("rules:${base_rules}->0")
    elif (( rule_count < base_rules )); then
        [[ "$severity" == "ok" ]] && { severity="warn"; event="audit_rules_reduced"; }
        reasons+=("rules:${base_rules}->${rule_count}")
    fi
fi
# conf changed (without the above) = warn.
if (( conf_changes > 0 )) && [[ "$severity" == "ok" ]]; then
    severity="warn"; event="audit_conf_changed"; reasons+=("conf_changes:${conf_changes}")
fi

reason_str=$(IFS='|'; echo "${reasons[*]:-}")
json=$(printf '{"tag":"selfdef-audit-config","severity":"%s","event":"%s","profile":"%s","rule_count":%s,"baseline_rules":%s,"enabled":"%s","auditd":"%s","conf_changes":%d,"reasons":"%s"}' \
    "$severity" "$event" "$PROFILE" "$rule_count" "${base_rules:-0}" "$enabled" "$adstate" "$conf_changes" "$reason_str")
logger -t selfdef-audit-config -- "$json"

# Refresh state so a legit reduce re-baselines on next run only
# via operator action; here we DO update so transient is not
# re-alerted forever — but the alert already fired this run.
cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
