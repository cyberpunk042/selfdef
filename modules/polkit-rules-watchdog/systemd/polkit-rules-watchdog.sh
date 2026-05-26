#!/usr/bin/env bash
# selfdef polkit-rules-watchdog — boot + daily delta of the
# admin/local polkit authorization rules vs a learned baseline.
#
# polkitd evaluates these AS ROOT to decide whether a subject may
# perform a privileged action (mount, install packages, manage
# units, reboot, …). A rogue rule grants privilege escalation:
#
#   # /etc/polkit-1/rules.d/99-evil.rules  (modern JS)
#   polkit.addRule(function(action, subject) {
#       return polkit.Result.YES;            // any action, any subject
#   });
#
#   # /etc/polkit-1/localauthority/50-local.d/evil.pkla  (legacy)
#   [allow]
#   Identity=unix-user:*
#   Action=*
#   ResultActive=yes
#
# Both let an unprivileged user run any polkit action as root —
# quiet privesc persistence (T1548). These admin dirs are
# sparsely populated, so a new rule is high-signal.
#
# Watched (admin / local / runtime — attacker-writable):
#   /etc/polkit-1/rules.d/*.rules
#   /usr/local/share/polkit-1/rules.d/*.rules
#   /run/polkit-1/rules.d/*.rules
#   /etc/polkit-1/localauthority/**/*.pkla
#   /var/lib/polkit-1/localauthority/**/*.pkla
# NOT /usr/share/polkit-1/rules.d (package-managed).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each rule/pkla file
#   own:<path>:<owner:mode>  — owner + mode
#   grant:<path>:<kind>      — YES (a .rules Result.YES) or a
#                              .pkla blanket allow (informational +
#                              escalates a NEW grant to alert)
#
# Severity:
#   ok    → no delta
#   warn  → a rule changed or removed
#   alert → a NEW rule file, OR one world-writable / non-root, OR
#           a NEW file that grants authorization (Result.YES /
#           ResultActive=yes)

set -u

PROFILE="${SELFDEF_POLKIT_PROFILE:-report}"
BASELINE="${SELFDEF_POLKIT_BASELINE:-/var/lib/selfdef/polkit-rules-baseline.tsv}"
if [[ -n "${SELFDEF_POLKIT_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_POLKIT_DIRS}"
else
    DIRS=(
        /etc/polkit-1/rules.d
        /usr/local/share/polkit-1/rules.d
        /run/polkit-1/rules.d
        /etc/polkit-1/localauthority/50-local.d
        /etc/polkit-1/localauthority/90-mandatory.d
        /var/lib/polkit-1/localauthority/50-local.d
        /var/lib/polkit-1/localauthority/90-mandatory.d
    )
fi

have=0
for d in "${DIRS[@]}"; do [[ -d "$d" ]] && { have=1; break; }; done
if [[ "$have" -eq 0 ]]; then
    logger -t selfdef-polkit-rules -- '{"tag":"selfdef-polkit-rules","severity":"ok","event":"no_polkit_rules","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.rules "$d"/*.pkla; do
        [[ -f "$f" ]] || continue
        h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
        printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
        owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
        mode=$(stat -c '%a' "$f" 2>/dev/null || echo '?')
        printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
        if [[ "$mode" =~ [2367]$ ]]; then
            suspicious+=("$(basename "$f"):world-writable($mode)")
        elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
            suspicious+=("$(basename "$f"):owned-by-$owner")
        fi
        # Does this file GRANT authorization?
        if grep -qE 'polkit\.Result\.YES|ResultActive[[:space:]]*=[[:space:]]*yes|ResultAny[[:space:]]*=[[:space:]]*yes|ResultInactive[[:space:]]*=[[:space:]]*yes' "$f" 2>/dev/null; then
            printf 'grant\t%s\t%s\n' "$f" "YES" >> "$current"
        fi
    done
done

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if (( ${#suspicious[@]} > 0 )); then
    mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)
fi

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp_str=$(IFS='|'; echo "${suspicious[*]:-}")
    sev="ok"; [[ ${#suspicious[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-polkit-rules -- "$(printf '{"tag":"selfdef-polkit-rules","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# A NEW rule file (new PATH, not a content edit) is high-signal —
# these dirs are sparse. A NEW grant likewise. Compare path sets.
base_paths=$(grep '^file' "$BASELINE" 2>/dev/null | cut -f2 | sort -u)
cur_paths=$(grep '^file' "$current"  2>/dev/null | cut -f2 | sort -u)
new_paths=$(comm -23 <(printf '%s\n' "$cur_paths") <(printf '%s\n' "$base_paths") | grep -c . || true)
new_grant=$(printf '%s' "$added" | grep -c '^grant' || true)

severity="ok"; event="polkit_rules_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="polkit_rules_suspicious"
elif (( new_paths > 0 || new_grant > 0 )); then
    severity="alert"; event="polkit_rules_new"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="polkit_rules_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-polkit-rules","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-polkit-rules -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-polkit-rules-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-polkit-rules-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
