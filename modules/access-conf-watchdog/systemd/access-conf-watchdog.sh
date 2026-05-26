#!/usr/bin/env bash
# selfdef access-conf-watchdog — boot + daily delta of the
# pam_access login-access-control rules vs a learned baseline.
#
# When pam_access.so is in the PAM stack (account phase), the
# rules in /etc/security/access.conf decide WHO may log in FROM
# WHERE. Format (first match wins):
#
#   permission : users/groups : origins
#   -  : ALL EXCEPT root admins : ALL        # lock down
#   +  : eviluser : ALL                       # attacker grant
#
# An attacker who appends a broad PERMIT rule grants themselves
# login access from anywhere; one who removes a DENY rule
# weakens the lockdown — both are quiet access persistence
# (T1556 / T1098). pam-config-watchdog watches the PAM STACK
# (whether pam_access is even invoked); this watches the RULE
# DATA the module reads.
#
# Records (each line: kind<TAB>...):
#   file:<path>:<sha12>            — hash of access.conf + access.d/*
#   rule:<perm>:<users>:<origins>  — each normalized rule
#
# Severity:
#   ok    → no delta
#   warn  → any rule added / removed / changed
#   alert → a PERMIT (+) rule whose origin is ALL/broad (a
#           permit-from-anywhere grant — the backdoor signature)

set -u

PROFILE="${SELFDEF_ACCESSCONF_PROFILE:-report}"
BASELINE="${SELFDEF_ACCESSCONF_BASELINE:-/var/lib/selfdef/access-conf-baseline.tsv}"
ACCESS="${SELFDEF_ACCESSCONF_FILE:-/etc/security/access.conf}"
ACCESSD="${SELFDEF_ACCESSCONF_D:-/etc/security/access.d}"

files=()
[[ -f "$ACCESS" ]] && files+=("$ACCESS")
if [[ -d "$ACCESSD" ]]; then
    for f in "$ACCESSD"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-access-conf -- '{"tag":"selfdef-access-conf","severity":"ok","event":"no_access_conf","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    while IFS= read -r line; do
        line="${line%%#*}"
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        # Fields are ':'-separated: perm : users : origins
        IFS=':' read -r perm users origins _ <<< "$line"
        perm="${perm//[[:space:]]/}"
        users="$(printf '%s' "${users:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr -s '[:space:]' ' ')"
        origins="$(printf '%s' "${origins:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr -s '[:space:]' ' ')"
        [[ -z "$perm" ]] && continue
        printf 'rule\t%s\t%s\t%s\n' "$perm" "$users" "$origins" >> "$current"
        # A permit (+) rule that allows from ALL/broad origin is
        # the backdoor-access signature.
        if [[ "$perm" == "+" ]]; then
            case " ${origins^^} " in
                *" ALL "*) suspicious+=("permit:${users}:from-ALL") ;;
            esac
        fi
    done < "$f"
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
    logger -t selfdef-access-conf -- "$(printf '{"tag":"selfdef-access-conf","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# A broad permit is the backdoor signature only when NEWLY ADDED.
# A pre-existing legit `+ : (wheel) : ALL` lives in the baseline and
# must NOT re-alert every scan, so scan the ADDED set rather than the
# whole file. (baseline_initial above still flags pre-existing broad
# permits once, for operator vetting.)
new_broad=$(printf '%s' "$added" | awk -F'\t' '$1=="rule" && $2=="+" && toupper($4) ~ /(^| )ALL( |$)/ {print "permit:"$3":from-ALL"}')
suspicious=()
[[ -n "$new_broad" ]] && mapfile -t suspicious <<< "$new_broad"

severity="ok"; event="access_conf_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="access_conf_broad_permit"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="access_conf_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3":"$4}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3":"$4}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-access-conf","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-access-conf -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k a b c; do [[ -n "$k" ]] && logger -t selfdef-access-conf-detail -- "ADDED ${k} ${a} ${b} ${c}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k a b c; do [[ -n "$k" ]] && logger -t selfdef-access-conf-detail -- "REMOVED ${k} ${a} ${b} ${c}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
