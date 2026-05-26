#!/usr/bin/env bash
# selfdef capability-conf-watchdog — boot + daily delta of the
# pam_cap capability-grant config vs a learned baseline.
#
# When pam_cap.so is in the PAM stack (auth/session), the lines in
# /etc/security/capability.conf grant Linux capabilities to users
# at login. Format: `<cap-list> <user>`, e.g.
#
#   cap_net_raw,cap_net_admin   netadmin       # legit, scoped
#   cap_setuid,cap_sys_admin    eviluser       # privesc grant
#   all                         backdoor       # full caps = root
#
# A high-power capability granted to a user is privilege
# escalation without setuid or sudo (T1548): cap_setuid →
# become any uid; cap_dac_override → bypass all file perms;
# cap_sys_admin / cap_sys_module → effectively root; cap_sys_ptrace
# → inject into root processes; `all` → root.
#
# Records (each line: kind<TAB>key<TAB>value):
#   cap:<user>:<caplist>   — each capability grant
#   file:<path>:<sha12>    — hash of capability.conf
#
# Severity:
#   ok    → no delta
#   warn  → any grant added / removed / changed
#   alert → a NEWLY-ADDED grant containing a dangerous capability
#           (cap_setuid, cap_setgid, cap_sys_admin, cap_sys_module,
#            cap_dac_override, cap_dac_read_search, cap_sys_ptrace,
#            cap_fowner, cap_mknod, cap_sys_rawio, or `all`)

set -u

PROFILE="${SELFDEF_CAPCONF_PROFILE:-report}"
BASELINE="${SELFDEF_CAPCONF_BASELINE:-/var/lib/selfdef/capability-conf-baseline.tsv}"
CAPCONF="${SELFDEF_CAPCONF_FILE:-/etc/security/capability.conf}"

# Capabilities whose grant to a user is privilege-escalation-grade.
DANGER_CAPS=" cap_setuid cap_setgid cap_sys_admin cap_sys_module cap_dac_override cap_dac_read_search cap_sys_ptrace cap_fowner cap_mknod cap_sys_rawio cap_chown cap_setfcap all "

if [[ ! -f "$CAPCONF" ]]; then
    logger -t selfdef-capability-conf -- '{"tag":"selfdef-capability-conf","severity":"ok","event":"no_capability_conf","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

# Echo a dangerous-cap tag for any danger cap present in a grant line.
scan_dangerous() {  # caplist user
    local caps="$1" user="$2" c
    # caplist is comma- or space-separated.
    local norm; norm=$(printf '%s' "$caps" | tr ',' ' ' | tr '[:upper:]' '[:lower:]')
    for c in $norm; do
        case " $DANGER_CAPS " in
            *" $c "*) echo "${user}:${c}" ;;
        esac
    done
}

declare -a baseline_susp=()

while IFS= read -r line; do
    line="${line%%#*}"
    read -r -a F <<< "$line"
    [[ ${#F[@]} -lt 2 ]] && continue
    caps="${F[0]}"; user="${F[1]}"
    printf 'cap\t%s\t%s\n' "$user" "$caps" >> "$current"
    while IFS= read -r tag; do
        [[ -n "$tag" ]] && baseline_susp+=("$tag")
    done < <(scan_dangerous "$caps" "$user")
done < "$CAPCONF"

h=$(sha256sum "$CAPCONF" 2>/dev/null | awk '{print substr($1,1,12)}')
printf 'file\t%s\t%s\n' "$CAPCONF" "$h" >> "$current"

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp=()
    (( ${#baseline_susp[@]} > 0 )) && mapfile -t susp < <(printf '%s\n' "${baseline_susp[@]}" | sort -u)
    susp_str=$(IFS='|'; echo "${susp[*]:-}")
    sev="ok"; [[ ${#susp[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-capability-conf -- "$(printf '{"tag":"selfdef-capability-conf","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Dangerous detection only on NEWLY-ADDED cap grants.
declare -a suspicious=()
while IFS= read -r aline; do
    [[ "$aline" == cap$'\t'* ]] || continue
    IFS=$'\t' read -r _k user caps <<< "$aline"
    while IFS= read -r tag; do
        [[ -n "$tag" ]] && suspicious+=("$tag")
    done < <(scan_dangerous "$caps" "$user")
done <<< "$added"
(( ${#suspicious[@]} > 0 )) && mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)

severity="ok"; event="capability_conf_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="capability_conf_dangerous_grant"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="capability_conf_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-capability-conf","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-capability-conf -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-capability-conf-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-capability-conf-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
