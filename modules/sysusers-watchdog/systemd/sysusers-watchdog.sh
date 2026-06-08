#!/usr/bin/env bash
# selfdef sysusers-watchdog — boot + daily delta of the
# systemd-sysusers declarations vs a learned baseline + ownership +
# semantic scan.
#
# systemd-sysusers creates the declared users/groups AT BOOT (and on
# package install) from:
#   /etc/sysusers.d/*.conf   (admin)
#   /run/sysusers.d/*.conf   (runtime)
# Line format (whitespace-separated):
#   Type Name ID GECOS Home Shell
#   u  name  uid[:gid]  "gecos"  /home  /shell   (create user)
#   g  name  gid                                  (create group)
#   m  name  group                                (add user to group)
#   r  -     from-to                              (reserve id range)
# A planted declaration is a backdoor account/group created
# automatically and idempotently — it reappears at every boot even
# if deleted (T1136 create account / T1098 account manipulation).
# Distinct from account-watchdog (live /etc/passwd state): this
# watches the DECLARATIONS that regenerate accounts.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each .conf
#   own:<path>:<owner:mode>  — owner + mode
#   ent:<path>:<type>:<name>:<id>  — each declaration entry
#
# Severity:
#   ok    → no delta
#   warn  → an entry added / changed / removed
#   alert → a .conf world-writable/non-root, OR a `u` entry with
#           UID 0, OR an `m` membership into a privileged group

set -u

PROFILE="${SELFDEF_SYSUSERS_PROFILE:-report}"
BASELINE="${SELFDEF_SYSUSERS_BASELINE:-/var/lib/selfdef/sysusers-baseline.tsv}"
if [[ -n "${SELFDEF_SYSUSERS_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_SYSUSERS_DIRS}"
else
    DIRS=(/etc/sysusers.d /run/sysusers.d)
fi
# Privileged groups: membership grants escalation.
PRIV_GROUPS="${SELFDEF_SYSUSERS_PRIV_GROUPS:-root sudo wheel adm docker lxd disk shadow kvm systemd-journal}"

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-sysusers -- '{"tag":"selfdef-sysusers","severity":"ok","event":"no_sysusers","profile":"'"$PROFILE"'"}'
    exit 0
fi

is_priv_group() {
    local g="$1" p
    for p in $PRIV_GROUPS; do [[ "$g" == "$p" ]] && return 0; done
    return 1
}

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    owner=$(stat -L -c '%U' "$f" 2>/dev/null || echo '?')
    mode=$(stat -L -c '%a' "$f" 2>/dev/null || echo '?')
    printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
    base="$(basename "$f")"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("${base}:world-writable($mode)")
    elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
        suspicious+=("${base}:owned-by-$owner")
    fi
    # Field 3 (id / group) is robust: it precedes the quotable GECOS.
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        read -r typ name id _rest <<< "$line"
        [[ -z "$typ" ]] && continue
        printf 'ent\t%s\t%s:%s:%s\n' "$f" "$typ" "${name:--}" "${id:--}" >> "$current"
        case "$typ" in
            u|u!)
                # UID 0 account = root-equivalent backdoor.
                if [[ "$id" == "0" || "$id" == 0:* ]]; then
                    suspicious+=("${base}:uid0-account(${name:--})")
                fi
                ;;
            m|m!)
                # membership: field 3 is the target group.
                if is_priv_group "$id"; then
                    suspicious+=("${base}:priv-group-member(${name:--}->${id})")
                fi
                ;;
        esac
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
    logger -t selfdef-sysusers -- "$(printf '{"tag":"selfdef-sysusers","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="sysusers_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="sysusers_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="sysusers_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-sysusers","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-sysusers -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sysusers-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sysusers-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
