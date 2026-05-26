#!/usr/bin/env bash
# selfdef nsswitch-watchdog — boot + daily delta of the Name
# Service Switch map (/etc/nsswitch.conf) vs a learned baseline.
#
# nsswitch.conf maps each identity/name database (passwd, group,
# shadow, hosts, networks, services, ...) to an ORDERED list of
# lookup sources. Each source name `X` resolves at runtime to a
# shared object libnss_X.so loaded into every process that calls
# getpwnam/getgrnam/gethostbyname/etc. An attacker who appends a
# rogue source —
#
#   passwd:  files evil          # backed by /lib/libnss_evil.so.2
#
# — backdoors identity + auth resolution for the WHOLE host: the
# trojaned module can inject a phantom UID-0 account, leak every
# credential lookup, or redirect host resolution (T1556 / T1574).
# Distinct from pam-config (the PAM stack) and ld-so-conf (the
# linker search path): this is the resolver-source map itself.
#
# Records (each line: kind<TAB>value):
#   db:<database>:<sources>  — each db line + its normalized
#                              source list (catches add/remove/
#                              reorder of a source on any db)
#   file:<conf>:<sha12>      — hash of nsswitch.conf (catches an
#                              edit that the db parse misses)
#
# A source token that is NOT a known-standard NSS provider means
# a custom libnss_<token>.so is wired into name resolution — the
# rogue-module signature — and is flagged hard.
#
# Severity:
#   ok    → no delta
#   warn  → file hash changed / a known source added/reordered
#   alert → an UNKNOWN (non-standard) source appears on any db,
#           OR a database line removed

set -u

PROFILE="${SELFDEF_NSSWITCH_PROFILE:-report}"
BASELINE="${SELFDEF_NSSWITCH_BASELINE:-/var/lib/selfdef/nsswitch-baseline.tsv}"
CONF="${SELFDEF_NSSWITCH_CONF:-/etc/nsswitch.conf}"

# Known-standard NSS service providers (glibc + systemd + the
# common directory integrations). Anything else on a db line is
# a custom libnss_<name>.so — the thing we flag.
KNOWN_NSS=" files dns db compat systemd mymachines nis nisplus ldap sss sssd winbind mdns mdns4 mdns6 mdns_minimal mdns4_minimal mdns6_minimal resolve myhostname gw_name hesiod wins cache "

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

if [[ -f "$CONF" ]]; then
    h=$(sha256sum "$CONF" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$CONF" "$h" >> "$current"

    # Parse each "database: source [action] source ..." line.
    while IFS= read -r line; do
        line="${line%%#*}"                       # strip comment
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" == *:* ]] || continue
        db="${line%%:*}"
        db="${db//[[:space:]]/}"
        [[ -z "$db" ]] && continue
        rest="${line#*:}"
        # Normalize source list: collapse whitespace to single
        # spaces, trim. Keep action brackets verbatim (they are
        # part of the meaningful config).
        sources="$(printf '%s' "$rest" | tr '\t' ' ' | tr -s ' ' | sed -e 's/^ *//' -e 's/ *$//')"
        printf 'db\t%s\t%s\n' "$db" "$sources" >> "$current"
        # Scan tokens for unknown providers.
        for tok in $sources; do
            [[ "$tok" == \[* ]] && continue       # action bracket
            [[ "$tok" == *\] ]] && continue       # bracket tail
            case " $KNOWN_NSS " in
                *" $tok "*) ;;                    # known provider
                *) suspicious+=("$db:$tok") ;;    # rogue module
            esac
        done
    done < "$CONF"
fi

{ sort -u > "${current}.sorted"; } < "$current" && mv "${current}.sorted" "$current"
cur_count=$(wc -l < "$current" | tr -d ' ')

# Dedup the suspicious list.
if (( ${#suspicious[@]} > 0 )); then
    mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)
fi

if [[ ! -f "$BASELINE" ]]; then
    mkdir -p "$(dirname "$BASELINE")"
    cp "$current" "$BASELINE"
    chmod 0600 "$BASELINE"
    susp_str=$(IFS='|'; echo "${suspicious[*]:-}")
    sev="ok"; [[ ${#suspicious[@]} -gt 0 ]] && sev="alert"
    logger -t selfdef-nsswitch -- "$(printf '{"tag":"selfdef-nsswitch","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# True database removal = a db NAME present in the baseline but
# absent now (a whole database mapping deleted). A db line whose
# SOURCE LIST merely changed shows up in comm as remove-old +
# add-new, so we must compare the name set, not the line set, or
# every benign edit would over-escalate to the db_removed alert.
base_names=$(grep '^db' "$BASELINE" 2>/dev/null | cut -f2 | sort -u)
cur_names=$(grep '^db' "$current"  2>/dev/null | cut -f2 | sort -u)
db_name_removed=$(comm -23 <(printf '%s\n' "$base_names") <(printf '%s\n' "$cur_names") | grep -c . || true)

severity="ok"; event="nsswitch_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="nsswitch_rogue_source"
elif (( db_name_removed > 0 )); then
    severity="alert"; event="nsswitch_db_removed"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="nsswitch_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-nsswitch","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-nsswitch -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k v s; do [[ -n "$k" ]] && logger -t selfdef-nsswitch-detail -- "ADDED ${k} ${v} ${s}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k v s; do [[ -n "$k" ]] && logger -t selfdef-nsswitch-detail -- "REMOVED ${k} ${v} ${s}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
