#!/usr/bin/env bash
# selfdef krb5-plugins-watchdog — boot + daily delta of the MIT
# Kerberos config plugin registrations vs a learned baseline +
# ownership + module-path scan.
#
# The krb5 [plugins] section registers .so plugins loaded into kinit,
# the KDC (krb5kdc), kadmind, sshd's GSSAPI, and sssd:
#   [plugins]
#     clpreauth = { module = NAME:/path/to/plugin.so }
#     kdcpreauth = { module = NAME:/path/to/plugin.so }
#     (also pwqual, kadm5_hook, certauth, localauth, hostrealm, …)
# from /etc/krb5.conf and /etc/krb5.conf.d/*.conf. A planted
#   module = clpreauth:/tmp/evil.so
# loads attacker code directly into the Kerberos authentication path
# (T1574 hijack execution flow / T1556 modify authentication
# process). Distinct from gss-mech-watchdog (GSSAPI mechanism glue)
# and pkcs11-modules-watchdog.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>          — hash of each krb5 config
#   own:<path>:<owner:mode>      — owner + mode
#   module:<path>:<name>:<so>    — each [plugins] module .so
#
# Severity:
#   ok    → no delta
#   warn  → a module / file added / changed / removed
#   alert → a config world-writable/non-root, OR a module .so under
#           /tmp /var/tmp /dev/shm /home or relative-with-slash

set -u

PROFILE="${SELFDEF_KRB5_PROFILE:-report}"
BASELINE="${SELFDEF_KRB5_BASELINE:-/var/lib/selfdef/krb5-plugins-baseline.tsv}"
if [[ -n "${SELFDEF_KRB5_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_KRB5_DIRS}"
else
    DIRS=(/etc/krb5.conf.d)
fi
if [[ -n "${SELFDEF_KRB5_FILES:-}" ]]; then
    read -r -a EXTRA_FILES <<< "${SELFDEF_KRB5_FILES}"
else
    EXTRA_FILES=(/etc/krb5.conf)
fi

files=()
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done
for f in "${EXTRA_FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-krb5-plugins -- '{"tag":"selfdef-krb5-plugins","severity":"ok","event":"no_krb5_config","profile":"'"$PROFILE"'"}'
    exit 0
fi

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
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("${base}:owned-by-$owner")
    fi
    # [plugins] module = NAME:PATH  -> load PATH as a .so.  Handle both
    # the own-line form and the inline 'subsection = { module = ... }'
    # form; the 'module' key may sit mid-line after a '{'.
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*[#\;] ]] && continue
        # value after the 'module =' token (greedy .* cuts to the token)
        val=$(printf '%s' "$line" | sed -E 's/.*module[[:space:]]*=[[:space:]]*//I')
        val="${val%"${val##*[![:space:]]}"}"   # rtrim
        val="${val%\}}"                          # strip a trailing brace
        val="${val%"${val##*[![:space:]]}"}"   # rtrim again
        [[ -z "$val" ]] && continue
        name="${val%%:*}"
        so="${val#*:}"
        [[ "$so" == "$val" ]] && continue   # no colon → not a module=name:path line
        so="${so#"${so%%[![:space:]]*}"}"; so="${so%"${so##*[![:space:]]}"}"
        [[ -z "$so" ]] && continue
        printf 'module\t%s\t%s:%s\n' "$f" "$name" "$so" >> "$current"
        if [[ "$so" =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; then
            suspicious+=("${base}:module-writable($name:$so)")
        elif [[ "$so" == */* && "$so" != /* ]]; then
            suspicious+=("${base}:module-relative-path($name:$so)")
        fi
    done < <(grep -iE '(^|[^a-zA-Z_])module[[:space:]]*=' "$f" 2>/dev/null || true)
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
    logger -t selfdef-krb5-plugins -- "$(printf '{"tag":"selfdef-krb5-plugins","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="krb5_plugins_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="krb5_plugins_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="krb5_plugins_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-krb5-plugins","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-krb5-plugins -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-krb5-plugins-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-krb5-plugins-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
