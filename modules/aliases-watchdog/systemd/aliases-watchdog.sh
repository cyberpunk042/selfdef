#!/usr/bin/env bash
# selfdef aliases-watchdog — boot + daily delta of the mail aliases
# database vs a learned baseline + ownership + pipe/include scan.
#
# An alias of the form
#   name: |command
# makes the MTA run that command (as the default delivery user —
# often nobody/mail, sometimes root) whenever mail is delivered to
# the alias. This is the classic Unix mail-alias exec vector (the
# historic `decode:` alias RCE). A
#   name: :include:/path
# target reads recipients (and thus further pipe/file targets) from
# another file. A planted pipe alias — or one pointing at /tmp etc.,
# or a :include: of a writable file — is mail-triggered code
# execution / persistence (T1546.004), deliverable on demand by
# sending mail to the alias. Files watched:
#   /etc/aliases  /etc/mail/aliases  /etc/postfix/aliases
# Distinct from postfix-exec-watchdog (master.cf/main.cf service +
# command config): this is the alias-recipient pipe surface.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each aliases file
#   own:<path>:<owner:mode> — owner + mode
#   pipe:<path>:<command>   — a |command alias target
#   include:<path>:<inc>    — a :include: target file
#
# Severity:
#   ok    → no delta
#   warn  → a file / pipe / include added / changed / removed
#   alert → a file world-writable/non-root, a pipe command under
#           /tmp /var/tmp /dev/shm /home or with an injection pattern,
#           or a :include: of a file under those writable locations

set -u

PROFILE="${SELFDEF_ALIASES_PROFILE:-report}"
BASELINE="${SELFDEF_ALIASES_BASELINE:-/var/lib/selfdef/aliases-baseline.tsv}"
if [[ -n "${SELFDEF_ALIASES_FILES:-}" ]]; then
    read -r -a FILES <<< "${SELFDEF_ALIASES_FILES}"
else
    FILES=(/etc/aliases /etc/mail/aliases /etc/postfix/aliases)
fi

# SDD-061 D-6: consume the shared injection-pattern set + writable-
# location policy from module-lib instead of a per-module copy. Co-shipped
# by the .deb at /usr/share/selfdef/lib/module-lib.sh; selfdefctl exports
# SELFDEF_MODULE_LIB in a workspace. A missing or pre-v3 library is a real
# misconfiguration that would leave the watchdog scanning with a divergent/
# absent set, so we fail loud with a structured finding.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-aliases -- '{"tag":"selfdef-aliases","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 3 ]]; then
    logger -t selfdef-aliases -- '{"tag":"selfdef-aliases","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi
mapfile -t PATTERNS < <(selfdef_injection_patterns)

is_writable_path() { selfdef_is_writable_path "$1"; }

files=()
for f in "${FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-aliases -- '{"tag":"selfdef-aliases","severity":"ok","event":"no_aliases","profile":"'"$PROFILE"'"}'
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
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        # pipe targets: |command  (one or more per line, up to comma)
        while read -r piped; do
            [[ -z "$piped" ]] && continue
            cmd="${piped#|}"
            cmd="${cmd#\"}"; cmd="${cmd#"${cmd%%[![:space:]]*}"}"
            cmd="${cmd%\"}"; cmd="${cmd%"${cmd##*[![:space:]]}"}"
            [[ -z "$cmd" ]] && continue
            printf 'pipe\t%s\t%s\n' "$f" "$cmd" >> "$current"
            prog="${cmd%%[[:space:]]*}"
            if is_writable_path "$prog"; then
                suspicious+=("${base}:pipe-writable($prog)")
            fi
            for pat in "${PATTERNS[@]}"; do
                if printf '%s\n' "$cmd" | grep -qE "$pat"; then
                    suspicious+=("${base}:pipe:$pat")
                fi
            done
        done < <(printf '%s\n' "$line" | grep -oE '\|[^,]*')
        # :include: targets
        while read -r inc; do
            inc="${inc#:include:}"
            inc="${inc#"${inc%%[![:space:]]*}"}"; inc="${inc%"${inc##*[![:space:]]}"}"
            [[ -z "$inc" ]] && continue
            printf 'include\t%s\t%s\n' "$f" "$inc" >> "$current"
            if is_writable_path "$inc"; then
                suspicious+=("${base}:include-writable($inc)")
            fi
        done < <(printf '%s\n' "$line" | grep -oE ':include:[^,[:space:]]*')
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
    logger -t selfdef-aliases -- "$(printf '{"tag":"selfdef-aliases","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="aliases_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="aliases_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="aliases_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-aliases","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-aliases -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-aliases-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-aliases-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
