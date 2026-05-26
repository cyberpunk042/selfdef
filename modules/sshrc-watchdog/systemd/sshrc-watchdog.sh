#!/usr/bin/env bash
# selfdef sshrc-watchdog — boot + daily delta of the SSH login rc
# scripts vs a learned baseline + ownership + suspicious-pattern
# scan.
#
# sshd runs these AS THE LOGGING-IN USER on every SSH session:
#   /etc/ssh/sshrc   — run for any user that has NO ~/.ssh/rc
#   ~/.ssh/rc        — run instead of /etc/ssh/sshrc when present
#                      (root's is watched here; per-user rc is the
#                      home-dir surface)
# sshrc runs BEFORE the user's shell rc, on every SSH login — a
# planted one is exec-on-every-SSH-login persistence for every
# account lacking its own rc (T1546 / T1037). Distinct from
# sshd-config-watchdog (sshd_config), ssh-authkeys-watchdog
# (authorized_keys), ssh-client-config-watchdog (ssh_config), and
# shell-init-watchdog (bash/profile rc).
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each rc
#   own:<path>:<owner:mode> — owner + mode
#   susp:<path>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → an rc added / changed / removed
#   alert → an rc world-writable or non-root-owned, OR containing a
#           suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_SSHRC_PROFILE:-report}"
BASELINE="${SELFDEF_SSHRC_BASELINE:-/var/lib/selfdef/sshrc-baseline.tsv}"
if [[ -n "${SELFDEF_SSHRC_FILES:-}" ]]; then
    read -r -a FILES <<< "${SELFDEF_SSHRC_FILES}"
else
    FILES=(/etc/ssh/sshrc /root/.ssh/rc)
fi

PATTERNS=(
    'curl[^|;&]*\|[[:space:]]*(ba)?sh' 'wget[^|;&]*\|[[:space:]]*(ba)?sh'
    '/dev/tcp/' '/dev/udp/' 'nc[[:space:]]+.*-e' 'ncat[[:space:]]+.*-e'
    'bash[[:space:]]+-i' 'base64[[:space:]]+-d' 'base64[[:space:]]+--decode'
    'eval[[:space:]]*[`$]' 'python[0-9]*[[:space:]]+-c' 'perl[[:space:]]+-e'
    'mkfifo' 'setsid'
    '(^|[;&|][[:space:]]*)/(tmp|var/tmp|dev/shm|home)/'
)

files=()
for f in "${FILES[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-sshrc -- '{"tag":"selfdef-sshrc","severity":"ok","event":"no_sshrc","profile":"'"$PROFILE"'"}'
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
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("$f:world-writable($mode)")
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("$f:owned-by-$owner")
    fi
    scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$scan" | grep -qE "$pat"; then
            printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
            suspicious+=("$f:$pat")
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
    logger -t selfdef-sshrc -- "$(printf '{"tag":"selfdef-sshrc","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="sshrc_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="sshrc_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="sshrc_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-sshrc","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-sshrc -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sshrc-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sshrc-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
