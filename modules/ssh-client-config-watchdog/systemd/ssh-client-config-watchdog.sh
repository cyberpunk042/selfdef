#!/usr/bin/env bash
# selfdef ssh-client-config-watchdog — boot + daily delta of the
# SSH CLIENT config vs a learned baseline.
#
# The ssh client honours exec directives that run a shell command
# when it connects OUT (or when evaluating a Match):
#
#   ProxyCommand /tmp/.x %h %p          # runs on every ssh to a host
#   PermitLocalCommand yes
#   LocalCommand /tmp/.x                # runs after connect
#   Match exec "/tmp/.probe"            # runs to decide the match
#
# A directive pointing at /tmp /home /dev/shm, a world-writable
# target, or a fetch-pipe-shell payload is exec-on-ssh-out — a
# lateral-movement / persistence hook that fires whenever root (or
# a service) initiates ssh (T1059 / T1552.004). sshd-config-
# watchdog covers the SERVER; this is the outbound client side.
#
# Watched:
#   /etc/ssh/ssh_config  /etc/ssh/ssh_config.d/*.conf
#   /root/.ssh/config
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<path>:<sha12>      — hash of each config file
#   own:<path>:<owner:mode>  — owner + mode
#   exec:<path>:<directive>:<prog> — ProxyCommand/LocalCommand/
#                              Match-exec program (first token)
#
# Severity:
#   ok    → no delta
#   warn  → a file / directive added, removed, or changed
#   alert → an exec directive whose target is under /tmp /home
#           /dev/shm, world-writable, or bare/relative, OR a
#           fetch-pipe-shell pattern, OR a world-writable/non-root
#           config file

set -u

PROFILE="${SELFDEF_SSHCLIENT_PROFILE:-report}"
BASELINE="${SELFDEF_SSHCLIENT_BASELINE:-/var/lib/selfdef/ssh-client-config-baseline.tsv}"
SSH_CONFIG="${SELFDEF_SSHCLIENT_FILE:-/etc/ssh/ssh_config}"
SSH_CONFD="${SELFDEF_SSHCLIENT_D:-/etc/ssh/ssh_config.d}"
ROOT_CONFIG="${SELFDEF_SSHCLIENT_ROOT:-/root/.ssh/config}"

PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo'

# SDD-063: consume the shared writable-location policy from module-lib.
_LIB="${SELFDEF_MODULE_LIB:-/usr/share/selfdef/lib/module-lib.sh}"
if [[ ! -r "$_LIB" ]]; then
    logger -t selfdef-ssh-client-config -- '{"tag":"selfdef-ssh-client-config","severity":"alert","event":"module_lib_missing","profile":"'"$PROFILE"'"}'
    exit 1
fi
# shellcheck disable=SC1090
source "$_LIB"
if [[ "${SELFDEF_MODULE_LIB_VERSION:-0}" -lt 4 ]]; then
    logger -t selfdef-ssh-client-config -- '{"tag":"selfdef-ssh-client-config","severity":"alert","event":"module_lib_outdated","profile":"'"$PROFILE"'"}'
    exit 1
fi

is_suspicious_prog() {
    local p="$1"
    selfdef_is_writable_dir "$p" && return 0
    case "$p" in
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        ""|-*) return 1 ;;       # empty / option token, not a program
        ./*|../*|*/*) return 0 ;; # a RELATIVE path with a slash — abnormal
        *) return 1 ;;           # a bare command name (ssh, nc, corkscrew,
                                 # cloudflared) — PATH-resolved, normal for
                                 # ProxyCommand. tmp/writable/payload are the
                                 # real signals here.
    esac
}

files=()
[[ -f "$SSH_CONFIG" ]] && files+=("$SSH_CONFIG")
if [[ -d "$SSH_CONFD" ]]; then
    for f in "$SSH_CONFD"/*.conf; do [[ -f "$f" ]] && files+=("$f"); done
fi
[[ -f "$ROOT_CONFIG" ]] && files+=("$ROOT_CONFIG")

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-ssh-client-config -- '{"tag":"selfdef-ssh-client-config","severity":"ok","event":"no_ssh_client_config","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
    mode=$(stat -c '%a' "$f" 2>/dev/null || echo '?')
    printf 'own\t%s\t%s\n' "$f" "${owner}:${mode}" >> "$current"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("$(basename "$f"):world-writable($mode)")
    elif [[ "$owner" != "${SELFDEF_WATCHDOG_EXPECTED_OWNER:-root}" && "$owner" != "?" ]]; then
        suspicious+=("$(basename "$f"):owned-by-$owner")
    fi
    while IFS= read -r line; do
        line="${line%%#*}"
        # ProxyCommand / LocalCommand directives
        if printf '%s' "$line" | grep -qiE '(^|[[:space:]])(Proxy|Local)Command[[:space:]]'; then
            directive=$(printf '%s' "$line" | grep -oiE '(Proxy|Local)Command' | head -1)
            cmd=$(printf '%s' "$line" | sed -E 's/.*(Proxy|Local)Command[[:space:]]+//I')
            prog="${cmd%% *}"
            printf 'exec\t%s\t%s:%s\n' "$(basename "$f")" "$directive" "${prog:-(none)}" >> "$current"
            is_suspicious_prog "$prog" && suspicious+=("$(basename "$f"):${directive}=>${prog}")
            printf '%s\n' "$cmd" | grep -qE "$PATTERNS" && suspicious+=("$(basename "$f"):${directive}-payload")
        fi
        # Match exec "cmd"
        if printf '%s' "$line" | grep -qiE '(^|[[:space:]])Match[[:space:]].*[[:space:]]exec[[:space:]]'; then
            mcmd=$(printf '%s' "$line" | sed -E 's/.*[[:space:]]exec[[:space:]]+//I' | sed -e 's/^"//' -e 's/".*//' -e "s/^'//" -e "s/'.*//")
            mprog="${mcmd%% *}"
            printf 'exec\t%s\t%s:%s\n' "$(basename "$f")" "Match-exec" "${mprog:-(none)}" >> "$current"
            is_suspicious_prog "$mprog" && suspicious+=("$(basename "$f"):Match-exec=>${mprog}")
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
    logger -t selfdef-ssh-client-config -- "$(printf '{"tag":"selfdef-ssh-client-config","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="ssh_client_config_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="ssh_client_config_exec_directive"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="ssh_client_config_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-ssh-client-config","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-ssh-client-config -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-ssh-client-config-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-ssh-client-config-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
