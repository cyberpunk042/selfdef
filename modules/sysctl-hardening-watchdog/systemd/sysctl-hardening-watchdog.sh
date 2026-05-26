#!/usr/bin/env bash
# selfdef sysctl-hardening-watchdog — boot + daily delta of the
# sysctl config files vs a learned baseline, flagging WEAKENING of
# security-relevant kernel sysctls.
#
# An attacker who drops /etc/sysctl.d/99-x.conf with —
#
#   kernel.kptr_restrict = 0          # leak kernel pointers (exploit aid)
#   kernel.yama.ptrace_scope = 0      # ptrace any process (cred theft)
#   fs.protected_symlinks = 0         # symlink-race attacks
#   kernel.unprivileged_bpf_disabled = 0
#   kernel.kexec_load_disabled = 0    # load arbitrary kernel
#
# — re-opens kernel exploitation primitives that hardening closed
# (T1562.001). These take effect at the next boot or `sysctl -p`.
#
# Watched: /etc/sysctl.conf + /etc/sysctl.d/*.conf + /run/sysctl.d
#          + /usr/local/lib/sysctl.d (NOT /usr/lib/sysctl.d, package).
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<path>:<sha12>   — hash of each sysctl config
#   sysctl:<key>:<value>  — each security-relevant sysctl set
#
# Severity:
#   ok    → no delta
#   warn  → any config change
#   alert → a NEWLY-ADDED security sysctl set to its WEAK (unsafe)
#           value

set -u

PROFILE="${SELFDEF_SYSCTLH_PROFILE:-report}"
BASELINE="${SELFDEF_SYSCTLH_BASELINE:-/var/lib/selfdef/sysctl-hardening-baseline.tsv}"
if [[ -n "${SELFDEF_SYSCTLH_FILES:-}" ]]; then
    read -r -a SRC <<< "${SELFDEF_SYSCTLH_FILES}"
else
    SRC=(/etc/sysctl.conf)
    for d in /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d; do
        [[ -d "$d" ]] && for f in "$d"/*.conf; do [[ -f "$f" ]] && SRC+=("$f"); done
    done
fi

# Is (key,value) a weakening of a security sysctl? Returns 0 if weak.
is_weakening() {
    local k="$1" v="$2"
    case "$k" in
        kernel.kptr_restrict|kernel.dmesg_restrict|kernel.unprivileged_bpf_disabled|kernel.kexec_load_disabled|kernel.yama.ptrace_scope|kernel.modules_disabled|fs.protected_hardlinks|fs.protected_symlinks|fs.protected_fifos|fs.protected_regular)
            [[ "$v" == "0" ]] && return 0 ;;
        kernel.sysrq|kernel.unprivileged_userns_clone|fs.suid_dumpable)
            [[ "$v" != "0" ]] && return 0 ;;
        kernel.randomize_va_space)
            [[ "$v" != "2" ]] && return 0 ;;
        kernel.perf_event_paranoid)
            [[ "$v" =~ ^-?[0-9]+$ ]] && [ "$v" -lt 2 ] 2>/dev/null && return 0 ;;
    esac
    return 1
}

is_security_key() {
    case "$1" in
        kernel.kptr_restrict|kernel.dmesg_restrict|kernel.unprivileged_bpf_disabled|kernel.kexec_load_disabled|kernel.yama.ptrace_scope|kernel.modules_disabled|kernel.sysrq|kernel.unprivileged_userns_clone|kernel.randomize_va_space|kernel.perf_event_paranoid|fs.protected_hardlinks|fs.protected_symlinks|fs.protected_fifos|fs.protected_regular|fs.suid_dumpable) return 0 ;;
        *) return 1 ;;
    esac
}

files=()
for f in "${SRC[@]}"; do [[ -f "$f" ]] && files+=("$f"); done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-sysctl-hardening -- '{"tag":"selfdef-sysctl-hardening","severity":"ok","event":"no_sysctl_config","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a baseline_susp=()

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    while IFS= read -r line; do
        line="${line%%#*}"
        [[ "$line" == *=* ]] || continue
        key="${line%%=*}"; val="${line#*=}"
        # normalize: strip spaces, '/' separator → '.'
        key="$(printf '%s' "$key" | tr -d '[:space:]' | tr '/' '.')"
        val="$(printf '%s' "$val" | tr -d '[:space:]')"
        [[ -z "$key" ]] && continue
        is_security_key "$key" || continue
        printf 'sysctl\t%s\t%s\n' "$key" "$val" >> "$current"
        is_weakening "$key" "$val" && baseline_susp+=("${key}=${val}")
    done < "$f"
done

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
    logger -t selfdef-sysctl-hardening -- "$(printf '{"tag":"selfdef-sysctl-hardening","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Weakening detection only on NEWLY-ADDED sysctl lines.
declare -a suspicious=()
while IFS= read -r aline; do
    [[ "$aline" == sysctl$'\t'* ]] || continue
    IFS=$'\t' read -r _k key val <<< "$aline"
    is_weakening "$key" "$val" && suspicious+=("${key}=${val}")
done <<< "$added"
(( ${#suspicious[@]} > 0 )) && mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)

severity="ok"; event="sysctl_hardening_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="sysctl_hardening_weakened"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="sysctl_hardening_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-sysctl-hardening","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-sysctl-hardening -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sysctl-hardening-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-sysctl-hardening-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
