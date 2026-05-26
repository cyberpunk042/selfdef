#!/usr/bin/env bash
# selfdef udev-rules-watchdog — boot + daily delta of the
# admin/runtime udev rule directories vs a learned baseline.
#
# udevd runs as root and evaluates *.rules files on every device
# event (boot coldplug + hotplug). A rule directive —
#
#   ACTION=="add", RUN+="/tmp/.x"
#   PROGRAM=="/dev/shm/p", SYMLINK+="evil"
#   IMPORT{program}="/home/u/i"
#
# — executes its target AS ROOT when a matching event fires. A
# rule that matches a device always present at boot (or any USB
# insert) is a persistence + privilege vector (T1546). We watch
# the ADMIN/RUNTIME dirs an attacker writes to:
#   /etc/udev/rules.d   (admin rules; highest concern)
#   /run/udev/rules.d   (volatile runtime rules)
# We deliberately do NOT watch /usr/lib/udev/rules.d — that is
# package-managed and legitimately full of RUN+= directives;
# integrity-sentinel / aide-bridge cover package-owned content.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<rule>:<sha12>     — hash of each .rules file
#   exec:<rule>:<target>    — each RUN/PROGRAM/IMPORT{program}
#                             directive's target (the code-exec
#                             surface)
#
# An exec target under /tmp /var/tmp /dev/shm /home, a
# world-writable target, or a bare/relative path is the payload
# signature.
#
# Severity:
#   ok    → no delta
#   warn  → a rule file hash changed / a non-exec rule added or
#           removed
#   alert → a NEW exec directive appears, OR any exec target that
#           is writable / under tmp|home / bare-relative

set -u

PROFILE="${SELFDEF_UDEV_PROFILE:-report}"
BASELINE="${SELFDEF_UDEV_BASELINE:-/var/lib/selfdef/udev-rules-baseline.tsv}"
# Space-separated dir list (overridable for testing).
DIRS="${SELFDEF_UDEV_DIRS:-/etc/udev/rules.d /run/udev/rules.d}"

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a suspicious=()

# Classify an exec target token as suspicious (payload-grade).
is_suspicious_target() {
    local t="$1"
    case "$t" in
        /tmp/*|/tmp|/var/tmp*|/dev/shm*|/home/*) return 0 ;;
        /*) # absolute: suspicious only if the executed target is
            # world-writable. -L follows symlinks (a symlink's own
            # 0777 is meaningless on Linux; the target's mode matters).
            [[ -e "$t" && "$(stat -L -c '%a' "$t" 2>/dev/null)" =~ [2367]$ ]] && return 0
            return 1 ;;
        *) return 0 ;;  # bare / relative target — abnormal for udev
    esac
}

for d in $DIRS; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*.rules; do
        [[ -f "$f" ]] || continue
        h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
        printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
        # Extract code-exec directives: RUN / RUN{program} / RUN+=,
        # PROGRAM, IMPORT{program}. A rule line has many quoted
        # values (match keys too), so anchor on the directive
        # keyword + its operator and take the value that follows
        # it — NOT the first quote on the line.
        while IFS= read -r line; do
            line="${line%%#*}"
            while IFS= read -r m; do
                [[ -z "$m" ]] && continue
                # m is e.g.  RUN+="/tmp/x arg"  → pull the quoted value.
                target=$(printf '%s' "$m" | sed -E 's/.*=[[:space:]]*"([^"]*)".*/\1/')
                # First whitespace-delimited token is the program
                # path (args follow).
                prog="${target%% *}"
                [[ -z "$prog" ]] && continue
                printf 'exec\t%s\t%s\n' "$f" "$prog" >> "$current"
                is_suspicious_target "$prog" && suspicious+=("$(basename "$f"):$prog")
            done < <(printf '%s\n' "$line" | grep -oE '(RUN(\{[^}]*\})?|PROGRAM|IMPORT\{program\})[[:space:]]*[+:]?={1,2}[[:space:]]*"[^"]*"' || true)
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
    logger -t selfdef-udev-rules -- "$(printf '{"tag":"selfdef-udev-rules","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)
# A NEW exec directive (code-exec surface appearing) is itself
# high-signal regardless of target.
exec_added=$(printf '%s' "$added" | grep -c '^exec' || true)

severity="ok"; event="udev_rules_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="udev_rules_suspicious_exec"
elif (( exec_added > 0 )); then
    severity="alert"; event="udev_rules_new_exec"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="udev_rules_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-udev-rules","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-udev-rules -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-udev-rules-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-udev-rules-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
