#!/usr/bin/env bash
# selfdef fstab-watchdog — boot + daily ENTRY-level delta of
# /etc/fstab vs a learned baseline.
#
# mount-options-watchdog verifies the nosuid/nodev/noexec FLAGS on
# a fixed set of known mounts; this watches the fstab ENTRIES for
# tampering an attacker uses:
#
#   /tmp/.img       /usr/lib   ext4  loop          # mount attacker image
#   /tmp/evil       /usr/bin   none  bind          # shadow system binaries
#   /dev/sdb1       /mnt/x     ext4  defaults,suid  # suid on removable
#
# A bind-mount over a sensitive system path lets an attacker
# shadow trusted files (T1564.005 / T1036); a loop device under
# /tmp|/home is an attacker-controlled image; an explicit `suid`
# on a normally-hardened path is a privesc handle.
#
# Records (each line: kind<TAB>mountpoint<TAB>value):
#   file:<path>:<sha12>                  — hash of fstab
#   mount:<mountpoint>:<dev>|<fstype>|<opts> — each entry
#
# Severity:
#   ok    → no delta
#   warn  → any entry added / removed / changed
#   alert → a bind-mount over a sensitive path; a loop/file device
#           under /tmp /home /dev/shm; or an explicit `suid` option

set -u

PROFILE="${SELFDEF_FSTAB_PROFILE:-report}"
BASELINE="${SELFDEF_FSTAB_BASELINE:-/var/lib/selfdef/fstab-baseline.tsv}"
FSTAB="${SELFDEF_FSTAB_FILE:-/etc/fstab}"
FSTABD="${SELFDEF_FSTAB_D:-/etc/fstab.d}"

# Sensitive system paths a bind/over-mount would shadow.
is_sensitive_mp() {
    case "$1" in
        /etc|/etc/*|/bin|/bin/*|/sbin|/sbin/*|/usr/bin|/usr/bin/*|/usr/sbin|/usr/sbin/*|/usr/local/bin|/usr/local/bin/*|/usr/local/sbin|/usr/local/sbin/*|/lib|/lib/*|/lib64|/lib64/*|/usr/lib|/usr/lib/*|/boot|/boot/*|/root|/root/.ssh*) return 0 ;;
        *) return 1 ;;
    esac
}

files=()
[[ -f "$FSTAB" ]] && files+=("$FSTAB")
if [[ -d "$FSTABD" ]]; then
    for f in "$FSTABD"/*; do [[ -f "$f" ]] && files+=("$f"); done
fi

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-fstab -- '{"tag":"selfdef-fstab","severity":"ok","event":"no_fstab","profile":"'"$PROFILE"'"}'
    exit 0
fi

current="$(mktemp)"
trap 'rm -f "$current" "${current}.sorted"' EXIT

declare -a baseline_susp=()

scan_entry() {  # dev mp fstype opts  -> echo a tag if suspicious
    local dev="$1" mp="$2" fstype="$3" opts="$4"
    # bind-mount over a sensitive path
    if [[ "$fstype" == "none" || "$fstype" == "bind" ]] && [[ ",$opts," == *",bind,"* || "$opts" == bind || "$opts" == *bind* ]]; then
        is_sensitive_mp "$mp" && echo "shadow-bind:${mp}<-${dev}"
    fi
    # loop / file device under tmp|home|dev-shm
    case "$dev" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*) echo "loop-image:${dev}->${mp}" ;;
    esac
    [[ ",$opts," == *",loop,"* ]] && case "$dev" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*) echo "loop-image:${dev}->${mp}" ;;
    esac
    # explicit suid option (re-enabling setuid)
    [[ ",$opts," == *",suid,"* ]] && echo "explicit-suid:${mp}"
}

for f in "${files[@]}"; do
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    printf 'file\t%s\t%s\n' "$f" "$h" >> "$current"
    while IFS= read -r line; do
        line="${line%%#*}"
        read -r -a F <<< "$line"
        [[ ${#F[@]} -lt 4 ]] && continue
        dev="${F[0]}"; mp="${F[1]}"; fstype="${F[2]}"; opts="${F[3]}"
        printf 'mount\t%s\t%s|%s|%s\n' "$mp" "$dev" "$fstype" "$opts" >> "$current"
        while IFS= read -r tag; do
            [[ -n "$tag" ]] && baseline_susp+=("$tag")
        done < <(scan_entry "$dev" "$mp" "$fstype" "$opts")
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
    logger -t selfdef-fstab -- "$(printf '{"tag":"selfdef-fstab","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

# Suspicious detection only on NEWLY-ADDED mount entries.
declare -a suspicious=()
while IFS= read -r aline; do
    [[ "$aline" == mount$'\t'* ]] || continue
    IFS=$'\t' read -r _k mp rest <<< "$aline"
    IFS='|' read -r dev fstype opts <<< "$rest"
    while IFS= read -r tag; do
        [[ -n "$tag" ]] && suspicious+=("$tag")
    done < <(scan_entry "$dev" "$mp" "$fstype" "$opts")
done <<< "$added"
(( ${#suspicious[@]} > 0 )) && mapfile -t suspicious < <(printf '%s\n' "${suspicious[@]}" | sort -u)

severity="ok"; event="fstab_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="fstab_suspicious_mount"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="fstab_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-fstab","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-fstab -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-fstab-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-fstab-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
