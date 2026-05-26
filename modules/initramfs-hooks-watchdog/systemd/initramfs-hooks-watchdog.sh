#!/usr/bin/env bash
# selfdef initramfs-hooks-watchdog — boot + daily delta of the
# initramfs-tools hook + boot-script dirs vs a learned baseline +
# ownership + suspicious-pattern scan.
#
# Two exec surfaces, both AS ROOT:
#   build time — /etc/initramfs-tools/hooks/* run during
#     update-initramfs and copy arbitrary files INTO the image.
#   boot time  — /etc/initramfs-tools/scripts/<stage>/* are BAKED
#     INTO the initramfs and run in early userspace BEFORE
#     pivot_root, earlier than any disk-resident defense:
#       init-top init-premount init-bottom
#       local-top local-premount local-bottom
#       nfs-top nfs-premount nfs-bottom panic
#   plus /etc/initramfs/post-update.d/* (run after an image update).
# An added/tampered script is pre-pivot boot-time root-exec
# persistence / initramfs implant (T1542 pre-OS boot / T1546).
# Distinct from kernel-install-hooks (build-time package
# transaction hooks) — these execute INSIDE the initramfs at boot.
#
# Records (each line: kind<TAB>path<TAB>value):
#   file:<path>:<sha12>     — hash of each script
#   own:<path>:<owner:mode> — owner + mode
#   susp:<path>:<pattern>   — a high-risk exec pattern present
#
# Severity:
#   ok    → no delta
#   warn  → a script added / changed / removed
#   alert → a script world-writable or non-root-owned, OR containing
#           a suspicious command-injection pattern

set -u

PROFILE="${SELFDEF_INITRD_PROFILE:-report}"
BASELINE="${SELFDEF_INITRD_BASELINE:-/var/lib/selfdef/initramfs-hooks-baseline.tsv}"
if [[ -n "${SELFDEF_INITRD_DIRS:-}" ]]; then
    read -r -a DIRS <<< "${SELFDEF_INITRD_DIRS}"
else
    DIRS=(
        /etc/initramfs-tools/hooks
        /etc/initramfs-tools/scripts/init-top
        /etc/initramfs-tools/scripts/init-premount
        /etc/initramfs-tools/scripts/init-bottom
        /etc/initramfs-tools/scripts/local-top
        /etc/initramfs-tools/scripts/local-premount
        /etc/initramfs-tools/scripts/local-bottom
        /etc/initramfs-tools/scripts/nfs-top
        /etc/initramfs-tools/scripts/nfs-premount
        /etc/initramfs-tools/scripts/nfs-bottom
        /etc/initramfs-tools/scripts/panic
        /etc/initramfs/post-update.d
    )
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
for d in "${DIRS[@]}"; do
    [[ -d "$d" ]] || continue
    for f in "$d"/*; do [[ -f "$f" ]] && files+=("$f"); done
done

if [[ ${#files[@]} -eq 0 ]]; then
    logger -t selfdef-initramfs-hooks -- '{"tag":"selfdef-initramfs-hooks","severity":"ok","event":"no_initramfs_hooks","profile":"'"$PROFILE"'"}'
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
    rel="${f#/etc/initramfs-tools/}"; rel="${rel#/etc/}"
    if [[ "$mode" =~ [2367]$ ]]; then
        suspicious+=("${rel}:world-writable($mode)")
    elif [[ "$owner" != "root" && "$owner" != "?" ]]; then
        suspicious+=("${rel}:owned-by-$owner")
    fi
    scan=$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null || true)
    for pat in "${PATTERNS[@]}"; do
        if printf '%s\n' "$scan" | grep -qE "$pat"; then
            printf 'susp\t%s\t%s\n' "$f" "$pat" >> "$current"
            suspicious+=("${rel}:$pat")
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
    logger -t selfdef-initramfs-hooks -- "$(printf '{"tag":"selfdef-initramfs-hooks","severity":"%s","event":"baseline_initial","profile":"%s","entries":%d,"suspicious":"%s"}' "$sev" "$PROFILE" "$cur_count" "$susp_str")"
    [[ "$PROFILE" == "enforce" && "$sev" != "ok" ]] && exit 1
    exit 0
fi

added=$(comm -23 "$current" <(sort -u "$BASELINE"))
removed=$(comm -13 "$current" <(sort -u "$BASELINE"))
n_added=$(printf '%s' "$added"   | grep -c . || true)
n_removed=$(printf '%s' "$removed" | grep -c . || true)

severity="ok"; event="initramfs_hooks_intact"
if (( ${#suspicious[@]} > 0 )); then
    severity="alert"; event="initramfs_hooks_suspicious"
elif (( n_added > 0 || n_removed > 0 )); then
    severity="warn"; event="initramfs_hooks_changed"
fi

added_sample=$(printf '%s' "$added"   | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
removed_sample=$(printf '%s' "$removed" | awk -F'\t' '{print $1":"$2":"$3}' | head -8 | tr '\n' '|')
susp_str=$(IFS='|'; echo "${suspicious[*]:-}")

json=$(printf '{"tag":"selfdef-initramfs-hooks","severity":"%s","event":"%s","profile":"%s","added":%d,"removed":%d,"suspicious":"%s","added_sample":"%s","removed_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$n_added" "$n_removed" "$susp_str" "$added_sample" "$removed_sample")
logger -t selfdef-initramfs-hooks -- "$json"

[[ -n "$added" ]]   && printf '%s\n' "$added"   | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-initramfs-hooks-detail -- "ADDED ${k} ${p} ${v}"; done
[[ -n "$removed" ]] && printf '%s\n' "$removed" | while IFS=$'\t' read -r k p v; do [[ -n "$k" ]] && logger -t selfdef-initramfs-hooks-detail -- "REMOVED ${k} ${p} ${v}"; done

cp "$current" "$BASELINE" 2>/dev/null || true

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
