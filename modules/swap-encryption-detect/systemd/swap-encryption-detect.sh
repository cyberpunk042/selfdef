#!/usr/bin/env bash
# selfdef swap-encryption-detect — verify every active swap
# entry is encrypted.
#
# Encryption check per /proc/swaps line:
#   - Name starts with /dev/mapper/<name> → walk crypttab +
#     dm-table to confirm <name> is a dm-crypt mapping.
#   - Name starts with /dev/zram* → in-RAM only, no disk
#     leak; counts as encrypted-by-design.
#   - File-backed swap (Type=file) → check the backing file
#     resides on an encrypted filesystem (dm-crypt parent).
#   - Anything else (raw /dev/sdX partition, /dev/nvmeXp1) →
#     UNLESS the parent block device is encrypted, UNSAFE.
#
# Severity:
#   ok    → all swap encrypted OR no swap
#   warn  → 1 unsafe swap entry
#   alert → 2+ unsafe OR zswap enabled w/ disk-backing
#
# Output: JSON event tagged 'selfdef-swap-encryption'.

set -u

PROFILE="${SELFDEF_SWAPENC_PROFILE:-report}"

# Read /proc/swaps. First line is header; data starts line 2.
declare -a swap_lines=()
if [[ -r /proc/swaps ]]; then
    while IFS= read -r line; do swap_lines+=("$line"); done < <(tail -n +2 /proc/swaps)
fi

total=${#swap_lines[@]}
unsafe=0
safe=0
samples_unsafe=()

is_encrypted_dm() {
    local name="$1"           # /dev/mapper/<x>
    local short="${name##*/}" # <x>
    # dmsetup table is the gold-standard test for dm-crypt.
    if command -v dmsetup >/dev/null 2>&1; then
        local table
        table=$(dmsetup table "$short" 2>/dev/null | awk '{print $3}')
        if [[ "$table" == "crypt" ]]; then return 0; fi
    fi
    # Fallback: /etc/crypttab mention.
    if [[ -r /etc/crypttab ]] && grep -qE "^[[:space:]]*${short}\b" /etc/crypttab; then
        return 0
    fi
    return 1
}

is_encrypted_parent() {
    local path="$1"           # /dev/sdX, /dev/nvmeXp1
    if ! command -v lsblk >/dev/null 2>&1; then return 1; fi
    # Walk parents looking for a crypt fstype anywhere up.
    local fstype
    fstype=$(lsblk -no FSTYPE,TYPE "$path" 2>/dev/null | awk '$1=="crypto_LUKS" || $2=="crypt"' | head -1)
    [[ -n "$fstype" ]]
}

for entry in "${swap_lines[@]}"; do
    name=$(awk '{print $1}' <<<"$entry")
    type=$(awk '{print $2}' <<<"$entry")
    case "$name" in
        /dev/zram*|/dev/zd*)
            safe=$((safe + 1))
            ;;
        /dev/mapper/*)
            if is_encrypted_dm "$name"; then
                safe=$((safe + 1))
            else
                unsafe=$((unsafe + 1))
                (( ${#samples_unsafe[@]} < 5 )) && samples_unsafe+=("${name}/dm-no-crypt")
            fi
            ;;
        /dev/*)
            if is_encrypted_parent "$name"; then
                safe=$((safe + 1))
            else
                unsafe=$((unsafe + 1))
                (( ${#samples_unsafe[@]} < 5 )) && samples_unsafe+=("${name}/raw-device")
            fi
            ;;
        *)
            # File-backed swap. Check parent fs.
            if [[ "$type" == "file" ]]; then
                parent_dev=$(df --output=source "$name" 2>/dev/null | tail -1)
                if [[ -n "$parent_dev" ]] && is_encrypted_parent "$parent_dev"; then
                    safe=$((safe + 1))
                else
                    unsafe=$((unsafe + 1))
                    (( ${#samples_unsafe[@]} < 5 )) && samples_unsafe+=("${name}/file-on-unencrypted")
                fi
            else
                unsafe=$((unsafe + 1))
                (( ${#samples_unsafe[@]} < 5 )) && samples_unsafe+=("${name}/unknown-type")
            fi
            ;;
    esac
done

# zswap detection — if enabled, the compressed-cache pages
# eventually overflow to the backing swap. So zswap enabled
# with an UNSAFE backing swap is just as leaky as raw swap.
zswap_enabled=0
if [[ -r /sys/module/zswap/parameters/enabled ]]; then
    z=$(cat /sys/module/zswap/parameters/enabled 2>/dev/null)
    [[ "$z" == "Y" || "$z" == "1" ]] && zswap_enabled=1
fi

severity="ok"
event="all_swap_encrypted"
if (( total == 0 )); then
    event="no_swap"
elif (( unsafe == 0 )); then
    : # all good
elif (( unsafe == 1 )); then
    severity="warn"; event="unsafe_swap_found"
else
    severity="alert"; event="bulk_unsafe_swap"
fi
if (( zswap_enabled )) && (( unsafe > 0 )); then
    severity="alert"
    event="zswap_with_unsafe_backing"
fi

sample=$(IFS='|'; echo "${samples_unsafe[*]:-}")

json=$(printf '{"tag":"selfdef-swap-encryption","severity":"%s","event":"%s","profile":"%s","swap_total":%d,"swap_safe":%d,"swap_unsafe":%d,"zswap_enabled":%d,"unsafe_sample":"%s"}' \
    "$severity" "$event" "$PROFILE" "$total" "$safe" "$unsafe" "$zswap_enabled" "$sample")
logger -t selfdef-swap-encryption -- "$json"

for u in "${samples_unsafe[@]}"; do
    logger -t selfdef-swap-encryption-detail -- "UNSAFE ${u}"
done

if [[ "$PROFILE" == "enforce" && "$severity" != "ok" ]]; then
    exit 1
fi
exit 0
