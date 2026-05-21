#!/usr/bin/env bash
# selfdef secure-boot-status probe.
#
# Three sources of truth (probe order):
#   1. /sys/firmware/efi/efivars/SecureBoot-<GUID> (raw bytes;
#      kernel-exposed)
#   2. mokutil --sb-state (Debian/Ubuntu helper)
#   3. bootctl status (systemd-bootd helper)
#
# Emits a structured JSON event tagged selfdef-secure-boot.
# require profile: exit 1 if SB is NOT enabled (systemd marks
# unit failed).

set -u

PROFILE="${SELFDEF_SECURE_BOOT_PROFILE:-monitor}"

# State enums.
# secure_boot ∈ "enabled" | "disabled" | "setup-mode" | "unavailable"
# uefi        ∈ "yes" | "no"

state="unavailable"
uefi="no"

if [[ -d /sys/firmware/efi ]]; then
    uefi="yes"

    # Source 1: read the raw efivar (most authoritative; survives
    # mokutil + bootctl unavailability).
    sb_file=$(find /sys/firmware/efi/efivars -maxdepth 1 -name "SecureBoot-*" 2>/dev/null | head -1)
    if [[ -n "$sb_file" ]] && [[ -r "$sb_file" ]]; then
        # First 4 bytes are EFI variable attributes; byte 5 is
        # the SecureBoot value (0 = disabled, 1 = enabled).
        sb_byte=$(od -An -tu1 -N5 "$sb_file" 2>/dev/null | awk '{print $5}')
        case "${sb_byte:-?}" in
            1) state="enabled" ;;
            0) state="disabled" ;;
            *) state="unknown" ;;
        esac

        # Setup-mode check via SetupMode-<GUID>.
        sm_file=$(find /sys/firmware/efi/efivars -maxdepth 1 -name "SetupMode-*" 2>/dev/null | head -1)
        if [[ -n "$sm_file" ]] && [[ -r "$sm_file" ]]; then
            sm_byte=$(od -An -tu1 -N5 "$sm_file" 2>/dev/null | awk '{print $5}')
            if [[ "$sm_byte" == "1" ]]; then
                state="setup-mode"
            fi
        fi
    elif command -v mokutil >/dev/null 2>&1; then
        # Source 2: mokutil fallback.
        sb_text=$(mokutil --sb-state 2>&1 || true)
        if echo "$sb_text" | grep -q "SecureBoot enabled"; then
            state="enabled"
        elif echo "$sb_text" | grep -q "SecureBoot disabled"; then
            state="disabled"
        fi
    elif command -v bootctl >/dev/null 2>&1; then
        # Source 3: bootctl fallback.
        bc_text=$(bootctl status 2>&1 || true)
        if echo "$bc_text" | grep -qE "Secure Boot:\s*enabled"; then
            state="enabled"
        elif echo "$bc_text" | grep -qE "Secure Boot:\s*disabled"; then
            state="disabled"
        fi
    fi
fi

# Severity classification.
severity="info"
case "$state" in
    enabled) severity="ok" ;;
    disabled) severity="warn" ;;
    setup-mode) severity="alert" ;;
    unavailable) severity="info" ;;  # legacy BIOS — no UEFI exists
    *) severity="warn" ;;
esac

json=$(printf '{"tag":"selfdef-secure-boot","severity":"%s","state":"%s","uefi":"%s","profile":"%s"}' \
    "$severity" "$state" "$uefi" "$PROFILE")

logger -t selfdef-secure-boot -- "$json"

# require profile: exit 1 when SB is not enabled (but allow
# unavailable=legacy-BIOS hosts to pass).
if [[ "$PROFILE" == "require" ]]; then
    case "$state" in
        enabled|unavailable) exit 0 ;;
        *) exit 1 ;;
    esac
fi
exit 0
