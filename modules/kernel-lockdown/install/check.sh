#!/usr/bin/env bash
# kernel-lockdown — check. Read-only.
#
# Verifies the expected sysctl drop-ins exist + spot-checks live
# sysctl values for the most-critical knobs.

set -euo pipefail

MODULE="kernel-lockdown"
DRY_RUN=0
CONFIG_FILE="${SELFDEF_KERNEL_LOCKDOWN_CONFIG:-/etc/selfdef/modules/kernel-lockdown.toml}"
LIB_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
SYSCTL_DIR="${SELFDEF_SYSCTL_DIR:-/etc/sysctl.d}"

# shellcheck disable=SC1091
source "${LIB_DIR}/lib.sh"

[[ -r "$CONFIG_FILE" ]] || die "config not readable: $CONFIG_FILE"
PROFILE=$(toml_get profile "$CONFIG_FILE" || echo "balanced")

drift=0

if [[ ! -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown.conf" ]]; then
    emit_status "drift" "balanced drop-in missing"
    drift=$((drift + 1))
fi

if [[ "$PROFILE" == "strict" ]]; then
    if [[ ! -f "${SYSCTL_DIR}/50-selfdef-kernel-lockdown-strict.conf" ]]; then
        emit_status "drift" "strict drop-in missing"
        drift=$((drift + 1))
    fi
fi

# Spot-check live values (best-effort; not all kernels expose all
# of them).
check_sysctl() {
    local key="$1"
    local want="$2"
    if [[ ! -e "/proc/sys/$(echo "$key" | tr '.' '/')" ]]; then
        return 0   # not exposed on this kernel; ignore
    fi
    local got
    got=$(sysctl -n "$key" 2>/dev/null || echo "")
    if [[ "$got" != "$want" ]]; then
        emit_status "drift" "$key = $got (want $want)"
        return 1
    fi
}

check_sysctl "kernel.kexec_load_disabled" "1" || drift=$((drift + 1))
check_sysctl "kernel.unprivileged_bpf_disabled" "1" || drift=$((drift + 1))
check_sysctl "vm.unprivileged_userfaultfd" "0" || drift=$((drift + 1))
check_sysctl "kernel.dmesg_restrict" "1" || drift=$((drift + 1))

if [[ "$PROFILE" == "strict" ]]; then
    check_sysctl "kernel.modules_disabled" "1" || drift=$((drift + 1))
fi

if [[ "$drift" -gt 0 ]]; then
    emit_status "drift" "kernel-lockdown profile=$PROFILE drift=$drift"
    exit 1
fi
emit_status "ok" "kernel-lockdown profile=$PROFILE no drift"
