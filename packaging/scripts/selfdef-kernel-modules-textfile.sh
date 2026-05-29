#!/bin/bash
# selfdef-kernel-modules-textfile — emit Prometheus node_exporter
# textfile gauges for loaded kernel module state.
#
# Surfaces real IPS-host operator visibility: tracks total loaded
# kernel module count + per-state counts (loaded / in-use). Operators
# detect unexpected module loads (post-exploitation rootkits) and
# kernel-tainted state (operator drift to unsigned modules).
#
# Runs every 60s via the companion timer. 12th sibling observer.
#
# Kernel-module observability is a load-bearing IPS surface: a
# rootkit's first move is often to load an unsigned kernel module
# that hides itself. selfdef cannot enforce module-load policy
# without CAP_SYS_MODULE control of the kernel, but it CAN detect
# drift from the operator's baseline + page on unexpected loads.
#
# Honest-offline: when /proc/modules + /proc/sys/kernel/tainted are
# inaccessible, emit sentinel.
#
# Standing rule: We do not minimize anything.

set -euo pipefail

TEXTFILE_PATH="${SELFDEF_KERNEL_MODULES_TEXTFILE_PATH:-/var/lib/node_exporter/textfile_collector/selfdef-kernel-modules.prom}"

emit_failure_sentinel() {
  local tmp; tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
  {
    printf '# HELP selfdef_kernel_modules_textfile_emit_failed Wrapper exited unhealthy (proc unreadable).\n'
    printf '# TYPE selfdef_kernel_modules_textfile_emit_failed gauge\n'
    printf 'selfdef_kernel_modules_textfile_emit_failed 1\n'
    printf '# HELP selfdef_kernel_modules_last_run_unix Wall-clock seconds of the last wrapper invocation.\n'
    printf '# TYPE selfdef_kernel_modules_last_run_unix gauge\n'
    printf 'selfdef_kernel_modules_last_run_unix %d\n' "$(date +%s)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$TEXTFILE_PATH"
}

trap 'emit_failure_sentinel' ERR

# Preconditions — /proc/modules readable.
if ! [ -r /proc/modules ]; then
  emit_failure_sentinel
  exit 2
fi

# Total loaded module count.
total_modules="$(wc -l < /proc/modules 2>/dev/null || echo 0)"

# /proc/modules format: name size instances dependencies state offset
# Count "in-use" modules (instances > 0).
in_use_modules="$(awk '$3 > 0 {n++} END {print n+0}' /proc/modules 2>/dev/null || echo 0)"

# Tainted state — /proc/sys/kernel/tainted. Bitmask where:
#   bit 0  (1)   = proprietary module loaded
#   bit 12 (4096) = unsigned module loaded
#   bit 14 (16384) = out-of-tree module loaded
# Any non-zero value indicates the kernel is no longer purely upstream.
tainted_value=0
if [ -r /proc/sys/kernel/tainted ]; then
  tainted_value="$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)"
fi

# Specific tainted-bit checks (operator-actionable signals).
tainted_proprietary=0
tainted_unsigned=0
tainted_out_of_tree=0
if [ "$tainted_value" -gt 0 ]; then
  # Bit 0 = 1.
  if [ $(( tainted_value & 1 )) -ne 0 ]; then tainted_proprietary=1; fi
  # Bit 12 = 4096.
  if [ $(( tainted_value & 4096 )) -ne 0 ]; then tainted_unsigned=1; fi
  # Bit 14 = 16384.
  if [ $(( tainted_value & 16384 )) -ne 0 ]; then tainted_out_of_tree=1; fi
fi

# Build textfile.
tmp="$(mktemp "${TEXTFILE_PATH}.XXXXXX")"
{
  printf '# HELP selfdef_kernel_modules_total Count of loaded kernel modules.\n'
  printf '# TYPE selfdef_kernel_modules_total gauge\n'
  printf 'selfdef_kernel_modules_total %d\n' "$total_modules"

  printf '# HELP selfdef_kernel_modules_in_use Count of kernel modules currently in use (instances > 0).\n'
  printf '# TYPE selfdef_kernel_modules_in_use gauge\n'
  printf 'selfdef_kernel_modules_in_use %d\n' "$in_use_modules"

  printf '# HELP selfdef_kernel_tainted Raw /proc/sys/kernel/tainted bitmask value.\n'
  printf '# TYPE selfdef_kernel_tainted gauge\n'
  printf 'selfdef_kernel_tainted %d\n' "$tainted_value"

  printf '# HELP selfdef_kernel_tainted_proprietary 1 if a proprietary module is loaded (bit 0).\n'
  printf '# TYPE selfdef_kernel_tainted_proprietary gauge\n'
  printf 'selfdef_kernel_tainted_proprietary %d\n' "$tainted_proprietary"

  printf '# HELP selfdef_kernel_tainted_unsigned 1 if an unsigned module is loaded (bit 12) — page-worthy IPS hazard.\n'
  printf '# TYPE selfdef_kernel_tainted_unsigned gauge\n'
  printf 'selfdef_kernel_tainted_unsigned %d\n' "$tainted_unsigned"

  printf '# HELP selfdef_kernel_tainted_out_of_tree 1 if an out-of-tree module is loaded (bit 14).\n'
  printf '# TYPE selfdef_kernel_tainted_out_of_tree gauge\n'
  printf 'selfdef_kernel_tainted_out_of_tree %d\n' "$tainted_out_of_tree"

  printf '# HELP selfdef_kernel_modules_last_run_unix Wall-clock seconds of the last wrapper invocation (observer freshness).\n'
  printf '# TYPE selfdef_kernel_modules_last_run_unix gauge\n'
  printf 'selfdef_kernel_modules_last_run_unix %d\n' "$(date +%s)"

  printf '# HELP selfdef_kernel_modules_textfile_emit_failed Wrapper exited unhealthy (always 0 on successful emit).\n'
  printf '# TYPE selfdef_kernel_modules_textfile_emit_failed gauge\n'
  printf 'selfdef_kernel_modules_textfile_emit_failed 0\n'
} > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TEXTFILE_PATH"

trap - ERR
exit 0
