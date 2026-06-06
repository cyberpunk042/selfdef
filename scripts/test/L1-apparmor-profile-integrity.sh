#!/usr/bin/env bash
# L1-apparmor-profile-integrity.sh — selfdefd AppArmor profile
# structural integrity gate.
#
# packaging/apparmor/usr.bin.selfdefd is the AppArmor profile shipped
# for the selfdef daemon. It's a load-bearing security envelope:
# defines what filesystem paths + network transports + /proc reads
# the daemon is allowed AND carries a documented deny-list of
# sensitive paths the daemon must NEVER access (operator credentials
# / kernel memory / etc).
#
# Per the comment at the top: "Install: copy to /etc/apparmor.d/usr.
# bin.selfdefd / Reload: sudo apparmor_parser -r ...". A silent
# regression of any rule on this file ships a weaker confinement
# envelope to every operator's box.
#
# Two silent-drift classes:
#   1. A deny rule gets removed/weakened — sensitive paths the daemon
#      is now ALLOWED to read/write under AppArmor confinement.
#   2. The binary path or abstractions include drifts — profile fails
#      to load at apparmor_parser time, daemon runs UNCONFINED.
#
# This gate pins the structural invariants — what MUST be present,
# what MUST be denied. Pure text-shape assertions (no apparmor_parser
# invocation; that's the runtime contract not the commit-time one).
#
# Run with: bash scripts/test/L1-apparmor-profile-integrity.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROFILE="${REPO_ROOT}/packaging/apparmor/usr.bin.selfdefd"

failures=0

if [[ ! -f "${PROFILE}" ]]; then
    echo "L1-apparmor-profile-integrity FAIL: ${PROFILE} not present"
    exit 1
fi

assert_grep() {
    local label="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${PROFILE}"; then
        echo "  PASS ${label}"
    else
        echo "  FAIL ${label} — pattern not found: ${pattern}"
        failures=$((failures + 1))
    fi
}

# Gate 1: profile structure
echo "▶ Gate 1: profile envelope (binary path + abstractions + close brace)"
assert_grep "tunables/global included" \
    "^#include[[:space:]]+<tunables/global>"
assert_grep "/usr/bin/selfdefd profile block opens" \
    "^/usr/bin/selfdefd[[:space:]]+\\{"
assert_grep "abstractions/base included (baseline lib + glibc)" \
    "^[[:space:]]+#include[[:space:]]+<abstractions/base>"
assert_grep "abstractions/nameservice included (DNS resolution)" \
    "^[[:space:]]+#include[[:space:]]+<abstractions/nameservice>"
assert_grep "profile block closes" "^\\}\$"

# Gate 2: required filesystem allow rules
echo "▶ Gate 2: required allow rules"
assert_grep "binary self-execute (mr)" \
    "^[[:space:]]+/usr/bin/selfdefd[[:space:]]+mr,"
assert_grep "/etc/selfdef/ readable (config)" \
    "^[[:space:]]+/etc/selfdef/[[:space:]]+r,"
assert_grep "/etc/selfdef/\\*\\* readable (config tree)" \
    "^[[:space:]]+/etc/selfdef/\\*\\*[[:space:]]+r,"
assert_grep "/var/lib/selfdef/ writable (state)" \
    "^[[:space:]]+/var/lib/selfdef/[[:space:]]+rw,"
assert_grep "/var/log/selfdef/\\*\\* writable (logs)" \
    "^[[:space:]]+/var/log/selfdef/\\*\\*[[:space:]]+rw,"

# Gate 3: network transport allow-list (the only transports the
# daemon needs)
echo "▶ Gate 3: network transport allow-list"
assert_grep "inet stream allowed (TCP)" "^[[:space:]]+network inet stream,"
assert_grep "inet6 stream allowed (TCP6)" "^[[:space:]]+network inet6 stream,"
assert_grep "unix stream allowed (local IPC)" "^[[:space:]]+network unix stream,"
assert_grep "netlink raw allowed (kernel events)" "^[[:space:]]+network netlink raw,"

# Gate 4: load-bearing deny rules — silent removal would weaken the
# security envelope. These are the documented "deny everything else
# loudly" set; each protects an operator-credential or kernel-memory
# surface.
echo "▶ Gate 4: load-bearing deny rules"
assert_grep "deny /home/** rwx (operator data)" \
    "^[[:space:]]+deny /home/\\*\\*[[:space:]]+rwx,"
assert_grep "deny /root/** rwx (root home)" \
    "^[[:space:]]+deny /root/\\*\\*[[:space:]]+rwx,"
assert_grep "deny /etc/shadow rwx (password hashes)" \
    "^[[:space:]]+deny /etc/shadow[[:space:]]+rwx,"
assert_grep "deny /etc/gshadow rwx (group hashes)" \
    "^[[:space:]]+deny /etc/gshadow[[:space:]]+rwx,"
assert_grep "deny /etc/sudoers* rwx (sudoers + .d/)" \
    "^[[:space:]]+deny /etc/sudoers\\*[[:space:]]+rwx,"
assert_grep "deny /boot/** rwx (kernel + initrd)" \
    "^[[:space:]]+deny /boot/\\*\\*[[:space:]]+rwx,"
assert_grep "deny /proc/[0-9]*/mem rwx (process memory)" \
    "^[[:space:]]+deny @\\{PROC\\}/\\[0-9\\]\\*/mem[[:space:]]+rwx,"
assert_grep "deny /proc/kcore rwx (kernel core image)" \
    "^[[:space:]]+deny @\\{PROC\\}/kcore[[:space:]]+rwx,"
assert_grep "deny /proc/kmem rwx (kernel direct memory)" \
    "^[[:space:]]+deny @\\{PROC\\}/kmem[[:space:]]+rwx,"

# Gate 5: install hint comments preserved (operator-facing)
echo "▶ Gate 5: operator-facing install hints preserved"
assert_grep "install hint points at /etc/apparmor.d/usr.bin.selfdefd" \
    "# Install: copy to /etc/apparmor.d/usr.bin.selfdefd"
assert_grep "reload hint references apparmor_parser -r" \
    "# Reload:.*apparmor_parser -r"

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-apparmor-profile-integrity FAIL: ${failures} envelope violation(s)"
    exit 1
fi

echo "L1-apparmor-profile-integrity PASS: profile structure + allow rules + deny rules + operator hints all coherent"
