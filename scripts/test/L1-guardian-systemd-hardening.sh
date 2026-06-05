#!/usr/bin/env bash
# L1-guardian-systemd-hardening.sh — Guardian Daemon systemd unit
# contract integrity gate (MS044 R10411-R10420 + R10433-R10440).
#
# The shipped guardian-core.service is the production substrate Tetragon
# runs against. Every clause in the file is dump-grounded (avx-plus-plus
# 2026-05-18 lines 569-588) and catalog-bound to a specific R-row. A
# silent regression of any clause widens the IPS daemon's capability
# surface or breaks its boot contract — exactly the kind of drift L1
# gates exist to catch at commit time.
#
# Gates (each catches a distinct silent-regression failure mode):
#   1.  Description verbatim (R10411 — dump 571)
#   2.  After=tetragon.service (R10412 — dump 572)
#   3.  Requires=tetragon.service (R10413 — dump 573, hard dep)
#   4.  Type=simple (R10414 — dump 576)
#   5.  ExecStart=/usr/local/bin/guardian-core (R10415 — dump 581)
#   6.  Restart=always (R10416 — dump 582)
#   7.  RestartSec=1 (R10417 — dump 583)
#   8.  WantedBy=multi-user.target (R10418 — dump 586)
#   9.  CAP_BPF in capability bounding (R10435 — Tetragon socket access)
#  10.  CAP_SYS_ADMIN in capability bounding (R10434 — MS039 R09205)
#  11.  NoNewPrivileges=true (no-setuid-escape — bounds capability set)
#  12.  ProtectSystem=strict (full root read-only)
#  13.  ProtectHome=true (no /home access)
#  14.  PrivateTmp=true (no /tmp pivot)
#  15.  ProtectKernelTunables=true (no /proc/sys writes)
#  16.  ProtectControlGroups=true (no cgroup escape)
#  17.  RestrictAddressFamilies covers AF_UNIX + AF_NETLINK (Tetragon needs these,
#       nothing else)
#  18.  RestrictRealtime=true (no SCHED_FIFO escape)
#  19.  SystemCallArchitectures=native (no 32-bit syscall pivot)
#  20.  ReadWritePaths includes /mnt/vault/context (R10386 audit-log write)
#
# Source-grounding: every clause traces to a specific dump line + R-row;
# this gate enforces the verbatim contract, not a synthesized policy.
#
# Run with: bash scripts/test/L1-guardian-systemd-hardening.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UNIT="${REPO_ROOT}/config/systemd/guardian-core.service"

failures=0

assert_grep() {
    local label="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${UNIT}"; then
        echo "  PASS ${label}"
    else
        echo "  FAIL ${label} — pattern not found: ${pattern}"
        failures=$((failures + 1))
    fi
}

[[ -f "${UNIT}" ]] || {
    echo "FAIL: ${UNIT} not present (catalog row MS044 R10410 requires shipped unit)"
    exit 1
}

# 1-8: unit + service + install contract (R10411-R10418, dump 571-586)
assert_grep "R10411 Description verbatim (dump 571)" \
    "^Description=Sovereign Guardian Core eBPF Supervisor"
assert_grep "R10412 After=tetragon.service (dump 572)" \
    "^After=tetragon\\.service"
assert_grep "R10413 Requires=tetragon.service (dump 573)" \
    "^Requires=tetragon\\.service"
assert_grep "R10414 Type=simple (dump 576)" \
    "^Type=simple"
assert_grep "R10415 ExecStart=/usr/local/bin/guardian-core (dump 581)" \
    "^ExecStart=/usr/local/bin/guardian-core"
assert_grep "R10416 Restart=always (dump 582)" \
    "^Restart=always"
assert_grep "R10417 RestartSec=1 (dump 583)" \
    "^RestartSec=1"
assert_grep "R10418 WantedBy=multi-user.target (dump 586)" \
    "^WantedBy=multi-user\\.target"

# 9-10: Ring 0 capability contract (R10434-R10435)
assert_grep "R10435 CAP_BPF in CapabilityBoundingSet (Tetragon socket access)" \
    "^CapabilityBoundingSet=.*CAP_BPF"
assert_grep "R10434 CAP_SYS_ADMIN in CapabilityBoundingSet (MS039 R09205)" \
    "^CapabilityBoundingSet=.*CAP_SYS_ADMIN"

# 11-19: systemd hardening posture (each clause bounds a specific
# escape pattern; silent regression widens the daemon's host surface)
assert_grep "NoNewPrivileges=true (no setuid escape)" \
    "^NoNewPrivileges=true"
assert_grep "ProtectSystem=strict (full root read-only)" \
    "^ProtectSystem=strict"
assert_grep "ProtectHome=true (no /home access)" \
    "^ProtectHome=true"
assert_grep "PrivateTmp=true (no /tmp pivot)" \
    "^PrivateTmp=true"
assert_grep "ProtectKernelTunables=true (no /proc/sys writes)" \
    "^ProtectKernelTunables=true"
assert_grep "ProtectControlGroups=true (no cgroup escape)" \
    "^ProtectControlGroups=true"
assert_grep "RestrictAddressFamilies covers AF_UNIX + AF_NETLINK (Tetragon needs these)" \
    "^RestrictAddressFamilies=.*AF_UNIX.*AF_NETLINK|^RestrictAddressFamilies=.*AF_NETLINK.*AF_UNIX"
assert_grep "RestrictRealtime=true (no SCHED_FIFO escape)" \
    "^RestrictRealtime=true"
assert_grep "SystemCallArchitectures=native (no 32-bit syscall pivot)" \
    "^SystemCallArchitectures=native"

# 20: R10386 audit-log write surface
assert_grep "R10386 ReadWritePaths includes /mnt/vault/context (audit log write)" \
    "^ReadWritePaths=.*\\/mnt\\/vault\\/context"

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-guardian-systemd-hardening FAIL: ${failures} contract violation(s)"
    exit 1
fi

echo "L1-guardian-systemd-hardening PASS: all 20 R-row-grounded clauses present"
