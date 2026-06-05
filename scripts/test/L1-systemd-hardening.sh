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

# ============================================================================
# selfdef-ux-harness.service — MS045 R10738 + R10748 + hardening parallel
# ============================================================================
# Sister production unit to guardian-core.service. Type=oneshot (the harness
# runs to completion then exits, paired with a systemd timer for daily runs
# per R10738). Carries a 4-clause hardening posture (NoNewPrivileges,
# PrivateTmp, ProtectSystem=strict, ProtectHome=true) + ReadWritePaths scoped
# to its log dir. The MS045 catalog pins R10738 (timer) + R10748 (readiness
# on activation) but neither pins the unit's hardening clauses — silently
# regressing the hardening here is the same drift class this gate catches
# for Guardian.

UX_UNIT="${REPO_ROOT}/config/systemd/selfdef-ux-harness.service"

if [[ ! -f "${UX_UNIT}" ]]; then
    echo "  FAIL ux-harness unit not present at ${UX_UNIT}"
    failures=$((failures + 1))
else
    assert_grep_unit() {
        local label="$1"
        local pattern="$2"
        if grep -qE "${pattern}" "${UX_UNIT}"; then
            echo "  PASS ux-harness: ${label}"
        else
            echo "  FAIL ux-harness: ${label} — pattern not found: ${pattern}"
            failures=$((failures + 1))
        fi
    }
    # Unit + service contract
    assert_grep_unit "Description references MS045 UX coherence test harness" \
        "^Description=.*MS045.*UX[[:space:]]+coherence[[:space:]]+test[[:space:]]+harness"
    assert_grep_unit "Type=oneshot (R10738 daily-timer pairing — runs to completion)" \
        "^Type=oneshot"
    assert_grep_unit "ExecStart=/usr/bin/selfdef-ux-harness --json (R10748 readiness output)" \
        "^ExecStart=/usr/bin/selfdef-ux-harness[[:space:]]+--json"
    assert_grep_unit "StandardOutput appends to /var/log/selfdef/ux-harness.jsonl" \
        "^StandardOutput=append:/var/log/selfdef/ux-harness\\.jsonl"
    assert_grep_unit "ConditionPathExists guards on the binary (no-binary => clean skip)" \
        "^ConditionPathExists=/usr/bin/selfdef-ux-harness"
    # Hardening parallel to guardian-core
    assert_grep_unit "NoNewPrivileges=true" \
        "^NoNewPrivileges=true"
    assert_grep_unit "PrivateTmp=true" \
        "^PrivateTmp=true"
    assert_grep_unit "ProtectSystem=strict" \
        "^ProtectSystem=strict"
    assert_grep_unit "ProtectHome=true" \
        "^ProtectHome=true"
    assert_grep_unit "ReadWritePaths=/var/log/selfdef (the only writable namespace)" \
        "^ReadWritePaths=/var/log/selfdef"
    assert_grep_unit "TimeoutStartSec bounds run length (no hung-harness)" \
        "^TimeoutStartSec=[0-9]+"
    assert_grep_unit "WantedBy=multi-user.target" \
        "^WantedBy=multi-user\\.target"
fi

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-systemd-hardening FAIL: ${failures} contract violation(s)"
    exit 1
fi

echo "L1-systemd-hardening PASS: all 20 guardian-core R-rows + 12 ux-harness clauses present"
