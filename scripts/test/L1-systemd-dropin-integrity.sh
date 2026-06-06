#!/usr/bin/env bash
# L1-systemd-dropin-integrity.sh — selfdefd systemd drop-in
# integrity gate.
#
# packaging/systemd/selfdefd.service.d/ebpf.conf is a systemd
# unit drop-in that grants the daemon eBPF-collection capabilities
# (CAP_BPF + CAP_PERFMON + CAP_AUDIT_READ) and raises memlock to
# infinity (for kernels still charging BPF map memory against
# RLIMIT_MEMLOCK).
#
# This is a security-sensitive surface: the capabilities granted
# here are the daemon's collection authority — silently dropping
# CAP_BPF kills the daemon's primary observation path; silently
# adding more capabilities escalates beyond the documented intent.
# None of the existing L1 gates touched this drop-in.
#
# Two silent-drift classes:
#   1. A required capability gets removed — daemon's eBPF collection
#      silently breaks at next restart.
#   2. An extra capability gets added — daemon gains authority
#      beyond the documented "in-kernel BPF collection" purpose.
#
# Run with: bash scripts/test/L1-systemd-dropin-integrity.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DROPIN="${REPO_ROOT}/packaging/systemd/selfdefd.service.d/ebpf.conf"

failures=0

if [[ ! -f "${DROPIN}" ]]; then
    echo "L1-systemd-dropin-integrity FAIL: ${DROPIN} not present"
    exit 1
fi

assert_grep() {
    local label="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${DROPIN}"; then
        echo "  PASS ${label}"
    else
        echo "  FAIL ${label} — pattern not found: ${pattern}"
        failures=$((failures + 1))
    fi
}

assert_no_grep() {
    local label="$1"
    local pattern="$2"
    if grep -qE "${pattern}" "${DROPIN}"; then
        echo "  FAIL ${label} — unexpected pattern found: ${pattern}"
        failures=$((failures + 1))
    else
        echo "  PASS ${label}"
    fi
}

# Gate 1: [Service] section opener
echo "▶ Gate 1: drop-in section structure"
assert_grep "[Service] section present" "^\\[Service\\]"

# Gate 2: AmbientCapabilities is the EXACT 3-capability set
# (CAP_AUDIT_READ + CAP_BPF + CAP_PERFMON). A silent rename or
# omission of any breaks eBPF collection.
echo "▶ Gate 2: AmbientCapabilities — the 3-capability set"
assert_grep "AmbientCapabilities includes CAP_AUDIT_READ" \
    "^AmbientCapabilities=.*CAP_AUDIT_READ"
assert_grep "AmbientCapabilities includes CAP_BPF" \
    "^AmbientCapabilities=.*CAP_BPF"
assert_grep "AmbientCapabilities includes CAP_PERFMON" \
    "^AmbientCapabilities=.*CAP_PERFMON"

# Gate 3: NO capabilities beyond the documented 3 — silent escalation
# would grant the daemon more authority than the drop-in's purpose
# justifies. We assert absence of common dangerous ones.
echo "▶ Gate 3: no unexpected capability escalation"
assert_no_grep "AmbientCapabilities does NOT grant CAP_SYS_ADMIN (would be unrestricted root)" \
    "^AmbientCapabilities=.*CAP_SYS_ADMIN"
assert_no_grep "AmbientCapabilities does NOT grant CAP_SYS_MODULE (kernel module load)" \
    "^AmbientCapabilities=.*CAP_SYS_MODULE"
assert_no_grep "AmbientCapabilities does NOT grant CAP_SYS_RAWIO (raw device I/O)" \
    "^AmbientCapabilities=.*CAP_SYS_RAWIO"
assert_no_grep "AmbientCapabilities does NOT grant CAP_NET_ADMIN (network config)" \
    "^AmbientCapabilities=.*CAP_NET_ADMIN"

# Gate 4: LimitMEMLOCK=infinity required (BPF map memory accounting)
echo "▶ Gate 4: memlock limit raised"
assert_grep "LimitMEMLOCK=infinity (BPF map memory)" \
    "^LimitMEMLOCK=infinity"

# Gate 5: install hint preserved
echo "▶ Gate 5: install hint preserved"
assert_grep "install hint references /etc/systemd/system/selfdefd.service.d/" \
    "# Install:.*selfdefd\\.service\\.d/"
assert_grep "reload hint references daemon-reload + restart" \
    "daemon-reload.*restart selfdefd|restart.*daemon-reload"

if [[ "${failures}" -gt 0 ]]; then
    echo "L1-systemd-dropin-integrity FAIL: ${failures} drop-in violation(s)"
    exit 1
fi

echo "L1-systemd-dropin-integrity PASS: ebpf.conf drop-in capabilities + memlock + hints all coherent"
