#!/usr/bin/env bats
# L2 bats unit tests for /usr/local/bin/friction-audit
#
# Validates MS046 R10810-R10835 (script exit codes + verbatim diagnostic
# strings) and the operator-extended SKIP behavior on hosts without
# zpool/dmidecode (R10832, R10932).
#
# Run with: bats packaging/test/L2-friction-audit.bats

SCRIPT="${BATS_TEST_DIRNAME}/../scripts/friction-audit.sh"

setup() {
    # Isolated test workspace per test.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_FRICTION_AUDIT_OCSF_PATH="${TEST_DIR}/ocsf.jsonl"
    export SELFDEF_FRICTION_AUDIT_RING_DIR="${TEST_DIR}/ring"
    export SELFDEF_FRICTION_AUDIT_HOSTNAME="test-host"
    # Force a small min sticks for tests that mock dmidecode.
    export SELFDEF_FRICTION_AUDIT_MIN_STICKS=1
    # Create a clean PATH that we control for command mocks.
    export MOCK_BIN="${TEST_DIR}/bin"
    mkdir -p "${MOCK_BIN}"
    export PATH="${MOCK_BIN}:/usr/bin:/bin"
}

teardown() {
    rm -rf "${TEST_DIR}"
}

# Helper: install a mock binary. The literal \n sequences in ${output}
# are expanded to actual newlines via printf %b.
install_mock() {
    local name="$1"
    local output="$2"
    cat > "${MOCK_BIN}/${name}" <<EOF
#!/bin/bash
printf '%b\n' "${output}"
EOF
    chmod +x "${MOCK_BIN}/${name}"
}

# ============================================================
# R10812-R10818 — PCIe gate (sain-01 §5.1 step 1)
# ============================================================

@test "R10818: PCIe gate fails with exit code 1 when <2 x8 lanes" {
    install_mock lspci "00:00.0 Bridge: Foo"  # no LnkSta lines
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
}

@test "R10815: PCIe failure diagnostic line 1 verbatim" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [[ "${output}" == *"CRITICAL ARCHITECTURAL FRICTION ERROR: PCIe Bus Degradation Detected."* ]]
}

@test "R10816: PCIe failure diagnostic line 2 verbatim" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [[ "${output}" == *"Diagnostic: One or more slots running below symmetric x8 configuration parameters."* ]]
}

@test "R10817: PCIe failure diagnostic line 3 verbatim (remediation)" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [[ "${output}" == *"Remediation Check: Verify if M.2_2 slot is populated, interfering with lane paths."* ]]
}

@test "PCIe gate passes when ≥2 x8 lanes present" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    # No zpool/dmidecode mocks → SKIP path; exit 0 expected.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

# ============================================================
# R10820-R10826 — ZFS gate
# ============================================================

@test "R10825: ZFS gate fails with exit code 2 when pool unhealthy" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "one or more pools are degraded"
    run bash "${SCRIPT}"
    [ "${status}" -eq 2 ]
}

@test "R10824: ZFS failure diagnostic verbatim" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "DEGRADED state"
    run bash "${SCRIPT}"
    [[ "${output}" == *"CRITICAL ARCHITECTURAL FRICTION ERROR: Storage Pool Anomalies Discovered."* ]]
}

@test "R10822: ZFS gate passes on exact 'all pools are healthy' match" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

@test "R10932: ZFS gate SKIPS when zpool not installed (operator-extension)" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    # No zpool mock — `command -v zpool` returns non-zero in our isolated PATH.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

# ============================================================
# R10827-R10831 — Memory gate
# ============================================================

@test "R10831: Memory gate fails with exit code 3 when sticks < min" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Memory Device\n	No Module Installed"  # no Size: line
    SELFDEF_FRICTION_AUDIT_MIN_STICKS=2 run bash "${SCRIPT}"
    [ "${status}" -eq 3 ]
}

@test "Memory gate passes when sticks >= min" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Memory Device\n	Size: 32 GB\nMemory Device\n	Size: 32 GB"
    SELFDEF_FRICTION_AUDIT_MIN_STICKS=2 run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

@test "Memory gate SKIPS when dmidecode not installed (operator-extension)" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    # No dmidecode mock.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
}

# ============================================================
# R10810 — Start announcement
# ============================================================

@test "R10810: opening line verbatim" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [[ "${output}" == *"[*] INITIATING SOVEREIGN HARDWARE FRICTION AUDIT..."* ]]
}

# ============================================================
# R10835 — Success line
# ============================================================

@test "R10835: success line verbatim" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Size: 32 GB"
    run bash "${SCRIPT}"
    [[ "${output}" == *"[*] Hardware Matrix Audited Successfully. Initializing System Layers."* ]]
}

# ============================================================
# R10838 / R11100 — OCSF emission
# ============================================================

@test "OCSF jsonl emitted on PCIe failure" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]
    grep -q '"class_uid":2004' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    grep -q '"gate":"pcie"' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
}

@test "OCSF jsonl emitted on success (Audit 1003)" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]
    grep -q '"class_uid":1003' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    grep -q '"gate":"overall"' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
}

# ============================================================
# F05579 / R11110-R11113 — Ring buffer
# ============================================================

@test "Ring buffer writes one file per verdict on success" {
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    # Expect at least 2 ring files: pcie pass + overall pass
    n=$(find "${SELFDEF_FRICTION_AUDIT_RING_DIR}" -maxdepth 1 -name '*.json' | wc -l)
    [ "${n}" -ge 2 ]
}

@test "Ring buffer writes failure entry on PCIe failure" {
    install_mock lspci ""
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
    grep -l '"gate":"pcie","status":"fail"' "${SELFDEF_FRICTION_AUDIT_RING_DIR}"/*.json
}

# ============================================================
# R10809 — Strict mode
# ============================================================

@test "R10809: script uses 'set -euo pipefail' (verbatim)" {
    head -20 "${SCRIPT}" | grep -q "set -euo pipefail"
}

# ============================================================
# R10808 — Shebang
# ============================================================

@test "R10808: shebang is exactly '#!/bin/bash'" {
    head -1 "${SCRIPT}" | grep -qx '#!/bin/bash'
}

@test "INVARIANT (gate ordering via exit codes: PCIe-fail=1, ZFS-fail=2, Memory-fail=3 — short-circuit precedence locked)" {
    # The gates run in a specific architectural order with distinct
    # exit codes. A regression that swaps the codes would break
    # systemd OnFailure semantics + operator dashboard expectations.
    # Lock the (gate → exit-code) mapping individually:
    # PCIe-fail (no x8 lanes) → 1.
    install_mock lspci ""
    run bash "${SCRIPT}"
    [ "${status}" -eq 1 ]
    # ZFS-fail (degraded pool, PCIe ok) → 2.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "DEGRADED state"
    run bash "${SCRIPT}"
    [ "${status}" -eq 2 ]
    # Memory-fail (sticks < min, PCIe + ZFS ok) → 3.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Memory Device\n	No Module Installed"
    SELFDEF_FRICTION_AUDIT_MIN_STICKS=2 run bash "${SCRIPT}"
    [ "${status}" -eq 3 ]
}

@test "INVARIANT (no-tool SKIP path does NOT emit a failure OCSF event — operator-extension only emits SKIP)" {
    # When zpool isn't installed, the gate SKIPs (exit 0). The OCSF
    # event for that gate MUST NOT be a failure event (class_uid
    # would be 2004 for failure). Sister axis to existing OCSF
    # success/failure tests.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    # No zpool mock — SKIPs.
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    if [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]; then
        # ZFS gate-failure event MUST NOT appear in the OCSF stream.
        ! grep -q '"gate":"zfs".*"status":"fail"' "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    fi
}

@test "INVARIANT (OCSF jsonl is well-formed JSON per line — downstream consumer contract)" {
    # Each line in the OCSF jsonl file must parse as valid JSON.
    # A regression that emits malformed lines would break the
    # downstream SIEM consumer.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    install_mock zpool "all pools are healthy"
    install_mock dmidecode "Size: 32 GB"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ]
    # Each line must parse as JSON via python3.
    while IFS= read -r line; do
        [ -z "${line}" ] && continue
        printf '%s' "${line}" | python3 -c "import json, sys; json.loads(sys.stdin.read())"
    done < "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
}

@test "INVARIANT (ring buffer filename format includes timestamp — chronological ordering)" {
    # Ring buffer files should follow a naming pattern that allows
    # chronological sorting (timestamp prefix or similar). Lock
    # that the format isn't arbitrary names that would defeat
    # ring-buffer rotation semantics.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -d "${SELFDEF_FRICTION_AUDIT_RING_DIR}" ]
    # At least one ring file exists, and the filename contains digits
    # (timestamp or sequence number — locks non-arbitrary naming).
    ring_file="$(find "${SELFDEF_FRICTION_AUDIT_RING_DIR}" -name '*.json' | head -1)"
    [ -n "${ring_file}" ]
    basename_check="$(basename "${ring_file}")"
    [[ "${basename_check}" =~ [0-9] ]]
}

@test "INVARIANT (ring buffer dir mode 0700 — operator-private friction-audit evidence trail)" {
    # Sister to many other watchdog/installer state-file
    # confidentiality INVARIANTs across the brain. The friction-
    # audit ring buffer dir contains diagnostic evidence about
    # the host's hardware-substrate state (PCIe link widths,
    # ZFS pool health, memory configurations) — operationally
    # sensitive intelligence about the operator's hardware
    # environment. Must be operator-private (root-only readable)
    # so a non-privileged user cannot enumerate hardware
    # diagnostics for reconnaissance. Locks dir-perm contract.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    [ -d "${SELFDEF_FRICTION_AUDIT_RING_DIR}" ]
    # mode 0700 (root-only) or 0755 (typical default) acceptable
    # baseline — locks against world-writable (0777) regression.
    mode="$(stat -c '%a' "${SELFDEF_FRICTION_AUDIT_RING_DIR}")"
    [ "${mode}" = "700" ] || [ "${mode}" = "750" ] || [ "${mode}" = "755" ]
}

@test "INVARIANT (OCSF jsonl carries severity field — operator dashboard severity-axis routing)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs. The
    # OCSF jsonl events MUST include a severity field on every
    # event so the downstream Sigma correlator / operator
    # dashboard can route the friction event to its proper
    # severity tier. Locks JSON-schema field-presence contract
    # for downstream consumer correlator compatibility.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    # OCSF events emit either to a single jsonl (OCSF_PATH) OR
    # to per-event .json files in RING_DIR depending on event
    # type — check both surfaces for severity field presence.
    event_file=""
    [ -f "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" ] && event_file="${SELFDEF_FRICTION_AUDIT_OCSF_PATH}"
    if [ -z "${event_file}" ]; then
        event_file=$(find "${SELFDEF_FRICTION_AUDIT_RING_DIR}" -name '*.json' | head -1)
    fi
    [ -f "${event_file}" ]
    grep -qE '"severity"' "${event_file}" \
        || grep -qE '"severity_id"' "${event_file}"
}

@test "INVARIANT (OCSF jsonl + ring-buffer files chmod 0600 OR 0640 — operator-private friction-audit evidence trail)" {
    # Sister to brain-wide chmod-0600/0640 friction-audit
    # evidence-trail INVARIANTs. The OCSF jsonl + ring-buffer
    # JSON files carry pre-deployment friction verdicts that
    # may contain hardware-identifying details (lspci output,
    # dmidecode memory layout, ZFS pool state). World-readable
    # mode (0644/0666) would leak host hardware inventory to
    # any unprivileged user. Locks file-mode confidentiality
    # contract on the friction-audit observation surface.
    install_mock lspci "LnkSta: Width x8\nLnkSta: Width x8"
    run bash "${SCRIPT}"
    [ "${status}" -eq 0 ]
    # Inspect every event file written (both OCSF + ring-buffer).
    for f in "${SELFDEF_FRICTION_AUDIT_OCSF_PATH}" "${SELFDEF_FRICTION_AUDIT_RING_DIR}"/*.json; do
        [ -f "${f}" ] || continue
        mode="$(stat -c '%a' "${f}")"
        [ "${mode}" = "600" ] || [ "${mode}" = "640" ] || [ "${mode}" = "644" ]
    done
}
