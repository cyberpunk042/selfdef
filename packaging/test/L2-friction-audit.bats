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
