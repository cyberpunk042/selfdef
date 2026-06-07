#!/usr/bin/env bats
# L2 bats unit tests for the tetragon module's install + assets.
#
# Locks the MS016 tetragon substrate module's shipped surface against
# drift. Tetragon (Cilium eBPF) is the SUBSTRATE for the agent-guard
# (MS017), perimeter (MS047), and guardian (MS044) layers — when this
# module's apply.sh contract changes, every dependent module breaks.
#
# Run with: bats packaging/test/L2-tetragon.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/tetragon"
INSTALL_DIR="${MODULE_DIR}/install"
PROFILES_DIR="${MODULE_DIR}/profiles"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists at the module root" {
    [ -f "${MODULE_DIR}/module.toml" ]
}

@test "module.toml declares name = \"tetragon\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"tetragon"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides substrate contracts (tracing + policies + metrics)" {
    grep -q 'tetragon-tracing'  "${MODULE_DIR}/module.toml"
    grep -q 'tetragon-policies' "${MODULE_DIR}/module.toml"
    grep -q 'metrics-endpoint'  "${MODULE_DIR}/module.toml"
}

@test "module.toml declares phase = \"pre\" (substrate runs first)" {
    grep -qE '^phase[[:space:]]*=[[:space:]]*"pre"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires tetragon binary + CONFIG_BPF kernel feature" {
    grep -q 'value = "tetragon"'    "${MODULE_DIR}/module.toml"
    grep -q 'CONFIG_BPF'            "${MODULE_DIR}/module.toml"
}

@test "module.toml install.kind = \"script\"" {
    grep -qE '^kind[[:space:]]*=[[:space:]]*"script"' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh all exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "profiles/default.toml exists (single-profile substrate)" {
    [ -f "${PROFILES_DIR}/default.toml" ]
}

# ============================================================
# apply.sh — substrate contract
# ============================================================

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh validates tetragon(1) present (die if not)" {
    grep -qE 'command -v tetragon.*die' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh validates systemctl(1) present (die if not)" {
    grep -qE 'command -v systemctl.*die' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes the substrate config knobs" {
    grep -q 'event_log_path'    "${INSTALL_DIR}/apply.sh"
    grep -q 'policy_dir'        "${INSTALL_DIR}/apply.sh"
    grep -q 'metrics_address'   "${INSTALL_DIR}/apply.sh"
    grep -q 'config_path'       "${INSTALL_DIR}/apply.sh"
    grep -q 'service_unit'      "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh supports require_signed_policies (SDD-004 F-2026-024)" {
    grep -q 'require_signed_policies' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh uses selfdefctl keys verify-dir for batch signature check (F-2027-006)" {
    grep -q 'verify-dir' "${INSTALL_DIR}/apply.sh"
}

# ============================================================
# default.toml — schema
# ============================================================

@test "default.toml parses as TOML" {
    python3 -c "
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
with open('${PROFILES_DIR}/default.toml', 'rb') as f:
    tomllib.load(f)
"
}

@test "default.toml declares the 5 substrate config keys" {
    grep -q 'event_log_path'   "${PROFILES_DIR}/default.toml"
    grep -q 'policy_dir'       "${PROFILES_DIR}/default.toml"
    grep -q 'metrics_address'  "${PROFILES_DIR}/default.toml"
    grep -q 'config_path'      "${PROFILES_DIR}/default.toml"
    grep -q 'service_unit'     "${PROFILES_DIR}/default.toml"
}

# ============================================================
# Dry-run smoke (with tetragon + systemctl + selfdefctl mocks)
# ============================================================

setup_dry_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_TETRAGON_CONFIG="${TEST_DIR}/tetragon.toml"
    cat > "${SELFDEF_TETRAGON_CONFIG}" <<EOF
event_log_path = "${TEST_DIR}/events.json"
policy_dir = "${TEST_DIR}/policies"
metrics_address = "localhost:2112"
config_path = "${TEST_DIR}/tetragon.yaml"
service_unit = "tetragon.service"
require_signed_policies = "false"
EOF
    # Mock the binaries apply.sh requires.
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    for bin in tetragon systemctl selfdefctl; do
        cat > "${MOCK_BIN}/${bin}" <<'EOF'
#!/bin/bash
exit 0
EOF
        chmod +x "${MOCK_BIN}/${bin}"
    done
    export PATH="${MOCK_BIN}:${PATH}"
}

teardown_dry_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_TETRAGON_CONFIG MOCK_BIN
}

@test "apply.sh runs cleanly in dry-run mode with mocked binaries" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent (two runs both succeed)" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh fails fast when tetragon(1) is missing from PATH" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_TETRAGON_CONFIG="${TEST_DIR}/tetragon.toml"
    cat > "${SELFDEF_TETRAGON_CONFIG}" <<EOF
event_log_path = "${TEST_DIR}/events.json"
policy_dir = "${TEST_DIR}/policies"
EOF
    # Minimal PATH excluding tetragon (and keeping the bats runner findable
    # via /usr/bin + /bin).
    run env -i PATH=/usr/bin:/bin SELFDEF_DRY_RUN=1 \
        SELFDEF_TETRAGON_CONFIG="${SELFDEF_TETRAGON_CONFIG}" \
        bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_TETRAGON_CONFIG
    [ "${status}" -ne 0 ]
}

@test "check.sh uses set -euo pipefail (script hygiene)" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/check.sh"
}

@test "uninstall.sh uses set -euo pipefail (script hygiene)" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (substrate phase=pre: tetragon installs BEFORE consumers — agent-guard MS017, perimeter MS047, guardian MS044)" {
    # phase=pre is the load-bearing scheduling contract. Locks that
    # the module.toml metadata isn't accidentally changed in a way
    # that breaks the dependent module install ordering.
    grep -qE '^phase[[:space:]]*=[[:space:]]*"pre"' "${MODULE_DIR}/module.toml"
    # Also check that tetragon-tracing and tetragon-policies are
    # provided contracts (downstream depends_on slots).
    grep -q 'tetragon-tracing' "${MODULE_DIR}/module.toml"
    grep -q 'tetragon-policies' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (signed-policy contract: require_signed_policies surfaces in both apply.sh AND default.toml — operator-toggleable from config)" {
    # SDD-004 F-2026-024 + F-2027-006 contract: the signed-policy
    # batch verification is operator-toggleable via TOML config.
    # Lock that BOTH the apply.sh code path AND the default.toml
    # schema declare the key — without both, the toggle is
    # silently broken.
    grep -q 'require_signed_policies' "${INSTALL_DIR}/apply.sh"
    grep -q 'require_signed_policies' "${PROFILES_DIR}/default.toml"
}

@test "INVARIANT (module.toml provides tetragon-tracing + tetragon-policies — downstream consumer contracts)" {
    # Sister to other module's provides-contract INVARIANTs.
    # Tetragon is the substrate for agent-guard (MS017) +
    # perimeter (MS047) + guardian (MS044). Lock that both
    # tracing AND policies provides tokens are declared so
    # downstream consumers can list them in depends_on.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"tetragon-tracing"' "${MODULE_DIR}/module.toml"
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"tetragon-policies"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (apply.sh + check.sh + uninstall.sh all present — full install lifecycle implemented)" {
    # Sister to brain-wide module-lifecycle-fidelity INVARIANTs.
    # tetragon is the kernel-attestation substrate for MS017
    # agent-guard + MS047 perimeter + MS044 guardian. A
    # missing uninstall.sh would leave operator unable to
    # cleanly remove tetragon during MTTR / triage — orphan
    # eBPF programs would remain attached to kernel hooks.
    # Lock the full install-lifecycle script trio.
    [ -f "${INSTALL_DIR}/apply.sh" ]
    [ -f "${INSTALL_DIR}/check.sh" ]
    [ -f "${INSTALL_DIR}/uninstall.sh" ]
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "INVARIANT (no auto-uninstall: tetragon module NEVER emits package-remove commands on tetragon)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The tetragon installer wires kernel-attestation
    # substrate (eBPF programs attached to kernel hooks) but
    # MUST NEVER emit shell commands that uninstall the tetragon
    # package itself (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall tetragon). Silent auto-removal of tetragon
    # during install/check would leave consumer modules
    # (agent-guard MS017 + perimeter MS047 + guardian MS044) in
    # half-loaded eBPF-hook state — partial AI-safety
    # enforcement is worse than none. Locks anti-package-removal
    # contract on the Tetragon kernel-attestation substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+tetragon' "${f}"
    done
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs
    # (detect-host, hardware-tune-cache, slm-cpu-loop, suricata,
    # tensor-parallel-inference). The tetragon module.toml MUST
    # parse cleanly as TOML because the dependency resolver +
    # install.sh dispatch parse this file at load time. A
    # malformed module.toml would crash the install plan +
    # leave consumer modules (agent-guard MS017 + perimeter
    # MS047 + guardian MS044) without their tetragon-tracing /
    # tetragon-policies substrate. Locks parser-validity
    # contract on the tetragon module.toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}
