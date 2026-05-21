#!/usr/bin/env bats
# L2 bats unit tests for the integrity-sentinel module (MS026 SHA256
# baseline verification for policy artifacts; fail-closed on drift).
#
# Profiles: strict | warn-only.
#
# Run with: bats packaging/test/L2-integrity-sentinel.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/integrity-sentinel"
INSTALL_DIR="${MODULE_DIR}/install"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists" { [ -f "${MODULE_DIR}/module.toml" ]; }

@test "module.toml declares name = \"integrity-sentinel\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"integrity-sentinel"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides baseline-attestation contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"baseline-attestation"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires sha256sum + diff binaries" {
    grep -q 'value = "sha256sum"' "${MODULE_DIR}/module.toml"
    grep -q 'value = "diff"'      "${MODULE_DIR}/module.toml"
}

@test "module.toml profiles.available = [strict, warn-only]" {
    grep -qE 'available[[:space:]]*=[[:space:]]*\[\s*"strict"\s*,\s*"warn-only"\s*\]' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh + lib.sh exist" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
    [ -f "${INSTALL_DIR}/lib.sh" ]
}

@test "paths.txt.default ships as default monitored-path manifest" {
    [ -f "${MODULE_DIR}/paths.txt.default" ]
}

# ============================================================
# apply.sh + check.sh contracts
# ============================================================

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh fails fast when sha256sum + diff are missing" {
    grep -qE 'command -v sha256sum.*die' "${INSTALL_DIR}/apply.sh"
    grep -qE 'command -v diff.*die'      "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh reads profile / paths_file / baseline_path / on_missing config keys" {
    for k in profile paths_file baseline_path on_missing; do
        grep -q "$k" "${INSTALL_DIR}/apply.sh"
    done
}

@test "check.sh declares DRY_RUN=0 (always read-only)" {
    grep -qE '^DRY_RUN=0$' "${INSTALL_DIR}/check.sh"
}

@test "check.sh differentiates strict (fail) vs warn-only (pass) on drift" {
    grep -q 'warn-only' "${INSTALL_DIR}/check.sh"
    grep -q 'DRIFT'     "${INSTALL_DIR}/check.sh"
}

# ============================================================
# Dry-run smoke
# ============================================================

setup_dry_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    # Create a small monitored-paths list + a known target.
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    echo "test content" > "${TEST_DIR}/target.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "strict"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
on_missing = "create"
EOF
}

teardown_dry_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_INTEGRITY_SENTINEL_CONFIG
}

@test "apply.sh runs cleanly in dry-run mode (strict profile, fresh baseline)" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent" {
    setup_dry_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    teardown_dry_run
    [ "${status}" -eq 0 ]
}

@test "apply.sh rejects malformed profile" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_INTEGRITY_SENTINEL_CONFIG="${TEST_DIR}/integrity.toml"
    echo "${TEST_DIR}/target.txt" > "${TEST_DIR}/paths.txt"
    cat > "${SELFDEF_INTEGRITY_SENTINEL_CONFIG}" <<EOF
profile = "bogus"
paths_file = "${TEST_DIR}/paths.txt"
baseline_path = "${TEST_DIR}/baseline.sha256"
EOF
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_INTEGRITY_SENTINEL_CONFIG
    [ "${status}" -ne 0 ]
}
