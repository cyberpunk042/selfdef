#!/usr/bin/env bats
# L2 bats unit tests for the hardware-tune-cache module (MS010, SD-R23).
#
# This module is the upstream substrate that bitnet-gpu-inference,
# slm-cpu-loop, tensor-parallel-inference, wasm-aot-cache all consume
# via `consumes = ["hardware-tune-env"]`. The contract: write a
# host-tuned env file at /etc/selfdef/hardware-tune.env that downstream
# build pipelines can source for the correct compile flags.
#
# Run with: bats packaging/test/L2-hardware-tune-cache.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache"
INSTALL_DIR="${MODULE_DIR}/install"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists" { [ -f "${MODULE_DIR}/module.toml" ]; }

@test "module.toml declares name = \"hardware-tune-cache\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides hardware-tune-env (downstream contract)" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"hardware-tune-env"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires selfdefctl binary" {
    grep -q 'value = "selfdefctl"' "${MODULE_DIR}/module.toml"
}

@test "module.toml [requires_hardware] declares avx512_vnni = true (SD-R14)" {
    grep -qE '^avx512_vnni[[:space:]]*=[[:space:]]*true' "${MODULE_DIR}/module.toml"
}

@test "module.toml declares phase = \"pre\" (runs before consumers)" {
    grep -qE '^phase[[:space:]]*=[[:space:]]*"pre"' "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh exist + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

# ============================================================
# apply.sh contract
# ============================================================

@test "apply.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh is SELFDEF_DRY_RUN aware" {
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_HARDWARE_TUNE_ENV override" {
    grep -q 'SELFDEF_HARDWARE_TUNE_ENV' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh fails fast when selfdefctl is missing" {
    grep -qE 'command -v selfdefctl' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh defaults output to /etc/selfdef/hardware-tune.env" {
    grep -q '/etc/selfdef/hardware-tune.env' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh calls selfdefctl hardware tune for cache content" {
    grep -qE 'selfdefctl hardware (tune|export)' "${INSTALL_DIR}/apply.sh"
}

# ============================================================
# check.sh contract
# ============================================================

@test "check.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/check.sh"
}

@test "check.sh respects SELFDEF_HARDWARE_TUNE_ENV override" {
    grep -q 'SELFDEF_HARDWARE_TUNE_ENV' "${INSTALL_DIR}/check.sh"
}

# ============================================================
# Dry-run smoke (mocked selfdefctl emits a stable hardware-tune.env)
# ============================================================

setup_dry_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    cat > "${MOCK_BIN}/selfdefctl" <<'EOF'
#!/bin/bash
case "$*" in
    *"hardware tune"*|*"hardware export"*)
        cat <<TUNE
# Synthesized hardware tune env for L2 test
CFLAGS="-march=native -mavx512f -mavx512vnni"
RUSTFLAGS="-Ctarget-cpu=native"
TUNE
        ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "${MOCK_BIN}/selfdefctl"
    export PATH="${MOCK_BIN}:${PATH}"
}

teardown_dry_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_HARDWARE_TUNE_ENV MOCK_BIN
}

@test "apply.sh runs cleanly in dry-run mode with mocked selfdefctl" {
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
