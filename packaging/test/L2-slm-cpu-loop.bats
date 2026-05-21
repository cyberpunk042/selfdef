#!/usr/bin/env bats
# L2 bats unit tests for the slm-cpu-loop module (MS029 SLM-on-CPU
# agent loop runtime — pins a small language model to CCD-0 cores
# for low-latency background agent work; SD-R72).
#
# Run with: bats packaging/test/L2-slm-cpu-loop.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + name = slm-cpu-loop" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"slm-cpu-loop"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on hardware-tune-cache (MS010 upstream)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides slm-loop-runtime contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"slm-loop-runtime"' "${MODULE_DIR}/module.toml"
}

@test "install scripts exist + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "apply.sh uses set -euo pipefail + DRY_RUN aware" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_DRY_RUN' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_SLM_LOOP_ENV override" {
    grep -q 'SELFDEF_SLM_LOOP_ENV' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh consumes hardware-tune.env from MS010" {
    grep -q 'SELFDEF_HARDWARE_TUNE_ENV' "${INSTALL_DIR}/apply.sh"
    grep -q 'hardware-tune.env'          "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh declares CCD-0 affinity defaults (SD-R72 core pinning)" {
    grep -q 'DEFAULT_AFFINITY'  "${INSTALL_DIR}/apply.sh"
    grep -q 'DEFAULT_THREADS'   "${INSTALL_DIR}/apply.sh"
}

# Dry-run smoke
@test "apply.sh runs cleanly in dry-run mode" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}
