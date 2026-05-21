#!/usr/bin/env bats
# L2 bats unit tests for the wasm-aot-cache module (MS031 — provisions
# /var/lib/selfdef/wasm-aot/ for cached .cwasm artifacts produced by
# `wasmtime compile` against the SD-R30 target-feature surface, SD-R48).
#
# Run with: bats packaging/test/L2-wasm-aot-cache.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + name = wasm-aot-cache" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"wasm-aot-cache"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on hardware-tune-cache (MS010 upstream)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides wasm-aot-cache-dir contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"wasm-aot-cache-dir"' "${MODULE_DIR}/module.toml"
}

@test "install scripts exist + executable" {
    [ -x "${INSTALL_DIR}/apply.sh" ]
    [ -x "${INSTALL_DIR}/check.sh" ]
    [ -x "${INSTALL_DIR}/uninstall.sh" ]
}

@test "apply.sh uses set -euo pipefail + DRY_RUN aware" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_DRY_RUN'    "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh exposes SELFDEF_WASM_AOT_CACHE_DIR override" {
    grep -q 'SELFDEF_WASM_AOT_CACHE_DIR' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh consumes hardware-tune.env from MS010" {
    grep -q 'SELFDEF_HARDWARE_TUNE_ENV'  "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh defaults cache dir to /var/lib/selfdef/wasm-aot" {
    grep -q '/var/lib/selfdef/wasm-aot' "${INSTALL_DIR}/apply.sh"
}

# Dry-run smoke
@test "apply.sh runs cleanly in dry-run mode" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}
