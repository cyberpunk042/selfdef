#!/usr/bin/env bats
# L2 bats unit tests for the bitnet-gpu-inference module's install + assets.
#
# Locks the MS028 GPU-side BitNet ternary inference provisioning module
# against drift. This module sets up /etc/selfdef/bitnet/ +
# /var/lib/selfdef/bitnet/ with a runtime.env that sources the
# hardware-tune.env from the MS010 hardware-tune-cache module, plus a
# schedule.json derived from `selfdefctl hardware probe`.
#
# Run with: bats packaging/test/L2-bitnet-gpu-inference.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/bitnet-gpu-inference"
INSTALL_DIR="${MODULE_DIR}/install"

# ============================================================
# Module shape
# ============================================================

@test "module.toml exists" {
    [ -f "${MODULE_DIR}/module.toml" ]
}

@test "module.toml declares name = \"bitnet-gpu-inference\"" {
    grep -qE '^name[[:space:]]*=[[:space:]]*"bitnet-gpu-inference"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on hardware-tune-cache (MS010 substrate)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "module.toml consumes hardware-tune-env contract" {
    grep -qE '^consumes[[:space:]]*=[[:space:]]*\[.*"hardware-tune-env"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides bitnet-gpu-runtime contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"bitnet-gpu-runtime"' "${MODULE_DIR}/module.toml"
}

@test "module.toml requires selfdefctl binary" {
    grep -q 'value = "selfdefctl"' "${MODULE_DIR}/module.toml"
}

@test "module.toml [requires_hardware] declares avx512_bf16 + GPU constraints (SD-R26)" {
    grep -qE '^avx512_bf16[[:space:]]*=[[:space:]]*true'  "${MODULE_DIR}/module.toml"
    grep -qE '^gpu_count_min'                              "${MODULE_DIR}/module.toml"
    grep -qE '^gpu_vram_gib_min'                           "${MODULE_DIR}/module.toml"
    grep -qE '^memory_gib_min'                             "${MODULE_DIR}/module.toml"
}

@test "install/apply.sh + check.sh + uninstall.sh all exist + executable" {
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

@test "apply.sh exposes override env vars (ETC_DIR + STATE_DIR + TUNE_FILE)" {
    grep -q 'SELFDEF_BITNET_ETC_DIR'      "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_BITNET_STATE_DIR'    "${INSTALL_DIR}/apply.sh"
    grep -q 'SELFDEF_HARDWARE_TUNE_ENV'   "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh writes runtime.env (SD-R28 output 1)" {
    grep -q 'runtime.env' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh writes schedule.json (SD-R28 output 2)" {
    grep -q 'schedule.json' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh sources hardware-tune.env (cross-module integration)" {
    grep -q 'hardware-tune.env\|TUNE_FILE' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh calls selfdefctl hardware export for per-GPU caps" {
    grep -q 'selfdefctl hardware export' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh fails fast when selfdefctl is missing" {
    grep -qE 'command -v selfdefctl' "${INSTALL_DIR}/apply.sh"
}

# ============================================================
# check.sh contract
# ============================================================

@test "check.sh uses set -euo pipefail" {
    grep -qE '^set -euo pipefail' "${INSTALL_DIR}/check.sh"
}

@test "check.sh verifies the 4 expected artifact paths" {
    grep -q 'ETC_DIR'                "${INSTALL_DIR}/check.sh"
    grep -q 'STATE_DIR'              "${INSTALL_DIR}/check.sh"
    grep -q 'runtime.env'            "${INSTALL_DIR}/check.sh"
    grep -q 'schedule.json'          "${INSTALL_DIR}/check.sh"
}

@test "check.sh emits structured status JSON via emit_status" {
    grep -q 'emit_status' "${INSTALL_DIR}/check.sh"
}

# ============================================================
# Dry-run smoke (tmpdir ETC + STATE + tune file, mocked selfdefctl)
# ============================================================

setup_dry_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_BITNET_ETC_DIR="${TEST_DIR}/etc"
    export SELFDEF_BITNET_STATE_DIR="${TEST_DIR}/state"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    # Provide an empty tune file so the cross-module integration path
    # is exercised without the upstream hardware-tune-cache module.
    cat > "${SELFDEF_HARDWARE_TUNE_ENV}" <<EOF
# Synthesized for L2 dry-run test.
CFLAGS="-march=native"
EOF
    # Mock selfdefctl so `selfdefctl hardware export` returns a
    # plausible per-GPU JSON.
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    cat > "${MOCK_BIN}/selfdefctl" <<'EOF'
#!/bin/bash
case "$*" in
    *"hardware export"*)
        echo '{"gpus":[{"index":0,"vram_gib":24,"name":"RTX 3090"}]}'
        ;;
    *)
        exit 0
        ;;
esac
EOF
    chmod +x "${MOCK_BIN}/selfdefctl"
    export PATH="${MOCK_BIN}:${PATH}"
}

teardown_dry_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_BITNET_ETC_DIR SELFDEF_BITNET_STATE_DIR \
        SELFDEF_HARDWARE_TUNE_ENV MOCK_BIN
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
