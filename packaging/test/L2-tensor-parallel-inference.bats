#!/usr/bin/env bats
# L2 bats unit tests for the tensor-parallel-inference module (MS030
# — provisions tensor-parallel inference splits; every GPU hosts a
# slice. Demonstrates SD-R51 ALL-semantics + SD-R55 signing composition,
# SD-R58).
#
# Run with: bats packaging/test/L2-tensor-parallel-inference.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + name = tensor-parallel-inference" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"tensor-parallel-inference"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on hardware-tune-cache (MS010 upstream)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides tensor-parallel-runtime contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"tensor-parallel-runtime"' "${MODULE_DIR}/module.toml"
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

@test "apply.sh exposes SELFDEF_TENSOR_PARALLEL_ETC_DIR override" {
    grep -q 'SELFDEF_TENSOR_PARALLEL_ETC_DIR' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh consumes hardware-tune.env from MS010" {
    grep -q 'SELFDEF_HARDWARE_TUNE_ENV' "${INSTALL_DIR}/apply.sh"
}

# Dry-run smoke
@test "apply.sh runs cleanly in dry-run mode (mocked selfdefctl)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_TENSOR_PARALLEL_ETC_DIR="${TEST_DIR}/etc"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    cat > "${MOCK_BIN}/selfdefctl" <<'EOF'
#!/bin/bash
case "$*" in
    *"hardware export"*)
        echo '{"gpus":[{"index":0,"vram_gib":24,"name":"RTX 3090"},{"index":1,"vram_gib":98,"name":"RTX PRO 6000"}]}'
        ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "${MOCK_BIN}/selfdefctl"
    export PATH="${MOCK_BIN}:${PATH}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_TENSOR_PARALLEL_ETC_DIR SELFDEF_HARDWARE_TUNE_ENV MOCK_BIN
    [ "${status}" -eq 0 ]
}
