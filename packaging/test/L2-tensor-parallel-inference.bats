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

# ============================================================
# Real-apply smoke + idempotency invariants (post-4c8e2cf fix)
# ============================================================

setup_real_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_TENSOR_PARALLEL_ETC_DIR="${TEST_DIR}/etc"
    mkdir -p "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}"
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
}

teardown_real_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_TENSOR_PARALLEL_ETC_DIR SELFDEF_HARDWARE_TUNE_ENV MOCK_BIN
}

@test "apply.sh runs cleanly in real-apply mode (writes slice-plan.json + runtime.env)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json" ]
    [ -f "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env" ]
    teardown_real_run
}

@test "INVARIANT (slice-plan.json idempotent — post-4c8e2cf cmp-s fix): re-apply with same inputs preserves mtime" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mtime_before="$(stat -c '%Y' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json")"
    sleep 1
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mtime_after="$(stat -c '%Y' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json")"
    teardown_real_run
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (runtime.env idempotent — post-4c8e2cf cmp-s fix): re-apply with same inputs preserves mtime" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mtime_before="$(stat -c '%Y' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env")"
    sleep 1
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mtime_after="$(stat -c '%Y' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env")"
    teardown_real_run
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (no render-timestamp in slice-plan.json): post-4c8e2cf — generated_at field DROPPED" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    # The generated_at field was removed by the 2026-06-06
    # variant-A fix; it must not return.
    has_ts=0
    grep -q 'generated_at' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json" && has_ts=1
    teardown_real_run
    [ "${has_ts}" = "0" ]
}

@test "INVARIANT (slice-plan.json is well-formed JSON): output parses as JSON regardless of /dev/nvidia* presence" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    # Parse the file as JSON — failure means the script wrote a
    # malformed file. Locks the JSON-validity invariant.
    python3 -c "import json; json.load(open('${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json'))"
    parse_ok=$?
    teardown_real_run
    [ "${parse_ok}" = "0" ]
}

@test "INVARIANT (slice-plan.json schema_version): the schema_version field IS present (downstream consumer contract)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -q 'schema_version' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json"
    teardown_real_run
}

@test "INVARIANT (runtime.env declares hardware-tune source + TP knobs): runtime.env carries both consumer references" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    # runtime.env must source the upstream hardware-tune.env AND
    # set the TP knobs (slice-plan path, nranks).
    grep -q 'hardware-tune.env' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env"
    grep -q 'TP_SLICE_PLAN=' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env"
    grep -q 'TP_NRANKS=' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env"
    teardown_real_run
}

@test "INVARIANT (slice-plan.json carries ranks field — schema contract for downstream consumer)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -q '"ranks"' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json"
    teardown_real_run
}

@test "INVARIANT (slice-plan.json carries slices array — schema contract for downstream consumer)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -q '"slices"' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json"
    teardown_real_run
}

@test "INVARIANT (slice-plan.json + runtime.env modes are chmod 0644 — system-config convention)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    plan_mode="$(stat -c '%a' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json")"
    env_mode="$(stat -c '%a' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env")"
    teardown_real_run
    [ "${plan_mode}" = "644" ]
    [ "${env_mode}" = "644" ]
}

@test "INVARIANT (TP_NRANKS in runtime.env equals ranks count in slice-plan.json — cross-file consistency)" {
    # Both files derive from the same nranks counter — they must
    # agree. Otherwise downstream TP runtime sees mismatched ranks.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    plan_ranks="$(python3 -c "import json; print(json.load(open('${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json')).get('ranks'))")"
    env_nranks="$(grep -oE 'TP_NRANKS="[0-9]+"' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env" | grep -oE '[0-9]+')"
    teardown_real_run
    [ "${plan_ranks}" = "${env_nranks}" ]
}
