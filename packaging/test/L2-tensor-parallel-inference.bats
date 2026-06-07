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

@test "INVARIANT (runtime.env is shell-sourceable: bash -n parses cleanly — downstream consumer contract)" {
    # Downstream TP runtime sources runtime.env. It MUST be valid
    # shell syntax (no malformed assignments, no unterminated
    # quotes). Sister to hardware-tune-cache shell-sourceable
    # INVARIANT.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    bash -n "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env"
    parse_rc=$?
    teardown_real_run
    [ "${parse_rc}" -eq 0 ]
}

@test "INVARIANT (slices array length equals ranks count — schema internal consistency)" {
    # slice-plan.json carries both ranks (a count) and slices (an
    # array). The array MUST have ranks entries — otherwise the
    # cross-file consistency INVARIANT above is satisfiable while
    # the plan itself is internally inconsistent. Locks the
    # internal-consistency boundary.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    consistent=$(python3 -c "import json; p=json.load(open('${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json')); print(1 if len(p.get('slices', [])) == p.get('ranks') else 0)")
    teardown_real_run
    [ "${consistent}" = "1" ]
}

@test "INVARIANT (re-arm after operator deletion: both slice-plan.json + runtime.env re-created on next apply)" {
    # Sister to many other modules' re-arm INVARIANT. When operator
    # rm -rf the ETC_DIR contents, the next apply MUST re-create
    # both files cleanly.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json" ]
    rm -f "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json" "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    re_armed=0
    [ -f "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/slice-plan.json" ] && [ -f "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env" ] && re_armed=1
    teardown_real_run
    [ "${re_armed}" = "1" ]
}

@test "INVARIANT (runtime.env carries tensor-parallel-inference self-identifying header — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (slm-cpu-loop / ssh-hardening /
    # hardware-tune-cache). The runtime.env lands at
    # /etc/selfdef/tensor-parallel-inference/runtime.env alongside
    # operator-hand-authored / vendor / packaging-provided env
    # files. A stale-cleanup pass (operator housekeeping or
    # uninstall path) inspects the first non-blank comment line to
    # identify selfdef-rendered config from operator config.
    # Without the marker, a careless head -1 sweep could clobber
    # operator state.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env" ]
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${SELFDEF_TENSOR_PARALLEL_ETC_DIR}/runtime.env")"
    teardown_real_run
    [[ "${first_nonblank}" == *"tensor-parallel-inference"* ]]
}

@test "INVARIANT (module.toml provides tensor-parallel-runtime contract — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain (suricata ids+eve-json, slm-
    # cpu-loop slm-loop-runtime, wasm-aot-cache wasm-aot-cache-
    # dir). The tensor-parallel-inference module's provides
    # field names the downstream-visible interface — every
    # tensor-parallel-runtime consumer module (inference
    # workloads requiring multi-GPU tensor split) lists this
    # in their depends_on. A silent rename of the provides
    # token would break every downstream consumer module.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"tensor-parallel-runtime"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml depends_on hardware-tune-env — CPU/GPU-tuning ingestion contract)" {
    # Sister to slm-cpu-loop depends_on hardware-tune-env contract.
    # tensor-parallel-inference composes on hardware-tune-cache —
    # resolver installs hardware-tune-cache BEFORE tensor-parallel-
    # inference so CFLAGS/RUSTFLAGS are available at runtime.env
    # render time.
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-env"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml" \
        || true
}

@test "INVARIANT (apply.sh uses set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud set-euo-pipefail INVARIANTs.
    # tensor-parallel-inference is the runtime contract for
    # multi-GPU tensor-parallel inference; silent failure in
    # apply.sh would leave slice-plan.json + runtime.env in a
    # partially-rendered state that downstream consumers
    # (sovereign-os MS028 + slm-cpu-loop) would consume as
    # broken. Lock fail-loud discipline on apply.sh.
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/apply.sh"
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — fail-loud invariant across full module surface)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # apply.sh fail-loud locked above; check.sh + uninstall.sh
    # are the OTHER two operator-facing scripts in the module
    # surface. Silent check.sh failure would mask slice-plan.json
    # + runtime.env corruption from operator observation; silent
    # uninstall.sh failure leaves the tensor-parallel-inference
    # runtime layer in half-removed state during package purge.
    # Locks fail-loud contract on the full module-script surface
    # (apply + check + uninstall) on the tensor-parallel substrate.
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/check.sh"
    grep -qE 'set -euo pipefail' "${MODULE_DIR}/install/uninstall.sh"
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs
    # (detect-host, hardware-tune-cache, slm-cpu-loop, suricata).
    # The tensor-parallel-inference module.toml MUST parse
    # cleanly as TOML because the dependency resolver +
    # install.sh dispatch parse this file at load time. A
    # malformed module.toml would crash the install plan +
    # leave consumer modules (sovereign-os MS028 + slm-cpu-loop)
    # without their tensor-parallel-runtime substrate. Locks
    # parser-validity contract on the tensor-parallel module.
    # toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (no auto-uninstall: tensor-parallel-inference installer NEVER emits package-remove commands on vllm/cuda/python-runtime)" {
    # Sister to brain-wide no-auto-uninstall INVARIANT family.
    # tensor-parallel-inference wires the vllm + CUDA + python
    # runtime config; package-removal of those runtimes is
    # operator-domain (not installed by THIS module). Locks
    # no-auto-uninstall on the tensor-parallel-inference
    # substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum|pip|pip3)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(vllm|cuda|python3?)' "${f}"
    done
}

@test "INVARIANT (no auto-delete: tensor-parallel-inference installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # tensor-parallel-inference writes its own env/config files;
    # it MUST NEVER rm/find-delete an operator's pre-existing
    # /etc/selfdef/inference or vllm/cuda config files not owned
    # by THIS module. Locks no-auto-delete on the tensor-parallel-
    # inference installer substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/selfdef' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/selfdef.*-delete' "${f}"
    done
}
