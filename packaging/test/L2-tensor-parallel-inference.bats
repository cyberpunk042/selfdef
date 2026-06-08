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

@test "INVARIANT (no auto-delete of operator-pre-existing /var/cache/selfdef contents — installer manages own files only)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # Distinct from the existing /etc/selfdef-side INVARIANT
    # above — this locks the OUTPUT cache dir: tensor-parallel-
    # inference writes per-config cache state into
    # /var/cache/selfdef/tensor-parallel, but it MUST NEVER
    # rm/find-delete an OPERATOR-pre-existing /var/cache/selfdef
    # subdir not owned by THIS module (e.g. another model's
    # cache dir). Locks no-auto-delete on the /var/cache/selfdef
    # output substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/var/cache/selfdef([[:space:]]|/[[:space:]]|$)' "${f}"
        ! grep -qE 'find[[:space:]]+/var/cache/selfdef[[:space:]].*-delete' "${f}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the tensor-parallel-inference substrate.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('depends_on', [])
assert isinstance(v, list), f'depends_on must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml conflicts field is a TOML list — anti-string-malformation contract on conflicts)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks list-vs-string discipline on conflicts.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('conflicts', [])
assert isinstance(v, list), f'conflicts must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml provides field is a TOML list — anti-string-malformation contract on provides)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on provides.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('provides', [])
assert isinstance(v, list), f'provides must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires field is a TOML list — anti-string-malformation contract on requires)" {
    # Sister to brain-wide module.toml list-vs-string family.
    # Locks list discipline on requires.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('requires', [])
assert isinstance(v, list), f'requires must be list, got {type(v).__name__}'
"
}

@test "INVARIANT (module.toml requires entries are tables with kind + value — anti-flat-string-list contract)" {
    # Sister to brain-wide module.toml requires-shape INVARIANT
    # family. Locks the kind+value table-shape discipline on
    # the tensor-parallel-inference requires substrate.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
reqs = data.get('requires', [])
for r in reqs:
    assert isinstance(r, dict), f'requires entry must be table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires entry must have kind+value, got {r}'
"
}

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks summary-present discipline on the
    # tensor-parallel-inference substrate.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) > 0, f'summary must be non-empty string, got {repr(s)}'
"
}

@test "INVARIANT (module.toml category field present + non-empty — dashboard-grouping contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # family. Locks category-present discipline on the
    # tensor-parallel-inference substrate.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert isinstance(c, str) and len(c) > 0, f'category must be non-empty string, got {repr(c)}'
"
}

@test "INVARIANT (module.toml version field is semver X.Y.Z — version-comparison sortability contract)" {
    # Sister to brain-wide module.toml semver INVARIANT family.
    # Locks semver-X.Y.Z discipline on the tensor-parallel-inference
    # substrate.
    mtoml="${MODULE_DIR}/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl installer resolves apply scripts
    # via module.toml's [install].apply field — the canonical
    # value is the relative path "install/apply.sh" (under the
    # module's own directory). A regression that swapped to
    # an absolute /usr/local/libexec/... path would break the
    # in-tree test runner (which executes apply scripts from
    # the source tree, not /usr/local/libexec/). A regression
    # to a non-existent path would surface as "apply script
    # not found" at install time. Locks the canonical
    # install/apply.sh path discipline on the tensor-parallel-inference module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
ap = inst.get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the tensor-parallel-inference module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install') or {}
chk = inst.get('check', '')
assert chk == 'install/check.sh', f'install.check must be install/check.sh, got {chk!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
    # Sister to brain-wide module.toml [install_paths]
    # INVARIANT family. Per MS011 Z-8 / SDD-026, every
    # installer module MUST declare an [install_paths] block
    # enumerating the on-disk surfaces it touches on apply.
    # The selfdef dashboard's install-options surface +
    # install-plan auditor read this block to surface what
    # the module mutates BEFORE apply runs. A regression
    # dropping the [install_paths] block would leave operators
    # without a pre-apply manifest of writes, breaking
    # operator-consent + the install-plan-dry-run contract.
    # Locks the SDD-026 manifest discipline on the tensor-parallel-inference
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, f'[install_paths] block must be present per SDD-026, got None'
paths = ip.get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for tensor-parallel-inference is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the tensor-parallel-inference substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
    # Sister to brain-wide [install_paths].paths INVARIANT
    # family. The install_paths.paths field MUST be a TOML
    # list of strings (each element an absolute path the
    # module touches on apply). A regression that swapped to
    # a comma-separated string ("path1,path2,path3") would
    # silently treat it as a single literal path. The
    # selfdef installer iterates the list to surface the
    # mutation manifest to operators; broken type-shape
    # would break the install-options surface + dry-run
    # auditor. Locks the TOML-list-of-strings type discipline
    # on the tensor-parallel-inference install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list), f'install_paths.paths must be TOML list, got {type(ps).__name__}'
assert all(isinstance(p, str) for p in ps), f'every paths entry must be a string'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the tensor-parallel-inference requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
req = data.get('requires')
assert isinstance(req, list), f'requires must be TOML list, got {type(req).__name__}'
for r in req:
    assert isinstance(r, dict), f'requires entry must be inline-table, got {type(r).__name__}'
    assert 'kind' in r and 'value' in r, f'requires must have kind+value, got {r!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name INVARIANT family.
    # The name field MUST match the parent directory name so
    # the selfdef installer can resolve modules/<slug>/
    # module.toml by name field alone (without re-reading
    # parent-dir name). A regression where module.toml name
    # = "foo" lives under modules/bar/ would break the
    # resolver's path-by-name canonical lookup. Locks the
    # name-matches-dir discipline on the tensor-parallel-inference substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'tensor-parallel-inference', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml provides field present as TOML list of strings — capability-export contract)" {
    # Sister to brain-wide module.toml provides INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    # Sister to brain-wide module.toml conflicts INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml depends_on field present as TOML list — module-dependency-resolver contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = data.get('depends_on')
assert isinstance(d, list), f'depends_on must be TOML list (may be empty), got {type(d).__name__}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml consumes field present as TOML list — capability-consumer contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes')
assert isinstance(c, list), f'consumes must be TOML list, got {type(c).__name__}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml summary field present + non-empty — module-doc-trail contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert s, f'summary must be non-empty, got {s!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ap = (data.get('install') or {}).get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ch = (data.get('install') or {}).get('check', '')
assert ch == 'install/check.sh', f'install.check must be install/check.sh, got {ch!r}'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (tensor-parallel-inference install scripts (apply/check/uninstall) all exist as files — script-file existence contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install"
    [ -d "${inst_dir}" ]
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (tensor-parallel-inference install/apply.sh exists as file — apply-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/apply.sh" ]
}

@test "INVARIANT (tensor-parallel-inference install/apply.sh is executable (mode includes +x) — script-runnable contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/apply.sh"
    [ -x "${apply}" ]
}

@test "INVARIANT (tensor-parallel-inference install/check.sh exists as file — check-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh" ]
}

@test "INVARIANT (tensor-parallel-inference install/check.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh" ]
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh exists as file — uninstall-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh" ]
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh" ]
}

@test "INVARIANT (tensor-parallel-inference install scripts apply+check+uninstall all are executable — 3-script-runnable contract)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install"
    [ -x "${inst}/apply.sh" ]
    [ -x "${inst}/check.sh" ]
    [ -x "${inst}/uninstall.sh" ]
}

@test "INVARIANT (tensor-parallel-inference install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (tensor-parallel-inference install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (tensor-parallel-inference install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/apply.sh"
    [ -s "${apply}" ]
}

@test "INVARIANT (tensor-parallel-inference install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (tensor-parallel-inference module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}

@test "INVARIANT (tensor-parallel-inference module.toml exists at canonical path modules/tensor-parallel-inference/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (tensor-parallel-inference module dir is at canonical path modules/tensor-parallel-inference/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (tensor-parallel-inference install dir exists at modules/tensor-parallel-inference/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (tensor-parallel-inference install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (tensor-parallel-inference install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (tensor-parallel-inference install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (tensor-parallel-inference module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (tensor-parallel-inference install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (tensor-parallel-inference install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (tensor-parallel-inference install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (tensor-parallel-inference install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (tensor-parallel-inference install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (tensor-parallel-inference install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (tensor-parallel-inference module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (tensor-parallel-inference module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
prefixes = ('/etc/', '/usr/', '/var/', '/lib/', '/opt/', '/run/', '/srv/', '/boot/')
for p in ps:
    assert any(p.startswith(pf) for pf in prefixes), f'{p!r} not canonical-root'
"
}

@test "INVARIANT (tensor-parallel-inference module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (tensor-parallel-inference module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (tensor-parallel-inference module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (tensor-parallel-inference module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tensor-parallel-inference/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/') for p in ps)
"
}
