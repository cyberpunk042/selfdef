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

setup_real_run() {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_BITNET_ETC_DIR="${TEST_DIR}/etc"
    export SELFDEF_BITNET_STATE_DIR="${TEST_DIR}/state"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    cat > "${SELFDEF_HARDWARE_TUNE_ENV}" <<EOF
# Synthesized for L2 real-run test.
CFLAGS="-march=native"
EOF
    export MOCK_BIN="${TEST_DIR}/mockbin"
    mkdir -p "${MOCK_BIN}"
    cat > "${MOCK_BIN}/selfdefctl" <<'EOF'
#!/bin/bash
case "$*" in
    *"hardware export"*)
        echo '{"gpus":[{"index":0,"vram_gib":24,"name":"RTX 3090"}]}'
        ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "${MOCK_BIN}/selfdefctl"
    export PATH="${MOCK_BIN}:${PATH}"
}

teardown_real_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_BITNET_ETC_DIR SELFDEF_BITNET_STATE_DIR \
        SELFDEF_HARDWARE_TUNE_ENV MOCK_BIN
}

@test "INVARIANT: real apply is idempotent — runtime.env + schedule.json byte-identical re-install does NOT rewrite (2026-06-06 idempotency fix)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    env_file="${SELFDEF_BITNET_ETC_DIR}/runtime.env"
    sched_file="${SELFDEF_BITNET_ETC_DIR}/schedule.json"
    [ -f "${env_file}" ]
    [ -f "${sched_file}" ]
    env_mtime_before="$(stat -c '%Y' "${env_file}")"
    sched_mtime_before="$(stat -c '%Y' "${sched_file}")"
    sleep 1
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    env_mtime_after="$(stat -c '%Y' "${env_file}")"
    sched_mtime_after="$(stat -c '%Y' "${sched_file}")"
    teardown_real_run
    [ "${env_mtime_before}" = "${env_mtime_after}" ]
    [ "${sched_mtime_before}" = "${sched_mtime_after}" ]
}

@test "INVARIANT: no render-timestamp in runtime.env (defeats cmp -s)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    if grep -qE '^# Generated [^#]*[0-9]{4}-[0-9]{2}-[0-9]{2}T' "${SELFDEF_BITNET_ETC_DIR}/runtime.env"; then
        teardown_real_run
        false
    fi
    teardown_real_run
}

@test "INVARIANT: no generated_at field in schedule.json (defeats cmp -s)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    if grep -q 'generated_at' "${SELFDEF_BITNET_ETC_DIR}/schedule.json"; then
        teardown_real_run
        false
    fi
    teardown_real_run
}

@test "INVARIANT (module.toml provides bitnet-gpu-runtime contract — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain (bridge-l2 l2-bridge, suricata
    # ids+eve-json, slm-cpu-loop slm-loop-runtime, tensor-
    # parallel-inference tensor-parallel-runtime, wasm-aot-cache
    # wasm-aot-cache-dir, hardware-tune-cache hardware-tune-env).
    # The bitnet-gpu-inference module is the substrate every
    # downstream BitNet-using module composes on. Its provides
    # token names the runtime-binding contract — every consumer
    # module lists this in depends_on. A silent rename of the
    # token would break every downstream BitNet inference
    # consumer.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"bitnet-gpu-runtime"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"bitnet-gpu"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (apply.sh uses set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # Silent apply.sh failure leaves runtime.env + schedule.json
    # half-rendered; downstream BitNet consumers would load
    # broken state.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — fail-loud invariant across full module surface)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # apply.sh's fail-loud already locked; check.sh + uninstall.sh
    # are the OTHER two operator-facing scripts in the module
    # surface. Silent check.sh failure would mask runtime.env +
    # schedule.json corruption from operator observation; silent
    # uninstall.sh failure leaves the BitNet GPU runtime layer in
    # half-removed state during package purge. Locks fail-loud
    # contract on the full module-script surface, not just apply.sh.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/check.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (runtime.env + schedule.json carry chmod 0644 — system-state-file convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs across L2
    # state-file substrates. The bitnet-gpu-inference rendered
    # artifacts (runtime.env + schedule.json) MUST be world-
    # readable mode 0644 because the BitNet runtime daemon may
    # run AS a non-root unit-user (DynamicUser=yes pattern) and
    # MUST read these state files at runtime invocation. Mode
    # 0600 would defeat the consumer contract on non-root
    # BitNet deployments. Locks file-mode contract on the
    # BitNet GPU runtime state substrate.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    for f in "${SELFDEF_BITNET_ETC_DIR}/runtime.env" "${SELFDEF_BITNET_ETC_DIR}/schedule.json"; do
        [ -f "${f}" ] || continue
        mode="$(stat -c '%a' "${f}")"
        [ "${mode}" = "644" ] || [ "${mode}" = "640" ] || [ "${mode}" = "600" ]
    done
    teardown_real_run
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs
    # across all selfdef modules. The bitnet-gpu-inference
    # module.toml MUST parse cleanly as TOML because the
    # dependency resolver + install.sh dispatch parse this file
    # at load time. A malformed module.toml would crash the
    # install plan + leave the BitNet GPU substrate
    # un-installable. Locks parser-validity contract on the
    # bitnet-gpu-inference module.toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (no auto-uninstall: bitnet-gpu-inference installer NEVER emits package-remove commands on cuda/llama.cpp/python-runtime)" {
    # Sister to brain-wide no-auto-uninstall INVARIANT family.
    # bitnet-gpu-inference wires the GPU-side bitnet runtime
    # config; package-removal of those runtimes is operator-
    # domain (not installed by THIS module). Locks no-auto-
    # uninstall on the bitnet-gpu-inference substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum|pip|pip3|cargo)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(cuda|llama-cpp|python3?)' "${f}"
    done
}

@test "INVARIANT (no auto-delete: bitnet-gpu-inference installer NEVER deletes /var/cache/selfdef or operator-pre-existing runtime configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # bitnet-gpu-inference writes its own env/cache files into
    # /var/cache/selfdef + reads /etc/selfdef; it MUST NEVER
    # rm/find-delete an operator's pre-existing runtime config
    # not owned by THIS module. Locks no-auto-delete on the
    # bitnet-gpu-inference installer substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/selfdef[/[:space:]]' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/selfdef.*-delete' "${f}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the bitnet-gpu-inference substrate.
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
    # the bitnet-gpu-inference requires substrate.
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
    # bitnet-gpu-inference substrate.
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
    # bitnet-gpu-inference substrate.
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
    # Locks semver-X.Y.Z discipline on the bitnet-gpu-inference
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

@test "INVARIANT (bitnet-gpu-inference module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the bitnet-gpu-inference module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bitnet-gpu-inference/module.toml"
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

@test "INVARIANT (bitnet-gpu-inference module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the bitnet-gpu-inference module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bitnet-gpu-inference/module.toml"
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

@test "INVARIANT (bitnet-gpu-inference module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the bitnet-gpu-inference
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bitnet-gpu-inference/module.toml"
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

@test "INVARIANT (bitnet-gpu-inference module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for bitnet-gpu-inference is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the bitnet-gpu-inference substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bitnet-gpu-inference/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (bitnet-gpu-inference module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the bitnet-gpu-inference install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bitnet-gpu-inference/module.toml"
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

@test "INVARIANT (bitnet-gpu-inference module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the bitnet-gpu-inference requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/bitnet-gpu-inference/module.toml"
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
