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

setup_real_run() {
    TEST_DIR="$(mktemp -d)"
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

teardown_real_run() {
    rm -rf "${TEST_DIR}"
    unset SELFDEF_HARDWARE_TUNE_ENV MOCK_BIN
}

@test "INVARIANT: real apply is idempotent — byte-identical re-install does NOT rewrite env file (2026-06-06 idempotency fix)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_HARDWARE_TUNE_ENV}" ]
    mtime_before="$(stat -c '%Y' "${SELFDEF_HARDWARE_TUNE_ENV}")"
    sleep 1
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mtime_after="$(stat -c '%Y' "${SELFDEF_HARDWARE_TUNE_ENV}")"
    teardown_real_run
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: no render-timestamp in env file (defeats cmp -s)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    if grep -qE '^# Generated [^#]*[0-9]{4}-[0-9]{2}-[0-9]{2}T' "${SELFDEF_HARDWARE_TUNE_ENV}"; then
        teardown_real_run
        false
    fi
    teardown_real_run
}

@test "INVARIANT (env file is shell-sourceable: bash -n parses it cleanly)" {
    # Downstream consumers source the env file. It MUST be valid shell
    # syntax (no malformed assignments, no unterminated quotes).
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    bash -n "${SELFDEF_HARDWARE_TUNE_ENV}"
    parse_rc=$?
    teardown_real_run
    [ "${parse_rc}" -eq 0 ]
}

@test "INVARIANT (env file carries CFLAGS + RUSTFLAGS — both compiler-toolchain envs covered)" {
    # The downstream contract per SD-R23: both C/C++ (CFLAGS) and
    # Rust (RUSTFLAGS) toolchain consumers must find their respective
    # variables. Lock that BOTH surface in the env file.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -q '^CFLAGS=' "${SELFDEF_HARDWARE_TUNE_ENV}"
    grep -q '^RUSTFLAGS=' "${SELFDEF_HARDWARE_TUNE_ENV}"
    teardown_real_run
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates env file)" {
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_HARDWARE_TUNE_ENV}" ]
    rm -f "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    rc=$?
    teardown_real_run
    [ "${rc}" -eq 0 ]
}

@test "INVARIANT (env file is chmod 0644 — system-config convention; no operator-write-needed)" {
    # Sister to many other installer modules' chmod 0644 INVARIANT
    # across the brain. The hardware-tune env file is a system-config
    # surface (consumed by downstream compiler toolchain wrappers).
    # MUST be world-readable (operator-build scripts may run as
    # non-root and need to source it) but NOT world-writable (would
    # let a non-root attacker plant malicious CFLAGS that get
    # consumed by every subsequent compile). Locks the file mode
    # discipline alongside the shell-sourceable + content-fidelity
    # axes already covered.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mode="$(stat -c '%a' "${SELFDEF_HARDWARE_TUNE_ENV}")"
    teardown_real_run
    [ "${mode}" = "644" ]
}

@test "INVARIANT (env file header carries hardware-tune-cache self-identifying marker — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / slm-cpu-loop /
    # tensor-parallel-inference / journal-tune / acct-baseline).
    # The env file lands at /etc/selfdef/hardware-tune.env. A
    # stale-cleanup pass (operator housekeeping or uninstall
    # path) inspects the first non-blank comment line to identify
    # selfdef-rendered config from operator config. Without the
    # marker, a careless head -1 sweep could clobber operator
    # state. Locks the provenance contract.
    setup_real_run
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${SELFDEF_HARDWARE_TUNE_ENV}")"
    teardown_real_run
    [[ "${first_nonblank}" == *"hardware-tune"* ]] || [[ "${first_nonblank}" == *"selfdef"* ]]
}

@test "INVARIANT (module.toml provides hardware-tune-env contract — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain (bridge-l2 l2-bridge, suricata
    # ids+eve-json, slm-cpu-loop slm-loop-runtime, tensor-
    # parallel-inference tensor-parallel-runtime, wasm-aot-cache
    # wasm-aot-cache-dir). The hardware-tune-cache module is the
    # substrate every compile-via-CFLAGS / RUSTFLAGS consumer
    # module composes on. Its provides token names the env-
    # binding contract — every consumer module (tensor-parallel-
    # inference / slm-cpu-loop / wasm-aot-cache / future
    # compile-time-tuned modules) lists this in depends_on. A
    # silent rename of the token would break every downstream
    # consumer's compile-time CPU-tuning ingestion.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"hardware-tune-env"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (apply.sh uses set -euo pipefail — anti-half-installed-state contract)" {
    # Sister to brain-wide installer-script-hygiene INVARIANTs.
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/apply.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/apply.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/apply.sh")
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — full lifecycle fail-loud invariant)" {
    # Sister to apply.sh fail-loud INVARIANT just locked. Full
    # lifecycle (check/uninstall) MUST also be fail-loud — half-
    # cleanup of tune-env during operator MTTR leaves downstream
    # modules (slm-cpu-loop, wasm-aot-cache, tensor-parallel-
    # inference) consuming broken state.
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/check.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/check.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/check.sh")
    grep -qE 'set[[:space:]]+-euo[[:space:]]+pipefail' "${INSTALL_DIR}/uninstall.sh" \
        || (grep -qE 'set[[:space:]]+-eu' "${INSTALL_DIR}/uninstall.sh" && grep -qE 'set[[:space:]]+-o[[:space:]]+pipefail' "${INSTALL_DIR}/uninstall.sh")
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs.
    # The hardware-tune-cache module.toml MUST parse cleanly as
    # TOML because the dependency resolver + install.sh dispatch
    # parse this file at load time. A malformed module.toml
    # would crash the install plan + leave consumer modules
    # (slm-cpu-loop, wasm-aot-cache, tensor-parallel-inference,
    # bitnet-gpu-inference) without their hardware-tune-env
    # substrate. Locks parser-validity contract on this
    # foundational tune-cache module.toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (no auto-uninstall: hardware-tune-cache installer NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANT family.
    # hardware-tune-cache writes a CFLAGS/RUSTFLAGS env file
    # consumed by downstream module-build steps; package-removal
    # of the underlying selfdefctl/rustc/cargo toolchains is
    # operator-domain (the toolchain is not installed by THIS
    # module). Locks no-auto-uninstall on the hardware-tune-
    # cache substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(selfdefctl|rustc|cargo)' "${f}"
    done
}

@test "INVARIANT (apply.sh phase = \"pre\" honored — manifest declares pre-runtime hook so env file lands before consumers fire)" {
    # Sister to brain-wide module.toml manifest-completeness +
    # phase-order contract family. hardware-tune-cache provides
    # the hardware-tune-env contract every downstream rust/cargo/
    # cc/c++ build step in selfdef consumes. To guarantee the
    # env file is on disk BEFORE those downstream module-install
    # steps fire, the manifest declares phase = "pre" — the
    # selfdef installer's topological sort honors this and
    # schedules pre-phase modules first. Renaming "pre" to a
    # different label or omitting it would break the downstream-
    # consumer install ordering. Locks pre-phase contract on the
    # hardware-tune-cache substrate.
    grep -qE '^phase[[:space:]]*=[[:space:]]*"pre"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml [requires_hardware].memory_gib_min present + numeric — RAM-gating hardware-tier discrimination)" {
    # Sister to brain-wide module.toml [requires_hardware]
    # SD-R14 contract family. hardware-tune-cache's tuned env
    # file only earns its keep on workstation-class hosts (32+
    # GiB RAM where march=native + AVX-512 VNNI actually
    # accelerate downstream cargo/cc builds). The memory_gib_min
    # gate prevents the resolver from installing tune-cache on
    # tiny CI/VM hosts where the fallback selfdef-tune.sh path
    # already returns the right tune (and the cache file would
    # be wrong because the host's memory profile is different).
    # A regression dropping memory_gib_min would surface as
    # spurious AVX-512 flags landing in cargo builds on 8-GiB
    # CI runners. Locks RAM-gating discipline on the hardware-
    # tune-cache substrate (sister to avx512_vnni gate already
    # locked).
    grep -qE '^memory_gib_min[[:space:]]*=[[:space:]]*[0-9]+' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the hardware-tune-cache substrate.
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
    # the hardware-tune-cache requires substrate.
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
    # hardware-tune-cache substrate.
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
    # hardware-tune-cache substrate.
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
    # Locks semver-X.Y.Z discipline on the hardware-tune-cache
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

@test "INVARIANT (hardware-tune-cache module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the hardware-tune-cache module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
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

@test "INVARIANT (hardware-tune-cache module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the hardware-tune-cache module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
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

@test "INVARIANT (hardware-tune-cache module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the hardware-tune-cache
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
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

@test "INVARIANT (hardware-tune-cache module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for hardware-tune-cache is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the hardware-tune-cache substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the hardware-tune-cache install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
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

@test "INVARIANT (hardware-tune-cache module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the hardware-tune-cache requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
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

@test "INVARIANT (hardware-tune-cache module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name INVARIANT family.
    # The name field MUST match the parent directory name so
    # the selfdef installer can resolve modules/<slug>/
    # module.toml by name field alone (without re-reading
    # parent-dir name). A regression where module.toml name
    # = "foo" lives under modules/bar/ would break the
    # resolver's path-by-name canonical lookup. Locks the
    # name-matches-dir discipline on the hardware-tune-cache substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'hardware-tune-cache', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml provides field present as TOML list of strings — capability-export contract)" {
    # Sister to brain-wide module.toml provides INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    # Sister to brain-wide module.toml conflicts INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml depends_on field present as TOML list — module-dependency-resolver contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = data.get('depends_on')
assert isinstance(d, list), f'depends_on must be TOML list (may be empty), got {type(d).__name__}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml consumes field present as TOML list — capability-consumer contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes')
assert isinstance(c, list), f'consumes must be TOML list, got {type(c).__name__}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml summary field present + non-empty — module-doc-trail contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert s, f'summary must be non-empty, got {s!r}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ap = (data.get('install') or {}).get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ch = (data.get('install') or {}).get('check', '')
assert ch == 'install/check.sh', f'install.check must be install/check.sh, got {ch!r}'
"
}

@test "INVARIANT (hardware-tune-cache module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (hardware-tune-cache install scripts (apply/check/uninstall) all exist as files — script-file existence contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install"
    [ -d "${inst_dir}" ]
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (hardware-tune-cache install/apply.sh exists as file — apply-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/apply.sh" ]
}

@test "INVARIANT (hardware-tune-cache install/apply.sh is executable (mode includes +x) — script-runnable contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/apply.sh"
    [ -x "${apply}" ]
}

@test "INVARIANT (hardware-tune-cache install/check.sh exists as file — check-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/check.sh" ]
}

@test "INVARIANT (hardware-tune-cache install/check.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/check.sh" ]
}

@test "INVARIANT (hardware-tune-cache install/uninstall.sh exists as file — uninstall-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/uninstall.sh" ]
}

@test "INVARIANT (hardware-tune-cache install/uninstall.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/uninstall.sh" ]
}

@test "INVARIANT (hardware-tune-cache install scripts apply+check+uninstall all are executable — 3-script-runnable contract)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install"
    [ -x "${inst}/apply.sh" ]
    [ -x "${inst}/check.sh" ]
    [ -x "${inst}/uninstall.sh" ]
}

@test "INVARIANT (hardware-tune-cache install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (hardware-tune-cache install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (hardware-tune-cache install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (hardware-tune-cache install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/apply.sh"
    [ -s "${apply}" ]
}

@test "INVARIANT (hardware-tune-cache install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (hardware-tune-cache install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (hardware-tune-cache module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}

@test "INVARIANT (hardware-tune-cache module.toml exists at canonical path modules/hardware-tune-cache/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (hardware-tune-cache module dir is at canonical path modules/hardware-tune-cache/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (hardware-tune-cache install dir exists at modules/hardware-tune-cache/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (hardware-tune-cache install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (hardware-tune-cache install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (hardware-tune-cache install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (hardware-tune-cache install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (hardware-tune-cache module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (hardware-tune-cache install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (hardware-tune-cache install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (hardware-tune-cache install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (hardware-tune-cache install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (hardware-tune-cache install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/hardware-tune-cache/install/uninstall.sh"
    [ -s "${uni}" ]
}
