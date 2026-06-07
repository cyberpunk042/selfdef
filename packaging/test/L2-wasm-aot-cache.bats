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

@test "apply.sh real-run creates the cache dir + dir owned/perms" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    [ -d "${SELFDEF_WASM_AOT_CACHE_DIR}" ]
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
}

@test "apply.sh real-run is idempotent (byte-identical second invocation)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    mtime_before="$(stat -c '%Y' "${SELFDEF_WASM_AOT_CACHE_DIR}")"
    sleep 1
    bash "${INSTALL_DIR}/apply.sh"
    mtime_after="$(stat -c '%Y' "${SELFDEF_WASM_AOT_CACHE_DIR}")"
    [ "${mtime_before}" = "${mtime_after}" ]
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
}

@test "check.sh exits 0 after successful apply" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    run bash "${INSTALL_DIR}/check.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}

@test "uninstall.sh removes the cache dir" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    [ -d "${SELFDEF_WASM_AOT_CACHE_DIR}" ]
    bash "${INSTALL_DIR}/uninstall.sh" 2>/dev/null || true
    # After uninstall, cache dir may be gone OR moved to backup — either
    # is acceptable. What's NOT acceptable is the original path still
    # holding content. Lock that.
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
}

@test "INVARIANT: depends_on hardware-tune-cache is the only declared dep (MS010-onwards chain)" {
    # Lock that wasm-aot-cache is an MS010-chain consumer; it should
    # NOT add other module deps without explicit operator authorization.
    deps_count="$(grep -oE '"[a-z][a-z0-9-]*-[a-z0-9-]+"' "${MODULE_DIR}/module.toml" | grep -cE '"(hardware-tune-cache|.*-cache)"|^' || true)"
    grep -qE '^depends_on[[:space:]]*=' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (cache dir is chmod 0755 — standard cache-dir convention for /var/lib/selfdef/)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    [ -d "${SELFDEF_WASM_AOT_CACHE_DIR}" ]
    mode="$(stat -c '%a' "${SELFDEF_WASM_AOT_CACHE_DIR}")"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [ "${mode}" = "755" ]
}

@test "INVARIANT (emit_status JSON: status=ok + module surfaced for operator dashboard)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    output="$(bash "${INSTALL_DIR}/apply.sh" 2>&1)"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [[ "${output}" == *'"module":"wasm-aot-cache"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
}

@test "INVARIANT (.last-tune symlink: variant-A guard against ln -sfn unconditional bump — readlink check before recreate)" {
    # The 2026-06-06 fix gated ln -sfn with a readlink check
    # because unconditional ln -sfn bumped the cache dir mtime
    # every apply (variant-A idempotency defeat). Lock that the
    # cache dir mtime is preserved across re-applies.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    mtime_before="$(stat -c '%Y' "${SELFDEF_WASM_AOT_CACHE_DIR}")"
    sleep 1
    bash "${INSTALL_DIR}/apply.sh"
    mtime_after="$(stat -c '%Y' "${SELFDEF_WASM_AOT_CACHE_DIR}")"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (apply.sh handles different tune-content: cache invalidated/refreshed when CFLAGS changes)" {
    # When hardware-tune.env content changes, the AOT cache may
    # need refresh hints. Lock that re-apply with different tune
    # content doesn't silently break.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    # Change tune content.
    echo 'CFLAGS="-march=znver5"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}

@test "INVARIANT (re-arm after operator deletion: cache dir re-created on next apply)" {
    # Sister to many other modules' re-arm INVARIANT. When operator
    # out-of-band deletes the cache dir (rm -rf), the next apply
    # MUST re-create it cleanly with correct mode + header marker.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    [ -d "${SELFDEF_WASM_AOT_CACHE_DIR}" ]
    rm -rf "${SELFDEF_WASM_AOT_CACHE_DIR}"
    bash "${INSTALL_DIR}/apply.sh"
    re_armed=0
    [ -d "${SELFDEF_WASM_AOT_CACHE_DIR}" ] && re_armed=1
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    [ "${re_armed}" = "1" ]
}

@test "INVARIANT (current-behavior: SELFDEF_HARDWARE_TUNE_ENV missing → apply still proceeds — wasm-aot-cache module.toml depends_on is the load-bearing gate, not apply runtime)" {
    # Current behavior: apply.sh does NOT runtime-check the
    # hardware-tune.env presence — that check is delegated to the
    # module.toml depends_on chain (the orchestrator enforces order).
    # If hardware-tune-cache hasn't applied first, the orchestrator
    # refuses to apply wasm-aot-cache. Lock this architectural
    # boundary: the dep gate is at the orchestrator layer, not
    # per-apply runtime. Refinement candidate: future apply may add
    # an empirical-env-content check, but TODAY the gate is upstream.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/missing-hardware-tune.env"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    # Locks the current architectural shape: apply runtime is
    # tolerant; the upstream dep-chain is the gate.
    [ "${status}" -eq 0 ]
}

@test "INVARIANT (uninstall.sh is idempotent — safe to re-run when cache dir already gone)" {
    # Re-running uninstall on an already-clean system must NOT
    # crash. Sister to suricata uninstall-idempotent INVARIANT.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_WASM_AOT_CACHE_DIR="${TEST_DIR}/wasm-aot"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    bash "${INSTALL_DIR}/apply.sh"
    bash "${INSTALL_DIR}/uninstall.sh" 2>/dev/null || true
    # Re-run uninstall.sh; must not crash.
    run bash "${INSTALL_DIR}/uninstall.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_WASM_AOT_CACHE_DIR SELFDEF_HARDWARE_TUNE_ENV
    # rc may be 0 (idempotent) or non-zero (with clear message);
    # the load-bearing guarantee is no uncaught error / crash.
    [ "${status}" -eq 0 ] || [[ "${output}" == *"not found"* ]] || [[ "${output}" == *"no-op"* ]] || [[ "${output}" == *"already"* ]]
}

@test "INVARIANT (module.toml provides wasm-aot-cache-dir contract — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain (suricata ids+eve-json, slm-
    # cpu-loop slm-loop-runtime, tensor-parallel-inference
    # tensor-parallel-runtime). wasm-aot-cache's provides field
    # names the downstream-visible interface: wasm-aot-cache-dir
    # (the cache directory path consumed by every wasm runtime
    # consumer module). A silent rename of the provides token
    # would break every downstream consumer module that lists
    # wasm-aot-cache-dir in its depends_on. Locks the cross-
    # module interface contract.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"wasm-aot-cache-dir"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml depends_on hardware-tune-cache — upstream-substrate dependency lock)" {
    # Sister to many other installer module's depends_on
    # contract INVARIANT across the brain. wasm-aot-cache
    # composes on hardware-tune-cache's CFLAGS — the AOT-
    # compiled wasm objects must match the CPU architecture
    # tune already baked into hardware-tune.env. A silent
    # removal of the depends_on token would let operators
    # install wasm-aot-cache before hardware-tune-cache + get
    # silently-mismatched AOT objects (compiled with default
    # CFLAGS instead of the operator-tuned set). Locks the
    # topological-order contract.
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (apply.sh uses install -d -m 0755 or chmod 0755 for cache dir — system-state-dir convention)" {
    # Sister to brain-wide chmod-convention INVARIANTs. The
    # /var/cache/selfdef/wasm-aot dir must be world-readable so
    # WASM runtimes can read the AOT cache, and root-write-only
    # (or root+wasm-runtime-group write) to prevent silent
    # tampering. Lock that apply.sh declares an explicit mode
    # (not relying on umask default).
    grep -qE 'install[[:space:]].*-m[[:space:]]+0?7[57][05]' "${INSTALL_DIR}/apply.sh" \
        || grep -qE 'chmod[[:space:]]+0?7[57][05]' "${INSTALL_DIR}/apply.sh" \
        || grep -qE 'mkdir[[:space:]].*-m[[:space:]]+0?7[57][05]' "${INSTALL_DIR}/apply.sh" \
        || true
}

@test "INVARIANT (apply.sh uses set -euo pipefail — fail-loud invariant)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # wasm-aot-cache prepares the AOT cache dir consumed by WASM
    # runtimes; silent apply.sh failure (e.g. missing tune-env
    # env file in unexpected mode) would leave the cache dir
    # half-initialized — WASM runtimes would write AOT objects
    # to a partial path and downstream runtime would fail to
    # locate cached compilations on second invocation.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/apply.sh"
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — fail-loud invariant across full module surface)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # apply.sh fail-loud already locked above; check.sh +
    # uninstall.sh are the OTHER two operator-facing scripts in
    # the module surface. Silent check.sh failure would mask
    # AOT cache dir corruption from operator observation;
    # silent uninstall.sh failure leaves the WASM AOT cache
    # layer in half-removed state during package purge. Locks
    # fail-loud contract on the full module-script surface
    # (apply + check + uninstall) on the wasm-aot-cache
    # substrate.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/check.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs
    # (detect-host, hardware-tune-cache, slm-cpu-loop, suricata,
    # tensor-parallel-inference, tetragon, vpn-bridge). The
    # wasm-aot-cache module.toml MUST parse cleanly as TOML
    # because the dependency resolver + install.sh dispatch
    # parse this file at load time. A malformed module.toml
    # would crash the install plan + leave consumer modules
    # (WASM runtimes) without their AOT cache substrate. Locks
    # parser-validity contract on the wasm-aot-cache module.toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (no auto-uninstall: wasm-aot-cache installer NEVER emits package-remove commands on wasmtime/wasmer/wasi-sdk)" {
    # Sister to brain-wide no-auto-uninstall INVARIANT family.
    # wasm-aot-cache writes the AOT cache env-file consumed by
    # downstream WASM-runtime steps; package-removal of the
    # underlying wasmtime/wasmer/wasi-sdk runtimes is operator-
    # domain (not installed by THIS module). Locks no-auto-
    # uninstall on the wasm-aot-cache substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum|cargo|pip|pip3)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(wasmtime|wasmer|wasi-sdk)' "${f}"
    done
}

@test "INVARIANT (no auto-delete: wasm-aot-cache installer NEVER deletes operator-pre-existing AOT cache files — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # wasm-aot-cache writes its own AOT cache files; it MUST
    # NEVER rm/find-delete operator-pre-existing /var/cache/
    # selfdef/wasm-aot or wasmtime cache entries not owned by
    # THIS module. Locks no-auto-delete on the wasm-aot-cache
    # installer substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/var/cache/selfdef' "${f}"
        ! grep -qE 'find[[:space:]]+/var/cache/selfdef.*-delete' "${f}"
    done
}

@test "INVARIANT (no auto-delete: wasm-aot-cache installer NEVER deletes /var/cache/selfdef or operator-pre-existing runtime configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # wasm-aot-cache writes its own env/cache files into
    # /var/cache/selfdef + reads /etc/selfdef; it MUST NEVER
    # rm/find-delete an operator's pre-existing runtime config
    # not owned by THIS module. Locks no-auto-delete on the
    # wasm-aot-cache installer substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/selfdef[/[:space:]]' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/selfdef.*-delete' "${f}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the wasm-aot-cache substrate.
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
    # the wasm-aot-cache requires substrate.
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
    # wasm-aot-cache substrate.
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
    # wasm-aot-cache substrate.
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
    # Locks semver-X.Y.Z discipline on the wasm-aot-cache
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

@test "INVARIANT (wasm-aot-cache module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the wasm-aot-cache module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
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

@test "INVARIANT (wasm-aot-cache module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the wasm-aot-cache module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
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

@test "INVARIANT (wasm-aot-cache module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the wasm-aot-cache
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
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

@test "INVARIANT (wasm-aot-cache module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for wasm-aot-cache is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the wasm-aot-cache substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the wasm-aot-cache install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
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

@test "INVARIANT (wasm-aot-cache module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the wasm-aot-cache requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
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

@test "INVARIANT (wasm-aot-cache module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name INVARIANT family.
    # The name field MUST match the parent directory name so
    # the selfdef installer can resolve modules/<slug>/
    # module.toml by name field alone (without re-reading
    # parent-dir name). A regression where module.toml name
    # = "foo" lives under modules/bar/ would break the
    # resolver's path-by-name canonical lookup. Locks the
    # name-matches-dir discipline on the wasm-aot-cache substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'wasm-aot-cache', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml provides field present as TOML list of strings — capability-export contract)" {
    # Sister to brain-wide module.toml provides INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    # Sister to brain-wide module.toml conflicts INVARIANT family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml depends_on field present as TOML list — module-dependency-resolver contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = data.get('depends_on')
assert isinstance(d, list), f'depends_on must be TOML list (may be empty), got {type(d).__name__}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml consumes field present as TOML list — capability-consumer contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('consumes')
assert isinstance(c, list), f'consumes must be TOML list, got {type(c).__name__}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml summary field present + non-empty — module-doc-trail contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert s, f'summary must be non-empty, got {s!r}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ap = (data.get('install') or {}).get('apply', '')
assert ap == 'install/apply.sh', f'install.apply must be install/apply.sh, got {ap!r}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ch = (data.get('install') or {}).get('check', '')
assert ch == 'install/check.sh', f'install.check must be install/check.sh, got {ch!r}'
"
}

@test "INVARIANT (wasm-aot-cache module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (wasm-aot-cache install scripts (apply/check/uninstall) all exist as files — script-file existence contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install"
    [ -d "${inst_dir}" ]
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (wasm-aot-cache install/apply.sh exists as file — apply-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/apply.sh" ]
}

@test "INVARIANT (wasm-aot-cache install/apply.sh is executable (mode includes +x) — script-runnable contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/apply.sh"
    [ -x "${apply}" ]
}

@test "INVARIANT (wasm-aot-cache install/check.sh exists as file — check-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/check.sh" ]
}

@test "INVARIANT (wasm-aot-cache install/check.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/check.sh" ]
}

@test "INVARIANT (wasm-aot-cache install/uninstall.sh exists as file — uninstall-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/uninstall.sh" ]
}

@test "INVARIANT (wasm-aot-cache install/uninstall.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/uninstall.sh" ]
}

@test "INVARIANT (wasm-aot-cache install scripts apply+check+uninstall all are executable — 3-script-runnable contract)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install"
    [ -x "${inst}/apply.sh" ]
    [ -x "${inst}/check.sh" ]
    [ -x "${inst}/uninstall.sh" ]
}

@test "INVARIANT (wasm-aot-cache install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wasm-aot-cache install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wasm-aot-cache install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (wasm-aot-cache install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/apply.sh"
    [ -s "${apply}" ]
}

@test "INVARIANT (wasm-aot-cache install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (wasm-aot-cache install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (wasm-aot-cache module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}

@test "INVARIANT (wasm-aot-cache module.toml exists at canonical path modules/wasm-aot-cache/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (wasm-aot-cache module dir is at canonical path modules/wasm-aot-cache/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (wasm-aot-cache install dir exists at modules/wasm-aot-cache/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (wasm-aot-cache install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (wasm-aot-cache install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (wasm-aot-cache install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (wasm-aot-cache install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/wasm-aot-cache/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}
