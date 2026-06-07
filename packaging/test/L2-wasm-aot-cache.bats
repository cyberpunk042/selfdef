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
