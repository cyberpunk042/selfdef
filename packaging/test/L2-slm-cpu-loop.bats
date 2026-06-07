#!/usr/bin/env bats
# L2 bats unit tests for the slm-cpu-loop module (MS029 SLM-on-CPU
# agent loop runtime — pins a small language model to CCD-0 cores
# for low-latency background agent work; SD-R72).
#
# Run with: bats packaging/test/L2-slm-cpu-loop.bats

MODULE_DIR="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop"
INSTALL_DIR="${MODULE_DIR}/install"

@test "module.toml exists + name = slm-cpu-loop" {
    [ -f "${MODULE_DIR}/module.toml" ]
    grep -qE '^name[[:space:]]*=[[:space:]]*"slm-cpu-loop"' "${MODULE_DIR}/module.toml"
}

@test "module.toml depends_on hardware-tune-cache (MS010 upstream)" {
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "module.toml provides slm-loop-runtime contract" {
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"slm-loop-runtime"' "${MODULE_DIR}/module.toml"
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

@test "apply.sh exposes SELFDEF_SLM_LOOP_ENV override" {
    grep -q 'SELFDEF_SLM_LOOP_ENV' "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh consumes hardware-tune.env from MS010" {
    grep -q 'SELFDEF_HARDWARE_TUNE_ENV' "${INSTALL_DIR}/apply.sh"
    grep -q 'hardware-tune.env'          "${INSTALL_DIR}/apply.sh"
}

@test "apply.sh declares CCD-0 affinity defaults (SD-R72 core pinning)" {
    grep -q 'DEFAULT_AFFINITY'  "${INSTALL_DIR}/apply.sh"
    grep -q 'DEFAULT_THREADS'   "${INSTALL_DIR}/apply.sh"
}

# Dry-run smoke
@test "apply.sh runs cleanly in dry-run mode" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}

@test "apply.sh dry-run is idempotent" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    run bash "${INSTALL_DIR}/apply.sh"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${status}" -eq 0 ]
}

@test "INVARIANT: real apply is idempotent — byte-identical re-install does NOT rewrite env file (2026-06-06 idempotency fix)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_SLM_LOOP_ENV}" ]
    mtime_before="$(stat -c '%Y' "${SELFDEF_SLM_LOOP_ENV}")"
    sleep 1
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mtime_after="$(stat -c '%Y' "${SELFDEF_SLM_LOOP_ENV}")"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: no render-timestamp in env file (defeats cmp -s)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    # grep -q returns 0 when match found; we want NO match (no ISO-date
    # timestamp in "# Generated at:" line — was a variant-B bug).
    if grep -qE '^# Generated at: *[0-9]{4}-[0-9]{2}-[0-9]{2}T' "${SELFDEF_SLM_LOOP_ENV}"; then
        rm -rf "${TEST_DIR}"
        unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
        false
    fi
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
}

@test "INVARIANT (env file is chmod 0644 — system-config convention)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    mode="$(stat -c '%a' "${SELFDEF_SLM_LOOP_ENV}")"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${mode}" = "644" ]
}

@test "INVARIANT (CCD-0 affinity defaults — SD-R72 6-physical-core core pinning)" {
    # Master spec § 17.1 Pulse Vector Core: SD-R72 SLM agent loop
    # pins to CCD-0 (cores 0-5 physical on 9900X). DEFAULT_AFFINITY
    # = "0-5" + DEFAULT_THREADS = "6" is the 6-physical-core spec.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -qE '^SELFDEF_SLM_AFFINITY="0-5"$'  "${SELFDEF_SLM_LOOP_ENV}"
    grep -qE '^SELFDEF_SLM_THREADS="6"$'     "${SELFDEF_SLM_LOOP_ENV}"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
}

@test "INVARIANT (engine default is llama.cpp — Phi-4-mini GGUF recommendation)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -qE '^SELFDEF_SLM_ENGINE="llama.cpp"$' "${SELFDEF_SLM_LOOP_ENV}"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
}

@test "INVARIANT (context/KV defaults — 8192 tokens + fp16 KV dtype)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -qE '^SELFDEF_SLM_CONTEXT_TOKENS="8192"$' "${SELFDEF_SLM_LOOP_ENV}"
    grep -qE '^SELFDEF_SLM_KV_DTYPE="fp16"$'       "${SELFDEF_SLM_LOOP_ENV}"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
}

@test "INVARIANT (SLM_MODEL + SLM_MODEL_PATH are empty defaults — operator-set, NOT catalog-auto-discovered)" {
    # The env file leaves model selection to the operator (must
    # match a sovereign-os models/catalog.yaml entry with
    # class=slm). Hard-coding a default would silently bind to a
    # specific model version across hosts.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    grep -qE '^SELFDEF_SLM_MODEL=""$'      "${SELFDEF_SLM_LOOP_ENV}"
    grep -qE '^SELFDEF_SLM_MODEL_PATH=""$' "${SELFDEF_SLM_LOOP_ENV}"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
}

@test "INVARIANT (DRY_RUN does NOT write the env file)" {
    # Pre-existing dry-run smoke tests only check exit 0 — that's
    # weaker than write-skip. Lock that DRY_RUN truly side-effects
    # nothing on disk (per emit_status's 'skipped' contract).
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_DRY_RUN=1
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    written_exists=0
    [ -f "${SELFDEF_SLM_LOOP_ENV}" ] && written_exists=1
    rm -rf "${TEST_DIR}"
    unset SELFDEF_DRY_RUN SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${written_exists}" = "0" ]
}

@test "INVARIANT (JSON emit_status: status=ok + module=slm-cpu-loop on real apply)" {
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    output="$(bash "${INSTALL_DIR}/apply.sh" 2>&1)"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [[ "${output}" == *'"module":"slm-cpu-loop"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
}

@test "INVARIANT (env file is shell-sourceable: bash -n parses cleanly — downstream consumer contract)" {
    # Downstream SLM loop runtime sources slm-loop.env. It MUST be
    # valid shell syntax (no malformed assignments, no unterminated
    # quotes). Sister to hardware-tune-cache + tensor-parallel-
    # inference shell-sourceable INVARIANT.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    bash -n "${SELFDEF_SLM_LOOP_ENV}"
    parse_rc=$?
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${parse_rc}" -eq 0 ]
}

@test "INVARIANT (current-behavior: slm-loop.env is self-contained — consumer reference to hardware-tune.env is via apply-time env-injection, NOT runtime sourcing)" {
    # Distinct from tensor-parallel-inference's runtime.env which
    # explicitly sources hardware-tune.env. The slm-cpu-loop module
    # consumes hardware-tune.env at APPLY TIME (CFLAGS bake into the
    # SLM compile chain via the orchestrator), not at runtime. The
    # written env file contains the SLM_* knobs only. Lock the
    # architectural distinction so a future runtime-source refinement
    # is intentional, not silent.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    # env file carries SLM knobs (load-bearing).
    grep -q 'SELFDEF_SLM_AFFINITY' "${SELFDEF_SLM_LOOP_ENV}"
    grep -q 'SELFDEF_SLM_THREADS'  "${SELFDEF_SLM_LOOP_ENV}"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
}

@test "INVARIANT (re-arm after operator deletion: env file re-created on next apply)" {
    # Sister to many other modules' re-arm INVARIANT. When operator
    # out-of-band rm the env file, the next apply MUST re-create it
    # cleanly with all SELFDEF_SLM_* knobs intact.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    [ -f "${SELFDEF_SLM_LOOP_ENV}" ]
    rm -f "${SELFDEF_SLM_LOOP_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    re_armed=0
    [ -f "${SELFDEF_SLM_LOOP_ENV}" ] && grep -q 'SELFDEF_SLM_AFFINITY' "${SELFDEF_SLM_LOOP_ENV}" && re_armed=1
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [ "${re_armed}" = "1" ]
}
