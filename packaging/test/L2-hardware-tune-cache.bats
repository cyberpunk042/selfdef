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
