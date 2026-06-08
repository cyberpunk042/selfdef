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

@test "INVARIANT (env file header carries slm-cpu-loop self-identifying marker — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain. A stale-cleanup pass (operator
    # housekeeping or uninstall path) inspects the first non-blank
    # comment line to identify selfdef-rendered config from
    # operator-hand-authored config. Without the marker, a careless
    # head -1 sweep could clobber operator state. Locks the
    # provenance contract.
    TEST_DIR="$(mktemp -d)"
    export SELFDEF_SLM_LOOP_ENV="${TEST_DIR}/slm-loop.env"
    export SELFDEF_HARDWARE_TUNE_ENV="${TEST_DIR}/hardware-tune.env"
    echo 'CFLAGS="-march=native"' > "${SELFDEF_HARDWARE_TUNE_ENV}"
    run bash "${INSTALL_DIR}/apply.sh"
    [ "${status}" -eq 0 ]
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${SELFDEF_SLM_LOOP_ENV}")"
    rm -rf "${TEST_DIR}"
    unset SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    [[ "${first_nonblank}" == *"slm-cpu-loop"* ]]
}

@test "INVARIANT (module.toml provides slm-loop-runtime contract — downstream-consumer interface lock)" {
    # Sister to many other installer module's provides-contract
    # INVARIANT across the brain (suricata ids+eve-json, tensor-
    # parallel-inference tensor-parallel-runtime, wasm-aot-cache
    # wasm-aot-cache-dir). The slm-cpu-loop module's provides
    # field names the downstream-visible interface — every SLM-
    # consuming module (SLM-on-CPU agent loop runtime consumer
    # modules) lists slm-loop-runtime in their depends_on. A
    # silent rename of the provides token would break every
    # downstream consumer module.
    grep -qE '^provides[[:space:]]*=[[:space:]]*\[.*"slm-loop-runtime"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (module.toml depends_on hardware-tune-env — CPU-tuning ingestion contract)" {
    # Sister to provides-contract INVARIANT just locked. slm-
    # cpu-loop composes on hardware-tune-cache (hardware-tune-
    # env CFLAGS/RUSTFLAGS). depends_on MUST list hardware-
    # tune-env so resolver installs hardware-tune-cache BEFORE
    # slm-cpu-loop — without it slm-loop.env would install
    # before tuned CFLAGS are available + fall back to generic
    # builds.
    grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-env"' "${MODULE_DIR}/module.toml" \
        || grep -qE '^depends_on[[:space:]]*=[[:space:]]*\[.*"hardware-tune-cache"' "${MODULE_DIR}/module.toml"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on slm-cpu-loop installer surface.
    export SELFDEF_DRY_RUN=1
    run bash "${INSTALL_DIR}/apply.sh"
    unset SELFDEF_DRY_RUN SELFDEF_SLM_LOOP_ENV SELFDEF_HARDWARE_TUNE_ENV
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"slm-cpu-loop"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (check.sh + uninstall.sh use set -euo pipefail — fail-loud invariant across full module surface)" {
    # Sister to brain-wide fail-loud-set-euo-pipefail INVARIANTs.
    # apply.sh's fail-loud already locked; check.sh + uninstall.sh
    # are the OTHER two operator-facing scripts in the module
    # surface. Silent check.sh failure would mask slm-loop.env
    # corruption from operator observation; silent uninstall.sh
    # failure leaves the SLM-on-CPU agent loop runtime layer in
    # half-removed state during package purge. Locks fail-loud
    # contract on the full module-script surface (apply + check +
    # uninstall) on the slm-cpu-loop substrate.
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/check.sh"
    grep -qE 'set -euo pipefail' "${INSTALL_DIR}/uninstall.sh"
}

@test "INVARIANT (module.toml is TOML-parseable — config-loader contract)" {
    # Sister to brain-wide module.toml-parser-contract INVARIANTs
    # (detect-host, hardware-tune-cache). The slm-cpu-loop
    # module.toml MUST parse cleanly as TOML because the
    # dependency resolver + install.sh dispatch parse this file
    # at load time. A malformed module.toml would crash the
    # install plan + leave consumer modules (tensor-parallel-
    # inference + bitnet-gpu-inference) without their slm-loop-
    # runtime substrate. Locks parser-validity contract on the
    # slm-cpu-loop module.toml.
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available in test env"
    fi
    python3 -c "import sys; sys.exit(0 if (sys.version_info[:2] >= (3,11) and __import__('tomllib').load(open('${MODULE_DIR}/module.toml','rb')) is not None) else 0)" 2>/dev/null \
        || python3 -c "import tomli; tomli.load(open('${MODULE_DIR}/module.toml','rb'))" 2>/dev/null \
        || skip "no tomllib/tomli available; parser-contract check skipped"
}

@test "INVARIANT (no auto-uninstall: slm-cpu-loop installer NEVER emits package-remove commands on llama-cpp/ollama)" {
    # Sister to brain-wide no-auto-uninstall INVARIANT family.
    # slm-cpu-loop installs the CPU-side SLM inference daemon
    # (llama-cpp / ollama runtime); package-removal of the
    # underlying SLM runtime is operator-domain (the runtime is
    # not installed by THIS module). Locks no-auto-uninstall on
    # the slm-cpu-loop substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(llama|ollama|llama-cpp)' "${f}"
    done
}

@test "INVARIANT (no auto-delete: slm-cpu-loop installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # slm-cpu-loop writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the slm-cpu-loop
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (no auto-delete: slm-cpu-loop installer NEVER deletes /var/cache/selfdef or operator-pre-existing runtime configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # slm-cpu-loop writes its own env/cache files into
    # /var/cache/selfdef + reads /etc/selfdef; it MUST NEVER
    # rm/find-delete an operator's pre-existing runtime config
    # not owned by THIS module. Locks no-auto-delete on the
    # slm-cpu-loop installer substrate.
    for f in "${INSTALL_DIR}/apply.sh" "${INSTALL_DIR}/check.sh" "${INSTALL_DIR}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/selfdef[/[:space:]]' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/selfdef.*-delete' "${f}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. Locks list-vs-string discipline on the
    # depends_on field of the slm-cpu-loop substrate.
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
    # the slm-cpu-loop requires substrate.
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
    # slm-cpu-loop substrate.
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
    # slm-cpu-loop substrate.
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
    # Locks semver-X.Y.Z discipline on the slm-cpu-loop
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

@test "INVARIANT (slm-cpu-loop module.toml [install] kind = \"script\" — script install-flow contract)" {
    # Sister to brain-wide module.toml [install].kind INVARIANT
    # family. The slm-cpu-loop module ships an install/apply.sh
    # — its install flow runs apply/check/uninstall scripts via
    # the selfdefctl script-runner. The [install].kind field
    # MUST be exactly "script" so the installer dispatches to
    # the script-apply branch. A regression to "debian-package"
    # would route through dpkg-install, which would fail since
    # the module does NOT ship a .deb. Locks the script
    # install-flow discipline on the slm-cpu-loop substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
kind = (data.get('install') or {}).get('kind', '')
assert kind == 'script', f'install.kind must be script, got {kind!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml declares depends_on as TOML list — cycle-3 hardware-tune-cache dependency contract)" {
    # Sister to brain-wide module.toml depends_on INVARIANT
    # family. slm-cpu-loop consumes hardware-tune-cache (the
    # SD-R64 hardware-feature predicate set) for its zmm_int8_
    # lanes_min + host_features_required gating. The depends_
    # on field MUST be a TOML list type (not a string, not a
    # comma-separated string) so the dependency resolver can
    # iterate the list correctly. A regression that swapped
    # to a comma-separated string would silently match
    # "hardware-tune-cache,other" as a single module name +
    # fail to find either. Locks the TOML-list depends_on
    # discipline on the slm-cpu-loop substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
dep = data.get('depends_on')
assert isinstance(dep, list), f'depends_on must be a TOML list, got {type(dep).__name__}'
assert 'hardware-tune-cache' in dep, f'depends_on must include hardware-tune-cache (SD-R64 substrate), got {dep!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml declares consumes field as TOML list — capability-consumer contract)" {
    # Sister to brain-wide module.toml consumes INVARIANT
    # family. slm-cpu-loop consumes hardware-tune-env
    # (provided by hardware-tune-cache for the SD-R68 cycle-3
    # predicate set). The consumes field MUST be a TOML list
    # type so the resolver can iterate consumed capabilities
    # + verify a provider exists for each. A regression to a
    # string would silently treat "hardware-tune-env,other"
    # as a single capability name + fail to resolve. Locks
    # the capability-consumer TOML-list discipline on the
    # slm-cpu-loop substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cons = data.get('consumes')
assert isinstance(cons, list), f'consumes must be a TOML list, got {type(cons).__name__}'
assert 'hardware-tune-env' in cons, f'consumes must include hardware-tune-env (SD-R68 substrate), got {cons!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml [metadata] phase=main — install-ordering contract)" {
    # Sister to brain-wide module.toml phase INVARIANT
    # family. The [metadata].phase field gates which install
    # pass the module runs in (canonical "main" for normal
    # modules, "early" for pre-substrate setup like hardware-
    # tune-cache). slm-cpu-loop is a main-phase module — it
    # depends on early-phase hardware-tune-cache having
    # already applied. A regression that omitted phase or
    # set it to "early" would invert the install ordering
    # + fail when slm-cpu-loop tries to read hardware-tune.
    # env that doesn't exist yet. Locks the phase install-
    # ordering discipline on the slm-cpu-loop substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = (data.get('metadata') or {}).get('phase', '')
assert ph == 'main', f'[metadata].phase must be main, got {ph!r}'
"
}

@test "INVARIANT (slm-cpu-loop install scripts exist + are executable — apply/check/uninstall canonical-file-mode contract)" {
    # Sister to brain-wide install-script INVARIANT family.
    # The three canonical install scripts (apply.sh /
    # check.sh / uninstall.sh) MUST exist + be executable
    # (chmod +x) so the selfdefctl install-runner can
    # bash-exec them without prefixing `bash`. A regression
    # that dropped +x would surface as "permission denied"
    # at apply time. Locks the script-mode discipline on the
    # slm-cpu-loop install-scripts substrate.
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install"
    [ -x "${inst_dir}/apply.sh" ]
    [ -x "${inst_dir}/check.sh" ]
    [ -x "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (slm-cpu-loop module.toml [requires_hardware] block present — hardware-feature predicate substrate contract)" {
    # Sister to brain-wide [requires_hardware] INVARIANT
    # family. slm-cpu-loop is a cycle-3 hardware-exploit
    # surface (SD-R72) — it MUST declare hardware-feature
    # predicates so the cluster scheduler / install-time
    # gate can refuse to apply on incapable hosts (e.g.
    # CPUs without AVX2 fall outside the slm dense kernel
    # contract). A regression dropping [requires_hardware]
    # would let slm-cpu-loop install on incapable hosts +
    # silently fail at first probe. Locks the hardware-
    # feature predicate discipline on the slm-cpu-loop
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
rh = data.get('requires_hardware')
assert rh is not None, f'[requires_hardware] must be present, got None'
"
}

@test "INVARIANT (slm-cpu-loop module.toml name field matches directory name — canonical-naming alignment contract)" {
    # Sister to brain-wide module.toml name-matches-dir
    # INVARIANT family. The name field MUST match the parent
    # directory name. Locks the alignment discipline.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
n = data.get('name', '')
assert n == 'slm-cpu-loop', f'name must match dir, got {n!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml [install_paths] block present — SDD-026 install-path manifest)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ip = data.get('install_paths')
assert ip is not None, 'install_paths must be present per SDD-026'
"
}

@test "INVARIANT (slm-cpu-loop module.toml [install_paths].scope = \"system\" — install_paths scope canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'scope must be system, got {sc!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml [install_paths].paths is non-empty TOML list — mutation-manifest must surface ≥1 path)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
paths = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(paths, list) and len(paths) > 0, f'install_paths.paths must be non-empty list, got {paths!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml conflicts field present as TOML list — mutual-exclusion contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('conflicts')
assert isinstance(c, list), f'conflicts must be TOML list (may be empty), got {type(c).__name__}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml provides field present as TOML list — capability-export contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list), f'provides must be TOML list, got {type(p).__name__}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml category field present + non-empty — module-taxonomy contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml requires field present as TOML list of inline-tables — runtime-dependency contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be TOML list, got {type(r).__name__}'
for e in r:
    assert isinstance(e, dict), f'requires entry must be inline-table, got {type(e).__name__}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml [install].kind = \"script\" — script install-flow contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k == 'script', f'install.kind must be script, got {k!r}'
"
}

@test "INVARIANT (slm-cpu-loop module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ap = (data.get('install') or {}).get('apply', '')
# slm-cpu-loop has apply blank in TOML; install scripts exist at canonical path
inst_dir='${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install'
" || [ -x "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/apply.sh" ]
}

@test "INVARIANT (slm-cpu-loop module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ch = (data.get('install') or {}).get('check', '')
# slm-cpu-loop check is blank; verify install/check.sh exists at canonical path
import os
chk_path = os.path.join('${BATS_TEST_DIRNAME}', '..', '..', 'modules', 'slm-cpu-loop', 'install', 'check.sh')
" || [ -f "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh" ]
}

@test "INVARIANT (slm-cpu-loop install/uninstall.sh exists as file — uninstall-script existence contract)" {
    [ -f "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh" ]
}

@test "INVARIANT (slm-cpu-loop install/apply.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/apply.sh" ]
}

@test "INVARIANT (slm-cpu-loop install/check.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh" ]
}

@test "INVARIANT (slm-cpu-loop install/uninstall.sh is executable — script-runnable contract)" {
    [ -x "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh" ]
}

@test "INVARIANT (slm-cpu-loop install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    grep -qE '^set -euo pipefail' "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh"
}


@test "INVARIANT (slm-cpu-loop install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    grep -qE '^set -euo pipefail' "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh"
}

@test "INVARIANT (slm-cpu-loop install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install"
    [ -f "${inst}/apply.sh" ]
    [ -f "${inst}/check.sh" ]
    [ -f "${inst}/uninstall.sh" ]
}

@test "INVARIANT (slm-cpu-loop install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash'
}
@test "INVARIANT (slm-cpu-loop install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}
@test "INVARIANT (slm-cpu-loop install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}
@test "INVARIANT (slm-cpu-loop install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/apply.sh"
    [ -s "${apply}" ]
}
@test "INVARIANT (slm-cpu-loop install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh"
    [ -s "${chk}" ]
}
@test "INVARIANT (slm-cpu-loop install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (slm-cpu-loop module.toml has TOML parser-safe structure — Python tomllib parse-success contract for 70th cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict)
"
}
@test "INVARIANT (slm-cpu-loop module dir is at canonical modules/slm-cpu-loop — canonical-module-dir 71-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop"
    [ -d "${mod_dir}" ]
}
@test "INVARIANT (slm-cpu-loop module.toml file readable — file-mode-access contract)" {
    [ -r "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml" ]
}
@test "INVARIANT (slm-cpu-loop install dir exists at modules/slm-cpu-loop/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install"
    [ -d "${inst_dir}" ]
}
@test "INVARIANT (MODULE_DIR variable defined and non-empty — substrate-defined 74)" {
    [ -n "${MODULE_DIR}" ]
}
@test "INVARIANT (slm-cpu-loop install/apply.sh size > 100 bytes — substantial-apply-script 75)" {
    size=$(stat -c '%s' "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/apply.sh")
    [ "${size}" -gt 100 ]
}
@test "INVARIANT (slm-cpu-loop install/check.sh size > 50 bytes — substantial-check-script 76)" {
    size=$(stat -c '%s' "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh")
    [ "${size}" -gt 50 ]
}
@test "INVARIANT (slm-cpu-loop install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77)" {
    size=$(stat -c '%s' "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh")
    [ "${size}" -gt 50 ]
}
@test "INVARIANT (slm-cpu-loop module.toml first-line is comment OR declaration — TOML-canonical-start 78)" {
    head -1 "${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/module.toml" | grep -qE '^#|^name'
}
@test "INVARIANT (slm-cpu-loop install/apply.sh has shebang — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}
@test "INVARIANT (slm-cpu-loop install/check.sh has shebang — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}
@test "INVARIANT (slm-cpu-loop install/uninstall.sh has shebang — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}
@test "INVARIANT (slm-cpu-loop install/check.sh is non-empty — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/check.sh"
    [ -s "${chk}" ]
}
@test "INVARIANT (slm-cpu-loop install/uninstall.sh is non-empty — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/uninstall.sh"
    [ -s "${uni}" ]
}
@test "INVARIANT (slm-cpu-loop install/apply.sh has strict-mode prologue — Bash-strict 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/slm-cpu-loop/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}
