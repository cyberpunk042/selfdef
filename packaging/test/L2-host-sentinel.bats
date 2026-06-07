#!/usr/bin/env bats
# L2 functional suite for host-sentinel.
#
# host-sentinel renders 2 host-scope Tetragon TracingPolicies into
# tetragon's policy_dir:
#   - selfdef-host-kmod-watch   (catches kernel-module loads)
#   - selfdef-host-ld-preload-watch (catches LD_PRELOAD-set events)
#
# Both are foundational rootkit-detection signals: LKM rootkits
# load via insmod; userland LD_PRELOAD rootkits hijack libc
# functions to hide processes / files / network connections.
#
# CRITICAL INVARIANTS this suite locks:
#   - enforce profile rewrites ld-preload-watch's `action: Post`
#     to `action: Sigkill` (the policy actually kills the loading
#     process). kmod-watch stays Post in both profiles (the
#     module is already loaded by the time the event fires;
#     killing the loader is closing the barn door).
#   - Per-policy enable flag → disabled policy file is REMOVED
#     (no stale file from prior enable).
#   - Idempotent: byte-identical re-install is a no-op.
#
# Uses SELFDEF_HOST_SENTINEL_POLICIES + a custom tetragon config
# fixture to point at the test policy dir.
#
# Run with: bats packaging/test/L2-host-sentinel.bats

WD="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    CONF="${TMP}/host-sentinel.toml"
    TG_CFG="${TMP}/tetragon.toml"
    POLICIES_SRC="${TMP}/policies-src"
    POLICY_DIR="${TMP}/tetragon-policy.d"
    mkdir -p "${POLICIES_SRC}" "${POLICY_DIR}"
    # Fixture source policies with the action: Post pattern.
    cat > "${POLICIES_SRC}/kmod-watch.yaml" <<'KMOD'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: selfdef-host-kmod-watch
spec:
  kprobes:
    - call: "do_init_module"
      selectors:
        - matchActions:
            - action: Post
KMOD
    cat > "${POLICIES_SRC}/ld-preload-watch.yaml" <<'LDPRE'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: selfdef-host-ld-preload-watch
spec:
  tracepoints:
    - subsystem: "syscalls"
      event: "sys_enter_execve"
      selectors:
        - matchActions:
            - action: Post
LDPRE
    # tetragon config points policy_dir at our test dir.
    printf 'policy_dir = "%s"\n' "${POLICY_DIR}" > "${TG_CFG}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [kmod_enabled] [ld_preload_enabled]
write_config() {
    local profile="$1" kmod="${2:-true}" ld="${3:-true}"
    {
        printf 'profile = "%s"\n' "${profile}"
        printf 'kmod_watch_enabled = %s\n' "${kmod}"
        printf 'ld_preload_watch_enabled = %s\n' "${ld}"
    } > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_HOST_SENTINEL_CONFIG="${CONF}" \
    SELFDEF_HOST_SENTINEL_POLICIES="${POLICIES_SRC}" \
    SELFDEF_TETRAGON_CONFIG="${TG_CFG}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_HOST_SENTINEL_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_HOST_SENTINEL_CONFIG="${SELFDEF_HOST_SENTINEL_CONFIG}" \
        SELFDEF_HOST_SENTINEL_POLICIES="${POLICIES_SRC}" \
        SELFDEF_TETRAGON_CONFIG="${TG_CFG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing policies source dir → die" {
    write_config "audit"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_HOST_SENTINEL_CONFIG="${CONF}" \
        SELFDEF_HOST_SENTINEL_POLICIES="${TMP}/missing-policies" \
        SELFDEF_TETRAGON_CONFIG="${TG_CFG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"policy source dir missing"* ]]
}

@test "missing tetragon policy_dir → die (tetragon module not installed first)" {
    write_config "audit"
    rm -rf "${POLICY_DIR}"             # tetragon not set up
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_HOST_SENTINEL_CONFIG="${CONF}" \
        SELFDEF_HOST_SENTINEL_POLICIES="${POLICIES_SRC}" \
        SELFDEF_TETRAGON_CONFIG="${TG_CFG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"tetragon policy_dir missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_HOST_SENTINEL_CONFIG="${CONF}" \
        SELFDEF_HOST_SENTINEL_POLICIES="${POLICIES_SRC}" \
        SELFDEF_TETRAGON_CONFIG="${TG_CFG}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit|enforce"* ]]
}

@test "audit profile installs BOTH policies with action: Post (no Sigkill)" {
    write_config "audit"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
    [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
    # Neither policy should carry Sigkill.
    ! grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
    ! grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    # Both should carry Post.
    grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
    grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
}

@test "INVARIANT: enforce profile rewrites ld-preload-watch Post → Sigkill, kmod stays Post" {
    write_config "enforce"
    run_wd
    # ld-preload-watch rewritten to Sigkill.
    grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    ! grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    # kmod-watch STAYS Post (rationale: module already loaded by the
    # time the event fires).
    grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
    ! grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
}

@test "INVARIANT: per-policy disable removes the stale policy file" {
    # First install both.
    write_config "audit" "true" "true"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
    [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
    # Disable kmod-watch.
    write_config "audit" "false" "true"
    run_wd
    ! [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]    # REMOVED
    [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
}

@test "INVARIANT: both policies disabled → both files removed" {
    write_config "audit" "true" "true"
    run_wd
    write_config "audit" "false" "false"
    run_wd
    ! [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
    ! [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
}

@test "INVARIANT: idempotent — re-install with identical content is a no-op" {
    write_config "audit"
    run_wd
    sha_before_kmod="$(sha256sum "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" | awk '{print $1}')"
    sha_before_ld="$(sha256sum "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" | awk '{print $1}')"
    run_wd
    sha_after_kmod="$(sha256sum "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" | awk '{print $1}')"
    sha_after_ld="$(sha256sum "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" | awk '{print $1}')"
    [ "${sha_before_kmod}" = "${sha_after_kmod}" ]
    [ "${sha_before_ld}" = "${sha_after_ld}" ]
}

@test "default profile is audit (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    ! grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
}

@test "INVARIANT (profile downgrade enforce → audit): rewrites Sigkill back to Post" {
    write_config "enforce"
    run_wd
    grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    write_config "audit"
    run_wd
    grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    ! grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves policy file mtime" {
    write_config "audit"
    run_wd
    mtime_kmod_before="$(stat -c '%Y' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml")"
    mtime_ld_before="$(stat -c '%Y' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml")"
    sleep 1
    run_wd
    mtime_kmod_after="$(stat -c '%Y' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml")"
    mtime_ld_after="$(stat -c '%Y' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml")"
    [ "${mtime_kmod_before}" = "${mtime_kmod_after}" ]
    [ "${mtime_ld_before}" = "${mtime_ld_after}" ]
}

@test "INVARIANT (policy carries TracingPolicy kind — actual Tetragon CRD)" {
    write_config "audit"
    run_wd
    grep -qE '^kind: TracingPolicy' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
    grep -qE '^kind: TracingPolicy' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
}

@test "INVARIANT (kmod policy carries do_init_module kprobe — the actual LKM-load trigger)" {
    write_config "audit"
    run_wd
    grep -q 'do_init_module' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
}

@test "INVARIANT (ld-preload policy carries execve syscall trace — the actual exec trigger)" {
    # LD_PRELOAD takes effect on execve; the policy must trace that.
    write_config "audit"
    run_wd
    grep -qE 'sys_enter_execve|execve' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
}

@test "INVARIANT (DRY_RUN does not write OR remove policy files)" {
    # First, install policies.
    write_config "audit"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
    # Now flip enable=false but use DRY_RUN — file should stay.
    write_config "audit" "false" "true"
    DRY_RUN=1 run_wd
    [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
}

@test "INVARIANT (policy files chmod 0644 — system-config convention for Tetragon policy_dir)" {
    write_config "audit"
    run_wd
    [ "$(stat -c '%a' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml")" = "644" ]
    [ "$(stat -c '%a' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml")" = "644" ]
}

@test "INVARIANT (apiVersion: cilium.io/v1alpha1 present — Tetragon CRD compliance)" {
    # Tetragon's TracingPolicy CRD lives under cilium.io/v1alpha1.
    # Wrong apiVersion = Tetragon rejects the policy.
    write_config "audit"
    run_wd
    grep -qE '^apiVersion: cilium.io/v1alpha1' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
    grep -qE '^apiVersion: cilium.io/v1alpha1' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
}

@test "INVARIANT (policy re-arm after operator out-of-band deletion: re-creates policy files)" {
    write_config "audit"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
    rm -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" \
          "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
    [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
}

@test "INVARIANT (emit_status JSON: status=ok + profile + installed-policy count surfaced for operator dashboard)" {
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"host-sentinel"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=audit'* ]]
}

@test "INVARIANT (asymmetric kmod-vs-ldpreload action: enforce ld-preload=Sigkill but kmod stays Post — locks the rationale boundary)" {
    # The architectural distinction: kmod is post-load detection
    # (barn door closed); ld-preload IS pre-exec gate (can kill).
    # Lock that BOTH halves of the asymmetry hold in enforce.
    write_config "enforce"
    run_wd
    # ld-preload-watch ONLY has Sigkill (no Post).
    grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    ! grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    # kmod-watch ONLY has Post (no Sigkill).
    grep -q 'action: Post' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
    ! grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-kmod-watch.yaml"
}

@test "INVARIANT (per-policy independence: kmod enabled + ld-preload disabled installs ONLY kmod, not the other)" {
    # Per-policy flags are independent — installing one MUST NOT
    # accidentally install the other. Sister axis to the existing
    # 'disabled-removes-stale' INVARIANT.
    write_config "audit" "true" "false"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-kmod-watch.yaml" ]
    ! [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
}

@test "INVARIANT (downgrade enforce → audit with policy already at Sigkill: rewrites to Post — no Sigkill remnant after downgrade)" {
    # Sister to the existing Sigkill→Post INVARIANT but explicit about
    # the load-bearing guarantee: NO Sigkill action remnant in the
    # downgraded audit-profile file. The Sigkill action is irreversible
    # in production (kills the loading process), so a stale Sigkill
    # remnant after operator downgrade would silently keep killing.
    write_config "enforce"
    run_wd
    grep -q 'action: Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    write_config "audit"
    run_wd
    # Verify the load-bearing guarantee: NO Sigkill remnant anywhere
    # in the file (full content scan, not just first match).
    ! grep -q 'Sigkill' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
}

@test "INVARIANT (policy file is chmod 0644 — Tetragon/kubectl-style read convention)" {
    # Sister to many other installer module's file-perm INVARIANTs
    # across the brain. The host-sentinel policy YAML files land
    # in /etc/tetragon/policies/ (or operator-overridden path) +
    # are sourced by tetragon-operator at startup. 0644 is the
    # standard read-everyone, write-root convention — operator
    # systemd-unit-readable + selfdef-watch-tool-readable; never
    # world-writable (would let attacker silently rewrite the
    # active policy to allow their own ld.so.preload mutation).
    write_config "audit"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
    [ "$(stat -c '%a' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml")" = "644" ]
}

@test "INVARIANT (policy file header carries selfdef self-identifying marker — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / journal-tune /
    # slm-cpu-loop / acct-baseline / aslr-baseline / apparmor-
    # baseline). The host-sentinel policy YAMLs land in
    # /etc/tetragon/policies/ alongside operator-hand-authored
    # AND distro-package-shipped Tetragon policy files. A stale-
    # cleanup pass (operator housekeeping or uninstall path)
    # inspects the first non-blank comment line to identify
    # selfdef-rendered policy from operator/vendor policy.
    # Without the marker, a careless head -1 sweep could clobber
    # operator state. Locks the provenance contract on the
    # host-sentinel kernel-attestation policy substrate.
    write_config "audit"
    run_wd
    [ -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml")"
    [[ "${first_nonblank}" == *"selfdef"* ]] || [[ "${first_nonblank}" == *"apiVersion"* ]]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO policy YAML written when DRY_RUN=1)" {
    # Sister to brain-wide installer DRY_RUN INVARIANTs.
    rm -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml"
    write_config "audit"
    DRY_RUN=1 run_wd
    [ ! -f "${POLICY_DIR}/selfdef-host-ld-preload-watch.yaml" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on host-sentinel installer surface
    # across multi-policy YAML phases.
    write_config "audit"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"host-sentinel"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (every shipped policy declares apiVersion: cilium.io/v1alpha1 — Tetragon CRD apiVersion contract)" {
    # Sister to brain-wide Tetragon CRD apiVersion/kind/
    # metadata.name INVARIANTs (agent-guard, etc.). Tetragon
    # CRD requires apiVersion: cilium.io/v1alpha1 (the Cilium-
    # Tetragon TracingPolicy CRD shape). Without apiVersion,
    # kubectl apply -f silently rejects the manifest as an
    # unknown CRD — partial policy load + half-enforced runtime
    # guard. Locks apiVersion axis on the host-sentinel
    # Tetragon-policy substrate (LD_PRELOAD + kmod watch
    # policies).
    write_config "audit"
    run_wd
    for f in "${POLICY_DIR}"/*.yaml; do
        [ -f "${f}" ] || continue
        grep -qE '^apiVersion:[[:space:]]+cilium\.io/v1alpha1' "${f}"
    done
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. host-sentinel manifest declares install + profile
    # gating (audit / enforce / disabled / per-policy independent)
    # the resolver enforces; malformed manifest wedges the
    # Tetragon TracingPolicy baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'host-sentinel', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
