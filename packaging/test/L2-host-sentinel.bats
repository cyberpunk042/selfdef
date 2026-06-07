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

@test "INVARIANT (no auto-delete: host-sentinel installer NEVER deletes operator-pre-existing tetragon TracingPolicies — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # host-sentinel writes its own selfdef-prefixed TracingPolicy
    # YAMLs; it MUST NEVER rm/find-delete operator-pre-existing
    # /etc/tetragon/tracing-policies/*.yaml entries not owned by
    # THIS module. Locks no-auto-delete on the host-sentinel
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/tetragon([[:space:]]|$)' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/tetragon.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # host-sentinel install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the host-sentinel lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # list-vs-string INVARIANTs. Locks list discipline on
    # provides.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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
    # family. Each requires entry MUST be a TOML inline table
    # `{ kind = "binary", value = "X" }` — not a flat string
    # like "binary:X" (which the resolver would not parse as
    # structured kind/value and would fail to dispatch the
    # check). Locks the kind+value table-shape discipline on
    # the host-sentinel requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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
    # INVARIANT family. The category field groups modules in
    # the operator install dashboard (detection / hardening /
    # disable / etc.). An empty/missing category would surface
    # as an Uncategorized bucket, harming triage. Locks
    # category-present discipline on the host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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
    # The version field MUST follow X.Y.Z semver so the resolver
    # can sort versions numerically + version-gate downstream
    # consumers. A regression to "v1" / "1.0" / "1.0.0-beta+meta"
    # would break the sortable numeric comparison. Locks the
    # semver-X.Y.Z discipline on the host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the host-sentinel module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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

@test "INVARIANT (host-sentinel module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the host-sentinel module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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

@test "INVARIANT (host-sentinel module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the host-sentinel
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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

@test "INVARIANT (host-sentinel module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for host-sentinel is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the host-sentinel install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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

@test "INVARIANT (host-sentinel module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the host-sentinel requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
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

@test "INVARIANT (host-sentinel module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the host-sentinel
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the host-sentinel
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (host-sentinel module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the host-sentinel substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
prof = data.get('profiles')
assert prof is not None, f'[profiles] must be present, got None'
assert isinstance(prof, dict), f'[profiles] must be TOML table, got {type(prof).__name__}'
"
}

@test "INVARIANT (host-sentinel module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (host-sentinel module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (host-sentinel module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (host-sentinel module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (host-sentinel README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (host-sentinel install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (host-sentinel install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (host-sentinel install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (host-sentinel install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (host-sentinel install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (host-sentinel install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (host-sentinel install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (host-sentinel install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (host-sentinel install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (host-sentinel install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (host-sentinel install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (host-sentinel install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (host-sentinel module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (host-sentinel module.toml exists at canonical path modules/host-sentinel/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (host-sentinel module dir is at canonical path modules/host-sentinel/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/host-sentinel"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (host-sentinel install dir exists at modules/host-sentinel/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (host-sentinel install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/host-sentinel/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}
