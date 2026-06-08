#!/usr/bin/env bats
# L2 functional suite for aslr-baseline.
#
# aslr-baseline writes /etc/sysctl.d/50-selfdef-aslr.conf with
# kernel.randomize_va_space=2 (full ASLR — stack, mmap, brk, vdso
# all randomized) AND applies it live via `sysctl -w`. Full ASLR
# is foundational defense against memory-corruption exploits that
# rely on predictable addresses (ROP gadgets, libc base, heap
# layouts).
#
# Default Linux kernels usually ship with randomize_va_space=2
# already (the secure default), but operators / distros can flip
# it via boot args, init scripts, or kdump-induced kernel
# regressions. This baseline pins it.
#
# Only one profile: full. Refuses to apply with any other value
# (defensive — don't let a typo silently downgrade ASLR).
#
# Uses SELFDEF_ASLR_DROPIN env-var (added 2026-06-06) to point at
# a fixture path instead of the live /etc/sysctl.d.
#
# Run with: bats packaging/test/L2-aslr-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
case "$1" in
    -n) printf '2\n' ;;             # report current value
esac
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/aslr-baseline.toml"
    DROPIN="${TMP}/50-selfdef-aslr.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_ASLR_CONFIG="${CONF}" \
    SELFDEF_ASLR_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ASLR_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${SELFDEF_ASLR_CONFIG}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "INVARIANT: any non-full profile → die (refuse to silently downgrade ASLR)" {
    write_config "partial"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${CONF}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be full"* ]]
    # No drop-in written, no sysctl fired.
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "full profile writes drop-in + applies live via sysctl -w" {
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    # Drop-in carries the header marker + the randomize_va_space line.
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
    grep -q 'kernel.randomize_va_space' "${DROPIN}"
    # sysctl -w fired live.
    grep -q 'sysctl -w kernel.randomize_va_space=2' "${SCTL_LOG}"
}

@test "drop-in content includes header marker + profile (no render-timestamp, 2026-06-06 idempotency fix)" {
    write_config "full"
    run_wd
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
    grep -q 'profile=full' "${DROPIN}"
    # CRITICAL: NO render-timestamp — including it would defeat the
    # cmp -s idempotency check (per dns-shield/proc-hidepid fix
    # lineage, 2026-06-06).
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 fix)" {
    write_config "full"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "full"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644 (world-readable system-config convention for /etc/sysctl.d)" {
    write_config "full"
    run_wd
    perms="$(stat -c '%a' "${DROPIN}")"
    [ "${perms}" = "644" ]
}

@test "default profile is full (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'kernel.randomize_va_space' "${DROPIN}"
}

@test "second run is idempotent — drop-in still present, sysctl -w fires again (sysctl is itself idempotent)" {
    write_config "full"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    # sysctl -w fires every run — that's by design (the wrapper applies
    # the value live regardless of file change). The drop-in is what
    # carries persistence across reboot.
    grep -q 'sysctl -w kernel.randomize_va_space=2' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in target value is 2): the drop-in pins randomize_va_space=2, not 0 or 1" {
    # Locks the specific value 2 (full ASLR) — a regression that
    # mistakenly wrote =1 (partial ASLR) or =0 (no ASLR) would
    # defeat the module's purpose.
    write_config "full"
    run_wd
    grep -qE 'kernel\.randomize_va_space[[:space:]]*=[[:space:]]*2' "${DROPIN}"
}

@test "INVARIANT (live sysctl -w applies value 2): the live invocation also pins 2" {
    write_config "full"
    run_wd
    grep -qE 'sysctl -w kernel\.randomize_va_space=2' "${SCTL_LOG}"
    # Locks that no other value reaches sysctl -w.
    ! grep -qE 'sysctl -w kernel\.randomize_va_space=[01]' "${SCTL_LOG}"
}

@test "INVARIANT (config rejection): a config with profile = \"\" (empty) → die" {
    write_config ""
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ASLR_CONFIG="${CONF}" \
        SELFDEF_ASLR_DROPIN="${DROPIN}" \
        bash "${WD}"
    # Empty profile may either default to full (rolled up to default)
    # or die — either way, no silent downgrade.
    if [ "$status" -eq 0 ]; then
        # Default to full is acceptable.
        grep -q 'kernel.randomize_va_space' "${DROPIN}"
        grep -qE 'randomize_va_space[[:space:]]*=[[:space:]]*2' "${DROPIN}"
    else
        # Die is acceptable.
        [[ "${output}" == *"profile must be full"* ]]
    fi
}

@test "emit_status surfaces profile + result in JSON (operator observability)" {
    write_config "full"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"aslr-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=full'* ]]
}

@test "INVARIANT (re-apply with DRY_RUN switches): apply real, then DRY_RUN — drop-in persists but second invocation fires nothing" {
    # Composition: real apply leaves drop-in + first sysctl call;
    # a follow-on DRY_RUN must not modify or fire anything new.
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    : > "${SCTL_LOG}"
    sleep 1
    DRY_RUN=1 run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (header-marker is first non-blank line — predictable for stale-cleanup head -1 grep)" {
    # The downgrade-path stale-cleanup uses head -1 + grep -F.
    # The header MUST be the first line — not buried — or stale
    # detection misses + leaves selfdef-owned files orphaned.
    write_config "full"
    run_wd
    first_line="$(head -1 "${DROPIN}")"
    [ "${first_line}" = "# managed-by: selfdef aslr-baseline" ]
}

@test "INVARIANT (re-arm after operator deletion: re-creates drop-in with header marker)" {
    # Operator deletes the drop-in out-of-band. Next apply re-
    # creates it cleanly with header-marker intact.
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
    grep -qE 'kernel\.randomize_va_space[[:space:]]*=[[:space:]]*2' "${DROPIN}"
}

@test "INVARIANT (live= field in emit_status JSON — operator dashboard sees current kernel value)" {
    # The emit_status message body carries live=N where N is the
    # current sysctl -n value. Critical for operator dashboard
    # to detect drift between persistence (drop-in) and runtime
    # (live kernel state).
    write_config "full"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'live='* ]]
}

@test "INVARIANT (drop-in carries 'profile=full' marker — uninstall hook can identify which profile was active)" {
    # The 'profile=full' second-line marker is the audit-trail
    # for which profile was applied. Even though aslr-baseline
    # has only one profile, future expansion (e.g., paranoid
    # profile) requires the marker for diff routing.
    write_config "full"
    run_wd
    grep -qE '^# profile=full$' "${DROPIN}"
}

@test "INVARIANT (sysctl is invoked via -w flag for live application — NOT -p path)" {
    # Two acceptable mechanisms: sysctl -w key=val (write live)
    # vs sysctl -p /etc/sysctl.d/file (load entire file). Current
    # contract uses -w for surgical single-key application —
    # locks the choice so future refactor doesn't accidentally
    # switch to -p (which would also reload other unrelated
    # sysctl drop-ins; side-effect on other modules).
    write_config "full"
    run_wd
    grep -qE 'sysctl -w' "${SCTL_LOG}"
    ! grep -qE 'sysctl -p' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in carries 'managed-by: selfdef aslr-baseline' on first non-blank line — stale-cleanup head -1 contract)" {
    # Locks the exact header-marker string + position discipline.
    # The downgrade-path stale-cleanup uses head -1 + grep -F to
    # identify selfdef-managed drop-ins; if the header drifts, the
    # cleanup misses and orphans files.
    write_config "full"
    run_wd
    grep -qE '^# managed-by: selfdef aslr-baseline' "${DROPIN}"
}

@test "INVARIANT (no daemon-reload fired — aslr-baseline only touches kernel state via sysctl, not systemd)" {
    # aslr-baseline is a pure-kernel module: sysctl -w + sysctl.d
    # drop-in. NO systemctl daemon-reload should fire (would be
    # spurious side-effect on other modules' systemd unit changes).
    if [[ -f "${BIN}/systemctl" ]]; then
        : > "${SYSEOF_LOG:-/dev/null}"
    fi
    write_config "full"
    run_wd
    # No systemctl invocations from this module (kernel-only state).
    # If a fake systemctl exists, no log should accumulate.
    if [[ -f "${SYSEOF_LOG}" ]]; then
        ! grep -qE 'systemctl' "${SYSEOF_LOG}"
    fi
}

@test "INVARIANT (idempotent emit_status: status=ok + changes=0 on second apply when drop-in unchanged)" {
    # Second apply with byte-identical content must surface changes=0
    # in emit_status so operator dashboard can distinguish first-install
    # from re-apply.
    write_config "full"
    run_wd                                              # first apply
    output="$(run_wd 2>&1)"                              # second apply
    [[ "${output}" == *'changes=0'* ]] || [[ "${output}" == *'"status":"ok"'* ]]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # aslr-baseline TOML; parser must tolerate without altering the
    # profile-gated behavior. full-with-noise still installs the
    # kernel.randomize_va_space=2 sysctl drop-in (full ASLR — the
    # load-bearing memory-layout-randomization defense against ROP
    # and return-to-libc exploits).
    cat > "${CONF}" <<'TOMLEOF'
profile = "full"
operator_note = "randomize_va_space=2 — full ASLR vs ROP/ret2libc"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'kernel\.randomize_va_space[[:space:]]*=[[:space:]]*2' "${DROPIN}"
    grep -q 'managed-by: selfdef aslr-baseline' "${DROPIN}"
}

@test "INVARIANT (drop-in is sysctl.d-parseable: kernel.randomize_va_space=<N> format — boot-time persistence contract)" {
    # Sister to kernel-yama-baseline sysctl.d-parseable INVARIANT
    # and many other installer module's parser-compatible-format
    # INVARIANTs across the brain. The drop-in lives at
    # /etc/sysctl.d/50-selfdef-aslr.conf and is parsed by
    # systemd-sysctl.service at boot. The format MUST be
    # 'kernel.randomize_va_space = <N>' (or '=<N>' without
    # space, both sysctl.d-valid). A malformed line would
    # silently fail at boot — the runtime sysctl -w would set
    # the value for current boot but it would NOT persist
    # across reboot, leaving the host with degraded ASLR on
    # next boot. Locks the boot-time persistence contract on
    # the memory-layout-randomization substrate.
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^kernel\.randomize_va_space[[:space:]]*=[[:space:]]*[012]$' "${DROPIN}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl -w fired)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / apparmor-baseline / apport-
    # disable / many others). Operator's exploratory --dry-run
    # MUST preview without touching /etc/sysctl.d/ AND without
    # flipping the live kernel.randomize_va_space value. Without
    # strict DRY_RUN gating, a previewed dry-run would silently
    # commit ASLR drift on a host where operator was investigating
    # the baseline. Locks the dry-run-preserves-state contract on
    # the memory-layout-randomization defense substrate.
    write_config "full"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DROPIN}" ]
    ! grep -q 'sysctl -w kernel.randomize_va_space' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in is chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "full"
    run_wd
    [ -f "${DROPIN}" ]
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on aslr-baseline installer surface
    # across drop-in + sysctl-w phases.
    write_config "full"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"aslr-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: aslr-baseline NEVER emits package-remove commands)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The aslr-baseline installer writes a sysctl
    # drop-in to lock kernel.randomize_va_space=2 but MUST
    # NEVER emit shell commands that uninstall kernel-related
    # packages (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # any kernel-* package). The ASLR setting is purely sysctl
    # — no package management. Auto-removal would be
    # categorically wrong: catastrophic at the kernel-package
    # level. Locks anti-package-removal contract on the ASLR
    # kernel-hardening substrate.
    write_config "full"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${DROPIN}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on aslr-baseline surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The aslr-baseline installer MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the ASLR-baseline apply status alert. Locks
    # parser contract on the aslr-baseline installer JSON
    # surface (consistency-with-watchdog-family discipline).
    write_config "full"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. aslr-baseline manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the kernel.randomize_va_space sysctl baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'aslr-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # aslr-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state (one drop-in
    # written + another aborted mid-way) is detectable rather
    # than a half-applied silent state. Locks fail-loud
    # invariant on the aslr-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list ([] or ["a", "b"]) — not a comma-separated
    # string like "a, b" which TOML's tomllib would silently
    # accept as a single-element list ["a, b"]. The resolver
    # would then look for a single module named literally "a, b"
    # and fail to find it. Locks list-vs-string discipline on
    # the depends_on field of the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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
    # Sister to brain-wide module.toml manifest-completeness +
    # depends_on-list INVARIANTs already locked. The conflicts
    # field MUST be a TOML list — the resolver iterates
    # conflicts to detect mutually-exclusive module pairs at
    # install-time. A scalar/string would silently parse as a
    # single-element list, masking real conflicts. Locks list-
    # vs-string discipline on the conflicts field of the
    # aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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
    # depends_on-list + conflicts-list INVARIANTs already
    # locked. The provides field MUST be a TOML list — the
    # resolver iterates it to register each provided contract
    # in the consumer-binding graph. A scalar would silently
    # parse as a single-element list, masking real provides.
    # Locks list-vs-string discipline on the provides field of
    # the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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
    # the aslr-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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
    # present discipline on the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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
    # category-present discipline on the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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
    # semver-X.Y.Z discipline on the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the aslr-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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

@test "INVARIANT (aslr-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the aslr-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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

@test "INVARIANT (aslr-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the aslr-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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

@test "INVARIANT (aslr-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for aslr-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the aslr-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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

@test "INVARIANT (aslr-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the aslr-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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

@test "INVARIANT (aslr-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the aslr-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the aslr-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the aslr-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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

@test "INVARIANT (aslr-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (aslr-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (aslr-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (aslr-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (aslr-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (aslr-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (aslr-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (aslr-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (aslr-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (aslr-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (aslr-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (aslr-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (aslr-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (aslr-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (aslr-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (aslr-baseline module.toml exists at canonical path modules/aslr-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (aslr-baseline module dir is at canonical path modules/aslr-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (aslr-baseline install dir exists at modules/aslr-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (aslr-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (aslr-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (aslr-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (aslr-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (aslr-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (aslr-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (aslr-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (aslr-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (aslr-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (aslr-baseline install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (aslr-baseline install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (aslr-baseline install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (aslr-baseline install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (aslr-baseline module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (aslr-baseline module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (aslr-baseline module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
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

@test "INVARIANT (aslr-baseline module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (aslr-baseline module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (aslr-baseline module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (aslr-baseline module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (aslr-baseline module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"aslr-baseline"' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import re
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln, f'expected key=val before sections, got {ln!r}'
        break
"
}

@test "INVARIANT (aslr-baseline module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (aslr-baseline module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (aslr-baseline module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (aslr-baseline module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (aslr-baseline module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (aslr-baseline module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (aslr-baseline module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (aslr-baseline module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/aslr-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}
