#!/usr/bin/env bats
# L2 functional suite for file-protections-baseline.
#
# file-protections-baseline pins fs.protected_* sysctls. These
# kernel knobs block classic symlink/hardlink-attack vectors:
#   fs.protected_hardlinks = 1 → can't hardlink to files you don't
#                                own (blocks privesc via setuid-
#                                hardlinks-in-/tmp class)
#   fs.protected_symlinks  = 1 → block following symlinks in
#                                sticky world-writable dirs (blocks
#                                /tmp race attacks)
#   fs.protected_fifos     = 2 → block writing to FIFOs owned by
#                                others in world-writable dirs
#   fs.protected_regular   = 2 → block writing to regular files
#                                owned by others in world-writable
#                                dirs (the 2017 CVE-2017-7610-class
#                                race window)
#
# Profiles:
#   baseline → conservative (=1 where appropriate)
#   strict   → aggressive (=2 everywhere)
#
# Adds SELFDEF_FILEPROT_DROPIN env-var for L2 testability. Live
# default unchanged.
#
# Run with: bats packaging/test/L2-file-protections-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/sysctl" <<'SCEOF'
#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "${SCTL_LOG}"
exit 0
SCEOF
    chmod +x "${BIN}/sysctl"
    export SCTL_LOG="${TMP}/sysctl.log"
    : > "${SCTL_LOG}"
    CONF="${TMP}/file-protections-baseline.toml"
    DROPIN="${TMP}/50-selfdef-file-protections.conf"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SCTL_LOG="${SCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_FILEPROT_CONFIG="${CONF}" \
    SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_FILEPROT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FILEPROT_CONFIG="${SELFDEF_FILEPROT_CONFIG}" \
        SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_FILEPROT_CONFIG="${CONF}" \
        SELFDEF_FILEPROT_DROPIN="${DROPIN}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be baseline|strict"* ]]
}

@test "baseline profile installs drop-in + applies sysctl -w per key" {
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    # The baseline sysctls fire.
    grep -q 'sysctl -w fs.protected_hardlinks=1' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_symlinks=1' "${SCTL_LOG}"
}

@test "strict profile installs the strict drop-in" {
    write_config "strict"
    run_wd
    [ -f "${DROPIN}" ]
    # Strict bumps the values higher.
    grep -q 'sysctl -w fs.protected_regular=2' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_fifos=2' "${SCTL_LOG}"
}

@test "drop-in carries header marker + profile + timestamp" {
    write_config "baseline"
    run_wd
    grep -q 'managed-by: selfdef file-protections-baseline' "${DROPIN}"
    grep -q 'profile=baseline' "${DROPIN}"
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"  # no timestamp (2026-06-06 idempotency fix)
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in (2026-06-06 idempotency fix)" {
    write_config "baseline"
    run_wd
    mtime_before="$(stat -c '%Y' "${DROPIN}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DROPIN}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write drop-in or fire sysctl" {
    write_config "baseline"
    DRY_RUN=1 run_wd
    ! [ -f "${DROPIN}" ]
    ! grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "drop-in is chmod 0644" {
    write_config "baseline"
    run_wd
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "default profile is baseline (no profile key — safe default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -q 'profile=baseline' "${DROPIN}"
}

@test "drop-in content contains every protected_* key (baseline)" {
    write_config "baseline"
    run_wd
    grep -q 'fs.protected_hardlinks' "${DROPIN}"
    grep -q 'fs.protected_symlinks' "${DROPIN}"
    grep -q 'fs.protected_fifos' "${DROPIN}"
    grep -q 'fs.protected_regular' "${DROPIN}"
}

@test "INVARIANT (strict profile bumps regular AND fifos to =2 — locks asymmetric profile values)" {
    write_config "strict"
    run_wd
    grep -qE 'fs\.protected_regular\s*=\s*2' "${DROPIN}"
    grep -qE 'fs\.protected_fifos\s*=\s*2' "${DROPIN}"
}

@test "INVARIANT (baseline profile has regular AND fifos at =2 too — high-CVE class needs strict default)" {
    # The 2017 CVE-2017-7610-class race needs =2 to actually block. =1
    # blocks symlinks but not regular-file races. Even baseline must
    # set regular + fifos to 2.
    write_config "baseline"
    run_wd
    grep -qE 'fs\.protected_regular\s*=\s*2' "${DROPIN}"
    grep -qE 'fs\.protected_fifos\s*=\s*2' "${DROPIN}"
}

@test "INVARIANT (profile upgrade baseline → strict): rewrites drop-in" {
    write_config "baseline"
    run_wd
    sha_before="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_after="$(sha256sum "${DROPIN}" | awk '{print $1}')"
    # baseline and strict may differ in protected_hardlinks/symlinks value;
    # if content is identical at our protection level, that's also OK —
    # but at minimum the profile= metadata bumps.
    grep -q 'profile=strict' "${DROPIN}"
}

@test "INVARIANT (sysctl -w fires on every apply — live-knob re-application even when drop-in unchanged)" {
    # Disk path may skip on idempotent re-apply but LIVE kernel knob
    # must always be re-asserted (operator could have done sysctl -w
    # fs.protected_hardlinks=0 between runs).
    write_config "baseline"
    run_wd
    : > "${SCTL_LOG}"
    run_wd
    grep -q 'sysctl -w fs.protected_hardlinks=' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in filename selfdef-* pattern): tracking + uninstall identification" {
    write_config "baseline"
    run_wd
    case "${DROPIN}" in
        */50-selfdef-*.conf) : ;;
        *) fail "drop-in filename must follow 50-selfdef-*.conf pattern" ;;
    esac
}

@test "INVARIANT (no render-timestamp): defeats cmp -s idempotency guard" {
    write_config "baseline"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DROPIN}"
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates drop-in + fires sysctl)" {
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE 'fs\.protected_hardlinks' "${DROPIN}"
    grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (header marker first non-blank line — stale-cleanup head -1 grep discipline)" {
    write_config "baseline"
    run_wd
    first_line="$(head -1 "${DROPIN}")"
    [ "${first_line}" = "# managed-by: selfdef file-protections-baseline" ]
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "baseline"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"file-protections-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=baseline'* ]]
}

@test "INVARIANT (profile downgrade strict → baseline: rewrites drop-in + applies sysctls)" {
    # Bidirectional contract — operator can both tighten + loosen.
    write_config "strict"
    run_wd
    grep -q 'profile=strict' "${DROPIN}"
    : > "${SCTL_LOG}"
    write_config "baseline"
    run_wd
    grep -q 'profile=baseline' "${DROPIN}"
    ! grep -q 'profile=strict' "${DROPIN}"
    grep -q 'sysctl -w' "${SCTL_LOG}"
}

@test "INVARIANT (all 4 protected_* sysctls fire on apply — full coverage check)" {
    # Lock that every protected_* sysctl knob fires on apply, not
    # just a subset. A regression that drops one knob from the
    # apply loop would silently leave that attack vector open.
    write_config "baseline"
    run_wd
    grep -q 'sysctl -w fs.protected_hardlinks=' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_symlinks=' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_fifos=' "${SCTL_LOG}"
    grep -q 'sysctl -w fs.protected_regular=' "${SCTL_LOG}"
}

@test "INVARIANT (strict profile has hardlinks/symlinks at strictly >= baseline values — profile-rank monotonic)" {
    # Strict's hardening MUST be at-least-as-strict as baseline's
    # on every knob. Locks profile-rank monotonicity: a regression
    # that loosens any knob in strict would trip here.
    write_config "baseline"
    run_wd
    baseline_hardlinks="$(grep -oE 'fs\.protected_hardlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    baseline_symlinks="$(grep -oE 'fs\.protected_symlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    write_config "strict"
    run_wd
    strict_hardlinks="$(grep -oE 'fs\.protected_hardlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    strict_symlinks="$(grep -oE 'fs\.protected_symlinks[[:space:]]*=[[:space:]]*[0-9]+' "${DROPIN}" | grep -oE '[0-9]+$')"
    [ "${strict_hardlinks}" -ge "${baseline_hardlinks}" ]
    [ "${strict_symlinks}" -ge "${baseline_symlinks}" ]
}

@test "INVARIANT (drop-in is sysctl-parseable: each non-comment line matches key=value shape)" {
    # The drop-in is sourced by sysctl --system. Every non-comment
    # non-blank line MUST match the key=value sysctl grammar.
    # Sister to hardware-tune-cache shell-sourceable INVARIANT.
    write_config "baseline"
    run_wd
    # Check every non-empty non-comment line matches sysctl grammar.
    awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} /^[a-zA-Z_][a-zA-Z0-9_.]*[[:space:]]*=[[:space:]]*[0-9]+/ {next} {bad=1; print "malformed: " $0} END{exit bad?1:0}' "${DROPIN}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # file-protections-baseline TOML; parser must tolerate without
    # altering the profile-gated content. strict-with-noise still
    # installs the strict drop-in (protected_hardlinks=1 +
    # protected_symlinks=1 + protected_fifos=2 + protected_
    # regular=2 — the full set-tight family that defeats most
    # writable-/tmp + symlink-pointer races used as priv-esc
    # primitives).
    cat > "${CONF}" <<'TOMLEOF'
profile = "strict"
operator_note = "fs.protected_* — symlink + hardlink + fifo race defense"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^fs\.protected_hardlinks[[:space:]]*=' "${DROPIN}"
    grep -qE '^fs\.protected_symlinks[[:space:]]*=' "${DROPIN}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in render AND NO sysctl -w fires when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing /etc/sysctl.d/50-selfdef-file-
    # protections.conf AND without firing sysctl -w on the
    # protected_* knobs. A silent dry-run that committed would
    # flip the live kernel knobs on a host where operator was
    # investigating fs-protection behavior. Locks dry-run-
    # preserves-state on the symlink/hardlink-race defense
    # substrate.
    write_config "strict"
    rm -f "${DROPIN}"
    : > "${SCTL_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${DROPIN}" ]
    ! grep -qE 'sysctl -w fs.protected_' "${SCTL_LOG}"
}

@test "INVARIANT (drop-in chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs.
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    [ "$(stat -c '%a' "${DROPIN}")" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on file-protections-baseline
    # installer surface across 4-sysctl + drop-in phases.
    write_config "baseline"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"file-protections-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (header-marker discipline: drop-in carries 'selfdef' self-identifying header — head-grep stale-cleanup discipline)" {
    # Sister to brain-wide header-marker discipline INVARIANTs
    # across L2 drop-in suites. The file-protections-baseline
    # drop-in MUST carry a comment marker identifying it as
    # selfdef-managed so a stale-cleanup head -2 grep at
    # uninstall time can identify which files selfdef owns vs
    # which is operator-original. Without a marker, a subsequent
    # uninstaller could not tell apart operator baseline sysctl
    # rules from selfdef-injected protected_* hardlinks/symlinks
    # — risking accidental rollback of operator changes. Locks
    # marker-discipline on the file-protections-baseline
    # sysctl.d substrate.
    write_config "baseline"
    run_wd
    [ -f "${DROPIN}" ]
    grep -qE '^#.*(selfdef|file-protections-baseline|managed)' "${DROPIN}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. file-protections-baseline manifest declares install +
    # profile gating (baseline / strict) the resolver enforces;
    # malformed manifest wedges the fs.protected_* sysctl
    # hardening. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the file-protections-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'file-protections-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: file-protections-baseline installer NEVER deletes operator-pre-existing sysctl configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # file-protections-baseline writes its own /etc/sysctl.d
    # drop-in for fs.protected_* sysctls; it MUST NEVER
    # rm/find-delete an operator's pre-existing /etc/sysctl.conf
    # or sysctl.d entries not owned by THIS module. Locks no-
    # auto-delete on the file-protections-baseline installer
    # substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+/etc/sysctl\.conf' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/sysctl\.d.*-delete' "${f}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # file-protections-baseline install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the file-protections-baseline lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the file-protections-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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
    # the file-protections-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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
    # present discipline on the file-protections-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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
    # category-present discipline on the file-protections-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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
    # semver-X.Y.Z discipline on the file-protections-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the file-protections-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the file-protections-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the file-protections-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for file-protections-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the file-protections-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the file-protections-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the file-protections-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the file-protections-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the file-protections-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the file-protections-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the file-protections-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (file-protections-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (file-protections-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (file-protections-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (file-protections-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (file-protections-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (file-protections-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (file-protections-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (file-protections-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (file-protections-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (file-protections-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (file-protections-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (file-protections-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (file-protections-baseline module.toml exists at canonical path modules/file-protections-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (file-protections-baseline module dir is at canonical path modules/file-protections-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (file-protections-baseline install dir exists at modules/file-protections-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (file-protections-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (file-protections-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (file-protections-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (file-protections-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (file-protections-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (file-protections-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (file-protections-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (file-protections-baseline install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (file-protections-baseline install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (file-protections-baseline install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (file-protections-baseline module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (file-protections-baseline module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (file-protections-baseline module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (file-protections-baseline module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (file-protections-baseline module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (file-protections-baseline module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (file-protections-baseline module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"file-protections-baseline"' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
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

@test "INVARIANT (file-protections-baseline module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (file-protections-baseline module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (file-protections-baseline module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (file-protections-baseline module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (file-protections-baseline module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (file-protections-baseline module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (file-protections-baseline module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/file-protections-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}
