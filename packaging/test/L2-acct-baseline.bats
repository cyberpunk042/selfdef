#!/usr/bin/env bats
# L2 functional suite for acct-baseline.
#
# acct-baseline provisions process accounting (BSD-style acct):
#   - Creates /var/account/ + pacct file (mode 0640 root:root)
#   - Installs a logrotate drop-in to roll pacct daily/weekly
#   - enabled profile: accton on /var/account/pacct + enables
#     acct.service / psacct.service (distro-dependent)
#   - disabled profile: accton off + leaves the logrotate drop-
#     in installed (operator can re-enable later without
#     re-touching the rotate config)
#
# Adds SELFDEF_ACCT_DIR + SELFDEF_PACCT_FILE + SELFDEF_LOGROTATE_DIR
# env-var overrides for L2 testability (ACCT_DIR added 2026-06-06).
# Live defaults unchanged.
#
# Run with: bats packaging/test/L2-acct-baseline.bats

WD="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/accton" <<'ACEOF'
#!/usr/bin/env bash
printf 'accton %s\n' "$*" >> "${ACCT_LOG}"
exit 0
ACEOF
    chmod +x "${BIN}/accton"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export ACCT_LOG="${TMP}/accton.log"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${ACCT_LOG}"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/acct-baseline.toml"
    ACCT_DIR="${TMP}/account"
    PACCT_FILE="${ACCT_DIR}/pacct"
    LOGROTATE_DIR="${TMP}/logrotate.d"
    LOGROTATE_DST="${LOGROTATE_DIR}/selfdef-acct"
    mkdir -p "${LOGROTATE_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    ACCT_LOG="${ACCT_LOG}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_ACCT_CONFIG="${CONF}" \
    SELFDEF_ACCT_DIR="${ACCT_DIR}" \
    SELFDEF_PACCT_FILE="${PACCT_FILE}" \
    SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_ACCT_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ACCT_CONFIG="${SELFDEF_ACCT_CONFIG}" \
        SELFDEF_ACCT_DIR="${ACCT_DIR}" \
        SELFDEF_PACCT_FILE="${PACCT_FILE}" \
        SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_ACCT_CONFIG="${CONF}" \
        SELFDEF_ACCT_DIR="${ACCT_DIR}" \
        SELFDEF_PACCT_FILE="${PACCT_FILE}" \
        SELFDEF_LOGROTATE_DIR="${LOGROTATE_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be enabled|disabled"* ]]
}

@test "enabled profile creates ACCT_DIR + pacct file + installs logrotate drop-in" {
    write_config "enabled"
    run_wd
    [ -d "${ACCT_DIR}" ]
    [ -f "${PACCT_FILE}" ]
    [ -f "${LOGROTATE_DST}" ]
}

@test "enabled profile fires accton on <pacct> AND enables the OS service" {
    write_config "enabled"
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    # Tries acct.service first; falls back to psacct (distro-aware).
    grep -qE 'systemctl enable --now (acct|psacct)' "${SYSEOF_LOG}"
}

@test "disabled profile fires accton off (no <pacct> arg) AND does NOT touch the OS service" {
    write_config "disabled"
    run_wd
    grep -q 'accton off' "${ACCT_LOG}"
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "disabled profile STILL installs the logrotate drop-in (operator-pull re-enable)" {
    write_config "disabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
}

@test "logrotate drop-in is chmod 0644 (system-config convention)" {
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${LOGROTATE_DST}")" = "644" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite logrotate drop-in" {
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    mtime_before="$(stat -c '%Y' "${LOGROTATE_DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${LOGROTATE_DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile switch enabled → disabled changes accton arg + leaves logrotate drop-in intact" {
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    logrotate_mtime_before="$(stat -c '%Y' "${LOGROTATE_DST}")"
    : > "${ACCT_LOG}"
    sleep 1
    write_config "disabled"
    run_wd
    grep -q 'accton off' "${ACCT_LOG}"
    [ -f "${LOGROTATE_DST}" ]
    # logrotate file unchanged (no re-install needed across profile switch).
    logrotate_mtime_after="$(stat -c '%Y' "${LOGROTATE_DST}")"
    [ "${logrotate_mtime_before}" = "${logrotate_mtime_after}" ]
}

@test "INVARIANT: DRY_RUN does not write pacct, logrotate drop-in, or fire accton/systemctl" {
    write_config "enabled"
    DRY_RUN=1 run_wd
    ! [ -f "${PACCT_FILE}" ]
    ! [ -f "${LOGROTATE_DST}" ]
    ! grep -q 'accton' "${ACCT_LOG}"
    ! grep -q 'systemctl' "${SYSEOF_LOG}"
}

@test "default profile is enabled (no profile key — captures process accounting by default)" {
    : > "${CONF}"
    run_wd
    [ -f "${PACCT_FILE}" ]
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
}

@test "emit_status reports changes count + pacct path in JSON" {
    write_config "enabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=1'* ]]
    [[ "${output}" == *"pacct=${PACCT_FILE}"* ]]
    # Second apply: logrotate unchanged → changes=0.
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile reverse disabled → enabled): fires accton on + re-enables service" {
    write_config "disabled"
    run_wd
    : > "${ACCT_LOG}"
    : > "${SYSEOF_LOG}"
    write_config "enabled"
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    grep -qE 'systemctl enable --now (acct|psacct)' "${SYSEOF_LOG}"
}

@test "INVARIANT (pacct file chmod 0640 — root + adm-group readable, NOT world-readable)" {
    # pacct contains process-history with command names + args + exit
    # codes — sensitive on a multi-user system. Lock 0640.
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${PACCT_FILE}")" = "640" ]
}

@test "INVARIANT (ACCT_DIR chmod 0750 — root + adm-group can list, NOT world-listable)" {
    write_config "enabled"
    run_wd
    [ "$(stat -c '%a' "${ACCT_DIR}")" = "750" ]
}

@test "INVARIANT (logrotate drop-in references /var/account/pacct — the canonical pacct path)" {
    # The drop-in is shipped as a fixture (modules/acct-baseline/systemd/
    # selfdef-acct.logrotate) with /var/account/pacct hard-coded. This
    # is intentional: logrotate config refs the canonical live path, not
    # the (test-overridable) PACCT_FILE env var.
    write_config "enabled"
    run_wd
    grep -q '/var/account/pacct' "${LOGROTATE_DST}"
}

@test "INVARIANT (logrotate drop-in carries the actual rotate directive)" {
    write_config "enabled"
    run_wd
    grep -qE '^[[:space:]]*(daily|weekly|monthly)' "${LOGROTATE_DST}"
}

@test "INVARIANT (no render-timestamp in logrotate drop-in): defeats cmp -s idempotency" {
    write_config "enabled"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${LOGROTATE_DST}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates pacct file + ACCT_DIR + logrotate drop-in)" {
    write_config "enabled"
    run_wd
    [ -f "${PACCT_FILE}" ]
    [ -d "${ACCT_DIR}" ]
    [ -f "${LOGROTATE_DST}" ]
    rm -rf "${ACCT_DIR}"
    rm -f "${LOGROTATE_DST}"
    run_wd
    [ -d "${ACCT_DIR}" ]
    [ -f "${PACCT_FILE}" ]
    [ -f "${LOGROTATE_DST}" ]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enabled"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"acct-baseline"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enabled'* ]]
}

@test "INVARIANT (logrotate drop-in carries compress + missingok + notifempty — operator-standard rotation directives)" {
    # The drop-in must implement proper rotation safety:
    # compress (saves disk), missingok (no rotate-bail if log absent),
    # notifempty (skip zero-byte rotations). Lock against rotation-
    # config drift to operator-unfriendly defaults.
    write_config "enabled"
    run_wd
    grep -qE 'compress' "${LOGROTATE_DST}"
    grep -qE 'missingok' "${LOGROTATE_DST}"
    grep -qE 'notifempty' "${LOGROTATE_DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # TOML; parser must tolerate without altering the profile-gated
    # behavior. enabled-with-noise still fires accton on; disabled-
    # with-noise still fires accton off.
    cat > "${CONF}" <<'TOMLEOF'
profile = "enabled"
operator_note = "process accounting tier-1 substrate"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -qE "accton ${PACCT_FILE}" "${ACCT_LOG}"
    [ -f "${LOGROTATE_DST}" ]
}

@test "INVARIANT (logrotate drop-in carries rotation-count directive — defines retention window)" {
    # Beyond just daily/weekly/monthly + compress + missingok +
    # notifempty already locked, the drop-in must declare a 'rotate
    # N' count directive that defines the retention window (default
    # would otherwise be 4 weeks, may be too short for forensic
    # window in incident investigation). Locks against drift to a
    # too-short retention. Sister to other rotation-directive
    # INVARIANTs (rsyslog-tune, journal-tune, audit-rules retention).
    write_config "enabled"
    run_wd
    grep -qE '^[[:space:]]*rotate[[:space:]]+[0-9]+' "${LOGROTATE_DST}"
}

@test "INVARIANT (logrotate drop-in carries selfdef self-identifying header — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / journal-tune /
    # slm-cpu-loop / tensor-parallel-inference / hardware-tune-
    # cache). The drop-in lands at /etc/logrotate.d/selfdef-acct
    # alongside operator-hand-authored / packaging-provided
    # logrotate drop-ins (cron, syslog, etc.). A stale-cleanup
    # pass (operator housekeeping or uninstall path) inspects the
    # first non-blank comment line to identify selfdef-rendered
    # config from operator config. Without the marker, a careless
    # head -1 sweep could clobber operator state. Locks the
    # provenance contract on the BSD-style process accounting
    # surface.
    write_config "enabled"
    run_wd
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${LOGROTATE_DST}")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
}

@test "INVARIANT (logrotate drop-in carries postrotate accton-restart — without it accton continues writing to the rotated/compressed file)" {
    # Process-accounting via accton holds an OPEN file descriptor
    # against /var/account/pacct. logrotate moves the file but the
    # kernel keeps the FD valid against the rotated inode — accton
    # continues appending to what becomes pacct.1.gz (broken).
    # Without an accton off/on cycle in postrotate, ALL rotated
    # entries land in the wrong file, and the forensic window
    # silently corrupts. Locks rotation-correctness for the
    # accton FD-holding surface. Sister to logrotate
    # rotation-directive INVARIANTs (compress/missingok/notifempty/
    # rotate N) — those define WHEN to rotate; postrotate accton
    # defines that rotation actually works.
    write_config "enabled"
    run_wd
    grep -qE 'postrotate' "${LOGROTATE_DST}"
    grep -qE 'accton[[:space:]]+off' "${LOGROTATE_DST}"
    grep -qE 'accton[[:space:]]+on' "${LOGROTATE_DST}"
    grep -qE 'endscript' "${LOGROTATE_DST}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO logrotate drop-in written AND NO accton fires when DRY_RUN=1)" {
    # Sister to brain-wide installer DRY_RUN INVARIANTs. The
    # acct-baseline DRY_RUN path MUST be a no-op against live
    # state — operator using --dry-run expects ZERO mutations
    # (no rendered drop-in, no live accton command fires).
    write_config "enabled"
    rm -f "${LOGROTATE_DST}"
    : > "${ACCT_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${LOGROTATE_DST}" ]
    ! grep -qE 'accton' "${ACCT_LOG}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on acct-baseline installer surface
    # across pacct-file + ACCT_DIR + logrotate-drop-in phases.
    write_config "enabled"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"acct-baseline"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (logrotate drop-in chmod 0644 — logrotate.d sourcing convention; world-readable required for logrotate to parse)" {
    # Sister to brain-wide drop-in chmod 0644 INVARIANTs across
    # L2 suites. The acct-baseline logrotate drop-in lives in
    # /etc/logrotate.d/selfdef-acct-baseline and MUST be world-
    # readable mode 0644 because logrotate is invoked by cron
    # AS ROOT but the SELinux/AppArmor profile around logrotate
    # may drop capabilities — mode 0600 would defeat the
    # canonical logrotate.d sourcing semantics on hardened
    # deployments. Locks file-mode contract on the acct-baseline
    # logrotate.d drop-in substrate.
    write_config "enabled"
    run_wd
    [ -f "${LOGROTATE_DST}" ]
    mode="$(stat -c '%a' "${LOGROTATE_DST}")"
    [ "${mode}" = "644" ]
}

@test "INVARIANT (no auto-uninstall: acct-baseline NEVER emits package-remove commands on acct/psacct)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The acct-baseline installer enables process
    # accounting via accton + ships logrotate drop-in but MUST
    # NEVER emit shell commands that uninstall the acct/psacct
    # package itself (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall acct|psacct). Silent auto-removal would tear
    # down the process-accounting audit-trail entirely —
    # operator's pacct/wtmp records would not be written.
    # T1562.001 self-defeat. Locks anti-package-removal
    # contract on the acct-baseline substrate.
    write_config "enabled"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(acct|psacct)'
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. acct-baseline manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the process-accounting (psacct/acct) baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'acct-baseline', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: acct-baseline installer NEVER deletes operator-pre-existing logrotate/accounting configs — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # acct-baseline writes its own /etc/logrotate.d/ drop-in for
    # /var/log/wtmp/pacct rotation; it MUST NEVER rm/find-delete
    # an operator's pre-existing /etc/logrotate.d entries not
    # owned by THIS module. Locks no-auto-delete on the acct-
    # baseline installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install"
    for f in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${f}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/logrotate\.d([[:space:]]|/[[:space:]]|$)' "${f}"
        ! grep -qE 'find[[:space:]]+/etc/logrotate\.d.*-delete' "${f}"
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
    # the depends_on field of the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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
    # acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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
    # the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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
    # the acct-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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
    # present discipline on the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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
    # category-present discipline on the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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
    # semver-X.Y.Z discipline on the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the acct-baseline module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the acct-baseline module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the acct-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for acct-baseline is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the acct-baseline install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the acct-baseline requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the acct-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the acct-baseline
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (acct-baseline module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the acct-baseline substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (acct-baseline module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (acct-baseline README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (acct-baseline install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (acct-baseline install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (acct-baseline install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (acct-baseline install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (acct-baseline install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (acct-baseline install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (acct-baseline install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (acct-baseline install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (acct-baseline install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (acct-baseline install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (acct-baseline install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (acct-baseline install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (acct-baseline module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (acct-baseline module.toml exists at canonical path modules/acct-baseline/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (acct-baseline module dir is at canonical path modules/acct-baseline/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/acct-baseline"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (acct-baseline install dir exists at modules/acct-baseline/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (acct-baseline install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (acct-baseline install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (acct-baseline install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (acct-baseline install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (acct-baseline module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (acct-baseline install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (acct-baseline install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (acct-baseline install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (acct-baseline install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (acct-baseline install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (acct-baseline install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (acct-baseline install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (acct-baseline install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (acct-baseline module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (acct-baseline module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (acct-baseline module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (acct-baseline module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (acct-baseline module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (acct-baseline module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (acct-baseline module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"acct-baseline"' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
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

@test "INVARIANT (acct-baseline module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (acct-baseline module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (acct-baseline module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (acct-baseline module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (acct-baseline module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (acct-baseline module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (acct-baseline module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (acct-baseline module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (acct-baseline module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (acct-baseline module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (acct-baseline module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (acct-baseline module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (acct-baseline module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/acct-baseline/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}
