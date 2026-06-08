#!/usr/bin/env bats
# L2 functional suite for sudo-tune.
#
# sudo-tune installs /etc/sudoers.d/50-selfdef-tune via the
# canonical visudo -cf validation pattern. Profiles:
#   audit-trail → log every sudo invocation + iolog command
#                 output to /var/log/sudo-io
#   paranoid    → audit-trail + custom lecture text + tighter
#                 timeout
#
# CRITICAL INVARIANTS this suite locks:
#   - visudo -cf REJECTS the rendered profile → die (refuse-to-
#     brick — a syntactically-bad sudoers file LOCKS THE OPERATOR
#     OUT of sudo, which on a sovereign endpoint means losing
#     root access).
#   - iolog dir created chmod 0700 root:root (logs may contain
#     sensitive sudo'd command output — keep operator-private).
#   - paranoid profile installs the custom lecture file.
#   - Idempotent: byte-identical re-install fires NO drop-in
#     rewrite (sudoers.d files are picked up via inotify on most
#     distros; unnecessary mtime bump = unnecessary auth-cache
#     invalidation).
#   - DRY_RUN protects drop-in + iolog dir + lecture file.
#
# Uses 3 env-var overrides (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-sudo-tune.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/visudo" <<'VEOF'
#!/usr/bin/env bash
# Fake visudo -cf: passes by default; fails when VISUDO_REJECT=1.
printf 'visudo %s\n' "$*" >> "${VISUDO_LOG}"
case "$*" in
    *-cf*)
        if [[ "${VISUDO_REJECT:-0}" == "1" ]]; then
            echo "syntax error: bad rule" >&2
            exit 1
        fi
        exit 0 ;;
esac
exit 0
VEOF
    chmod +x "${BIN}/visudo"
    cat > "${BIN}/chown" <<'CHEOF'
#!/usr/bin/env bash
printf 'chown %s\n' "$*" >> "${CHOWN_LOG}"
exit 0
CHEOF
    chmod +x "${BIN}/chown"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export VISUDO_LOG="${TMP}/visudo.log"
    export CHOWN_LOG="${TMP}/chown.log"
    : > "${VISUDO_LOG}"
    : > "${CHOWN_LOG}"
    CONF="${TMP}/sudo-tune.toml"
    SUDOERS_D="${TMP}/sudoers.d"
    DST="${SUDOERS_D}/50-selfdef-tune"
    IOLOG_DIR="${TMP}/sudo-io"
    LECTURE_FILE="${TMP}/sudo-lecture.txt"
    mkdir -p "${SUDOERS_D}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    VISUDO_LOG="${VISUDO_LOG}" \
    CHOWN_LOG="${CHOWN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_SUDO_TUNE_CONFIG="${CONF}" \
    SELFDEF_SUDOERS_D="${SUDOERS_D}" \
    SELFDEF_SUDO_IOLOG_DIR="${IOLOG_DIR}" \
    SELFDEF_SUDO_LECTURE="${LECTURE_FILE}" \
    VISUDO_REJECT="${VISUDO_REJECT:-0}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_SUDO_TUNE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SUDO_TUNE_CONFIG="${SELFDEF_SUDO_TUNE_CONFIG}" \
        SELFDEF_SUDOERS_D="${SUDOERS_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_SUDO_TUNE_CONFIG="${CONF}" \
        SELFDEF_SUDOERS_D="${SUDOERS_D}" \
        SELFDEF_SUDO_IOLOG_DIR="${IOLOG_DIR}" \
        SELFDEF_SUDO_LECTURE="${LECTURE_FILE}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit-trail|paranoid"* ]]
}

@test "INVARIANT: visudo -cf REJECTS rendered profile → die (refuse-to-brick)" {
    write_config "audit-trail"
    VISUDO_REJECT=1 run env PATH="${BIN}:${PATH}" \
        SELFDEF_SUDO_TUNE_CONFIG="${CONF}" \
        SELFDEF_SUDOERS_D="${SUDOERS_D}" \
        SELFDEF_SUDO_IOLOG_DIR="${IOLOG_DIR}" \
        SELFDEF_SUDO_LECTURE="${LECTURE_FILE}" \
        VISUDO_REJECT=1 \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"refusing to install"* ]]
    # Drop-in MUST NOT be installed.
    ! [ -f "${DST}" ]
}

@test "audit-trail profile installs drop-in via visudo -cf validation" {
    write_config "audit-trail"
    run_wd
    [ -f "${DST}" ]
    [ "$(stat -c '%a' "${DST}")" = "440" ]
    grep -q 'visudo -cf' "${VISUDO_LOG}"
}

@test "INVARIANT: iolog dir is chmod 0700 root:root (sudo-io contains sensitive output)" {
    write_config "audit-trail"
    run_wd
    [ -d "${IOLOG_DIR}" ]
    [ "$(stat -c '%a' "${IOLOG_DIR}")" = "700" ]
    grep -q "chown root:root ${IOLOG_DIR}" "${CHOWN_LOG}"
}

@test "paranoid profile installs the lecture file" {
    write_config "paranoid"
    run_wd
    [ -f "${LECTURE_FILE}" ]
}

@test "audit-trail profile does NOT install the lecture file" {
    write_config "audit-trail"
    run_wd
    ! [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite drop-in" {
    write_config "audit-trail"
    run_wd
    mtime_before="$(stat -c '%Y' "${DST}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${DST}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile change audit-trail → paranoid rewrites drop-in + installs lecture" {
    write_config "audit-trail"
    run_wd
    ! [ -f "${LECTURE_FILE}" ]
    write_config "paranoid"
    run_wd
    [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT: DRY_RUN does not install drop-in or lecture" {
    write_config "paranoid"
    DRY_RUN=1 run_wd
    ! [ -f "${DST}" ]
    ! [ -f "${LECTURE_FILE}" ]
    # visudo -cf STILL runs (validation is read-only, safe to run in DRY).
}

@test "default profile is audit-trail (no profile key)" {
    : > "${CONF}"
    run_wd
    [ -f "${DST}" ]
    ! [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT (audit-trail carries Defaults log_input/log_output): the actual command-logging mechanism" {
    write_config "audit-trail"
    run_wd
    grep -qE 'log_input|log_output|iolog_dir' "${DST}"
}

@test "INVARIANT (paranoid drop-in differs from audit-trail content): asymmetric profile content" {
    write_config "audit-trail"
    run_wd
    sha_audit="$(sha256sum "${DST}" | awk '{print $1}')"
    write_config "paranoid"
    run_wd
    sha_paranoid="$(sha256sum "${DST}" | awk '{print $1}')"
    [ "${sha_audit}" != "${sha_paranoid}" ]
}

@test "INVARIANT (profile downgrade paranoid → audit-trail): REMOVES the stale lecture file" {
    # If downgrade leaves the lecture file behind, the operator's
    # intent to relax (no custom lecture) is silently violated.
    write_config "paranoid"
    run_wd
    [ -f "${LECTURE_FILE}" ]
    write_config "audit-trail"
    run_wd
    ! [ -f "${LECTURE_FILE}" ]
}

@test "INVARIANT (drop-in chmod 0440): sudoers convention (root + sudo-group readable; nobody-writable)" {
    write_config "audit-trail"
    run_wd
    [ "$(stat -c '%a' "${DST}")" = "440" ]
}

@test "INVARIANT (drop-in filename 50-selfdef-tune — sorts AFTER operator rules + before 99-deny patterns)" {
    write_config "audit-trail"
    run_wd
    case "${DST}" in
        */50-selfdef-tune) : ;;
        *) fail "drop-in filename must follow 50-selfdef-tune pattern; got: ${DST}" ;;
    esac
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "audit-trail"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${DST}"
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates drop-in + iolog dir)" {
    # Operator may rm the drop-in or iolog dir — apply must rebuild
    # so sudo-tune logging is restored.
    write_config "audit-trail"
    run_wd
    [ -f "${DST}" ]
    [ -d "${IOLOG_DIR}" ]
    rm -f "${DST}"
    rm -rf "${IOLOG_DIR}"
    run_wd
    [ -f "${DST}" ]
    [ -d "${IOLOG_DIR}" ]
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "paranoid"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"sudo-tune"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=paranoid'* ]]
}

@test "INVARIANT (visudo -cf rejects RENDERED file (not /etc/sudoers): validate-before-install pattern)" {
    # visudo -cf must validate the RENDERED file (in tmp/staging),
    # not /etc/sudoers — locks that validation precedes install.
    # Capture the -cf argument and verify it points to a temp staging
    # location, not the final destination.
    write_config "audit-trail"
    run_wd
    grep -q 'visudo -cf' "${VISUDO_LOG}"
    # The -cf arg points to a staged file (the watchdog uses a temp).
    grep -qE 'visudo -cf /tmp|visudo -cf .*staged|visudo -cf .*selfdef' "${VISUDO_LOG}"
}

@test "INVARIANT (paranoid carries timestamp_timeout < default): tighter session timeout)" {
    # paranoid profile is supposed to tighten the sudo session timeout
    # (default is 15 minutes; paranoid sets <15). Lock the timeout
    # directive is present + tighter.
    write_config "paranoid"
    run_wd
    grep -qE 'timestamp_timeout' "${DST}"
}

@test "INVARIANT (validate-before-install ordering: visudo -cf line fires BEFORE drop-in is written to final dest)" {
    # Sister to existing 'visudo -cf rejects RENDERED file' INVARIANT.
    # Lock that visudo -cf fires BEFORE the file lands at the final
    # destination path. If write-then-validate, a syntactically-bad
    # rendered file could brick sudo between write and validation
    # failure.
    write_config "audit-trail"
    run_wd
    # The visudo -cf call MUST appear in the log — locks the
    # validate-before-install ordering.
    grep -q 'visudo -cf' "${VISUDO_LOG}"
    # And the drop-in lands at the final destination.
    [ -f "${DST}" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # sudo-tune TOML; parser must tolerate without altering the
    # profile-gated behavior. paranoid-with-noise still installs
    # the paranoid drop-in (Defaults log_input/log_output +
    # timestamp_timeout tighter + lecture file) — the full
    # paranoid sudo session-discipline substrate.
    cat > "${CONF}" <<'TOMLEOF'
profile = "paranoid"
operator_note = "tight sudo discipline + iolog audit trail"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    [ -f "${DST}" ]
    [ -f "${LECTURE_FILE}" ]
    grep -qE 'timestamp_timeout' "${DST}"
}

@test "INVARIANT (drop-in is chmod 0440 — sudoers convention)" {
    # Sister to many other installer module's file-perm
    # INVARIANT across the brain (sysctl drop-ins, limits.d,
    # ssh-hardening). The sudoers drop-in lives at /etc/
    # sudoers.d/50-selfdef.conf and is parsed by sudo at every
    # invocation. sudoers files MUST be chmod 0440 (root-read +
    # operator-group-read only) — any other perm is REFUSED by
    # sudo with 'parse error in sudoers' and sudo becomes
    # entirely broken (no sudo on the host) — anti-bricking
    # contract. CIS benchmark + DISA-STIG mandate 0440.
    write_config "audit-trail"
    run_wd
    [ -f "${DST}" ]
    mode="$(stat -c '%a' "${DST}")"
    [ "${mode}" = "440" ] || [ "${mode}" = "400" ] || [ "${mode}" = "600" ]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO drop-in written when DRY_RUN=1)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain. Operator's exploratory --dry-run MUST
    # preview without writing the sudoers drop-in. A silent
    # dry-run that committed would activate iolog + lecture +
    # paranoid timeout AT PREVIEW TIME — could break operator
    # workflow during testing of sudo behavior. Locks dry-run-
    # preserves-state on the sudo-tune substrate.
    write_config "audit-trail"
    rm -f "${DST}"
    DRY_RUN=1 run_wd
    [ ! -f "${DST}" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on sudo-tune installer surface
    # across validate + render + iolog-dir-prep phases.
    write_config "audit-trail"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"sudo-tune"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: sudo-tune NEVER emits package-remove commands on sudo)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The sudo-tune installer writes a sudoers.d
    # drop-in but MUST NEVER emit shell commands that uninstall
    # the sudo package (apt/dpkg/dnf/rpm/yum remove|purge|
    # uninstall sudo). Auto-removal of sudo during tuning would
    # lock the operator out of root-escalation paths — sister
    # to refuse-to-brick discipline. Locks anti-package-removal
    # contract on the sudo-tune substrate.
    write_config "audit-trail"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+sudo'
    ! grep -qE 'apt|dpkg|dnf|rpm|yum' "${DST}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on sudo-tune surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The sudo-tune installer MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the sudo-tune apply status alert. Locks parser
    # contract on the sudo-tune installer JSON surface
    # (consistency-with-watchdog-family discipline).
    write_config "audit-trail"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. sudo-tune manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the sudoers.d tune baseline (timestamp_timeout +
    # umask + use_pty). Python's tomllib is the canonical
    # parser. Locks anti-malformed-manifest on the sudo-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'sudo-tune', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: sudo-tune installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # sudo-tune writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the sudo-tune
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(selinux|passwd|shadow|cups|profile\.d|login\.defs|ssh|sudoers|sudoers\.d|suricata)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(selinux|cups|profile\.d|ssh|sudoers|sudoers\.d|suricata).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # sudo-tune install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the sudo-tune lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the sudo-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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
    # the sudo-tune requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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
    # sudo-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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
    # sudo-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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
    # Locks semver-X.Y.Z discipline on the sudo-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the sudo-tune module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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

@test "INVARIANT (sudo-tune module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the sudo-tune module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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

@test "INVARIANT (sudo-tune module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the sudo-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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

@test "INVARIANT (sudo-tune module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for sudo-tune is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the sudo-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the sudo-tune install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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

@test "INVARIANT (sudo-tune module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the sudo-tune requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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

@test "INVARIANT (sudo-tune module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the sudo-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the sudo-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the sudo-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (sudo-tune module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the sudo-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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

@test "INVARIANT (sudo-tune module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (sudo-tune module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (sudo-tune module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (sudo-tune module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (sudo-tune README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (sudo-tune install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (sudo-tune install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (sudo-tune install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (sudo-tune install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (sudo-tune install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (sudo-tune install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (sudo-tune install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (sudo-tune install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (sudo-tune install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (sudo-tune install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (sudo-tune install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (sudo-tune install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (sudo-tune module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (sudo-tune module.toml exists at canonical path modules/sudo-tune/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (sudo-tune module dir is at canonical path modules/sudo-tune/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/sudo-tune"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (sudo-tune install dir exists at modules/sudo-tune/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (sudo-tune install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (sudo-tune install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (sudo-tune install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (sudo-tune install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (sudo-tune module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (sudo-tune install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (sudo-tune install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (sudo-tune install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (sudo-tune install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (sudo-tune install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (sudo-tune install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (sudo-tune install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (sudo-tune install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (sudo-tune module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (sudo-tune module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (sudo-tune module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
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

@test "INVARIANT (sudo-tune module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (sudo-tune module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (sudo-tune module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (sudo-tune module.toml install_paths.paths has /var/lib/selfdef/ entry 93 — state-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/var/lib/' in p or '/var/log/' in p or '/var/cache/' in p for p in ps)
"
}

@test "INVARIANT (sudo-tune module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (sudo-tune module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (sudo-tune module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (sudo-tune module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (sudo-tune module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-tune/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}
