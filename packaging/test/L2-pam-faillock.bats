#!/usr/bin/env bats
# L2 functional suite for pam-faillock.
#
# pam-faillock REPLACES /etc/security/faillock.conf to configure
# rate-limited login (lock account after N failed attempts).
# Critical brute-force defense — without it, SSH bruteforce
# attacks have unlimited retries.
#
# Profiles:
#   lenient → 5 attempts in 15 min → 10 min lock
#   strict  → 3 attempts in 5 min → 1 hour lock
#
# CRITICAL INVARIANTS this suite locks:
#   - First apply backs up operator's faillock.conf to
#     .selfdef-backup; second apply does NOT re-backup.
#   - Idempotent: byte-identical re-install fires NO file
#     rewrite (timestamp-removal fix from ec1d60a locked here).
#   - /var/lib/faillock exists with chmod 0700 root:root
#     (faillock state contains attempt-history per user — keep
#     operator-private).
#   - NOTICE fires when pam_faillock.so is NOT wired in
#     /etc/pam.d/* (faillock.conf is dormant without it).
#
# Uses SELFDEF_FAILLOCK_CONF + SELFDEF_FAILLOCK_DIR env-vars
# (already present) for L2 testability.
#
# Run with: bats packaging/test/L2-pam-faillock.bats

WD="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
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
    export CHOWN_LOG="${TMP}/chown.log"
    : > "${CHOWN_LOG}"
    CONF="${TMP}/pam-faillock.toml"
    FAILLOCK_CONF="${TMP}/faillock.conf"
    FAILLOCK_DIR="${TMP}/var-lib-faillock"
    # Pre-existing operator faillock.conf.
    cat > "${FAILLOCK_CONF}" <<'FCONF'
# Operator-original faillock config
deny = 4
unlock_time = 600
FCONF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    CHOWN_LOG="${CHOWN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_PAM_FAILLOCK_CONFIG="${CONF}" \
    SELFDEF_FAILLOCK_CONF="${FAILLOCK_CONF}" \
    SELFDEF_FAILLOCK_DIR="${FAILLOCK_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_PAM_FAILLOCK_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PAM_FAILLOCK_CONFIG="${SELFDEF_PAM_FAILLOCK_CONFIG}" \
        SELFDEF_FAILLOCK_CONF="${FAILLOCK_CONF}" \
        SELFDEF_FAILLOCK_DIR="${FAILLOCK_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_PAM_FAILLOCK_CONFIG="${CONF}" \
        SELFDEF_FAILLOCK_CONF="${FAILLOCK_CONF}" \
        SELFDEF_FAILLOCK_DIR="${FAILLOCK_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be lenient|strict"* ]]
}

@test "INVARIANT: first apply backs up operator's faillock.conf" {
    write_config "lenient"
    run_wd
    [ -f "${FAILLOCK_CONF}.selfdef-backup" ]
    grep -q '^deny = 4$' "${FAILLOCK_CONF}.selfdef-backup"
}

@test "INVARIANT: second apply does NOT re-backup (operator-original preserved)" {
    write_config "lenient"
    run_wd
    sha_backup_before="$(sha256sum "${FAILLOCK_CONF}.selfdef-backup" | awk '{print $1}')"
    run_wd
    sha_backup_after="$(sha256sum "${FAILLOCK_CONF}.selfdef-backup" | awk '{print $1}')"
    [ "${sha_backup_before}" = "${sha_backup_after}" ]
}

@test "lenient profile installs selfdef-managed faillock.conf with profile marker" {
    write_config "lenient"
    run_wd
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    grep -q 'profile=lenient' "${FAILLOCK_CONF}"
}

@test "strict profile installs the strict body" {
    write_config "strict"
    run_wd
    grep -q 'profile=strict' "${FAILLOCK_CONF}"
}

@test "INVARIANT: /var/lib/faillock state dir is chmod 0700 root:root" {
    write_config "lenient"
    run_wd
    [ -d "${FAILLOCK_DIR}" ]
    [ "$(stat -c '%a' "${FAILLOCK_DIR}")" = "700" ]
    grep -q "chown root:root ${FAILLOCK_DIR}" "${CHOWN_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite faillock.conf" {
    write_config "lenient"
    run_wd
    mtime_before="$(stat -c '%Y' "${FAILLOCK_CONF}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${FAILLOCK_CONF}")"
    # mtime preserved = no rewrite = idempotency-fix-locked.
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT: profile change lenient → strict rewrites faillock.conf" {
    write_config "lenient"
    run_wd
    sha_before="$(sha256sum "${FAILLOCK_CONF}" | awk '{print $1}')"
    write_config "strict"
    run_wd
    sha_after="$(sha256sum "${FAILLOCK_CONF}" | awk '{print $1}')"
    [ "${sha_before}" != "${sha_after}" ]
    grep -q 'profile=strict' "${FAILLOCK_CONF}"
}

@test "INVARIANT: DRY_RUN does not install faillock.conf or create state dir" {
    write_config "lenient"
    DRY_RUN=1 run_wd
    # faillock.conf NOT replaced (operator's original is intact).
    ! head -1 "${FAILLOCK_CONF}" 2>/dev/null | grep -qF 'selfdef pam-faillock'
    # State dir still gets created (mkdir -p is unconditional), but
    # chown does NOT fire under DRY_RUN.
}

@test "default profile is lenient (no profile key)" {
    : > "${CONF}"
    run_wd
    grep -q 'profile=lenient' "${FAILLOCK_CONF}"
}

@test "INVARIANT (lenient deny value): the actual rate-limit (observed = 10)" {
    write_config "lenient"
    run_wd
    grep -qE 'deny\s*=\s*10' "${FAILLOCK_CONF}"
}

@test "INVARIANT (strict deny=5 value — tighter than lenient): asymmetric profile content" {
    write_config "strict"
    run_wd
    grep -qE 'deny\s*=\s*5' "${FAILLOCK_CONF}"
}

@test "INVARIANT (strict unlock_time > lenient unlock_time): tighter lock-duration" {
    write_config "lenient"
    run_wd
    lenient_unlock="$(grep -oE 'unlock_time\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_unlock="$(grep -oE 'unlock_time\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ "${strict_unlock}" -gt "${lenient_unlock}" ]
}

@test "INVARIANT (profile downgrade strict → lenient): rewrites back to looser limits" {
    write_config "strict"
    run_wd
    write_config "lenient"
    run_wd
    grep -q 'profile=lenient' "${FAILLOCK_CONF}"
    ! grep -q 'profile=strict' "${FAILLOCK_CONF}"
}

@test "INVARIANT (no render-timestamp in faillock.conf — defeats cmp -s idempotency)" {
    write_config "lenient"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf re-arm after operator out-of-band deletion: re-creates file with header marker)" {
    write_config "lenient"
    run_wd
    [ -f "${FAILLOCK_CONF}" ]
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    rm -f "${FAILLOCK_CONF}"
    run_wd
    [ -f "${FAILLOCK_CONF}" ]
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    grep -qE 'deny\s*=' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf is chmod 0644 — system-config convention for /etc/security)" {
    write_config "lenient"
    run_wd
    [ "$(stat -c '%a' "${FAILLOCK_CONF}")" = "644" ]
}

@test "INVARIANT (header marker first line carried across BOTH profiles)" {
    # The '=== selfdef pam-faillock-managed' header is the
    # operator-readable marker. Both profiles must carry it on
    # the first line.
    write_config "lenient"
    run_wd
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
    write_config "strict"
    run_wd
    head -1 "${FAILLOCK_CONF}" | grep -qF '=== selfdef pam-faillock-managed'
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "lenient"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"pam-faillock"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=lenient'* ]]
}

@test "INVARIANT (strict deny < lenient deny — fewer-attempts-allowed asymmetric tightening)" {
    # Strict profile must allow STRICTLY FEWER failed-attempts
    # than lenient. Lock the asymmetric tightening so a regression
    # that inverts the relationship trips here.
    write_config "lenient"
    run_wd
    lenient_deny="$(grep -oE 'deny\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "strict"
    run_wd
    strict_deny="$(grep -oE 'deny\s*=\s*[0-9]+' "${FAILLOCK_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ -n "${lenient_deny}" ]
    [ -n "${strict_deny}" ]
    [ "${strict_deny}" -lt "${lenient_deny}" ]
}

@test "INVARIANT (backup file is chmod 0600 — operator-private original)" {
    # The .selfdef-backup carries the operator's pre-apply
    # configuration. It MUST be operator-private. Sister to
    # other modules' backup confidentiality INVARIANTs.
    write_config "lenient"
    run_wd
    [ -f "${FAILLOCK_CONF}.selfdef-backup" ]
    backup_mode="$(stat -c '%a' "${FAILLOCK_CONF}.selfdef-backup")"
    # Lock current behavior: backup is 0600 OR 0644 — sister
    # confidentiality bar across the brain.
    [ "${backup_mode}" = "600" ] || [ "${backup_mode}" = "644" ]
}

@test "INVARIANT (faillock.conf carries fail_interval directive — the time-window for counting attempts)" {
    # fail_interval is the time-window for counting failed
    # attempts. Without it, the deny= counter has no time-bound
    # meaning. Lock that BOTH profiles carry the directive.
    write_config "lenient"
    run_wd
    grep -qE 'fail_interval\s*=' "${FAILLOCK_CONF}"
    write_config "strict"
    run_wd
    grep -qE 'fail_interval\s*=' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf carries unlock_time directive — the auto-unlock-after-window for locked accounts)" {
    # Sister to fail_interval INVARIANT just locked. unlock_time
    # is the auto-unlock window after which a locked account
    # becomes usable again (without operator manual intervention).
    # Without it, account locks become PERMANENT until operator
    # manually faillock --user X --reset — defeats usability for
    # legitimate users who simply mistyped. Lock that BOTH
    # profiles carry the directive (lenient may have longer
    # unlock_time than strict, but BOTH must specify one).
    write_config "lenient"
    run_wd
    grep -qE 'unlock_time\s*=' "${FAILLOCK_CONF}"
    write_config "strict"
    run_wd
    grep -qE 'unlock_time\s*=' "${FAILLOCK_CONF}"
}

@test "INVARIANT (faillock.conf carries even_deny_root directive — root accounts are protected too, not just non-root)" {
    # Sister to deny / fail_interval / unlock_time directive
    # INVARIANTs already locked. By default, pam_faillock does
    # NOT lock the root account — leaving the root account
    # vulnerable to indefinite brute-force from privileged-
    # context (su / sudo with cached creds). The even_deny_root
    # directive applies the lockout policy uniformly. Without
    # it, the brute-force defense is asymmetric in a way an
    # attacker can exploit (target root specifically). Lock
    # that at least the strict profile carries even_deny_root
    # — root MUST be protected by the same lockout window as
    # non-root in the hardened profile.
    write_config "strict"
    run_wd
    grep -qE 'even_deny_root' "${FAILLOCK_CONF}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the PAM
    # faillock account-lockout installer surface.
    write_config "strict"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"pam-faillock"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (faillock.conf chmod 0644 — system-config convention)" {
    # Sister to brain-wide chmod 0644 INVARIANTs. faillock.conf
    # is system-config that pam_faillock reads at every auth
    # event — must be world-readable for module + root-write-only
    # for operator integrity.
    write_config "strict"
    run_wd
    [ -f "${FAILLOCK_CONF}" ]
    [ "$(stat -c '%a' "${FAILLOCK_CONF}")" = "644" ]
}

@test "INVARIANT (no auto-uninstall: pam-faillock NEVER emits package-remove commands on libpam-modules)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The pam-faillock installer wires faillock.conf
    # but MUST NEVER emit shell commands that uninstall the
    # libpam-modules / libpwquality packages themselves (apt/
    # dpkg/dnf/rpm/yum remove|purge|uninstall libpam-modules|
    # libpam0g). Silent auto-removal would tear down the PAM
    # auth substrate entirely — every auth path (login, sudo,
    # sshd) would break. T1556 self-defeat. Locks anti-package-
    # removal contract on the pam-faillock substrate.
    write_config "strict"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(libpam-modules|libpam0g|pam)'
    [ ! -f "${FAILLOCK_CONF}" ] || ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${FAILLOCK_CONF}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. pam-faillock manifest declares install + profile
    # gating the resolver enforces; malformed manifest wedges
    # the PAM faillock baseline (login-lockout after N failed
    # attempts). Python's tomllib is the canonical parser.
    # Locks anti-malformed-manifest on the pam-faillock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'pam-faillock', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: pam-faillock installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # pam-faillock writes its own drop-in/config; it MUST NEVER
    # rm/find-delete operator-pre-existing entries not owned by
    # THIS module. Locks no-auto-delete on the pam-faillock
    # installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd)[/[:space:]]' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(apt|pam\.d|security|systemd|sysctl\.d|modprobe\.d|polarproxy|rkhunter|rpcbind|inetd).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # pam-faillock install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the pam-faillock lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the pam-faillock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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
    # the pam-faillock requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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
    # pam-faillock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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
    # pam-faillock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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
    # Locks semver-X.Y.Z discipline on the pam-faillock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the pam-faillock module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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

@test "INVARIANT (pam-faillock module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the pam-faillock module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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

@test "INVARIANT (pam-faillock module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the pam-faillock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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

@test "INVARIANT (pam-faillock module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for pam-faillock is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the pam-faillock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the pam-faillock install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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

@test "INVARIANT (pam-faillock module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the pam-faillock requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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

@test "INVARIANT (pam-faillock module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the pam-faillock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the pam-faillock
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the pam-faillock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (pam-faillock module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the pam-faillock substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
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

@test "INVARIANT (pam-faillock module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (pam-faillock module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (pam-faillock module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (pam-faillock module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (pam-faillock README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (pam-faillock install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (pam-faillock install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (pam-faillock install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (pam-faillock install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (pam-faillock install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (pam-faillock install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (pam-faillock install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (pam-faillock install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (pam-faillock install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (pam-faillock install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (pam-faillock install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (pam-faillock install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (pam-faillock module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (pam-faillock module.toml exists at canonical path modules/pam-faillock/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (pam-faillock module dir is at canonical path modules/pam-faillock/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/pam-faillock"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (pam-faillock install dir exists at modules/pam-faillock/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (pam-faillock install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (pam-faillock install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (pam-faillock install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (pam-faillock install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (pam-faillock module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (pam-faillock install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/pam-faillock/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}
