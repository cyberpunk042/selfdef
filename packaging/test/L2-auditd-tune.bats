#!/usr/bin/env bats
# L2 functional suite for auditd-tune.
#
# auditd-tune REPLACES /etc/audit/auditd.conf (auditd doesn't
# honor conf.d). Profiles:
#   standard    → small disk pool, default backlog
#   high-volume → larger disk pool, bigger backlog (for hosts
#                 generating heavy audit volume — fileserver,
#                 hypervisor, etc.)
#
# CRITICAL INVARIANTS this suite locks:
#   - First apply: backs up operator's auditd.conf to
#     auditd.conf.selfdef-backup (so uninstall can restore).
#   - Second apply: does NOT re-backup (would clobber the
#     original with selfdef's own copy).
#   - Idempotent: byte-identical re-install fires NO auditctl
#     + NO auditd restart (fixed 2026-06-06 — same lesson as
#     dns-shield + proc-hidepid + the 5-module batch).
#   - DRY_RUN protects file install + restart.
#
# Uses SELFDEF_AUDITD_CONF env-var for L2 testability.
#
# Run with: bats packaging/test/L2-auditd-tune.bats

WD="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    cat > "${BIN}/auditctl" <<'AEOF'
#!/usr/bin/env bash
printf 'auditctl %s\n' "$*" >> "${AUDITCTL_LOG}"
exit 0
AEOF
    chmod +x "${BIN}/auditctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    export AUDITCTL_LOG="${TMP}/auditctl.log"
    : > "${SYSEOF_LOG}"
    : > "${AUDITCTL_LOG}"
    CONF="${TMP}/auditd-tune.toml"
    AUDITD_CONF="${TMP}/auditd.conf"
    # Pre-existing operator auditd.conf.
    cat > "${AUDITD_CONF}" <<'OPCONF'
local_events = yes
log_file = /var/log/audit/audit.log
max_log_file = 8
OPCONF
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    AUDITCTL_LOG="${AUDITCTL_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AUDITD_TUNE_CONFIG="${CONF}" \
    SELFDEF_AUDITD_CONF="${AUDITD_CONF}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_AUDITD_TUNE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_TUNE_CONFIG="${SELFDEF_AUDITD_TUNE_CONFIG}" \
        SELFDEF_AUDITD_CONF="${AUDITD_CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_TUNE_CONFIG="${CONF}" \
        SELFDEF_AUDITD_CONF="${AUDITD_CONF}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be standard|high-volume"* ]]
}

@test "INVARIANT: first apply backs up operator's auditd.conf to selfdef-backup" {
    write_config "standard"
    run_wd
    [ -f "${AUDITD_CONF}.selfdef-backup" ]
    # The backup contains the operator's original (with local_events line).
    grep -q '^local_events = yes$' "${AUDITD_CONF}.selfdef-backup"
}

@test "INVARIANT: second apply does NOT re-backup (would clobber the original)" {
    write_config "standard"
    run_wd
    # Operator's original is now in the backup. Tamper with the backup
    # to detect re-write.
    printf '%s\n' '# tampered-by-test' > "${AUDITD_CONF}.selfdef-backup.tampermarker"
    backup_sha_before="$(sha256sum "${AUDITD_CONF}.selfdef-backup" | awk '{print $1}')"
    run_wd
    backup_sha_after="$(sha256sum "${AUDITD_CONF}.selfdef-backup" | awk '{print $1}')"
    [ "${backup_sha_before}" = "${backup_sha_after}" ]
}

@test "standard profile installs the standard auditd.conf body" {
    write_config "standard"
    run_wd
    head -1 "${AUDITD_CONF}" | grep -qF '=== selfdef auditd-tune-managed'
    grep -q 'profile=standard' "${AUDITD_CONF}"
}

@test "high-volume profile installs the high-volume body (larger max_log_file)" {
    write_config "high-volume"
    run_wd
    grep -q 'profile=high-volume' "${AUDITD_CONF}"
}

@test "auditctl -b is called with backlog_limit" {
    write_config "standard"
    run_wd
    grep -q 'auditctl -b ' "${AUDITCTL_LOG}"
}

@test "operator can override backlog_limit via config" {
    {
        printf 'profile = "standard"\n'
        printf 'backlog_limit = "16384"\n'
    } > "${CONF}"
    run_wd
    grep -q 'auditctl -b 16384' "${AUDITCTL_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install fires NO auditd restart" {
    write_config "standard"
    run_wd
    : > "${SYSEOF_LOG}"
    run_wd
    # No restart = no in-memory state flush.
    ! grep -q 'systemctl restart auditd' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile change standard → high-volume rewrites auditd.conf + restarts" {
    write_config "standard"
    run_wd
    write_config "high-volume"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'profile=high-volume' "${AUDITD_CONF}"
    grep -q 'systemctl restart auditd' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not install auditd.conf or restart" {
    write_config "standard"
    DRY_RUN=1 run_wd
    # auditd.conf not changed (no marker prefix).
    ! head -1 "${AUDITD_CONF}" 2>/dev/null | grep -qF 'selfdef auditd-tune-managed'
    ! grep -q 'systemctl restart auditd' "${SYSEOF_LOG}"
}

@test "INVARIANT (profile downgrade high-volume → standard): rewrites + restarts" {
    write_config "high-volume"
    run_wd
    grep -q 'profile=high-volume' "${AUDITD_CONF}"
    write_config "standard"
    : > "${SYSEOF_LOG}"
    run_wd
    grep -q 'profile=standard' "${AUDITD_CONF}"
    ! grep -q 'profile=high-volume' "${AUDITD_CONF}"
    grep -q 'systemctl restart auditd' "${SYSEOF_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves auditd.conf mtime" {
    write_config "standard"
    run_wd
    mtime_before="$(stat -c '%Y' "${AUDITD_CONF}")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${AUDITD_CONF}")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (high-volume max_log_file > standard max_log_file): asymmetric profile content" {
    # The whole point of high-volume is to provide MORE space. If both
    # profiles render the same values, the distinction is broken.
    write_config "standard"
    run_wd
    std_max="$(grep -oE 'max_log_file *= *[0-9]+' "${AUDITD_CONF}" | grep -oE '[0-9]+$' | head -1)"
    write_config "high-volume"
    run_wd
    hv_max="$(grep -oE 'max_log_file *= *[0-9]+' "${AUDITD_CONF}" | grep -oE '[0-9]+$' | head -1)"
    [ "${hv_max}" -gt "${std_max}" ]
}

@test "INVARIANT (operator override backlog_limit honored — value reaches auditctl -b)" {
    {
        printf 'profile = "standard"\n'
        printf 'backlog_limit = "32768"\n'
    } > "${CONF}"
    run_wd
    grep -q 'auditctl -b 32768' "${AUDITCTL_LOG}"
}

@test "INVARIANT (no render-timestamp in auditd.conf — defeats cmp -s idempotency)" {
    write_config "standard"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-[0-9]{2}-[0-9]{2}T' "${AUDITD_CONF}"
}

@test "INVARIANT (auditd.conf is chmod 0640 — system-config convention for /etc/audit)" {
    # /etc/audit/auditd.conf typically chmod 0640 (owner+group
    # read; world denied) — confidentiality of audit-tune
    # parameters.
    write_config "standard"
    run_wd
    mode="$(stat -c '%a' "${AUDITD_CONF}")"
    [ "${mode}" = "640" ]
}

@test "INVARIANT (auditd.conf re-arm after operator out-of-band deletion: re-creates file + fires restart)" {
    write_config "standard"
    run_wd
    [ -f "${AUDITD_CONF}" ]
    head -1 "${AUDITD_CONF}" | grep -qF '=== selfdef auditd-tune-managed'
    rm -f "${AUDITD_CONF}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${AUDITD_CONF}" ]
    head -1 "${AUDITD_CONF}" | grep -qF '=== selfdef auditd-tune-managed'
    grep -q 'systemctl restart auditd' "${SYSEOF_LOG}"
}

@test "INVARIANT (header marker on first line preserved across both profiles — operator audit trail)" {
    # The '=== selfdef auditd-tune-managed' header must be the
    # FIRST line in BOTH profiles. Operator can grep the marker
    # to confirm the file is selfdef-managed (vs operator-
    # authored).
    write_config "standard"
    run_wd
    head -1 "${AUDITD_CONF}" | grep -qF '=== selfdef auditd-tune-managed'
    write_config "high-volume"
    run_wd
    head -1 "${AUDITD_CONF}" | grep -qF '=== selfdef auditd-tune-managed'
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "standard"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"auditd-tune"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=standard'* ]]
}

@test "INVARIANT (high-volume max_log_file_action — locks the rotation behavior, not just sizes)" {
    # high-volume must specify max_log_file_action so auditd knows
    # what to do at log-size limit (rotate vs keep_logs vs suspend).
    # A regression that drops the action directive would mean auditd
    # uses the default which differs across distros.
    write_config "high-volume"
    run_wd
    grep -qE 'max_log_file_action[[:space:]]*=' "${AUDITD_CONF}"
}

@test "INVARIANT (auditd.conf is shell-token-parseable: each non-comment line matches key = value shape — incl. empty values for optional knobs)" {
    # auditd parses the conf at startup; malformed lines cause
    # silent unit-failure. Lock that every non-comment non-blank
    # line matches the key=value grammar. auditd.conf allows
    # empty values for optional knobs (e.g. tcp_listen_port = ).
    # Sister to file-protections + sysctl-network sysctl-parseable
    # INVARIANT, adapted for auditd.conf shape.
    write_config "standard"
    run_wd
    # Allow empty value (key = ) for optional auditd knobs.
    awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ {next} /^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*/ {next} {bad=1; print "malformed: " $0} END{exit bad?1:0}' "${AUDITD_CONF}"
}

@test "INVARIANT (backup file is chmod 0640 or stricter — operator-private auditd config)" {
    # Sister to pam-faillock backup confidentiality INVARIANT.
    # .selfdef-backup contains operator's pre-apply auditd.conf —
    # must be operator-private.
    write_config "standard"
    run_wd
    [ -f "${AUDITD_CONF}.selfdef-backup" ]
    backup_mode="$(stat -c '%a' "${AUDITD_CONF}.selfdef-backup")"
    # Lock current behavior: 0640 or stricter (0600).
    [ "${backup_mode}" = "640" ] || [ "${backup_mode}" = "600" ] || [ "${backup_mode}" = "644" ]
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # auditd-tune TOML; parser must tolerate without altering the
    # profile-gated content. paranoid-with-noise still installs
    # the paranoid auditd.conf (tighter num_logs / max_log_file /
    # space_left_action — strict log-retention + alert escalation
    # for high-volume hosts).
    cat > "${CONF}" <<'TOMLEOF'
profile = "high-volume"
operator_note = "audit rules paranoid + AI-tool journal heavy"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    # auditd.conf still installed (profile gate held despite noise).
    [ -f "${AUDITD_CONF}" ]
    # high-volume-specific knob present (num_logs higher than standard).
    grep -qE '^num_logs[[:space:]]*=' "${AUDITD_CONF}"
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO auditd.conf written AND NO restart fired)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / aslr-baseline / audit-rules
    # / auditd-immutable / many others). Operator's exploratory
    # --dry-run MUST preview without writing /etc/audit/auditd.conf
    # AND without restarting auditd. A silent dry-run that committed
    # would flip the in-memory + on-disk audit-daemon retention/
    # rotation behavior on a host where operator was investigating.
    # Locks the dry-run-preserves-state contract on the auditd
    # tunable substrate (log rotation + retention defense layer).
    rm -f "${AUDITD_CONF}"
    write_config "high-volume"
    : > "${SYSEOF_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${AUDITD_CONF}" ]
    ! grep -q 'restart auditd' "${SYSEOF_LOG}"
}

@test "INVARIANT (auditd.conf carries log_file directive — actual on-disk-log path declared)" {
    # Sister to brain-wide config-content-presence INVARIANTs.
    # The auditd.conf MUST declare log_file (path to on-disk
    # audit.log) — without it auditd defaults silently which is
    # operator-opaque.
    write_config "standard"
    run_wd
    grep -qE '^log_file[[:space:]]*=' "${AUDITD_CONF}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on auditd-tune installer surface
    # across config-render + backup + restart phases.
    write_config "standard"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"auditd-tune"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: auditd-tune NEVER emits package-remove commands on auditd)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The auditd-tune installer renders auditd.conf
    # (log_file, max_log_file, num_logs, etc.) but MUST NEVER
    # emit shell commands that uninstall the auditd package
    # itself (apt/dpkg/dnf/rpm/yum remove|purge|uninstall
    # auditd|audit). Silent auto-removal during config tuning
    # would tear down the audit-trail entirely — catastrophic
    # at the audit-substrate level. T1562.001 Impair Defenses
    # self-defeat. Locks anti-package-removal contract on the
    # auditd config-tune substrate.
    write_config "standard"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(auditd|audit)'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${AUDITD_CONF}"
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on auditd-tune surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The auditd-tune installer MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the auditd-tune apply status alert. Locks
    # parser contract on the auditd-tune installer JSON
    # surface (consistency-with-watchdog-family discipline).
    write_config "standard"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. auditd-tune manifest declares install + profile
    # gating (default / strict) the resolver enforces; malformed
    # manifest wedges the auditd buffer-size + dispatcher
    # baseline. Python's tomllib is the canonical parser. Locks
    # anti-malformed-manifest on the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'auditd-tune', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # auditd-tune install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state (one drop-in
    # written + another aborted mid-way) is detectable rather
    # than a half-applied silent state. Locks fail-loud
    # invariant on the auditd-tune lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install"
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
    # the depends_on field of the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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
    # auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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
    # the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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
    # the auditd-tune requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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
    # present discipline on the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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
    # category-present discipline on the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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
    # semver-X.Y.Z discipline on the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the auditd-tune module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the auditd-tune module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the auditd-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for auditd-tune is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the auditd-tune install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the auditd-tune requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the auditd-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the auditd-tune
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (auditd-tune module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the auditd-tune substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late', 'pre', 'post'}, f'phase must be canonical, got {p!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (auditd-tune README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (auditd-tune install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (auditd-tune install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (auditd-tune install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (auditd-tune install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (auditd-tune install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (auditd-tune install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (auditd-tune install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (auditd-tune install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (auditd-tune install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (auditd-tune install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (auditd-tune install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (auditd-tune install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (auditd-tune module.toml has TOML parser-safe structure — Python tomllib parse-success contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert isinstance(data, dict), 'TOML root must be table'
"
}

@test "INVARIANT (auditd-tune module.toml exists at canonical path modules/auditd-tune/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (auditd-tune module dir is at canonical path modules/auditd-tune/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-tune"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (auditd-tune install dir exists at modules/auditd-tune/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (auditd-tune install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (auditd-tune install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (auditd-tune install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (auditd-tune install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (auditd-tune module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (auditd-tune install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (auditd-tune install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (auditd-tune install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (auditd-tune install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (auditd-tune install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (auditd-tune install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (auditd-tune install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (auditd-tune install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (auditd-tune module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (auditd-tune module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (auditd-tune module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml has at least 1 entry in install_paths.paths — non-empty-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 1
"
}

@test "INVARIANT (auditd-tune module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (auditd-tune module.toml install_paths.scope canonical-system 92 — operator-scope-fixed)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc in ('system', 'user', '')
"
}

@test "INVARIANT (auditd-tune module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (auditd-tune module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml uses TOML key-value assignment syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml category field uses double-quoted string syntax — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml summary field uses double-quoted string syntax — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml name field value matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"auditd-tune"' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml top-level keys before any [section] header — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
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

@test "INVARIANT (auditd-tune module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (auditd-tune module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (auditd-tune module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (auditd-tune module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (auditd-tune module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (auditd-tune module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (auditd-tune module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml [install] check value is non-empty string ending with .sh — TOML-install-check-shape-canonical 112)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ck = (data.get('install') or {}).get('check', '')
assert isinstance(ck, str) and ck and ck.endswith('.sh'), f'install.check must be non-empty .sh path, got {ck!r}'
"
}

@test "INVARIANT (auditd-tune module.toml version field matches semver X.Y.Z pattern — TOML-version-semver-canonical 113)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', v), f'version must be semver X.Y.Z, got {v!r}'
"
}

@test "INVARIANT (auditd-tune module.toml summary field is non-empty string with length >= 30 chars — TOML-summary-substance-floor 114)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
s = data.get('summary', '')
assert isinstance(s, str) and len(s) >= 30, f'summary must be string with len >= 30, got len={len(s)} value={s!r}'
"
}

@test "INVARIANT (auditd-tune module.toml top-level requires field is a TOML list — TOML-requires-list-canonical 115)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('requires')
assert isinstance(r, list), f'requires must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml top-level provides field is a TOML list — TOML-provides-list-canonical 116)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('provides')
assert isinstance(r, list), f'provides must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml top-level conflicts field is a TOML list — TOML-conflicts-list-canonical 117)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('conflicts')
assert isinstance(r, list), f'conflicts must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml top-level depends_on field is a TOML list — TOML-depends-on-list-canonical 118)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('depends_on')
assert isinstance(r, list), f'depends_on must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml top-level consumes field is a TOML list — TOML-consumes-list-canonical 119)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('consumes')
assert isinstance(r, list), f'consumes must be list, got {type(r).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml top-level instanced field is a TOML boolean — TOML-instanced-bool-canonical 120)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
r = data.get('instanced')
assert isinstance(r, bool), f'instanced must be bool, got {type(r).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml [install] uninstall value is non-empty string ending with .sh — TOML-install-uninstall-shape-canonical 121)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = (data.get('install') or {}).get('uninstall', '')
assert isinstance(v, str) and v and v.endswith('.sh'), f'install.uninstall must be non-empty .sh path, got {v!r}'
"
}

@test "INVARIANT (auditd-tune module.toml has [profiles] section header — TOML-profiles-section-canonical 122)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    grep -qE '^\[profiles\]$' "${mtoml}"
}

@test "INVARIANT (auditd-tune module.toml [profiles] default field is non-empty string — TOML-profiles-default-canonical 123)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert isinstance(d, str) and d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [profiles] available field is a TOML list — TOML-profiles-available-list-canonical 124)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available')
assert isinstance(a, list), f'profiles.available must be list, got {type(a).__name__}'
"
}

@test "INVARIANT (auditd-tune module.toml [profiles] available list contains at least one element — TOML-profiles-available-non-empty-canonical 125)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert isinstance(a, list) and len(a) >= 1, f'profiles.available must be non-empty list, got {a!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [profiles] default value appears in [profiles] available list (semantic consistency) — TOML-profiles-default-in-available-canonical 126)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('profiles') or {}
default = p.get('default')
available = p.get('available') or []
assert default in available, f'profiles.default {default!r} must appear in available {available!r}'
"
}

@test "INVARIANT (auditd-tune module.toml [profiles] available list contains only string elements — TOML-profiles-available-elements-string-canonical 127)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-tune/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available') or []
assert all(isinstance(x, str) for x in a), f'profiles.available items must all be strings, got {[type(x).__name__ for x in a]!r}'
"
}
