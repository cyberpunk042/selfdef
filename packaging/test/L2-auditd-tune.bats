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
