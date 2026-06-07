#!/usr/bin/env bats
# L2 functional suite for auditd-immutable.
#
# auditd-immutable installs /etc/audit/rules.d/99-selfdef-
# immutable.rules. The audit profile is the safe option —
# observation only. The enforce profile triggers `-e 2` which
# LOCKS the audit subsystem until reboot: no auditctl -D, no
# auditctl -e 0, no rule additions/removals. Attackers who
# T1562.001-blind audit can't, until reboot. Operators who need
# to tune audit during normal operation also can't.
#
# CRITICAL INVARIANT: enforce profile requires
# acknowledge_immutable=true in config. Without it the script
# REFUSES — refuse-to-brick guard (parallel to kernel-lockdown
# strict + kernel-yama paranoid).
#
# Tests shadow augenrules + auditctl on PATH; uses
# SELFDEF_AUDIT_RULES_D env-var override.
#
# Run with: bats packaging/test/L2-auditd-immutable.bats

WD="${BATS_TEST_DIRNAME}/../../modules/auditd-immutable/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/augenrules" <<'AEEOF'
#!/usr/bin/env bash
printf 'augenrules %s\n' "$*" >> "${AUGEN_LOG}"
exit 0
AEEOF
    chmod +x "${BIN}/augenrules"
    cat > "${BIN}/auditctl" <<'ACEOF'
#!/usr/bin/env bash
case "$1" in
    -s) printf 'enabled %s\n' "${LIVE_AUDIT_ENABLED:-1}" ;;
esac
exit 0
ACEOF
    chmod +x "${BIN}/auditctl"
    export AUGEN_LOG="${TMP}/augen.log"
    : > "${AUGEN_LOG}"
    CONF="${TMP}/auditd-immutable.toml"
    RULES_D="${TMP}/audit-rules.d"
    mkdir -p "${RULES_D}"
}

teardown() { rm -rf "${TMP}"; }

# write_config <profile> [acknowledge_immutable]
write_config() {
    local profile="$1" ack="${2:-false}"
    printf 'profile = "%s"\n' "${profile}" > "${CONF}"
    printf 'acknowledge_immutable = %s\n' "${ack}" >> "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    AUGEN_LOG="${AUGEN_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
    SELFDEF_AUDIT_RULES_D="${RULES_D}" \
    LIVE_AUDIT_ENABLED="${LIVE_AUDIT_ENABLED:-1}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_AUDITD_IMMUTABLE_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${SELFDEF_AUDITD_IMMUTABLE_CONFIG}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "missing rules.d → die (auditd not installed)" {
    write_config "audit"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${TMP}/no-such-rules-d" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"audit rules.d missing"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be audit|enforce"* ]]
}

@test "INVARIANT: enforce profile without acknowledgment → die (refuse-to-brick)" {
    write_config "enforce" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"locks audit rules until reboot"* ]]
    # The enforce.rules file MUST NOT be installed.
    ! [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
}

@test "audit profile installs audit.rules + reloads via augenrules" {
    write_config "audit"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    # Drop-in chmod 0640 (audit-rules.d convention).
    [ "$(stat -c '%a' "${RULES_D}/99-selfdef-immutable.rules")" = "640" ]
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "enforce profile WITH acknowledgment installs enforce.rules" {
    write_config "enforce" "true"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    cmp -s modules/auditd-immutable/configs/enforce.rules "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT: idempotent — re-install with identical content fires NO augenrules" {
    write_config "audit"
    run_wd
    : > "${AUGEN_LOG}"
    run_wd
    ! grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT: DRY_RUN does not install rules or fire augenrules" {
    write_config "audit"
    DRY_RUN=1 run_wd
    ! [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    ! grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "default profile is audit (no profile key — the safe default)" {
    : > "${CONF}"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    # Default audit profile content matches audit.rules.
    cmp -s modules/auditd-immutable/configs/audit.rules "${RULES_D}/99-selfdef-immutable.rules"
}

@test "profile downgrade enforce→audit replaces drop-in + reloads" {
    write_config "enforce" "true"
    run_wd
    # Verify it's the enforce version first.
    cmp -s modules/auditd-immutable/configs/enforce.rules "${RULES_D}/99-selfdef-immutable.rules"
    # Downgrade.
    write_config "audit"
    : > "${AUGEN_LOG}"
    run_wd
    cmp -s modules/auditd-immutable/configs/audit.rules "${RULES_D}/99-selfdef-immutable.rules"
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT (profile upgrade audit → enforce WITH ack): writes enforce.rules + reloads" {
    # Reverse direction. Locks bidirectional contract.
    write_config "audit"
    run_wd
    cmp -s modules/auditd-immutable/configs/audit.rules "${RULES_D}/99-selfdef-immutable.rules"
    write_config "enforce" "true"
    : > "${AUGEN_LOG}"
    run_wd
    cmp -s modules/auditd-immutable/configs/enforce.rules "${RULES_D}/99-selfdef-immutable.rules"
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT (idempotent mtime): byte-identical re-install preserves drop-in mtime" {
    write_config "audit"
    run_wd
    mtime_before="$(stat -c '%Y' "${RULES_D}/99-selfdef-immutable.rules")"
    sleep 1
    run_wd
    mtime_after="$(stat -c '%Y' "${RULES_D}/99-selfdef-immutable.rules")"
    [ "${mtime_before}" = "${mtime_after}" ]
}

@test "INVARIANT (enforce.rules carries -e 2 LOCK directive — the actual immutability mechanism)" {
    write_config "enforce" "true"
    run_wd
    grep -qE '^-e[[:space:]]+2' "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT (audit.rules does NOT carry -e 2): the safe profile must not actually lock the subsystem" {
    write_config "audit"
    run_wd
    ! grep -qE '^-e[[:space:]]+2' "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT (no render-timestamp in drop-in): defeats cmp -s idempotency guard" {
    write_config "audit"
    run_wd
    ! grep -qE '^# Generated [0-9]{4}-' "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT (filename is 99- prefix — sorts AFTER operator rules + base rules, applies LAST)" {
    # The 99- prefix is critical: -e 2 must apply LAST so the immutable
    # flag fires AFTER all operator-authored rules load. A 10- or 50-
    # prefix would lock the subsystem BEFORE operator rules apply.
    write_config "enforce" "true"
    run_wd
    # Confirm the actual filename is 99-prefixed.
    ls "${RULES_D}/" | grep -qE '^99-selfdef-immutable\.rules$'
}

@test "INVARIANT (drop-in re-arm after operator out-of-band deletion: re-creates rule file + fires augenrules)" {
    write_config "audit"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    rm -f "${RULES_D}/99-selfdef-immutable.rules"
    : > "${AUGEN_LOG}"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    grep -q 'augenrules --load' "${AUGEN_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + profile surfaced for operator dashboard)" {
    write_config "audit"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"auditd-immutable"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=audit'* ]]
}

@test "INVARIANT (acknowledge_immutable=false on audit profile is benign — only enforce gates on the ack)" {
    # Audit profile is observation-only; the refuse-to-brick guard
    # is ONLY for enforce. Verify audit succeeds with ack=false.
    write_config "audit" "false"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    # Audit profile content (no -e 2).
    ! grep -qE '^-e[[:space:]]+2' "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT (acknowledge_immutable=true on audit profile is also benign — over-acknowledging doesn't fail)" {
    # Operator may set ack=true defensively. Audit profile should
    # accept it without quirky behavior.
    write_config "audit" "true"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    ! grep -qE '^-e[[:space:]]+2' "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT (refuse-to-brick precedence over profile-key: enforce+ack=false dies even after prior audit install — no silent escalation to enforce-empty)" {
    # Sister to kernel-lockdown + nftables-baseline + tmpfs-baseline
    # + unprivileged-userns + proc-hidepid + usbguard refuse-to-brick
    # precedence pattern.
    write_config "audit"
    run_wd
    cmp -s modules/auditd-immutable/configs/audit.rules "${RULES_D}/99-selfdef-immutable.rules"
    # Operator flips to enforce but forgets to set ack.
    write_config "enforce" "false"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    # Prior audit rules preserved — no silent escalation to enforce.
    cmp -s modules/auditd-immutable/configs/audit.rules "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT (config-layer-noise resilience: enforce + extra TOML keys does NOT bypass acknowledge_immutable gate)" {
    # Sister to kernel-lockdown + nftables-baseline + unprivileged-
    # userns + usbguard config-noise precedence INVARIANT. Lock
    # that extra TOML keys cannot accidentally bypass the gate.
    cat > "${CONF}" <<'EOF'
profile = "enforce"
acknowledge_immutable = false
extra_knob_that_should_not_help = "wrong"
maybe_an_alias_for_ack = true
EOF
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_AUDITD_IMMUTABLE_CONFIG="${CONF}" \
        SELFDEF_AUDIT_RULES_D="${RULES_D}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    ! [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
}

@test "INVARIANT (downgrade enforce → audit removes the -e 2 LOCK directive — no remnant immutability after operator-loosening)" {
    # Sister to host-sentinel downgrade enforce→audit Sigkill-remnant
    # INVARIANT. When operator downgrades, the -e 2 immutability
    # directive MUST be removed from the live rule file. A stale
    # -e 2 remnant after downgrade would keep the audit subsystem
    # locked silently.
    write_config "enforce" "true"
    run_wd
    grep -qE '^-e[[:space:]]+2' "${RULES_D}/99-selfdef-immutable.rules"
    write_config "audit"
    run_wd
    # NO -e 2 remnant in downgraded audit-profile file.
    ! grep -qE '^-e[[:space:]]+2' "${RULES_D}/99-selfdef-immutable.rules"
}

@test "INVARIANT (rule file carries selfdef self-identifying header — head -1 stale-cleanup discipline)" {
    # Sister to many other installer module's header-marker
    # INVARIANT across the brain (ssh-hardening / journal-tune /
    # slm-cpu-loop / tensor-parallel-inference). The rule file
    # lands at /etc/audit/rules.d/99-selfdef-immutable.rules
    # alongside operator-hand-authored / vendor / packaging-
    # provided rule files. A stale-cleanup pass (operator
    # housekeeping or uninstall path) inspects the first non-
    # blank comment line to identify selfdef-rendered config
    # from operator config. Without the marker, a careless
    # head -1 sweep could clobber operator state. Locks the
    # provenance contract.
    write_config "enforce" "true"
    run_wd
    [ -f "${RULES_D}/99-selfdef-immutable.rules" ]
    first_nonblank="$(grep -E -m1 -v '^[[:space:]]*$' "${RULES_D}/99-selfdef-immutable.rules")"
    [[ "${first_nonblank}" == *"selfdef"* ]]
}

@test "INVARIANT (DRY_RUN side-effect-freedom: NO rule file written AND NO augenrules --load fired)" {
    # Sister to every other installer module's DRY_RUN INVARIANT
    # across the brain (acct-baseline / aslr-baseline / apport-
    # disable / audit-rules / many others). Operator's exploratory
    # --dry-run MUST preview without writing /etc/audit/rules.d/
    # 99-selfdef-immutable.rules AND without firing augenrules
    # --load. The immutable lock (-e 2) is irreversible without
    # reboot once committed — a silent dry-run that committed
    # would lock the operator out of the audit subsystem until
    # reboot. Locks the dry-run-preserves-state contract on the
    # auditd-immutable-lock substrate.
    write_config "enforce" "true"
    : > "${AUGEN_LOG}"
    DRY_RUN=1 run_wd
    [ ! -f "${RULES_D}/99-selfdef-immutable.rules" ]
    ! grep -qE 'augenrules.*--load' "${AUGEN_LOG}"
}

@test "INVARIANT (rule file is chmod 0640 — sister to audit-rules chmod convention)" {
    # Sister to audit-rules + audit-config baseline file-perm
    # INVARIANTs.
    write_config "enforce" "true"
    run_wd
    file="${RULES_D}/99-selfdef-immutable.rules"
    [ -f "${file}" ]
    mode="$(stat -c '%a' "${file}")"
    [ "${mode}" = "640" ] || [ "${mode}" = "600" ] || [ "${mode}" = "644" ]
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # Single-record discipline on auditd-immutable installer
    # surface across rule-file + augenrules-reload phases.
    write_config "enforce" "true"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"auditd-immutable"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (no auto-uninstall: auditd-immutable NEVER emits package-remove commands on auditd)" {
    # Sister to brain-wide no-auto-uninstall INVARIANTs across
    # L2 suites. The auditd-immutable installer writes a rule
    # file that locks auditd configuration but MUST NEVER emit
    # shell commands that uninstall the auditd package itself
    # (apt/dpkg/dnf/rpm/yum remove|purge|uninstall auditd|
    # audit). Silent auto-removal of auditd during install
    # would tear down the audit-trail entirely + paradoxically
    # bypass the immutability lock the module itself installs.
    # T1562.001 Impair Defenses self-defeat. Locks anti-
    # package-removal contract on the auditd immutability
    # substrate.
    write_config "enforce" "true"
    output="$(run_wd 2>&1)"
    ! printf '%s\n' "${output}" | grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)[[:space:]]+(auditd|audit)'
    ! grep -qE '(apt-get|dpkg|dnf|rpm|yum)[[:space:]]+(remove|purge|uninstall)' "${RULES_D}/99-selfdef-immutable.rules" 2>/dev/null || true
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on auditd-immutable surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The auditd-immutable installer MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the auditd immutability lock
    # status alert. Locks parser contract on the auditd-
    # immutable installer JSON surface (consistency-with-
    # watchdog-family discipline).
    write_config "enforce" "true"
    output="$(run_wd 2>&1)"
    bad=$(printf '%s\n' "${output}" | grep -oE '"severity":"[^"]+"' | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. auditd-immutable manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the -e 2 auditd immutable-flag baseline. Python's
    # tomllib is the canonical parser. Locks anti-malformed-
    # manifest on the auditd-immutable substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/auditd-immutable/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'auditd-immutable', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
