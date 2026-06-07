#!/usr/bin/env bats
# L2 functional suite for mta-loopback-detect.
#
# mta-loopback-detect runs a per-boot + periodic check that the
# host's MTA (postfix / exim / sendmail) is bound to loopback
# only. Many distros ship MTAs configured to listen on 0.0.0.0
# by default — a routine information-disclosure / spam-relay
# vector if the host is exposed.
#
# Architecture:
#   - libexec script lands at /usr/local/libexec/selfdef/
#     mta-loopback-detect.sh
#   - systemd timer + service drive it (boot + daily)
#   - profile=report logs findings; profile=enforce attempts
#     remediation (kills non-loopback bind via service-level
#     override)
#
# Idempotency: every install_one() helper does cmp -s before
# writing. The systemctl daemon-reload + enable --now timer
# are gated on `changes > 0` — so a no-op apply is fully
# side-effect-free.
#
# Run with: bats packaging/test/L2-mta-loopback-detect.bats

WD="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/apply.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/systemctl" <<'SYSEOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${SYSEOF_LOG}"
exit 0
SYSEOF
    chmod +x "${BIN}/systemctl"
    export SYSEOF_LOG="${TMP}/systemctl.log"
    : > "${SYSEOF_LOG}"
    CONF="${TMP}/mta-loopback-detect.toml"
    LIBEXEC_DIR="${TMP}/libexec/selfdef"
    SYSTEMD_DIR="${TMP}/systemd"
    DROPIN_DIR_SVC="${SYSTEMD_DIR}/selfdef-mta-loopback.service.d"
    DROPIN_PROFILE="${DROPIN_DIR_SVC}/50-profile.conf"
    SCRIPT_DST="${LIBEXEC_DIR}/mta-loopback-detect.sh"
    SVC_DST="${SYSTEMD_DIR}/selfdef-mta-loopback.service"
    TIMER_DST="${SYSTEMD_DIR}/selfdef-mta-loopback.timer"
    mkdir -p "${SYSTEMD_DIR}"
}

teardown() { rm -rf "${TMP}"; }

write_config() {
    printf 'profile = "%s"\n' "$1" > "${CONF}"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SYSEOF_LOG="${SYSEOF_LOG}" \
    SELFDEF_DRY_RUN="${DRY_RUN:-0}" \
    SELFDEF_MTA_CONFIG="${CONF}" \
    SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
    SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
    bash "${WD}"
}

@test "missing config → die" {
    SELFDEF_MTA_CONFIG="${TMP}/missing.toml"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_MTA_CONFIG="${SELFDEF_MTA_CONFIG}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"config not readable"* ]]
}

@test "invalid profile → die" {
    write_config "exterminate"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_MTA_CONFIG="${CONF}" \
        SELFDEF_LIBEXEC_DIR="${LIBEXEC_DIR}" \
        SELFDEF_SYSTEMD_DIR="${SYSTEMD_DIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
    [[ "${output}" == *"profile must be report|enforce"* ]]
}

@test "report profile installs the libexec script + service + timer + profile dropin" {
    write_config "report"
    run_wd
    [ -f "${SCRIPT_DST}" ]
    [ -f "${SVC_DST}" ]
    [ -f "${TIMER_DST}" ]
    [ -f "${DROPIN_PROFILE}" ]
    # Profile drop-in records the active profile via Environment=.
    grep -q '^Environment=SELFDEF_MTA_PROFILE=report$' "${DROPIN_PROFILE}"
}

@test "enforce profile installs same artifact set with enforce profile env" {
    write_config "enforce"
    run_wd
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_MTA_PROFILE=enforce$' "${DROPIN_PROFILE}"
}

@test "libexec script is chmod 0755 (executable for the systemd unit)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SCRIPT_DST}")" = "755" ]
}

@test "service + timer + dropin are chmod 0644 (system-config convention)" {
    write_config "report"
    run_wd
    [ "$(stat -c '%a' "${SVC_DST}")" = "644" ]
    [ "$(stat -c '%a' "${TIMER_DST}")" = "644" ]
    [ "$(stat -c '%a' "${DROPIN_PROFILE}")" = "644" ]
}

@test "first apply fires daemon-reload + enables the timer" {
    write_config "report"
    run_wd
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-mta-loopback.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: idempotent — byte-identical re-install does NOT rewrite artifacts OR fire systemctl" {
    write_config "report"
    run_wd
    script_mtime_before="$(stat -c '%Y' "${SCRIPT_DST}")"
    svc_mtime_before="$(stat -c '%Y' "${SVC_DST}")"
    timer_mtime_before="$(stat -c '%Y' "${TIMER_DST}")"
    dropin_mtime_before="$(stat -c '%Y' "${DROPIN_PROFILE}")"
    : > "${SYSEOF_LOG}"
    sleep 1
    run_wd
    script_mtime_after="$(stat -c '%Y' "${SCRIPT_DST}")"
    svc_mtime_after="$(stat -c '%Y' "${SVC_DST}")"
    timer_mtime_after="$(stat -c '%Y' "${TIMER_DST}")"
    dropin_mtime_after="$(stat -c '%Y' "${DROPIN_PROFILE}")"
    [ "${script_mtime_before}" = "${script_mtime_after}" ]
    [ "${svc_mtime_before}" = "${svc_mtime_after}" ]
    [ "${timer_mtime_before}" = "${timer_mtime_after}" ]
    [ "${dropin_mtime_before}" = "${dropin_mtime_after}" ]
    # systemctl reload + enable are gated on changes > 0 — must NOT fire.
    ! grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    ! grep -q 'systemctl enable' "${SYSEOF_LOG}"
}

@test "INVARIANT: profile switch report → enforce REWRITES profile dropin AND fires daemon-reload + enable" {
    write_config "report"
    run_wd
    [ -f "${DROPIN_PROFILE}" ]
    : > "${SYSEOF_LOG}"
    write_config "enforce"
    run_wd
    grep -q '^Environment=SELFDEF_MTA_PROFILE=enforce$' "${DROPIN_PROFILE}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
    grep -q 'systemctl enable --now selfdef-mta-loopback.timer' "${SYSEOF_LOG}"
}

@test "INVARIANT: DRY_RUN does not write any artifact or fire systemctl" {
    write_config "report"
    DRY_RUN=1 run_wd
    ! [ -f "${SCRIPT_DST}" ]
    ! [ -f "${SVC_DST}" ]
    ! [ -f "${TIMER_DST}" ]
    ! [ -f "${DROPIN_PROFILE}" ]
    ! grep -q 'systemctl' "${SYSEOF_LOG}"
}

@test "default profile is report (no profile key — conservative read-only default)" {
    : > "${CONF}"
    run_wd
    [ -f "${DROPIN_PROFILE}" ]
    grep -q '^Environment=SELFDEF_MTA_PROFILE=report$' "${DROPIN_PROFILE}"
}

@test "emit_status reports changes count (4 on first install: script + svc + timer + dropin; 0 on idempotent)" {
    write_config "report"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'changes=4'* ]]
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'changes=0'* ]]
}

@test "INVARIANT (profile downgrade enforce → report): rewrites drop-in back + fires daemon-reload" {
    write_config "enforce"
    run_wd
    grep -q '^Environment=SELFDEF_MTA_PROFILE=enforce$' "${DROPIN_PROFILE}"
    : > "${SYSEOF_LOG}"
    write_config "report"
    run_wd
    grep -q '^Environment=SELFDEF_MTA_PROFILE=report$' "${DROPIN_PROFILE}"
    ! grep -q '^Environment=SELFDEF_MTA_PROFILE=enforce$' "${DROPIN_PROFILE}"
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (libexec script probes ss/netstat — actually checks listening-bind state)" {
    write_config "report"
    run_wd
    grep -qE 'ss|netstat' "${SCRIPT_DST}"
}

@test "INVARIANT (libexec script targets SMTP-family ports: 25/465/587 — the actual detection mechanism)" {
    # The detector classifies LISTENING sockets on SMTP-family ports
    # rather than MTA binary names — distro-agnostic approach.
    write_config "report"
    run_wd
    grep -qE '25|465|587' "${SCRIPT_DST}"
}

@test "INVARIANT (service unit references the libexec script): wiring is correct" {
    write_config "report"
    run_wd
    grep -qE '^ExecStart=' "${SVC_DST}"
    grep -q 'mta-loopback-detect' "${SVC_DST}"
}

@test "INVARIANT (timer unit carries OnCalendar or OnBootSec): actually fires periodically + on-boot)" {
    write_config "report"
    run_wd
    grep -qE '(OnCalendar|OnBootSec|OnUnitActiveSec)=' "${TIMER_DST}"
}

@test "INVARIANT (no render-timestamp in ANY of the 4 installed files): variant-A guard fleet-wide" {
    write_config "report"
    run_wd
    for f in "${SCRIPT_DST}" "${SVC_DST}" "${TIMER_DST}" "${DROPIN_PROFILE}"; do
        ! grep -qE '^# Generated [0-9]{4}-' "$f"
    done
}

@test "INVARIANT (re-arm after operator out-of-band deletion: re-creates all 4 files + fires daemon-reload)" {
    write_config "report"
    run_wd
    [ -f "${TIMER_DST}" ]
    rm -f "${SCRIPT_DST}" "${SVC_DST}" "${TIMER_DST}" "${DROPIN_PROFILE}"
    : > "${SYSEOF_LOG}"
    run_wd
    [ -f "${SCRIPT_DST}" ]
    [ -f "${SVC_DST}" ]
    [ -f "${TIMER_DST}" ]
    [ -f "${DROPIN_PROFILE}" ]
    grep -q 'systemctl daemon-reload' "${SYSEOF_LOG}"
}

@test "INVARIANT (emit_status JSON: status=ok + module + profile surfaced for operator dashboard)" {
    write_config "enforce"
    output="$(run_wd 2>&1)"
    [[ "${output}" == *'"module":"mta-loopback-detect"'* ]]
    [[ "${output}" == *'"status":"ok"'* ]]
    [[ "${output}" == *'profile=enforce'* ]]
}

@test "INVARIANT (enforce profile non-zero-exit semantics in libexec: PROFILE check translates non-loopback-bind to systemd-failure)" {
    # enforce profile is the lever that turns non-loopback MTA bind into
    # systemd service failure (operator alerting hook surface).
    write_config "enforce"
    run_wd
    grep -qE 'PROFILE|SELFDEF_MTA_PROFILE|enforce' "${SCRIPT_DST}"
    grep -qE 'exit\s+[1-9]|return\s+[1-9]' "${SCRIPT_DST}"
}

@test "INVARIANT (timer + service carry 'selfdef' identifier in Description/Documentation — operator-audit-trail)" {
    write_config "report"
    run_wd
    grep -qE '^Description=.*selfdef|^Documentation=.*selfdef' "${TIMER_DST}"
    grep -qE '^Description=.*selfdef|^Documentation=.*selfdef' "${SVC_DST}"
}

@test "INVARIANT (config-layer-noise resilience: extra TOML keys do NOT bypass profile gate)" {
    # Sister to every other watchdog/installer config-layer-noise
    # INVARIANT across the brain. Operator may add forward-compat
    # keys (commentary, future flags, vendor annotations) to the
    # mta-loopback-detect TOML; parser must tolerate without
    # altering the profile-gated behavior. enforce-with-noise
    # still writes the SELFDEF_MTA_PROFILE=enforce
    # drop-in (escalates non-loopback-bind from log-only to
    # systemd-failure-recorded — the operator-dashboard signal
    # for accidental-internet-facing-MTA exfil/abuse surface).
    cat > "${CONF}" <<'TOMLEOF'
profile = "enforce"
operator_note = "MTA bind to 0.0.0.0:25 = open-relay risk + spam abuse"
future_flag = "reserved"
vendor_annotation = "selfdef-2026.06"
TOMLEOF
    run_wd
    grep -q 'SELFDEF_MTA_PROFILE=enforce' "${DROPIN_PROFILE}"
    ! grep -q 'SELFDEF_MTA_PROFILE=report' "${DROPIN_PROFILE}"
}

@test "INVARIANT (libexec is shell-sourceable: bash -n parses cleanly — service ExecStart contract)" {
    # Sister to many other installer module's shell-sourceable
    # INVARIANT across the brain (secure-boot-status / swap-
    # encryption-detect / entropy-baseline). The libexec script
    # runs from systemd ExecStart. bash -n must parse cleanly. A
    # syntax regression would silently break the surveillance
    # every fire (timer scheduled; service can't ExecStart;
    # non-loopback-MTA-bind surface — open-relay / spam abuse —
    # goes unmonitored).
    write_config "report"
    run_wd
    bash -n "${SCRIPT_DST}"
}

@test "INVARIANT (timer unit carries Persistent=true — missed-fires catch up after long downtime)" {
    # Sister to doctor-timer + entropy-baseline + many other
    # selfdef timer-unit Persistent=true INVARIANTs across the
    # brain. Without Persistent=true, systemd does NOT remember
    # timer fires missed during host downtime — a host offline
    # for 24+ hours misses every non-loopback-MTA-bind probe
    # for that window. With Persistent=true, systemd fires
    # immediately on boot if interval has elapsed since last
    # successful fire. Locks missed-fire-catch-up contract on
    # MTA loopback-bind surveillance substrate.
    write_config "report"
    run_wd
    grep -qE '^Persistent=true' "${TIMER_DST}"
}

@test "INVARIANT (single emit_status JSON record per run — operator dashboard single-source-of-truth)" {
    # Sister to brain-wide single-emit_status / single-MAIN-
    # logger INVARIANTs (SDD-062 consumer dispatch contract).
    # One installer run must emit EXACTLY ONE emit_status JSON
    # record on stdout — not zero (silent run = invisible to
    # operator dashboard) and not multiple (duplicate records
    # corrupt the dashboard's apply-count + last-status
    # invariants). Locks single-record discipline on the
    # MTA loopback-bind installer surface.
    write_config "report"
    output="$(run_wd 2>&1)"
    count=$(printf '%s\n' "${output}" | grep -cE '"module":"mta-loopback-detect"')
    [ "${count}" = "1" ]
}

@test "INVARIANT (timer unit carries OnUnitActiveSec — recurrent re-armed cadence beyond OnBootSec one-shot)" {
    # Sister to brain-wide timer OnUnitActiveSec INVARIANTs. The
    # mta-loopback-detect timer MUST fire AT CADENCE not just on-
    # boot — operator can configure a new SMTP listener mid-uptime
    # (apt install postfix), and watchdog must catch it without
    # waiting for reboot.
    write_config "report"
    run_wd
    grep -qE '^OnUnitActiveSec=' "${TIMER_DST}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes (entropy-baseline,
    # secure-boot-status, swap-encryption-detect, doctor-timer,
    # bootloader-password-detect). The mta-loopback-detect probe
    # runs ON the timer's scheduled fire — executes ONCE, reads
    # SMTP listener state, emits a verdict, then exits. Type=
    # simple would leave systemd thinking the probe is a long-
    # running daemon, breaking timer's OnSuccess /
    # OnUnitActiveSec semantics. Locks oneshot-probe contract
    # on the mta-loopback-detect substrate.
    write_config "report"
    run_wd
    [ -f "${SVC_DST}" ]
    grep -qE '^Type=oneshot' "${SVC_DST}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. mta-loopback-detect manifest declares install +
    # profile gating (report / enforce) the resolver enforces;
    # malformed manifest wedges the MTA loopback-binding probe.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'mta-loopback-detect', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-delete: mta-loopback-detect installer NEVER deletes operator-pre-existing configs in target dir — surveillance not destruction)" {
    # Sister to brain-wide no-auto-delete INVARIANT family.
    # mta-loopback-detect writes its own drop-in or config; it MUST NEVER
    # rm/find-delete an operator's pre-existing entries not
    # owned by THIS module. Locks no-auto-delete on the
    # mta-loopback-detect installer substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        ! grep -qE '(^|[^a-z])rm[[:space:]]+-rf?[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana)' "${sh}"
        ! grep -qE 'find[[:space:]]+/etc/(postfix|exim|sendmail|nftables|nscd|pam|prometheus|grafana).*-delete' "${sh}"
    done
}

@test "INVARIANT (install scripts use set -euo pipefail — anti-half-installed-state contract across full lifecycle)" {
    # Sister to brain-wide set -euo pipefail INVARIANT family.
    # mta-loopback-detect install/check/uninstall scripts MUST fail-loud on
    # first error so a partial-install state is detectable.
    # Locks fail-loud invariant on the mta-loopback-detect lifecycle substrate.
    install_dir="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install"
    for sh in "${install_dir}/apply.sh" "${install_dir}/check.sh" "${install_dir}/uninstall.sh"; do
        [ -f "${sh}" ] || continue
        grep -qE '^set[[:space:]]+-euo[[:space:]]+pipefail' "${sh}"
    done
}

@test "INVARIANT (module.toml depends_on field is a TOML list — anti-string-malformation contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The depends_on field MUST be declared
    # as a TOML list. Locks list-vs-string discipline on the
    # depends_on field of the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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
    # the mta-loopback-detect requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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
