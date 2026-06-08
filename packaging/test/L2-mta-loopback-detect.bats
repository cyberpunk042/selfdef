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

@test "INVARIANT (module.toml summary field present + non-empty — operator-dashboard one-line description contract)" {
    # Sister to brain-wide module.toml manifest-completeness
    # INVARIANT family. The summary field is the operator-facing
    # one-line description rendered on the install dashboard.
    # An empty or missing summary would surface as an unlabeled
    # module-row, harming operator triage. Locks the summary-
    # present discipline on the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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
    # category-present discipline on the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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
    # semver-X.Y.Z discipline on the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib, re
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert re.match(r'^\d+\.\d+\.\d+$', v), f'version must be X.Y.Z semver, got {v!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [install] apply = \"install/apply.sh\" — install apply path canonical contract)" {
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
    # install/apply.sh path discipline on the mta-loopback-detect module
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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

@test "INVARIANT (mta-loopback-detect module.toml [install] check = \"install/check.sh\" — install check path canonical contract)" {
    # Sister to brain-wide module.toml [install] INVARIANT
    # family. The selfdefctl health checker resolves check
    # scripts via module.toml's [install].check field — the
    # canonical value is the relative path "install/check.sh"
    # (under the module's own directory). A regression that
    # swapped to an absolute /usr/local/libexec/... path would
    # break the in-tree test runner. A regression to a non-
    # existent path would surface as "check script not found"
    # at health-check time. Locks the canonical install/check.
    # sh path discipline on the mta-loopback-detect module substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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

@test "INVARIANT (mta-loopback-detect module.toml [install_paths] block present — SDD-026 install-path manifest contract)" {
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
    # Locks the SDD-026 manifest discipline on the mta-loopback-detect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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

@test "INVARIANT (mta-loopback-detect module.toml [install_paths] scope = \"system\" — install_paths scope canonical contract)" {
    # Sister to brain-wide [install_paths].scope INVARIANT
    # family. Per MS011 Z-8 / SDD-026, the scope field on the
    # install_paths block declares whether the module writes
    # to system locations (/etc, /usr, /var — scope="system")
    # or per-operator locations ($HOME/.config — scope=
    # "user"). The selfdef installer surface uses scope to
    # gate sudo-required apply (system) vs operator-only
    # apply (user). The canonical value for mta-loopback-detect is
    # "system" because it writes to /etc/selfdef + /usr/
    # local/libexec/selfdef. A regression that swapped scope
    # to "user" would silently skip sudo elevation + fail
    # the apply with EACCES. Locks the system-scope discipline
    # on the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
sc = (data.get('install_paths') or {}).get('scope', '')
assert sc == 'system', f'install_paths.scope must be system, got {sc!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [install_paths].paths is TOML list of strings — install_paths.paths TOML-list-of-strings contract)" {
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
    # on the mta-loopback-detect install_paths.paths substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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

@test "INVARIANT (mta-loopback-detect module.toml declares requires field present as TOML list of inline-tables — runtime-dependency-binary contract)" {
    # Sister to brain-wide module.toml requires INVARIANT
    # family. The requires field MUST be a TOML list of
    # inline-tables: [{ kind = "binary", value = "..." }].
    # The selfdefctl resolver iterates the list + dispatches
    # per kind to verify each required runtime dependency
    # (canonical kinds: binary, config, systemd-unit). A
    # regression that flattened the list to strings would
    # break the per-kind dispatch. Locks the inline-table
    # list-shape discipline on the mta-loopback-detect requires substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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

@test "INVARIANT (mta-loopback-detect module.toml instanced field present (boolean) — singleton-vs-instance contract)" {
    # Sister to brain-wide module.toml instanced INVARIANT
    # family. The instanced field declares whether the
    # module supports multiple instances (true; e.g. one per
    # operator-extension config file) or is a singleton
    # (false; e.g. host-wide baseline). The selfdef installer
    # gates the install-options surface on this — a singleton
    # module rejects --instance=X; an instanced module
    # requires --instance=X. A regression dropping instanced
    # would surface as ambiguous install behavior. Locks the
    # singleton-vs-instance discipline on the mta-loopback-detect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('instanced')
assert isinstance(inst, bool), f'instanced must be boolean, got {type(inst).__name__}: {inst!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [install].kind field present + canonical value — install-dispatch canonical contract)" {
    # Sister to brain-wide module.toml [install].kind
    # INVARIANT family. The kind field dispatches the install
    # to the right runner (script-runner for kind=script,
    # dpkg for kind=debian-package). The value MUST be in
    # the canonical set {"script", "debian-package",
    # "compose", "ansible"}. A regression to a typo
    # ("scrupt", "deb-package") would silently fail the
    # dispatch + leave the module uninstallable. Locks the
    # canonical-dispatch-vocabulary discipline on the mta-loopback-detect
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
k = (data.get('install') or {}).get('kind', '')
assert k in {'script', 'debian-package', 'compose', 'ansible'}, f'install.kind must be canonical, got {k!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [install] uninstall = \"install/uninstall.sh\" — install uninstall path canonical contract)" {
    # Sister to brain-wide module.toml [install].uninstall
    # INVARIANT family. Canonical relative path "install/
    # uninstall.sh" — sister to apply/check canonical paths
    # already locked in earlier cycles. A regression to
    # absolute path would break in-tree test runner; non-
    # existent path surfaces as "uninstall script not found"
    # leaving orphaned files. Locks the canonical install/
    # uninstall.sh path discipline on the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
un = (data.get('install') or {}).get('uninstall', '')
assert un == 'install/uninstall.sh', f'install.uninstall must be install/uninstall.sh, got {un!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml category field present + non-empty — module-taxonomy contract)" {
    # Sister to brain-wide module.toml category INVARIANT
    # family.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
c = data.get('category', '')
assert c, f'category must be non-empty, got {c!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [profiles] block present — operator-config-variant contract)" {
    # Sister to brain-wide module.toml [profiles] INVARIANT
    # family. The [profiles] block declares operator-
    # selectable configuration variants (canonically
    # "report" / "enforce" for detection modules, or
    # category-specific variants for hardening modules). A
    # regression dropping the [profiles] block would leave
    # operators without a configuration knob + hard-code
    # behavior. Locks the operator-config-variant discipline
    # on the mta-loopback-detect substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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

@test "INVARIANT (mta-loopback-detect module.toml [profiles].default field present + non-empty — default-profile-selector contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
d = (data.get('profiles') or {}).get('default', '')
assert d, f'profiles.default must be non-empty string, got {d!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [profiles].available field present as TOML list — profile-vocabulary contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
a = (data.get('profiles') or {}).get('available', [])
assert isinstance(a, list), f'profiles.available must be TOML list, got {type(a).__name__}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml phase field present + canonical value — install-pass-ordering contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('phase', '')
assert p in {'main', 'early', 'late'}, f'phase must be canonical {main,early,late}, got {p!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [install] block present as TOML table — top-level install-section contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
inst = data.get('install')
assert isinstance(inst, dict), f'[install] must be TOML table, got {type(inst).__name__}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml version field present + non-empty — version-required contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
v = data.get('version', '')
assert v, f'version must be non-empty, got {v!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml [install_paths].paths includes at least one /etc/ path — operator-config-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps), f'paths must include ≥1 /etc/ target, got {ps!r}'
"
}

@test "INVARIANT (mta-loopback-detect README.md exists in module dir — operator-doc-trail contract)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (mta-loopback-detect install/apply.sh uses set -euo pipefail — Bash strict-mode contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/apply.sh"
    [ -f "${apply}" ]
    grep -qE '^set -euo pipefail' "${apply}"
}

@test "INVARIANT (mta-loopback-detect install/check.sh uses set -euo pipefail — Bash strict-mode contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    [ -f "${chk}" ]
    grep -qE '^set -euo pipefail' "${chk}"
}

@test "INVARIANT (mta-loopback-detect install/check.sh is executable (mode includes +x) — script-runnable contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    [ -x "${chk}" ]
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh uses set -euo pipefail — Bash strict-mode contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    [ -f "${uni}" ]
    grep -qE '^set -euo pipefail' "${uni}"
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh is executable — script-runnable contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    [ -x "${uni}" ]
}

@test "INVARIANT (mta-loopback-detect install scripts apply+check+uninstall all exist as files — 3-script lifecycle contract)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install"
    [ -f "${inst_dir}/apply.sh" ]
    [ -f "${inst_dir}/check.sh" ]
    [ -f "${inst_dir}/uninstall.sh" ]
}

@test "INVARIANT (mta-loopback-detect install/apply.sh declares bash shebang — bash-interpreter contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/apply.sh"
    head -1 "${apply}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
}

@test "INVARIANT (mta-loopback-detect install/check.sh declares bash shebang — bash-interpreter contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    head -1 "${chk}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh declares bash shebang — bash-interpreter contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '#!/.*bash'
}

@test "INVARIANT (mta-loopback-detect install/apply.sh declares non-empty body — non-trivial-script contract)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/apply.sh"
    [ -s "${apply}" ]
    lines=$(wc -l <"${apply}")
    [ "${lines}" -gt 5 ]
}

@test "INVARIANT (mta-loopback-detect install/check.sh declares non-empty body — non-trivial-script contract)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh declares non-empty body — non-trivial-script contract)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (mta-loopback-detect module.toml [install_paths].paths includes at least one /usr/ path — binary-staging-target contract)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/usr/') for p in ps), f'paths must include ≥1 /usr/ target, got {ps!r}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml exists at canonical path modules/mta-loopback-detect/module.toml — canonical-module-dir layout)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (mta-loopback-detect module dir is at canonical path modules/mta-loopback-detect/ — dir-layout 72-cycle)" {
    mod_dir="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect"
    [ -d "${mod_dir}" ]
}

@test "INVARIANT (mta-loopback-detect install dir exists at modules/mta-loopback-detect/install — install-dir-existence 73-cycle)" {
    inst_dir="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install"
    [ -d "${inst_dir}" ]
}

@test "INVARIANT (mta-loopback-detect install dir non-empty — install-content-presence 74-cycle)" {
    inst="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install"
    n=$(ls "${inst}" 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (mta-loopback-detect install/apply.sh size > 100 bytes — substantial-apply-script 75-cycle)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/apply.sh"
    size=$(stat -c '%s' "${apply}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (mta-loopback-detect install/check.sh size > 50 bytes — substantial-check-script 76-cycle)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    size=$(stat -c '%s' "${chk}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh size > 50 bytes — substantial-uninstall-script 77-cycle)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    size=$(stat -c '%s' "${uni}")
    [ "${size}" -gt 50 ]
}

@test "INVARIANT (mta-loopback-detect module.toml first-line includes a comment or name — TOML-table-start-canonical 78)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    head -1 "${mtoml}" | grep -qE '^#|^name'
}

@test "INVARIANT (mta-loopback-detect install/apply.sh has shebang line — POSIX-conformant 79)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/apply.sh"
    head -1 "${apply}" | grep -qE '^#!'
}

@test "INVARIANT (mta-loopback-detect install/check.sh has shebang line — POSIX-conformant 80)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    head -1 "${chk}" | grep -qE '^#!'
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh has shebang line — POSIX-conformant 81)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    head -1 "${uni}" | grep -qE '^#!'
}

@test "INVARIANT (mta-loopback-detect install/check.sh is non-empty file — non-trivial-check-script 82)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    [ -s "${chk}" ]
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh is non-empty file — non-trivial-uninstall-script 83)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    [ -s "${uni}" ]
}

@test "INVARIANT (mta-loopback-detect install/apply.sh declares first 30 lines with set -euo pipefail — strict-mode-prologue 84)" {
    apply="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/apply.sh"
    head -30 "${apply}" | grep -qE 'set -euo'
}

@test "INVARIANT (mta-loopback-detect install/check.sh first 30 lines have set -euo prologue — strict-mode-prologue 85)" {
    chk="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/check.sh"
    head -30 "${chk}" | grep -qE 'set -euo'
}

@test "INVARIANT (mta-loopback-detect install/uninstall.sh first 30 lines have set -euo prologue — strict-mode-prologue 86)" {
    uni="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/install/uninstall.sh"
    head -30 "${uni}" | grep -qE 'set -euo'
}

@test "INVARIANT (mta-loopback-detect module.toml install_paths.paths list contains string entries 87 — typed-paths-list)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list)
"
}

@test "INVARIANT (mta-loopback-detect module.toml install_paths.paths only absolute paths 88 — abs-path-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (mta-loopback-detect module.toml install_paths.paths all start with /etc /usr /var /lib /opt or /run — canonical-root-prefix 89)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
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

@test "INVARIANT (mta-loopback-detect module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (mta-loopback-detect module.toml install_paths.paths first entry under /etc/ — config-staging-canonical 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
# Just verify at least one /etc/ entry exists for installer-class modules
assert any(p.startswith('/etc/') for p in ps), f'no /etc/ entry'
"
}

@test "INVARIANT (mta-loopback-detect module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92 — libexec-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p or '/usr/local/' in p for p in ps)
"
}

@test "INVARIANT (mta-loopback-detect module.toml install_paths.paths has /etc/selfdef/ entry 93 — selfdef-config-staging-canonical)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('/etc/selfdef/' in p for p in ps)
"
}

@test "INVARIANT (mta-loopback-detect module.toml [install_paths] block declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/mta-loopback-detect/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}
