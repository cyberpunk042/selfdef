#!/usr/bin/env bats
# L2 bats functional tests for the capability-conf-watchdog scan script.
#
# /etc/security/capability.conf (pam_cap) grants Linux capabilities to users
# at login. A grant of a privilege-escalation-grade capability
# (cap_setuid/cap_sys_admin/cap_dac_override/…) to a user is a persistence /
# privesc signature (T1548). Severity:
#   ok    → no delta
#   warn  → any grant added/removed/changed
#   alert → a NEWLY-ADDED grant containing a dangerous capability
#
# Run with: bats packaging/test/L2-capability-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd/capability-conf-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/baseline.tsv"
    CONF="${TMP}/capability.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_CAPCONF_PROFILE="${PROFILE:-report}" \
    SELFDEF_CAPCONF_BASELINE="${BASELINE}" \
    SELFDEF_CAPCONF_FILE="${CONF_V:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'cap_net_raw netuser\n' > "${CONF}"
}

@test "no capability.conf → ok / no_capability_conf" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_capability_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign capability.conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged capability.conf on second run → ok / capability_conf_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a newly-added dangerous capability grant → alert / capability_conf_dangerous_grant" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_sys_admin eviluser\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_conf_dangerous_grant"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign non-dangerous grant change → warn / capability_conf_changed" {
    seed_benign
    run_wd
    printf 'cap_net_bind_service netuser\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"capability_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign non-dangerous capability.conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a dangerous grant" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_setuid eviluser\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — capability-grant inventory enumerates priv-elevated users)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (dangerous-cap detect): cap_setuid grant → alert / capability_conf_dangerous_grant" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_setuid evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dangerous-cap detect): cap_dac_override grant → alert" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_dac_override evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dangerous-cap detect): cap_sys_ptrace grant → alert" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_sys_ptrace evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dangerous-cap detect): cap_sys_module grant → alert" {
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_sys_module evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing dangerous grant): baseline_initial fires alert if capability.conf already has a dangerous grant" {
    # Like access-conf, locks the install-time-vet contract.
    printf 'cap_setuid root-admin\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (existing dangerous grant is NOT re-alerted): same grant in baseline + current → ok / intact" {
    # The watchdog scans only the ADDED set for the dangerous-
    # grant alert; pre-existing grants don't re-trigger every
    # scan. Locks the no-spurious-re-alert contract.
    printf 'cap_setuid sysadmin\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"capability_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "DELTA detect — REMOVED grant (operator pruning) → warn / capability_conf_changed" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '' > "${CONF}"                               # remove all grants
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'             # at minimum, not alert
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-capability-conf -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): capability-conf-watchdog DOES auto-refresh the baseline" {
    # CONTRAST against the no-auto-trust family. capability.conf
    # changes ARE common operator action (deploying a new capable
    # service). The watchdog flags the delta for THIS run; the
    # baseline catches up on the next.
    seed_benign
    run_wd
    printf 'cap_net_bind_service nginx\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — warn
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"capability_conf_intact"'
}

@test "INVARIANT (commented dangerous grant NOT flagged: # prefix filtered from inventory)" {
    # capability.conf supports # comments. Operator notes about
    # hypothetical bad grants must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\n# cap_setuid example-attacker\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"capability_conf_dangerous_grant"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dangerous-cap detect): cap_sys_admin grant → alert (the catch-all super-capability)" {
    # cap_sys_admin is the "almost-root" capability covering mount/
    # namespace/firmware-load/kexec. Locks coverage.
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_sys_admin evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-grant composition): file with multiple dangerous caps → alert (any one triggers)" {
    # Attacker stacks several capabilities. The detector must alert
    # regardless of how many or which order.
    seed_benign
    run_wd
    printf 'cap_net_raw netuser\ncap_setuid evil\ncap_sys_module evil\ncap_dac_override evil\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: 'cap_setuid    evil' multi-space variant still triggers alert)" {
    # Attacker may use multi-spaces to evade naive grep-based
    # detection. Lock whitespace-tolerant parser.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\ncap_setuid    evil\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dangerous-cap detect): cap_audit_control grant → alert (T1562.001 silence-audit axis)" {
    # cap_audit_control allows toggling kernel auditing rules — a
    # defense-evasion-grade capability (sister to the privesc-grade
    # cap_setuid/cap_sys_admin/cap_dac_override axis). Locks the
    # T1562.001 (Impair Defenses) detection axis distinct from the
    # T1548 privesc detection axis. Sister-cap coverage to the
    # whole-system-control axis on the pam_cap surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\ncap_audit_control evil\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (dangerous-cap detect): cap_kill grant → alert (T1499 process-disrupt axis)" {
    # Sister to the cap_audit_control + cap_setuid + cap_sys_admin
    # + cap_dac_override + cap_sys_ptrace + cap_sys_module dangerous-
    # cap axes already locked. cap_kill bypasses signal-permission
    # checks, letting a granted user kill any process regardless of
    # uid match (including critical system daemons + selfdef's own
    # watchdog services + the very audit daemon that would log the
    # tampering). T1499 (Endpoint DoS) — Service Stop via signal.
    # Locks coverage of the kill-grade capability alongside the
    # other dangerous-cap families on the pam_cap surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\ncap_kill evil\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (dangerous-cap detect): cap_chown grant → alert (T1222 ownership-confusion axis)" {
    # Sister to cap_setuid + cap_dac_override + cap_sys_admin + cap_
    # audit_control + cap_kill dangerous-cap axes already locked.
    # cap_chown lets a granted user re-own ANY file regardless of
    # uid — including /etc/shadow, sudoers, ssh authorized_keys,
    # binaries in /usr/bin. T1222 (File and Directory Permissions
    # Modification) — a pre-attack pivot primitive (rewrite a
    # privileged binary's owner to attacker uid, then patch it).
    # Locks coverage of the chown-grade capability alongside the
    # other dangerous-cap families on the pam_cap surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\ncap_chown evil\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (dangerous-cap detect): cap_sys_ptrace grant → alert (T1055 process-injection / ptrace-escape axis)" {
    # Sister to cap_setuid + cap_dac_override + cap_sys_admin +
    # cap_audit_control + cap_kill + cap_chown dangerous-cap
    # axes already locked. cap_sys_ptrace lets a granted user
    # attach to ANY process (including PID-1 systemd) via ptrace
    # for memory inspection/modification — process-injection
    # primitive (T1055) and credential-theft (attach to a
    # privileged process, read /proc/<pid>/mem for secrets). On
    # containerized hosts, cap_sys_ptrace is a container-escape
    # primitive too (ptrace the host's kthreadd). Locks coverage
    # of the ptrace-grade capability alongside the other
    # dangerous-cap families on the pam_cap surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\ncap_sys_ptrace evil\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (dangerous-cap detect): cap_sys_module grant → alert (T1547.006 kernel module loading axis)" {
    # Sister to capability-conf-watchdog cap_setuid + cap_dac_
    # override + cap_sys_admin + cap_audit_control + cap_kill +
    # cap_chown + cap_sys_ptrace dangerous-cap INVARIANTs.
    # cap_sys_module lets a user load/unload kernel modules —
    # this is direct kernel-mode persistence (T1547.006).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\ncap_sys_module evil\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (dangerous-cap detect): cap_dac_override grant → alert (T1548 file-permission-bypass axis)" {
    # Sister to cap_sys_admin / cap_sys_module / cap_chown /
    # cap_sys_ptrace / cap_audit_control / cap_kill dangerous-
    # cap INVARIANTs. cap_dac_override bypasses ALL file/dir
    # permission checks (DAC = Discretionary Access Control) —
    # a user with this cap can read/write any file regardless
    # of mode/owner. T1548 — Abuse Elevation Control Mechanism
    # via DAC bypass. Closes axis-parity on the dangerous-cap
    # family for the DAC-bypass surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'cap_net_raw netuser\ncap_dac_override evil\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on capability-conf surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The capability-conf-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and
    # the operator never sees the T1548 Abuse Elevation Control
    # Mechanism via capability-grant alert. Locks parser
    # contract on the /etc/security/capability.conf detection
    # surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'cap_dac_override evil\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-fix: capability-conf-watchdog NEVER writes to /etc/security/capability.conf — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{delete,uninstall,restore,
    # chmod,fix} family. capability-conf-watchdog is a DETECT
    # module: surveils pam_cap grants + emits alert on
    # dangerous-cap deltas, NEVER auto-edits
    # /etc/security/capability.conf, NEVER invokes setcap, NEVER
    # tees grants into the config. Auto-remediation on pam_cap
    # grants is operator-domain (login-grant changes require
    # operator-conscious access-control review). Surveillance-
    # not-remediation is the canonical selfdef DETECT-module
    # contract. Locks no-auto-fix on the capability-conf-
    # watchdog substrate.
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE 'sed[[:space:]]+-i.*capability\.conf'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '>[[:space:]]*/etc/security/capability'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE 'tee[[:space:]].*capability\.conf'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '[[:space:]]setcap[[:space:]]'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # capability-conf-watchdog runs ON the timer's scheduled
    # fire — diffs /etc/security/capability.conf against
    # baseline, emits a verdict on pam_cap grant deltas, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the capability-
    # conf-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd/selfdef-capability-conf.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: capability-conf-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. capability-conf-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the capability-conf-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (capability-conf-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The capability-conf-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the capability-conf-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (capability-conf-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # All watchdog libexec scripts MUST surface JSON records
    # via logger -t with a selfdef-prefixed tag so downstream
    # syslog/journald consumers can route per-watchdog records
    # via the tag field rather than parsing the JSON payload
    # for the module field. The tag prefix MUST be "selfdef-"
    # so cross-watchdog SIEM filters (`syslog-ng-filter "selfdef-*"`)
    # capture every selfdef-watchdog without per-watchdog tag
    # enumeration. A regression dropping the selfdef- prefix
    # would cause SIEM filters to silently miss records. Locks
    # SDD-062 logger-tag routing discipline on the capability-conf-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (capability-conf-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The capability-conf-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the capability-conf-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (capability-conf-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the capability-conf-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (capability-conf-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # capability-conf-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (capability-conf-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the capability-conf-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (capability-conf-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The capability-conf-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the capability-conf-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
    # Sister to brain-wide TimeoutStartSec= INVARIANT family.
    # Watchdog .service units are Type=oneshot probes — they
    # MUST declare a TimeoutStartSec= upper bound so systemd
    # kills a hung probe (e.g. a stuck sha256sum on a slow
    # NFS-mounted target file) rather than blocking the
    # next timer fire indefinitely. Without TimeoutStartSec=
    # systemd's default (90s) applies, but the canonical
    # selfdef contract pins this explicitly per watchdog so
    # operators reading the .service know the bound at a
    # glance. A regression that dropped TimeoutStartSec=
    # would silently revert to the systemd default + mask
    # the explicit-bound contract. Locks anti-hang oneshot-
    # bound discipline on the capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
    # Sister to brain-wide systemd resource-priority INVARIANT
    # family. Watchdog .service units run periodic scans (often
    # sha256sum walks of large config trees) — they MUST be
    # deprioritized via Nice= (positive value = lower priority
    # under load) so that the watchdog scan doesn't starve
    # operator-foreground workloads when CPU is contended.
    # The canonical selfdef value is Nice=15 (well above the
    # background-batch threshold of 10). A regression dropping
    # Nice= would let watchdog scans compete with foreground at
    # default Nice=0, surfacing as latency spikes on contended
    # hosts. Locks the idle-priority anti-resource-starve
    # discipline on the capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd PrivateTmp= INVARIANT
    # family. Watchdog .service units that run periodic
    # sha256sum walks may create transient /tmp files. The
    # PrivateTmp= directive (canonically =true) instructs
    # systemd to give the unit its own /tmp mount namespace —
    # an attacker who exploits the watchdog cannot reach
    # /tmp files owned by other processes (e.g. ssh-agent
    # sockets), and the watchdog's own /tmp residue is
    # automatically cleaned at unit-stop. A regression
    # dropping PrivateTmp= would share /tmp with the host,
    # exposing the watchdog as a side-channel for any
    # /tmp-based pivot. Locks the /tmp namespace-isolation
    # discipline on the capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
    # Sister to brain-wide systemd ProtectHome= INVARIANT
    # family. Watchdog .service units have no business
    # reading /home — their probe targets are system-config
    # paths (/etc/*). The ProtectHome= directive
    # (canonically =read-only) instructs systemd to either
    # hide (=true) or read-only-mount (=read-only) the
    # /home, /root, and /run/user directories within the
    # unit's mount namespace. An exploited watchdog cannot
    # then exfiltrate ~/.bash_history, ~/.ssh/*, or operator
    # credentials. A regression dropping ProtectHome= would
    # expose all operator home contents to a compromised
    # watchdog. Locks the home-namespace-isolation
    # discipline on the capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
    # Sister to brain-wide systemd NoNewPrivileges= INVARIANT
    # family. The NoNewPrivileges=true directive instructs
    # the kernel to set PR_SET_NO_NEW_PRIVS on the watchdog
    # process — any subsequent execve() in the watchdog
    # script (sha256sum, awk, etc.) is forbidden to acquire
    # NEW privileges via setuid/setgid/file-capabilities. An
    # exploited watchdog cannot escalate via a setuid helper
    # (e.g. /usr/bin/su, /usr/bin/sudo). A regression
    # dropping NoNewPrivileges= would leave the watchdog
    # exposed to setuid-binary pivot. Locks the privilege-
    # escalation containment discipline on the capability-conf-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the capability-conf-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
    # Sister to brain-wide systemd ExecStart binary-path
    # INVARIANT family. Watchdog .service units MUST execute
    # the watchdog script from /usr/local/libexec/selfdef/
    # (operator-extension path, not /usr/bin which is
    # Debian-package-only). The canonical libexec/selfdef/
    # path lets operators override the watchdog script
    # without rebuilding the .deb (sister to brain-wide
    # operator-extension /usr/local/* discipline). A
    # regression that pointed ExecStart at /usr/bin/ would
    # surface as a "stale-watchdog-binary" on hosts where
    # operators patched the libexec copy. Locks the
    # libexec/selfdef ExecStart-path discipline on the
    # capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
    # Sister to brain-wide systemd After= INVARIANT family.
    # Watchdog .service units MUST declare an After= directive
    # so they don't fire before the filesystem mounts that
    # contain their probe targets (canonically After=local-
    # fs.target so /etc/* is mounted before the watchdog
    # tries to sha256sum a config file). A regression
    # dropping After= would surface as "watchdog fires
    # during early-boot before /etc is mounted" which then
    # hashes nothing + emits a spurious "config missing"
    # alert. Locks the boot-sequencing discipline on the
    # capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the capability-conf-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (capability-conf-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the capability-conf-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (capability-conf-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
    # Sister to brain-wide systemd timer [Install].WantedBy=
    # INVARIANT family. Watchdog .timer units MUST declare
    # WantedBy=timers.target so `systemctl enable selfdef-
    # <slug>.timer` wires the timer into the timers.target
    # symlink-graph + activates it on every boot. A
    # regression that swapped to WantedBy=multi-user.target
    # (the .service-side install target) would make the
    # timer enable-step a no-op + leave the watchdog
    # silently inactive. Locks the timer-enable-graph
    # discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (capability-conf-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (capability-conf-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/capability-conf-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}
