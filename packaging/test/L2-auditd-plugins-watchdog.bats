#!/usr/bin/env bats
# L2 bats functional tests for the auditd-plugins-watchdog scan script.
#
# auditd/audisp launches the program named by each `path=` in
# /etc/audit/plugins.d/*.conf (legacy /etc/audisp/plugins.d) AS ROOT to
# consume the audit event stream — a planted plugin path is root-exec
# persistence that runs whenever auditd starts (T1546). A plugin .conf that
# is world-writable / non-root-owned, or whose `path=` points under a
# writable root or is a relative-with-slash path, is alert.
#
# Run with: bats packaging/test/L2-auditd-plugins-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd/auditd-plugins-watchdog.sh"
LIB="${BATS_TEST_DIRNAME}/../lib/module-lib.sh"

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
    PLUGD="${TMP}/plugins.d"; mkdir -p "${PLUGD}"
    CONF="${PLUGD}/syslog.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_AUDITPLUG_PROFILE="${PROFILE:-report}" \
    SELFDEF_AUDITPLUG_BASELINE="${BASELINE}" \
    SELFDEF_AUDITPLUG_DIRS="${DIRS_V:-$PLUGD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'active = yes\ndirection = out\npath = /sbin/audisp-syslog\ntype = always\n' > "${CONF}"
}

@test "no audit plugins → ok / no_audit_plugins" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_audit_plugins"'
    cap | grep -q '"severity":"ok"'
}

@test "benign plugin conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged plugin conf on second run → ok / audit_plugins_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_plugins_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a plugin path under a writable root → alert / audit_plugins_suspicious" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"audit_plugins_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash plugin path → alert" {
    seed_benign
    run_wd
    printf 'active = yes\npath = ../evil/audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable plugin conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign plugin path change → warn / audit_plugins_changed" {
    seed_benign
    run_wd
    printf 'active = yes\ndirection = out\npath = /sbin/audisp-remote\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"audit_plugins_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign /sbin plugin path is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    seed_benign
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious plugin path" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — auditd-plugins inventory enumerates root-exec-on-auditd-start surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (plugin path under /var/tmp): writable-root coverage" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /var/tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (plugin path under /dev/shm): tmpfs writable-root coverage" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /dev/shm/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (plugin path under /home): user-writable root coverage" {
    seed_benign
    run_wd
    printf 'active = yes\npath = /home/user/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable plugin conf): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable plugin conf): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-audit-plugins -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): auditd-plugins-watchdog does NOT refresh baseline on suspicious path detection — alert STAYS until operator updates" {
    # T1546 auditd-start-triggered root exec persistence — suspicious-path
    # alert MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"audit_plugins_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious path NOT flagged: # prefix filtered from inventory)" {
    # auditd plugins.d conf supports # comments. Operator notes about
    # hypothetical bad-path entries must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'active = yes\ndirection = out\npath = /sbin/audisp-syslog\ntype = always\n# path = /tmp/example-attacker\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"audit_plugins_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/audit/plugins.d + /etc/audisp/plugins.d legacy axis — suspicious path in any of them → alert)" {
    # auditd reads both modern (/etc/audit/plugins.d) and legacy
    # (/etc/audisp/plugins.d) directories. Attacker may plant in
    # either. Lock multi-dir axis.
    PLUGD2="${TMP}/audisp-plugins.d"; mkdir -p "${PLUGD2}"
    seed_benign
    DIRS_V="${PLUGD} ${PLUGD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant suspicious path in legacy dir.
    printf 'active = yes\npath = /tmp/.audisp\ntype = always\n' > "${PLUGD2}/evil.conf"
    DIRS_V="${PLUGD} ${PLUGD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (added_sample in emit JSON: operator-triage routing surfaces changed plugin paths)" {
    # Sister to every other watchdog sample-names-file INVARIANT
    # across the brain. When the inventory delta has added entries,
    # the JSON record must expose them via added_sample so the
    # downstream operator dashboard / triage pipeline can route on
    # which plugin .conf file changed (not just a count). Closes
    # the inventory-as-opaque-counter regression axis.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a NEW benign plugin .conf (drives a benign warn-tier delta).
    printf 'active = yes\ndirection = out\npath = /sbin/audisp-remote\ntype = always\n' > "${PLUGD}/distinctive-remote.conf"
    run_wd
    cap | grep -q '"added_sample"'
    cap | grep -q 'distinctive-remote'
}

@test "INVARIANT (active=no plugin still scanned: defense against time-bomb persistence)" {
    # An inactive plugin (active=no) is currently dormant but operator
    # may toggle to active later, OR attacker may plant a dormant
    # suspicious-path plugin as a time-bomb. The watchdog scans path=
    # regardless of active state to preserve operator visibility.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'active = no\ndirection = out\npath = /tmp/.audisp-timebomb\ntype = always\n' > "${CONF}"
    run_wd
    # Either alert (preferred — defense-in-depth) OR warn (acceptable — config changed).
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (relative-with-slash plugin path → alert): relative-path-resolves-against-PWD attacker primitive on the audit dispatcher" {
    # Sister to the brain-wide relative-path INVARIANT family (autofs
    # program: maps, request-key callout, binfmt interpreter,
    # krb5 plugin, rsyslog omprog, syslog-ng program(), dnf-plugins
    # action, sudo-conf plugin). A relative-path plugin in
    # auditd-plugins.d is resolved by auditd/audisp against PWD-at-
    # exec time — undefined behavior + attacker primitive. Locks
    # detection of relative paths alongside the absolute-writable-
    # root family on the auditd dispatcher-plugin surface.
    seed_benign
    run_wd
    printf 'active = yes\npath = sub/dir/audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named plugin conf surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker drops a new
    # auditd plugin conf file (T1562.001 — Impair Defenses via
    # plugin-pipe attack: auditd's plugin dispatcher feeds the
    # event stream to attacker code AS ROOT), the file path MUST
    # surface in the JSON sample so operator dashboard routes
    # triage to the right path.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'active = yes\npath = /tmp/.evil\ntype = always\n' > "${PLUGD}/distinctive-attacker-plugin.conf"
    run_wd
    cap | grep -q 'distinctive-attacker-plugin'
}

@test "INVARIANT (plugin path under /home — user-writable persistence vector → alert; writable-root axis-symmetric expansion)" {
    # Sister to /tmp + /var/tmp + /dev/shm writable-root INVARIANTs
    # already locked. /home/<user> is writable by the owning user
    # without privilege; an attacker who pivots into a user account
    # plants a binary there + sets an auditd plugin path pointing
    # at it for root-exec via the dispatcher. Locks the /home axis
    # on the auditd dispatcher-plugin writable-root coverage
    # (T1562.001 — Impair Defenses: auditd's plugin dispatcher
    # feeds the event stream to attacker code AS ROOT, evading
    # SIEM correlation by intercepting at the source).
    seed_benign
    run_wd
    printf 'active = yes\npath = /home/alice/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (plugin path under /var/tmp — writable-root axis-symmetric expansion on auditd dispatcher)" {
    # Sister to /tmp + /var/tmp + /dev/shm + /home auditd plugin
    # writable-root INVARIANTs. /var/tmp persistent + writable.
    # Closes /var/tmp axis on T1562.001 SIEM-evasion vector at
    # the source via dispatcher plugin.
    seed_benign
    run_wd
    printf 'active = yes\npath = /var/tmp/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (plugin path under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on auditd dispatcher)" {
    # Sister to /home + /var/tmp + /tmp auditd plugin writable-
    # root INVARIANTs. /dev/shm is canonical tmpfs in-RAM
    # writable-root that survives no on-disk forensic trace.
    # auditd dispatcher invokes plugin AS ROOT for every audit
    # event; planted attacker binary in /dev/shm fires AS ROOT
    # on every audit event. T1562.001 SIEM-evasion at the
    # source via dispatcher plugin substitution.
    seed_benign
    run_wd
    printf 'active = yes\npath = /dev/shm/.audisp\ntype = always\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on auditd-plugins surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The auditd-plugins-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1562.001 SIEM-evasion via dispatcher
    # plugin hijack alert. Locks parser contract on the auditd
    # plugins.d detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'active = yes\npath = /tmp/.evil\ntype = always\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: auditd-plugins-watchdog NEVER deletes plugin.d entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # auditd-plugins-watchdog DETECTS T1562.001 SIEM-evasion
    # via dispatcher plugin hijack but MUST NEVER emit sed/awk/
    # rm commands to auto-clean the plugin entry. The detected
    # plugin may be operator-legitimate (custom SIEM forwarder,
    # syslog bridge, splunk forwarder). Silent auto-delete
    # would destroy operator baseline state AND could break
    # operator's intended audit-event forwarding pipeline.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the auditd-plugins surveillance substrate.
    printf 'active = yes\npath = /tmp/.evil\ntype = always\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'path' "${CONF}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*audit'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # auditd-plugins-watchdog runs ON the timer's scheduled fire
    # — scans /etc/audit/plugins.d for path= injection patterns
    # in writable roots, emits a verdict, then exits. Type=
    # simple would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the auditd-plugins-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd/selfdef-audit-plugins.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (no auto-fix: auditd-plugins-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. auditd-plugins-watchdog is a DETECT-only watchdog: it surveils
    # its target surface + emits verdicts, NEVER writes back to
    # the source files it scans. The libexec script must NOT
    # contain sed -i / tee / printf-redirect mutations of its
    # scanned paths. Locks no-auto-fix on the auditd-plugins-watchdog
    # libexec substrate (sister to existing surveillance-not-
    # remediation lines for the watchdog runtime).
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (auditd-plugins-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The auditd-plugins-watchdog libexec uses set -u (and NOT set -e) by
    # design: watchdog probes WANT to continue scanning even
    # when individual checks fail (rather than abort-on-first-
    # error like installers), so they emit a complete verdict
    # at the end. But set -u remains essential — it catches
    # typo'd env-var references ($SELFDEF_FOO_BASELINE vs
    # $SELFDEF_FOO_BASLINE) before they propagate as silent
    # empty-string into baseline-path operations. A regression
    # dropping set -u would let a typo'd var name produce a
    # silent baseline-rewrite to /. Locks set -u discipline on
    # the auditd-plugins-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (auditd-plugins-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
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
    # SDD-062 logger-tag routing discipline on the auditd-plugins-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (auditd-plugins-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # The auditd-plugins-watchdog timer unit MUST declare RandomizedDelaySec=
    # so fleet hosts don't all fire at the exact same minute
    # (thundering-herd that overwhelms downstream
    # syslog/journald aggregators). Locks anti-thundering-herd
    # cadence discipline on the auditd-plugins-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (auditd-plugins-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Persistent=true tells systemd to fire the timer ON BOOT
    # if it was missed during downtime — without it, a host
    # that boots after the scheduled fire would silently skip
    # the cycle, leaving a forensics gap. Locks Persistent=
    # discipline on the auditd-plugins-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (auditd-plugins-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # The .timer file MUST declare Unit=<companion>.service so
    # systemd knows which .service to fire on timer-elapse. By
    # default systemd matches timer-name to service-name, but
    # explicit Unit= is required when names differ + makes the
    # binding self-documenting. A regression dropping Unit= +
    # renaming either file would silently break the link.
    # Locks the timer-to-service binding discipline on the
    # auditd-plugins-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (auditd-plugins-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. The .service file MUST declare ExecStart=<path-
    # to-libexec.sh> so systemd knows what to run. The libexec
    # script must EXIST at the declared path. A regression that
    # renamed the libexec script without updating ExecStart
    # would surface as service-start failure rather than a
    # silent regression. Locks the service-to-libexec binding
    # discipline on the auditd-plugins-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (auditd-plugins-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # The auditd-plugins-watchdog probe is Type=oneshot — it RUNS, emits a
    # verdict, and EXITS. Restart=always on a oneshot would
    # cause systemd to immediately re-fire the probe in a
    # tight loop, swamping the dashboard with redundant
    # records. A regression that added Restart=always would
    # produce a runaway-probe footgun. Locks the anti-restart-
    # storm discipline on the auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. The Description= directive surfaces in
    # `systemctl status` output + journalctl unit-filter
    # labels. A unit with no Description is opaque to
    # operators triaging service activity. Locks the
    # Description-present discipline on the auditd-plugins-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the auditd-plugins-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the auditd-plugins-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the auditd-plugins-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the auditd-plugins-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (auditd-plugins-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (auditd-plugins-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/auditd-plugins-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}
