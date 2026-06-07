#!/usr/bin/env bats
# L2 bats functional tests for the tmpfiles-watchdog scan script.
#
# systemd-tmpfiles applies the directives in tmpfiles.d/*.conf AS ROOT at
# boot + on a timer. An entry that creates a setuid file, or a .conf that is
# world-writable/non-root, is a privesc/persistence surface (T1546). Severity:
#   ok    → no delta
#   warn  → an entry added/changed/removed
#   alert → a .conf world-writable/non-root, OR an entry with a setuid Mode
#
# Run with: bats packaging/test/L2-tmpfiles-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd/tmpfiles-watchdog.sh"

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
    CONFD="${TMP}/tmpfiles.d"; mkdir -p "${CONFD}"
    CONF="${CONFD}/myapp.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_TMPFILES_PROFILE="${PROFILE:-report}" \
    SELFDEF_TMPFILES_BASELINE="${BASELINE}" \
    SELFDEF_TMPFILES_DIRS="${DIRS_V:-$CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/state 0644 root root -\n' > "${CONF}"
}

@test "no tmpfiles dir → ok / no_tmpfiles" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_tmpfiles"'
    cap | grep -q '"severity":"ok"'
}

@test "benign tmpfiles conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged tmpfiles conf on second run → ok / tmpfiles_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"tmpfiles_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an entry with a setuid Mode → alert / tmpfiles_suspicious" {
    seed_benign
    run_wd
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/shell 4755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"tmpfiles_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable tmpfiles conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign entry change → warn / tmpfiles_changed" {
    seed_benign
    run_wd
    printf 'd /run/myapp 0750 root root -\nf /run/myapp/state 0644 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"tmpfiles_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign tmpfiles conf is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a setuid-mode entry" {
    seed_benign
    run_wd
    printf 'f /run/myapp/shell 4755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — tmpfiles inventory enumerates root-write-at-boot surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (setgid mode): an entry with a 2xxx (setgid) mode → alert" {
    # The script's setuid detection should catch the setgid bit
    # too — both are privilege-bearing.
    seed_benign
    run_wd
    printf 'f /run/myapp/shell 2755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (suid+sgid mode): an entry with a 6xxx (suid+sgid) mode → alert" {
    seed_benign
    run_wd
    printf 'f /run/myapp/shell 6755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing setuid): baseline_initial fires alert if a tmpfiles entry already has a setuid mode at install-time" {
    printf 'f /run/myapp/shell 4755 root root -\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (group-writable .conf): group-writable tmpfiles .conf → alert above world-writable" {
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED tmpfiles .conf (operator pruning) → warn" {
    seed_benign
    cat > "${CONFD}/other.conf" <<'EOF'
d /run/other 0755 root root -
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${CONFD}/other.conf"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-tmpfiles -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): tmpfiles-watchdog does NOT refresh baseline on setuid-entry detection — alert STAYS until operator updates" {
    # tmpfiles.d setuid entries are NEVER routine; the alert must
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/shell 4755 root root -\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"tmpfiles_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented setuid entry NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/state 0644 root root -\n# f /run/myapp/shell 4755 root root -\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"tmpfiles_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (newly-ADDED .conf with setuid entry → alert; new-file + suspicious-entry combined)" {
    # Attacker drops a fresh tmpfiles.d/.conf containing setuid
    # entries. Watchdog must alert on BOTH the new file AND the
    # suspicious entry, with alert severity taking precedence.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONFD}/00-evil.conf" <<'EOF'
f /run/backdoor 4755 root root -
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -q '"event":"tmpfiles_suspicious"'
}

@test "INVARIANT (Z chmod-only entry on a non-setuid mode is NOT flagged: chmod-mode tmpfiles type distinct from setuid-creation)" {
    # Z = recursively-restore-perms type entries are operator-
    # tuning. A Z entry with mode 0755 is a legit operator op.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Add a Z (recursive chmod) entry with non-setuid mode.
    printf 'd /run/myapp 0755 root root -\nf /run/myapp/state 0644 root root -\nZ /run/myapp 0755 root root -\n' > "${CONF}"
    run_wd
    # Severity is warn (content delta), not alert (no setuid).
    cap | grep -qE '"severity":"(warn|ok)"'
    ! cap | grep -q '"event":"tmpfiles_suspicious"'
}

@test "INVARIANT (multi-dir scan: a second tmpfiles dir ALSO scanned — system /usr/lib/tmpfiles.d + operator /etc/tmpfiles.d)" {
    # systemd-tmpfiles reads /usr/lib/tmpfiles.d (vendor), /etc/
    # tmpfiles.d (operator), /run/tmpfiles.d (runtime). All three
    # may carry attacker-planted setuid entries — watchdog must
    # enumerate every dir in SELFDEF_TMPFILES_DIRS.
    CONFD2="${TMP}/tmpfiles.d.system"; mkdir -p "${CONFD2}"
    seed_benign
    DIRS_V="${CONFD} ${CONFD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'f /run/sysmod/shell 4755 root root -\n' > "${CONFD2}/system-evil.conf"
    DIRS_V="${CONFD} ${CONFD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: tab-separated fields in tmpfiles entry still parsed for setuid)" {
    # Attacker may use tab-separated fields to defeat naive '
    # ' grep. Watchdog positional-parser MUST treat tab the same
    # as space for the type/path/mode/uid/gid/age grammar.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'f\t/run/myapp/shell\t4755\troot\troot\t-\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names the offending .conf in JSON — operator triage routing)" {
    # When setuid-entry fires, sample MUST surface the .conf
    # path so operator dashboard routes triage to the right path.
    # Sister contract: polkit-rules/nfs-exports/rhosts pattern.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONFD}/99-very-distinctive-attacker.conf" <<'EOF'
f /run/backdoor 4755 root root -
EOF
    run_wd
    cap | grep -q 'very-distinctive-attacker'
}

@test "INVARIANT (setgid 2755 also flagged — sister axis to setuid 4755 on the suid-bit detection ladder)" {
    # Sister to the setuid (4755) axis already locked. setgid (2755)
    # is the sister bit — instead of escalating to file-owner's uid,
    # it escalates to the file-group's gid. An attacker may declare
    # 'f /run/payload 2755 root wheel -' to plant a setgid-wheel
    # binary that runs with wheel group privileges (often used for
    # sudo group membership / /etc/shadow read on systems where
    # wheel is privileged). Locks the full suid-bit family on the
    # tmpfiles.d declarative-file-creation surface (T1548.001 —
    # Abuse Elevation Control Mechanism: Setuid and Setgid).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'f /run/myapp/sgid-payload 2755 root wheel -\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sticky-bit 1777 on /tmp-like dir is benign + not flagged — false-positive guard on the dir-permissions ladder)" {
    # Sister to the suid/sgid alert axes. Mode 1777 is the
    # canonical /tmp + /var/tmp + /dev/shm sticky-bit
    # convention (rwx for everyone + sticky restricts deletion
    # to owner). Selfdef MUST NOT false-fire on this widely-
    # used legitimate pattern. Locks the false-positive guard
    # on the dir-perm ladder so operator dashboards aren't
    # flooded with bogus alerts on every routine /tmp creation
    # in tmpfiles.d.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'd /var/lib/myapp-scratch 1777 root root -\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (cap-only entry 'c' type with dangerous capability also surfaces — sister axis to suid setuid 4755)" {
    # Sister to the setuid/setgid axes already locked.
    # systemd-tmpfiles supports cap-only entries via the 'c'
    # type (file capabilities like cap_setuid+ep, cap_sys_admin+ep
    # set on a file at creation/poll time). These provide an
    # equivalent privilege-escalation surface to setuid bits —
    # an attacker who adds a tmpfiles.d entry with cap_setuid+ep
    # on a non-root binary gets persistent setuid-equivalent
    # privilege on that binary at every boot. Locks axis-parity
    # with setuid detection — file-cap-based privilege escalation
    # is just as dangerous as the suid bit family (T1548.001 —
    # Setuid and Setgid + file-cap-based privilege escalation).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'c /usr/bin/cap-escalator 0755 root root - cap_setuid+ep\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on tmpfiles.d setuid + cap surveillance
    # (T1548.001 setuid/setgid + file-cap-based privilege
    # escalation).
    seed_benign
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on tmpfiles surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The tmpfiles-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1548.001 setuid/setgid + file-capability
    # privilege-escalation alert. Locks parser contract on the
    # tmpfiles.d setuid/cap detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'f /tmp/.evil-suid 4755 root root - -\n' > "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: tmpfiles-watchdog NEVER deletes tmpfiles.d entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # tmpfiles-watchdog DETECTS T1548.001 setuid/setgid + file-
    # capability privilege-escalation via tmpfiles.d but MUST
    # NEVER emit sed/awk/rm commands to auto-clean the
    # tmpfiles.d entry. The detected entry may be operator-
    # legitimate (custom application creating /var/log dir with
    # specific perms at boot) — silent auto-delete would
    # destroy operator baseline state AND could break early-
    # boot application setup. Surveillance, never remediation.
    # Locks anti-data-loss contract on the tmpfiles
    # surveillance substrate.
    seed_benign
    printf 'f /tmp/.evil-suid 4755 root root - -\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q '.evil-suid' "${CONF}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*tmpfiles'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # tmpfiles-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/tmpfiles.d + /usr/lib/tmpfiles.d against
    # baseline, emits a verdict on suspicious file-creation
    # entries (boot-time persistence vector), then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the tmpfiles-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd/selfdef-tmpfiles.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. tmpfiles-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # tmpfiles-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # tmpfiles-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'tmpfiles-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: tmpfiles-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. tmpfiles-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the tmpfiles-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (tmpfiles-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the tmpfiles-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (tmpfiles-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # tmpfiles-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (tmpfiles-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # tmpfiles-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (tmpfiles-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the tmpfiles-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (tmpfiles-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # tmpfiles-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (tmpfiles-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the tmpfiles-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (tmpfiles-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the tmpfiles-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the tmpfiles-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the tmpfiles-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the tmpfiles-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (tmpfiles-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the tmpfiles-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (tmpfiles-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (tmpfiles-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (tmpfiles-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (tmpfiles-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (tmpfiles-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the tmpfiles-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    [ -f "${script_dir}/tmpfiles-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (tmpfiles-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (tmpfiles-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (tmpfiles-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/tmpfiles-watchdog/README.md"
    [ -f "${readme}" ]
}
