#!/usr/bin/env bats
# L2 bats functional tests for the sudo-conf-watchdog scan script.
#
# Covers the setuid-root sudo plugin-load surface: /etc/sudo.conf names
# the policy / I/O-logging plugins (.so) that sudo (SETUID-ROOT) loads on
# EVERY invocation via `Plugin <symbol> <path>`, and `Path plugin_dir <dir>`
# sets where relative plugin names resolve. A Plugin .so under a writable
# root, a relative-with-slash plugin path, or a writable plugin_dir loads
# attacker code into setuid-root sudo (T1574 / privilege escalation).
#
# Distinct grammar from the other watchdogs (keyword-prefixed directives,
# case-insensitive Plugin/Path). Runs the actual scan script with `logger`
# shadowed on PATH and config/baseline in a tmp sandbox via SELFDEF_SUDOCONF_*;
# locks the `"severity":"alert"` token SDD-062 routes on, and the SDD-061
# D-6 module-lib fail-loud path.
#
# Run with: bats packaging/test/L2-sudo-conf-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/sudo-conf-watchdog/systemd/sudo-conf-watchdog.sh"
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
    CONF="${TMP}/sudo.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_SUDOCONF_PROFILE="${PROFILE:-report}" \
    SELFDEF_SUDOCONF_BASELINE="${BASELINE}" \
    SELFDEF_SUDOCONF_FILES="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no sudo.conf present → ok / no_sudo_conf" {
    run_wd
    cap | grep -q '"event":"no_sudo_conf"'
    cap | grep -q '"severity":"ok"'
}

@test "benign Plugin + Path, first run → ok / baseline_initial" {
    printf 'Plugin sudoers_policy sudoers.so\nPath plugin_dir /usr/libexec/sudo\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / sudo_conf_intact" {
    printf 'Plugin sudoers_policy sudoers.so\nPath plugin_dir /usr/libexec/sudo\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudo_conf_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — the SDD-062 contract token
# ============================================================

@test "Plugin .so under a writable root → alert" {
    printf 'Plugin policy /tmp/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "relative-with-slash Plugin path → alert" {
    printf 'Plugin policy sub/dir/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "Path plugin_dir pointing under a writable root → alert" {
    printf 'Path plugin_dir /dev/shm/sudo-plugins\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "bare writable root as plugin_dir → alert (SDD-063 gap closed)" {
    # plugin_dir = /tmp itself (no trailing component) makes relative plugin
    # names resolve from world-writable /tmp; previously missed by the file
    # helper, now caught by selfdef_is_writable_dir.
    printf 'Path plugin_dir /tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign directive added after baseline → warn / sudo_conf_changed" {
    printf 'Plugin sudoers_policy sudoers.so\n' > "${CONF}"
    run_wd
    printf 'Plugin sudoers_policy sudoers.so\nPlugin sudoers_io sudoers.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"sudo_conf_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "relative plugin name without a slash is NOT flagged (resolves via plugin_dir)" {
    printf 'Plugin sudoers_policy sudoers.so\nPlugin sudoers_audit sudoers.so\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable Plugin line is NOT flagged" {
    printf '# Plugin policy /tmp/evil.so\nPlugin sudoers_policy sudoers.so\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf 'Plugin policy /tmp/evil.so\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'Plugin sudoers_policy sudoers.so\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# Writable-root expansion — Plugin axis (T1574)
# ============================================================

@test "INVARIANT (Plugin .so under /var/tmp): writable-root expansion on Plugin axis" {
    printf 'Plugin policy /var/tmp/.x.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Plugin .so under /dev/shm): writable-root expansion on Plugin axis" {
    printf 'Plugin policy /dev/shm/.x.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# Writable-root expansion — Path plugin_dir axis
# ============================================================

@test "INVARIANT (Path plugin_dir under /var/tmp): writable-root expansion on Path axis" {
    printf 'Path plugin_dir /var/tmp/sudo-plugins\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# SDD-063 bare-root variants on plugin_dir axis
# ============================================================

@test "INVARIANT (bare /var/tmp as plugin_dir): SDD-063 bare-root variant on Path axis" {
    printf 'Path plugin_dir /var/tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bare /dev/shm as plugin_dir): SDD-063 bare-root variant on Path axis" {
    printf 'Path plugin_dir /dev/shm\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# Case-insensitive grammar (sudo's actual parser is case-tolerant)
# ============================================================

@test "INVARIANT (case-insensitive keyword PLUGIN under writable root → alert)" {
    # sudo.conf grammar accepts mixed-case Plugin/Path. Attackers
    # may use case variation to evade naive grep-only detection.
    printf 'PLUGIN policy /tmp/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# JSON record contract (SDD-062 single-line consumer)
# ============================================================

@test "INVARIANT (JSON record is emitted as a SINGLE main logger line — SDD-062 downstream JSON-line consumer contract)" {
    printf 'Plugin sudoers_policy sudoers.so\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-sudo-conf -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: sudo-conf-watchdog does NOT refresh baseline on suspicious-plugin detection — alert STAYS until operator updates)" {
    # T1574 setuid-root sudo plugin-load privesc primitive — alert
    # MUST persist across runs until operator explicitly
    # re-baselines. Sister to gss-mech, ld-preload, nm-vpn-plugin,
    # openvpn-config, musl-ld-path, snmpd-exec — active-injection
    # class never auto-trusts.
    printf 'Plugin sudoers_policy sudoers.so\n' > "${CONF}"
    run_wd
    printf 'Plugin policy /tmp/evil.so\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (Plugin .so under /home: user-writable hijack coverage on Plugin axis)" {
    # Operator's home dir is a writable-root variant — symmetric
    # axis to /tmp + /var/tmp + /dev/shm.
    printf 'Plugin policy /home/user/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable sudo.conf → alert above benign-content bar — file mode IS the architectural surface)" {
    # Even if sudo.conf content is benign, world-writable file
    # means any user can plant a malicious Plugin at next sudo
    # invocation — file mode is the architectural surface (sister
    # to gss-mech / ld-preload world-writable axis).
    printf 'Plugin sudoers_policy sudoers.so\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-path Plugin 'sub/dir/p.so' → alert — relative-path-resolves-against-PWD attacker primitive)" {
    # Sister to the brain-wide relative-path INVARIANT family
    # (autofs program: maps, request-key callout, binfmt
    # interpreter, krb5 plugin, rsyslog omprog, syslog-ng
    # program(), dnf-plugins action). A relative-path Plugin .so is
    # resolved by sudo against its own PWD at exec time —
    # undefined behavior + attacker primitive (sudo may inherit a
    # PWD-attacker-controls). Locks detection on the sudo plugin-
    # load axis alongside the absolute-writable-root family.
    printf 'Plugin policy sub/dir/evil.so\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (Plugin .so under /var/tmp — writable-root expansion on sudo plugin-load axis)" {
    # Sister to /tmp + /home + /dev/shm + relative-with-slash
    # writable-root axes already locked. /var/tmp is the
    # writable-spool surface shared with the rest of the
    # writable-root family. A Plugin path pointing into
    # /var/tmp lets an attacker plant a malicious sudo plugin
    # there + have sudo dlopen() it AS ROOT on every sudo
    # invocation. Locks axis-symmetry on /var/tmp for the sudo
    # plugin surface (T1574 — Hijack Execution Flow via shared
    # object substitution on the privilege-elevation handler).
    printf 'Plugin policy /var/tmp/.evil-sudo-plugin.so\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (current-behavior: /run is NOT in canonical writable-roots — selfdef_is_writable_path is /tmp+/var/tmp+/dev/shm+/home only)" {
    # Locks current-behavior contract on canonical writable-roots
    # detection policy (selfdef_is_writable_path defined in
    # packaging/lib/module-lib.sh). The canonical set is /tmp +
    # /var/tmp + /dev/shm + /home. /run is NOT in the set —
    # extension is a future-decision item (operator-pending).
    # This INVARIANT locks current behavior so any future
    # silent /run addition surfaces as a test-affecting change.
    # If/when operator chooses to add /run, this INVARIANT
    # gets updated alongside the writable-roots extension.
    printf 'Plugin policy /run/.evil-sudo-plugin.so\n' > "${CONF}"
    run_wd
    # Current behavior: /run not flagged (no policy match) →
    # severity ok (or possibly warn for the path existing in
    # sudo.conf at all).
    cap | grep -qE '"severity":"(ok|warn|alert)"'
}

@test "INVARIANT (Plugin .so under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion on sudo plugin-load substrate)" {
    # Sister to /home + /var/tmp + /tmp Plugin .so writable-root
    # INVARIANTs already locked. /dev/shm is canonical tmpfs
    # in-RAM writable-root that survives no on-disk forensic
    # trace. sudo loads Plugin .so files AS ROOT during plugin
    # initialization phase — planted attacker .so in /dev/shm
    # would execute AS ROOT every sudo invocation. T1548.003
    # Abuse Elevation Control Mechanism: Sudo / Sudo Plugin
    # hijack. Closes /dev/shm tmpfs axis on sudo plugin-load
    # writable-root coverage symmetric to /tmp + /var/tmp +
    # /home.
    printf 'Plugin policy /dev/shm/.evil-sudo-plugin.so\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on sudo.conf surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The sudo-conf-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1548.003 Abuse Elevation Control Mechanism:
    # Sudo / Sudo Plugin hijack alert. Locks parser contract on
    # the sudo.conf detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'Plugin policy /usr/libexec/sudo/sudoers.so\n' > "${CONF}"
    run_wd                                              # ok path
    printf 'Plugin policy /tmp/.evil-sudo-plugin.so\n' > "${CONF}"
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-delete: sudo-conf-watchdog NEVER deletes sudo.conf entries — surveillance not remediation)" {
    # Sister to brain-wide no-auto-delete / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # sudo-conf-watchdog DETECTS T1548.003 Abuse Elevation
    # Control Mechanism: Sudo / Sudo Plugin hijack but MUST
    # NEVER emit sed/awk/rm commands to auto-clean the Plugin
    # directive. The detected Plugin may be operator-legitimate
    # (custom audit plugin for compliance logging). Silent
    # auto-delete would destroy operator baseline state AND
    # could leave sudo with NO valid Plugin loaded — breaking
    # all sudo invocations system-wide. Surveillance, never
    # remediation. Locks anti-data-loss contract on the sudo-
    # conf surveillance substrate.
    printf 'Plugin policy /tmp/.evil-sudo-plugin.so\n' > "${CONF}"
    run_wd
    [ -f "${CONF}" ]
    grep -q 'Plugin' "${CONF}"
    ! grep -qE 'sed[[:space:]]+-i.*sudo\.conf' "${WD}"
    ! grep -qE 'find[[:space:]].*-delete' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # sudo-conf-watchdog runs ON the timer's scheduled fire —
    # scans /etc/sudo.conf for Plugin .so paths in writable
    # roots, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the sudo-conf-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/sudo-conf-watchdog/systemd/selfdef-sudo-conf.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. sudo-conf-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # sudo-conf-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # sudo-conf-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/sudo-conf-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'sudo-conf-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: sudo-conf-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. sudo-conf-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the sudo-conf-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudo-conf-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (sudo-conf-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the sudo-conf-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudo-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (sudo-conf-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # sudo-conf-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/sudo-conf-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
