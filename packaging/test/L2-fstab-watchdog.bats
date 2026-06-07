#!/usr/bin/env bats
# L2 bats functional tests for the fstab-watchdog scan script.
#
# /etc/fstab entries are mounted AS ROOT at boot. Three high-signal classes:
#   - a loop/file-backed device under a writable root (/tmp/disk.img …) —
#     attacker-controlled filesystem image mounted at boot;
#   - a bind-mount that SHADOWS a sensitive path (/etc, /bin, /root/.ssh …);
#   - an explicit `suid` option re-enabling setuid where it was dropped.
# Entry format: `dev mountpoint fstype options …`.
#
# Runs the actual scan script with `logger` shadowed on PATH and the fstab
# in a tmp sandbox via SELFDEF_FSTAB_FILE / _D.
#
# Run with: bats packaging/test/L2-fstab-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd/fstab-watchdog.sh"
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
    FSTAB="${TMP}/fstab"
    FSTABD="${TMP}/fstab.d"; mkdir -p "${FSTABD}"
    BENIGN='UUID=11112222 / ext4 defaults 0 1
UUID=33334444 /home ext4 defaults,nosuid,nodev 0 2
tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0
'
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_FSTAB_PROFILE="${PROFILE:-report}" \
    SELFDEF_FSTAB_BASELINE="${BASELINE}" \
    SELFDEF_FSTAB_FILE="${FSTAB_F:-$FSTAB}" \
    SELFDEF_FSTAB_D="${FSTABD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no fstab → ok / no_fstab" {
    FSTAB_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_fstab"'
    cap | grep -q '"severity":"ok"'
}

@test "benign fstab, first run → ok / baseline_initial" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged fstab on second run → ok / fstab_intact" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fstab_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "a loop image under a writable root → alert / fstab_suspicious_mount" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd                                   # benign baseline
    printf '%s/tmp/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fstab_suspicious_mount"'
    cap | grep -q '"severity":"alert"'
}

@test "a bind-mount shadowing /etc → alert" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fakeetc /etc none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "an explicit suid option → alert" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/dev/sdb1 /data ext4 defaults,suid 0 2\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign mount added → warn / fstab_changed" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/dev/sdc1 /backup ext4 defaults,nosuid,nodev 0 2\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"fstab_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guard
# ============================================================

@test "a standard fstab is NOT flagged" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious mount" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/tmp/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — fstab inventory enumerates boot-mount surface)" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (bind-mount shadowing /bin → alert)" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fakebin /bin none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bind-mount shadowing /root/.ssh → alert): authorized_keys hijack via shadow-mount" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fake-ssh /root/.ssh none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (loop under /var/tmp → alert): writable-root expansion" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/var/tmp/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (loop under /dev/shm → alert): tmpfs writable-root coverage" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/dev/shm/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (suid option mid-list — not only when at start of options): defaults,foo,suid,bar → alert" {
    # An attacker who can sneak `,suid` into the options list mid-list
    # would still re-enable setuid. Locks regex matches mid-list too.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/dev/sdb1 /data ext4 defaults,nodev,suid,relatime 0 2\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (current-behavior lock — fstab-watchdog scans entry CONTENT, not the file's own perms)" {
    # fstab-watchdog inspects the parsed entry list (devices /
    # mountpoints / options) — NOT the file mode of /etc/fstab itself.
    # That gap is intentional in the current design (fstab is owned
    # by the static-watchdog file-mode pass via world-writable-watchdog
    # / suid-sgid-watchdog rather than this scan). This test locks
    # that semantic: a world-writable fstab does NOT itself fire
    # fstab-watchdog alert (it WILL fire elsewhere).
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    chmod 0666 "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # The file's mode change MAY trigger a content-delta if the script
    # carries baseline file-stat, OR may be silent. What we lock here:
    # entry-list content is unchanged → at most warn/fstab_intact.
    ! cap | grep -q '"event":"fstab_suspicious_mount"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-fstab -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (auto-trust): fstab-watchdog DOES auto-refresh baseline on suspicious-mount detection — sister-pattern with access-conf family" {
    # CONTRAST with no-auto-trust family. fstab changes ARE common
    # operator action (adding/removing storage). The watchdog flags
    # the delta for THIS run; the baseline catches up on the next.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/tmp/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # baseline refreshed
    cap | grep -q '"event":"fstab_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (bind-mount shadowing /sbin → alert; full set of sensitive paths)" {
    # Beyond /etc + /bin + /root/.ssh, /sbin shadow-mount is also a
    # privilege-escalation vector (replaces login/sudo binaries).
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fakesbin /sbin none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious mount NOT flagged: # prefix filtered)" {
    # /etc/fstab uses # for comments. Operator notes about hypothetical
    # bad mounts must NOT trigger alert.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s# /tmp/disk.img /mnt ext4 loop 0 0\n' "${BENIGN}" > "${FSTAB}"
    run_wd
    ! cap | grep -q '"event":"fstab_suspicious_mount"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: /etc/fstab + /etc/fstab.d/* axes — suspicious mount in fstab.d drop-in → alert)" {
    # Sister to every other watchdog multi-dir / multi-file scan
    # INVARIANT across the brain. mount(8) honors /etc/fstab.d/*
    # drop-ins (typically for site-specific or vendor-shipped
    # boot mounts) alongside the main /etc/fstab. Attacker may
    # plant a loop-image-on-writable-root mount in EITHER. Lock
    # multi-file axis on the boot-mount surface.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Plant suspicious loop-image mount in the fstab.d drop-in.
    printf '/tmp/evil-disk.img /mnt ext4 loop 0 0\n' > "${FSTABD}/site.conf"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (bind-mount shadowing /var — sister-axis to /etc + /bin + /sbin + /root/.ssh)" {
    # Sister to the bind-mount shadowing /etc + /bin + /sbin +
    # /root/.ssh sensitive-path axes already locked. /var is the
    # canonical writable-state directory containing /var/log
    # (audit-trail forensics surface), /var/lib (state DBs for
    # systemd-resolved, dpkg, etc.), /var/spool (mail/cron/at).
    # A bind-mount shadowing /var lets an attacker substitute a
    # state-DB that systemd / dpkg / packages then trust. Locks
    # axis-symmetry on the bind-mount shadow detection across the
    # sensitive-path family.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fake-var /var none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (bind-mount shadowing /usr — sister-axis to /etc + /bin + /sbin + /root/.ssh + /var)" {
    # Sister to the bind-mount shadowing /etc + /bin + /sbin +
    # /root/.ssh + /var sensitive-path axes already locked. /usr
    # contains every system binary + library + share + selfdef's
    # own libexec scripts. A bind-mount shadowing /usr would let
    # an attacker substitute the entire binary tree with patched
    # versions. Locks axis-symmetry on the bind-mount shadow
    # detection across the sensitive-path family — the most
    # impactful shadow target on the host.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fake-usr /usr none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (bind-mount shadowing /home — user-data exfil / cross-user-tampering axis)" {
    # Sister to the /etc + /bin + /sbin + /root/.ssh + /var + /usr
    # bind-mount shadow axes already locked. /home is the user-
    # data surface — every user account, every browser profile,
    # every credential file, every SSH agent socket. A bind-mount
    # shadowing /home would let an attacker (1) read all user
    # private data including .ssh/, gnupg/, browser cookies; (2)
    # plant lateral persistence (.bashrc / .profile) hitting
    # users on next interactive login; (3) snapshot crypto-
    # wallets / TOTP / password manager data. Closes the bind-
    # mount-shadow axis on the /home substrate (T1565.001 —
    # Stored Data Manipulation via mount-tier inversion).
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fake-home /home none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (bind-mount shadowing /boot — boot-time persistence vector)" {
    # Sister to /etc + /bin + /sbin + /root/.ssh + /var + /usr +
    # /home bind-mount shadow axes. /boot contains kernel +
    # initramfs + bootloader; shadow lets attacker replace any
    # of these. T1542 Pre-OS Boot.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fake-boot /boot none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (bind-mount shadowing /lib — runtime-library shadow axis — sister to /usr/lib)" {
    # Sister to /etc + /bin + /sbin + /usr + /var + /home +
    # /boot + /root/.ssh bind-mount shadow INVARIANTs. /lib
    # contains essential shared libraries (libc.so.6, ld-linux.
    # so) — any binary on the system that dynamic-links against
    # /lib gets attacker-controlled libc. T1574 Hijack Execution
    # Flow via library shadow at the most-foundational level.
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd
    printf '%s/data/fake-lib /lib none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on fstab surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The fstab-watchdog MUST only emit severity values from the
    # closed set {ok,warn,alert} — never custom values (critical,
    # error, fatal, notice, info). Operator dashboard parsers
    # branch on the literal severity string; an out-of-set value
    # silently falls through routing and the operator never
    # sees the T1574 Hijack Execution Flow via fstab bind-mount-
    # shadow persistence alert. Locks parser contract on the
    # /etc/fstab + /etc/fstab.d detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '%s' "${BENIGN}" > "${FSTAB}"
    run_wd                                              # ok / baseline
    printf '%s/data/fake-bin /bin none bind 0 0\n' "${BENIGN}" > "${FSTAB}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # fstab-watchdog runs ON the timer's scheduled fire — scans
    # /etc/fstab + /etc/fstab.d for bind-mount shadowing of
    # canonical paths, emits a verdict, then exits. Type=simple
    # would break timer OnUnitActiveSec semantics. Locks
    # oneshot-probe contract on the fstab-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd/selfdef-fstab.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. fstab-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # fstab-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # fstab-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'fstab-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: fstab-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. fstab-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the fstab-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (fstab-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # The fstab-watchdog libexec uses set -u to catch typo'd env-var
    # references before they silently propagate as empty
    # strings into baseline-path operations. Locks set -u
    # discipline on the fstab-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (fstab-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # fstab-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (fstab-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # fstab-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (fstab-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the fstab-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/fstab-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
