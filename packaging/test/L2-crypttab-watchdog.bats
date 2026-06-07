#!/usr/bin/env bats
# L2 bats functional tests for the crypttab-watchdog scan script.
#
# /etc/crypttab's `keyscript=` option runs a program AS ROOT at early boot
# to obtain the unlock key — a rogue keyscript is root-exec-at-boot
# persistence; a keyfile under a writable root is an unlock-key compromise.
# Entry format: `target source keyfile options`.
#
# Runs the actual scan script with `logger` shadowed on PATH and the
# crypttab in a tmp sandbox via SELFDEF_CRYPTTAB_FILE.
#
# Run with: bats packaging/test/L2-crypttab-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/crypttab-watchdog/systemd/crypttab-watchdog.sh"
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
    CRYPTTAB="${TMP}/crypttab"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_CRYPTTAB_PROFILE="${PROFILE:-report}" \
    SELFDEF_CRYPTTAB_BASELINE="${BASELINE}" \
    SELFDEF_CRYPTTAB_FILE="${CRYPTTAB_F:-$CRYPTTAB}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no crypttab → ok / no_crypttab" {
    CRYPTTAB_F="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_crypttab"'
    cap | grep -q '"severity":"ok"'
}

@test "benign crypttab, first run → ok / baseline_initial" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged crypttab on second run → ok / crypttab_intact" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"crypttab_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier
# ============================================================

@test "keyscript under a writable root → alert / crypttab_suspicious" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd                                   # benign baseline
    printf 'data /dev/sda2 none luks,keyscript=/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"crypttab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "keyfile under /dev/shm → alert" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 /dev/shm/k luks\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare/relative keyscript → alert" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign options change → warn / crypttab_changed" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,discard\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"crypttab_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "keyfile=none + no keyscript is NOT flagged" {
    printf 'data /dev/sda2 none luks,discard\nroot UUID=abcd none luks\n' > "${CRYPTTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a keyfile under /etc is NOT flagged" {
    printf 'data /dev/sda2 /etc/luks-keys/data.key luks\n' > "${CRYPTTAB}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious keyscript" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — crypttab inventory enumerates LUKS-unlock root-exec surface)" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (keyscript under /var/tmp): writable-root expansion" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/var/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyscript under /home): user-writable hijack coverage" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/home/user/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyfile under /tmp → alert): keyfile vs keyscript axis-symmetric" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 /tmp/key luks\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyfile under /var/tmp → alert): writable-root expansion on keyfile axis" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 /var/tmp/key luks\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable crypttab file → alert)" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    chmod 0666 "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-crypttab -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): crypttab-watchdog does NOT refresh baseline on suspicious-keyscript detection — alert STAYS until operator updates" {
    # LUKS-unlock root-exec persistence — suspicious-keyscript alert
    # MUST persist across runs until operator explicitly re-baselines.
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    printf 'data /dev/sda2 none luks,keyscript=/tmp/.getkey\n' > "${CRYPTTAB}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"crypttab_suspicious"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented suspicious keyscript NOT flagged: # prefix filtered)" {
    # crypttab uses # for comments. Operator notes about hypothetical
    # bad keyscripts must NOT trigger alert.
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 none luks\n# data /dev/sda2 none luks,keyscript=/tmp/.example-attacker\n' > "${CRYPTTAB}"
    run_wd
    ! cap | grep -q '"event":"crypttab_suspicious"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyscript with absolute path BUT relative subpath traversal '/usr/lib/../../../tmp/.evil' → flagged)" {
    # An attacker may try to evade detection by using path traversal
    # within an absolute path. Either explicit detection OR canonical
    # path resolution must catch this. Lock current behavior.
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 none luks,keyscript=/usr/lib/../../../tmp/.evil\n' > "${CRYPTTAB}"
    run_wd
    # Either alert (preferred — canonical path resolution catches /tmp/) OR warn (acceptable — config change).
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (keyfile under /home → alert): keyfile-vs-keyscript axis-symmetric on user-writable root" {
    # Sister to keyscript-under-/home INVARIANT above. A LUKS keyfile
    # in user-home is an unlock-key-compromise vector — a user-mode
    # attacker can swap the keyfile to hijack disk encryption. Locks
    # axis-symmetry between keyscript-/home and keyfile-/home on the
    # user-writable hijack surface.
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 /home/user/.luks-key luks\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyscript under /dev/shm — tmpfs writable-root variant on the keyscript axis)" {
    # Sister to the keyscript-under-/tmp + /var/tmp + /home axes
    # already locked. /dev/shm is tmpfs world-writable on most
    # distros — an attacker-planted keyscript there would be reset
    # at reboot but if the attacker can sync this exec across a
    # reboot via a sister persistence hook (e.g. a systemd-power-
    # hook that re-writes /dev/shm/.getkey at boot), the LUKS
    # unlock surface is hijacked. Locks the tmpfs writable-root
    # axis on the keyscript surface (T1546 — Event Triggered
    # Execution via LUKS unlock keyscript).
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 none luks,keyscript=/dev/shm/.getkey\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyfile under /var/tmp → alert: writable-root variant on the keyfile axis)" {
    # Sister to keyfile-under-/tmp + /home axes already locked
    # and the keyscript-under-/var/tmp axis already locked. /var/
    # tmp is the writable-spool surface shared with the keyscript
    # writable-root family. A keyfile placed under /var/tmp lets
    # an attacker with /var/tmp write access replace the LUKS
    # unlock-key at any time, then unlock the encrypted volume on
    # next boot — anti-encryption-at-rest defense. Locks the
    # keyfile axis symmetric with the keyscript /var/tmp axis on
    # the disk-encryption substrate.
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 /var/tmp/.lukskey luks\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named crypttab entry surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain (sudoers / suid-sgid / unowned /
    # access-conf / systemd-unit / account / cron / autofs / nfs).
    # When an attacker drops a new crypttab entry pointing at an
    # attacker-controlled keyfile/keyscript, the entry NAME MUST
    # surface in the JSON sample so operator dashboard routes
    # triage to the right path. Locks the crypttab-entry-
    # discovered operator-visibility contract on the disk-
    # encryption substrate (LUKS unlock-key surface = data-at-
    # rest defense neutralization vector).
    printf 'data /dev/sda2 /etc/luks-keys/data.key luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 /etc/luks-keys/data.key luks\ndistinctive-attacker-vol /dev/sdc1 /tmp/.evil-key luks\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q 'distinctive-attacker-vol'
}

@test "INVARIANT (keyfile under /dev/shm — tmpfs writable-root axis-symmetric expansion on keyfile axis)" {
    # Sister to /tmp + /var/tmp + /home keyfile writable-root
    # INVARIANTs. /dev/shm is tmpfs writable by ALL users + RAM-
    # resident; attacker plants keyfile in /dev/shm, gets LUKS
    # unlock-key replacement primitive on every boot (anti-
    # encryption-at-rest defense).
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 /dev/shm/.lukskey luks\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (keyscript under /var/tmp — writable-root axis-symmetric expansion on keyscript axis)" {
    # Sister to /home + /dev/shm keyscript writable-root
    # INVARIANTs. /var/tmp writable + persistent. keyscript fires
    # AS ROOT at boot for LUKS unlock; planted attacker keyscript
    # in /var/tmp gets boot-time root-exec primitive AND can
    # exfiltrate the unlock-key. T1611 boot-time-disk-decrypt
    # axis sister to keyfile-on-writable-root.
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 none luks,keyscript=/var/tmp/.keyscript\n' > "${CRYPTTAB}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on crypttab surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The crypttab-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1611 boot-time-disk-decrypt hijack alert.
    # Locks parser contract on the /etc/crypttab keyfile/
    # keyscript detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'data /dev/sda2 none luks\n' > "${CRYPTTAB}"
    run_wd                                              # ok path
    printf 'data /dev/sda2 /tmp/.evil-key luks\n' > "${CRYPTTAB}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # crypttab-watchdog runs ON the timer's scheduled fire —
    # reads /etc/crypttab, alerts on suspicious keyfile/keyscript
    # paths, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the crypttab-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/crypttab-watchdog/systemd/selfdef-crypttab.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. crypttab-watchdog manifest declares install +
    # profile gating the resolver enforces; malformed manifest
    # wedges the /etc/crypttab keyfile/keyscript scanner.
    # Python's tomllib is the canonical parser. Locks anti-
    # malformed-manifest on the crypttab-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/crypttab-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as f:
    data = tomllib.load(f)
assert data['name'] == 'crypttab-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: crypttab-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. crypttab-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the crypttab-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/crypttab-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}
