#!/usr/bin/env bats
# L2 bats functional tests for the musl-ld-path-watchdog scan script.
#
# On musl-libc systems (Alpine — the most common container base),
# /etc/ld-musl-<arch>.path is the ENTIRE library search path the musl
# loader uses. A prepended writable directory makes the loader resolve
# shared libraries from there first, hijacking libc/library loads for every
# dynamically-linked binary (T1574.006 dynamic linker hijacking). Entries
# are newline- or colon-separated.
#
# Notably this LOCKS a special case the SDD-061 D-6 migration preserved: the
# compound writable check keeps an extra bare-root exact-match clause
# (`^/(tmp|var/tmp|dev/shm|home)$`, no trailing slash) ALONGSIDE the shared
# selfdef_is_writable_path (which requires a trailing component) — so a path
# entry that is exactly `/tmp` is still flagged.
#
# Runs the actual scan script with `logger` shadowed on PATH and the path
# file + baseline in a tmp sandbox via SELFDEF_MUSL_*; locks the
# `"severity":"alert"` token SDD-062 routes on + the D-6 fail-loud path.
#
# Run with: bats packaging/test/L2-musl-ld-path-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd/musl-ld-path-watchdog.sh"
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
    CONF="${TMP}/ld-musl-x86_64.path"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MUSL_PROFILE="${PROFILE:-report}" \
    SELFDEF_MUSL_BASELINE="${BASELINE}" \
    SELFDEF_MUSL_FILES="${FILES:-$CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no musl path file present → ok / no_musl_path" {
    FILES="${TMP}/nonexistent.path" run_wd
    cap | grep -q '"event":"no_musl_path"'
    cap | grep -q '"severity":"ok"'
}

@test "benign search path, first run → ok / baseline_initial" {
    printf '/lib\n/usr/lib\n/usr/local/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged path on second run → ok / musl_path_intact" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"musl_path_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — incl. the PRESERVED bare-root exact-match clause
# ============================================================

@test "library dir under a writable root → alert" {
    printf '/tmp/evil/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a bare writable root (exactly /tmp, no trailing slash) → alert (preserved compound clause)" {
    printf '/lib\n/tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "colon-separated path with one writable dir → alert" {
    printf '/lib:/usr/lib:/dev/shm/x\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "benign dir added after baseline → warn / musl_path_changed" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    printf '/lib\n/usr/lib\n/opt/lib\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"musl_path_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "standard library dirs are NOT flagged" {
    printf '/lib\n/usr/lib\n/usr/local/lib\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable dir line is NOT flagged" {
    printf '/lib\n# /tmp/evil/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile + SDD-061 D-6 fail-loud
# ============================================================

@test "enforce profile exits non-zero on an alert" {
    printf '/tmp/evil/lib\n' > "${CONF}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — musl-ld-path inventory enumerates dynamic-linker hijack surface)" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (preserved bare /var/tmp exact-match clause)" {
    printf '/lib\n/var/tmp\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (preserved bare /dev/shm exact-match clause)" {
    printf '/lib\n/dev/shm\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (preserved bare /home exact-match clause)" {
    printf '/lib\n/home\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (path entry under /var/tmp/<subdir>): trailing-slash form" {
    printf '/lib\n/var/tmp/attacker/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (path entry under /home/<user>/lib): user-writable hijack coverage" {
    printf '/lib\n/home/user/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable path file → alert)" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-musl-ld-path -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no-auto-trust: musl-ld-path-watchdog does NOT refresh baseline on writable-dir detection — alert STAYS until operator updates)" {
    # T1574.006 dynamic-linker hijacking on musl substrate — alert
    # MUST persist across runs until operator explicitly re-baselines.
    # Sister to gss-mech, ld-preload, postfix-exec et al. — the
    # active-injection class never auto-trusts.
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    printf '/lib\n/tmp/evil/lib\n/usr/lib\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (multi-file scan: a second musl-ld file ALSO scanned — not only the x86_64 path)" {
    # Musl-libc systems may have multi-arch path files
    # (/etc/ld-musl-aarch64.path on cross-compile substrate). A planted
    # writable-dir entry in any arch-file MUST be flagged.
    CONF2="${TMP}/ld-musl-aarch64.path"
    printf '/lib\n/usr/lib\n' > "${CONF}"
    printf '/lib\n/tmp/evil/lib\n' > "${CONF2}"
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_MUSL_PROFILE=report \
    SELFDEF_MUSL_BASELINE="${BASELINE}" \
    SELFDEF_MUSL_FILES="${CONF} ${CONF2}" \
        bash "${WD}"
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (mixed-form line: newline-separated AND colon-separated in same file → any writable entry alerts)" {
    # Musl loader accepts BOTH newline-separated and colon-separated
    # entries on the same line. Mixed-form files are valid musl
    # configuration; watchdog must parse both grammars.
    printf '/lib:/usr/lib\n/opt/lib:/tmp/evil/lib\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing world-writable musl path file → baseline_initial fires alert at install-time)" {
    # Sister to every other watchdog pre-existing-world-writable
    # baseline_initial INVARIANT across the brain. The install-
    # time-vet contract: if the musl path file is ALREADY
    # world-writable when selfdef first installs the watchdog,
    # the first run MUST raise alert (or at least warn) — not
    # silently baseline a broken security posture. Closes the
    # install-time-vet axis on the musl ld.so library-search-
    # path surface (T1574 — dynamic-loader hijack via writable
    # config file letting attacker prepend evil dir at any time).
    printf '/lib\n/usr/lib\n' > "${CONF}"
    chmod 0666 "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (path entry under /var/tmp): writable-root expansion on musl ld.so search-path surface" {
    # Sister to /tmp + /home + /dev/shm writable-root axes
    # already locked. /var/tmp is the writable-spool surface
    # shared with the other writable-root family entries. A
    # musl ld.so path entry pointing into /var/tmp lets an
    # attacker plant a libc.so.6 with the right soname there +
    # have every musl-linked binary on the host load it. Lock
    # axis-symmetry with the rest of the writable-root family
    # on the musl ld.so library-search-path surface.
    printf '/lib\n/usr/lib\n/var/tmp/.attacker-libs\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named musl ld-path entry surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When attacker adds a new
    # distinctively-named writable directory to musl ld.so's
    # search path, the path MUST surface in the JSON sample so
    # operator dashboard routes triage to the right code-load
    # surface (T1574 dynamic-loader hijack).
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/lib\n/usr/lib\n/tmp/distinctive-attacker-libs\n' > "${CONF}"
    run_wd
    cap | grep -q 'distinctive-attacker-libs'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # Operator may wipe /var/lib/selfdef/musl-baseline.tsv
    # during host triage to force a fresh inventory. The
    # watchdog MUST re-create the baseline cleanly on the
    # next scan AND emit baseline_initial (not crash with
    # read-error AND not silently no-op). Locks state-
    # resilience on the musl ld.so library-search-path
    # surveillance surface (T1574 hijack execution flow).
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (path entry under /dev/shm — tmpfs in-RAM writable-root axis-symmetric expansion)" {
    # Sister to /tmp + /var/tmp + /home musl-ld path-entry
    # writable-root INVARIANTs. /dev/shm tmpfs in-RAM: no on-
    # disk forensic trace. T1574 dynamic-linker hijack via
    # musl ld.so library-search-path.
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/lib\n/usr/lib\n/dev/shm/.evil-libs\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on musl-ld-path surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The musl-ld-path-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1574 dynamic-linker hijack via musl ld.so
    # library-search-path alert. Locks parser contract on the
    # /etc/ld-musl-*.path detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '/lib\n/usr/lib\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf '/lib\n/usr/lib\n/tmp/.evil-libs\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # musl-ld-path-watchdog runs ON the timer's scheduled fire —
    # scans /etc/ld-musl-*.path for writable-root entries, emits
    # a verdict, then exits. Type=simple would break timer
    # OnUnitActiveSec semantics. Locks oneshot-probe contract on
    # the musl-ld-path-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd/selfdef-musl-ld-path.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. musl-ld-path-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # musl-ld-path-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # musl-ld-path-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'musl-ld-path-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: musl-ld-path-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. musl-ld-path-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the musl-ld-path-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (musl-ld-path-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the musl-ld-path-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (musl-ld-path-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # musl-ld-path-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (musl-ld-path-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # musl-ld-path-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (musl-ld-path-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the musl-ld-path-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (musl-ld-path-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # musl-ld-path-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (musl-ld-path-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the musl-ld-path-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (musl-ld-path-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the musl-ld-path-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (musl-ld-path-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # musl-ld-path-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (musl-ld-path-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the musl-ld-path-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/musl-ld-path-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}
