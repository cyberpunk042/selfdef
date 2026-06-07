#!/usr/bin/env bats
# L2 bats functional tests for the request-key-watchdog scan script.
#
# /etc/request-key.conf{,.d} map kernel key-request "upcalls" (dns_resolver,
# cifs.upcall, NFS idmap, …) to a callout PROGRAM the kernel runs AS ROOT
# when a key of that type is requested — a kernel-triggered exec surface an
# unprivileged action can reach. Rule format:
#   op type description callout-info program [args...]
# A callout program under a writable root is alert.
#
# Runs the actual scan script with `logger` shadowed on PATH and the config
# in a tmp sandbox via SELFDEF_REQKEY_FILE / _D.
#
# Run with: bats packaging/test/L2-request-key-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/systemd/request-key-watchdog.sh"
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
    CONF="${TMP}/request-key.conf"
    CONFD="${TMP}/request-key.d"; mkdir -p "${CONFD}"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_MODULE_LIB="${LIB}" \
    SELFDEF_REQKEY_PROFILE="${PROFILE:-report}" \
    SELFDEF_REQKEY_BASELINE="${BASELINE}" \
    SELFDEF_REQKEY_FILE="${CONF_F:-$CONF}" \
    SELFDEF_REQKEY_D="${CONFD}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

# ============================================================
# ok tier
# ============================================================

@test "no request-key config → ok / no_request_key" {
    CONF_F="${TMP}/nonexistent" CONFD="${TMP}/nonexistent.d" run_wd
    cap | grep -q '"event":"no_request_key"'
    cap | grep -q '"severity":"ok"'
}

@test "benign callout, first run → ok / baseline_initial" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged config on second run → ok / request_key_intact" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"request_key_intact"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# alert tier — callout under a writable root
# ============================================================

@test "callout program under a writable root → alert / request_key_suspicious_callout" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd                                   # benign baseline
    printf 'create dns_resolver * * /tmp/.evil %%k\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"request_key_suspicious_callout"'
    cap | grep -q '"severity":"alert"'
}

@test "callout program under /dev/shm → alert" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    printf 'create cifs.spnego * * /dev/shm/upcall %%k\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

# ============================================================
# warn tier
# ============================================================

@test "a benign callout added after baseline → warn / request_key_changed" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\ncreate cifs.spnego * * /usr/sbin/cifs.upcall %%k\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"request_key_changed"'
    cap | grep -q '"severity":"warn"'
}

# ============================================================
# false-positive guards
# ============================================================

@test "a /usr/sbin callout is NOT flagged" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "a commented-out writable callout is NOT flagged" {
    printf '# create dns_resolver * * /tmp/.evil %%k\ncreate dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

# ============================================================
# enforce profile
# ============================================================

@test "missing module-lib → alert / module_lib_missing + non-zero exit" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    LIB="${TMP}/nonexistent-module-lib.sh" run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"event":"module_lib_missing"'
    cap | grep -q '"severity":"alert"'
}

@test "enforce profile exits non-zero on a suspicious callout" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    printf 'create dns_resolver * * /tmp/.evil %%k\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — request-key inventory enumerates kernel-trigger root-exec surface)" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (callout under /var/tmp): writable-root expansion" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    printf 'create dns_resolver * * /var/tmp/.evil %%k\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (callout under /home): user-writable hijack coverage" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    printf 'create dns_resolver * * /home/user/.evil %%k\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (request-key.d drop-in axis): suspicious callout in /etc/request-key.d/*.conf also fires" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    printf 'create cifs.spnego * * /tmp/.dropin-attacker %%k\n' > "${CONFD}/99-evil.conf"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (world-writable request-key.conf): file itself world-writable → alert" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    chmod 0666 "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (negate operation 'negate dns_resolver' is NOT itself an exec — should not false-positive)" {
    # Some valid request-key syntax doesn't carry a callout program at
    # all (negate op). Lock that this doesn't false-fire.
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\nnegate * * /bin/false\n' > "${CONF}"
    run_wd
    # Although negate has /bin/false, it's not under a writable root,
    # so should not alert.
    ! cap | grep -q '"severity":"alert"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-request-key -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): request-key-watchdog does NOT refresh baseline on suspicious-callout detection — alert STAYS until operator updates" {
    # Kernel-trigger root-exec persistence — suspicious-callout alert
    # MUST persist across runs until operator explicitly re-baselines.
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    printf 'create dns_resolver * * /tmp/.evil %%k\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"request_key_suspicious_callout"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (whitespace tolerance: tab-separated callout still parsed — multi-whitespace anti-evasion)" {
    # Attacker may use tabs or multi-spaces between fields to evade
    # naive grep-based detection. Lock whitespace-tolerant parser.
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'create\tdns_resolver\t*\t*\t/tmp/.evil\t%%k\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (relative-path callout 'sub/dir/p' → alert)" {
    # A relative-path callout is resolved against the kernel's PWD
    # at upcall time — undefined behavior + attacker primitive.
    # Lock detection.
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'create dns_resolver * * sub/dir/evil %%k\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (callout with args: '/tmp/.evil arg1 arg2' — args don't hide the writable-root)" {
    # An attacker may try to hide the writable-root path by appending
    # arguments after it. The watchdog must extract the program (first
    # word after callout-info) and still alert.
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'create dns_resolver * * /tmp/.evil --kernel-arg1 --kernel-arg2 %%k\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (callout under /var/tmp): writable-root expansion on request-key surface" {
    # Sister to the /tmp + /home + /dev/shm writable-root axes
    # already locked. /var/tmp is an equally-writable surface;
    # kernel-triggered root-exec must alert regardless of which
    # writable-root the callout program lives under. Locks axis-
    # symmetry across the writable-root family on the kernel
    # upcall surface (T1574 — request-key.conf maps kernel key-
    # request upcalls to a callout the kernel runs AS ROOT;
    # /var/tmp callout = kernel-triggered code-load primitive).
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'create dns_resolver * * /var/tmp/.evil %%k\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (negate operation 'negate * * /bin/false' canonical pattern — NOT flagged as exec)" {
    # Sister to the negate-not-exec false-positive-guard already
    # locked. The canonical request-key negate-operation pattern is
    # 'negate * * /bin/false' which intentionally fails the upcall
    # without exec. Lock that this canonical operator-pattern does
    # NOT false-fire even when the binary path is absolute (/bin/
    # false is a system binary; not a writable-root signal).
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver %%k\nnegate * * /bin/false\n' > "${CONF}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    # Second run on unchanged config → severity ok / intact.
    cap | grep -q '"event":"request_key_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (callout under /home — user-writable hijack on kernel-keyring upcall surface)" {
    # Sister to many other watchdog's /home user-writable
    # INVARIANT across the brain. /home is the user-writable
    # surface — an attacker with regular user account can drop
    # a malicious callout binary into their home and have the
    # kernel invoke it AS ROOT every time the keyring requests
    # an upcall. Locks axis-symmetry on /home for the request-
    # key callout surface (T1546 — Event Triggered Execution
    # via kernel-keyring upcall; the kernel calls into the
    # configured callout binary AS ROOT to resolve key
    # requests).
    printf 'create dns_resolver * * /home/user/.evil-callout\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (callout under /dev/shm — tmpfs writable-root axis-symmetric expansion on kernel-keyring upcall surface)" {
    # Sister to /home + /var/tmp callout writable-root INVARIANTs
    # already locked. /dev/shm is tmpfs writable by ALL users
    # without privilege, lives in RAM (boot-wiped), and slips
    # past disk-monitoring tools — high-velocity drop surface
    # for T1546 kernel-keyring upcall hijack. The kernel calls
    # into the configured callout AS ROOT every time keyring
    # requests an upcall; planted binary in /dev/shm fires AS
    # ROOT on every cache miss.
    printf 'create dns_resolver * * /dev/shm/.evil-callout\n' > "${CONF}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # Operator may wipe baseline during host triage. Watchdog
    # MUST re-create cleanly AND emit baseline_initial. State-
    # resilience on T1546 kernel-keyring upcall surveillance.
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver\n' > "${CONF}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs.
    printf 'create dns_resolver * * /tmp/.evil1\ncreate cifs.spnego * * /var/tmp/.evil2\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-request-key -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on request-key surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The request-key-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1546 kernel-keyring-upcall root-exec
    # persistence alert. Locks parser contract on the /etc/
    # request-key.conf + request-key.d detection surface.
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'create dns_resolver * * /usr/sbin/key.dns_resolver\n' > "${CONF}"
    run_wd                                              # ok / baseline
    printf 'create dns_resolver * * /tmp/.evil\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # request-key-watchdog runs ON the timer's scheduled fire —
    # scans /etc/request-key.conf for kernel-keyring-callback
    # exec directives in writable paths, emits a verdict, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the request-
    # key-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/systemd/selfdef-request-key.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. request-key-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # request-key-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # request-key-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'request-key-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: request-key-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. request-key-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the request-key-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (request-key-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the request-key-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (request-key-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # request-key-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (request-key-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # request-key-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (request-key-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the request-key-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/request-key-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
