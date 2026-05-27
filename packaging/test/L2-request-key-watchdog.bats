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
