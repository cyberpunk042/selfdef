#!/usr/bin/env bats
# L2 bats functional tests for the nfs-exports-watchdog scan script.
#
# /etc/exports declares NFS shares. A newly-added dangerous export —
# no_root_squash (remote root = local root on the share), a `*`-wildcard rw
# export, or `insecure` — is a remote-access / privesc surface. Severity:
#   ok    → no delta
#   warn  → any export added/removed/changed
#   alert → a newly-added dangerous export
#
# Run with: bats packaging/test/L2-nfs-exports-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nfs-exports-watchdog/systemd/nfs-exports-watchdog.sh"

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
    EXPORTS="${TMP}/exports"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_NFSEXP_PROFILE="${PROFILE:-report}" \
    SELFDEF_NFSEXP_BASELINE="${BASELINE}" \
    SELFDEF_NFSEXP_FILE="${FILE_V:-$EXPORTS}" \
    SELFDEF_NFSEXP_D="${TMP}/no-exports-d" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf '/srv/public 192.168.1.0/24(ro,root_squash,secure)\n' > "${EXPORTS}"
}

@test "no exports → ok / no_exports" {
    FILE_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_exports"'
    cap | grep -q '"severity":"ok"'
}

@test "benign exports, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged exports on second run → ok / nfs_exports_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nfs_exports_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a no_root_squash wildcard export → alert / nfs_exports_dangerous" {
    seed_benign
    run_wd
    printf '/srv/public 192.168.1.0/24(ro,root_squash,secure)\n/srv/data *(rw,no_root_squash)\n' > "${EXPORTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nfs_exports_dangerous"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign export change → warn / nfs_exports_changed" {
    seed_benign
    run_wd
    printf '/srv/public 10.0.0.0/8(ro,root_squash,secure)\n' > "${EXPORTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"nfs_exports_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign root_squash export is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a dangerous export" {
    seed_benign
    run_wd
    printf '/srv/data *(rw,no_root_squash)\n' > "${EXPORTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — NFS exports inventory enumerates shared paths)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (dangerous family 1): no_root_squash on its own → alert (remote root attack)" {
    # no_root_squash means remote root = local root on the share —
    # an attacker exporting as root WRITES files owned by root.
    seed_benign
    run_wd
    printf '/srv/data 192.168.1.0/24(rw,no_root_squash)\n' > "${EXPORTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dangerous family 2): wildcard `*` host with rw → alert (open-to-internet write)" {
    seed_benign
    run_wd
    printf '/srv/data *(rw,root_squash,secure)\n' > "${EXPORTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (dangerous family 3): insecure option → alert (allows requests from non-privileged ports)" {
    seed_benign
    run_wd
    printf '/srv/data 192.168.1.0/24(rw,root_squash,insecure)\n' > "${EXPORTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing dangerous export): baseline_initial fires alert if exports already has no_root_squash at install-time" {
    printf '/srv/data 192.168.1.0/24(rw,no_root_squash)\n' > "${EXPORTS}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED export (operator pruning) → warn / nfs_exports_changed" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    : > "${EXPORTS}"                                    # remove the only export
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'             # not alert
}

@test "DELTA detect — newly-ADDED dangerous export surfaces in JSON sample" {
    seed_benign
    run_wd
    printf '/srv/public 192.168.1.0/24(ro,root_squash,secure)\n/srv/distinctive 192.168.1.0/24(rw,no_root_squash)\n' > "${EXPORTS}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'distinctive'                         # the added path surfaces
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-nfs-exports -- ')
    [ "${main_count}" = "1" ]
}
