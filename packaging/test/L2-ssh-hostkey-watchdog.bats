#!/usr/bin/env bats
# L2 functional suite for ssh-hostkey-watchdog.
#
# ssh-hostkey-watchdog tracks the SSH host-key fingerprints — the
# server's cryptographic identity. If they CHANGE on a stable host:
#   - MITM prep: attacker swapped the key, clients that TOFU-accept
#     get intercepted
#   - Unauthorized reinstall / re-image of the host
#   - Key theft → operator rotated (legit) OR attacker rotated
# Legit host keys NEVER change on a stable host; a change is always
# operator-explainable-or-incident.
#
# Severity tiers:
#   ok    → no delta (hostkeys_intact)
#   warn  → key REMOVED (type retired) or ADDED (new type enabled)
#   alert → EXISTING key-type's fingerprint CHANGED (identity swap —
#           the MITM/reinstall signature). This is the ALERT path.
#
# Uses SELFDEF_HOSTKEY_DIR env-var override (added 2026-06-06) to
# point at a fixture key directory. Shadows ssh-keygen on PATH with a
# fake that emits a deterministic SHA256:<fp> based on file content,
# so editing the .pub file changes the "fingerprint".
#
# Run with: bats packaging/test/L2-ssh-hostkey-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd/ssh-hostkey-watchdog.sh"

setup() {
    TMP="$(mktemp -d)"
    BIN="${TMP}/bin"; mkdir -p "${BIN}"
    cat > "${BIN}/logger" <<'FAKELOGGER'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SELFDEF_TEST_LOGCAP}"
FAKELOGGER
    chmod +x "${BIN}/logger"
    # Fake ssh-keygen: -lf <file> → emit "<bits> SHA256:<content-hash> <comment> (<TYPE>)"
    # The TYPE is derived from the filename pattern ssh_host_<TYPE>_key.pub.
    cat > "${BIN}/ssh-keygen" <<'SSHEOF'
#!/usr/bin/env bash
# Fake ssh-keygen for L2-ssh-hostkey-watchdog.
mode=""
target=""
i=1
while (( i <= $# )); do
    case "${!i}" in
        -lf) mode="lf"; j=$((i+1)); target="${!j}"; i=$((j+1)) ;;
        *)   i=$((i+1)) ;;
    esac
done
if [[ "${mode}" != "lf" || -z "${target}" || ! -f "${target}" ]]; then
    echo "fake ssh-keygen: invalid invocation" >&2
    exit 1
fi
# Derive TYPE from filename: ssh_host_<TYPE>_key.pub → TYPE in upper.
base="$(basename "${target}")"
type_lower="${base#ssh_host_}"
type_lower="${type_lower%_key.pub}"
case "${type_lower}" in
    ed25519) type="ED25519" ;;
    rsa)     type="RSA"     ;;
    ecdsa)   type="ECDSA"   ;;
    dsa)     type="DSA"     ;;
    *)       type="$(printf '%s' "${type_lower}" | tr '[:lower:]' '[:upper:]')" ;;
esac
# Content-hash → emitted fingerprint. The watchdog parses `awk '{print $2}'`
# which gives us SHA256:<hash>.
fp="$(sha256sum "${target}" 2>/dev/null | awk '{print $1}')"
fp="${fp:0:43}"   # ssh-keygen real format truncates at 43 chars
printf '%d SHA256:%s root@host (%s)\n' 256 "${fp}" "${type}"
SSHEOF
    chmod +x "${BIN}/ssh-keygen"
    export SELFDEF_TEST_LOGCAP="${TMP}/log.out"
    : > "${SELFDEF_TEST_LOGCAP}"
    BASELINE="${TMP}/ssh-hostkey-baseline.tsv"
    KEYDIR="${TMP}/etc/ssh"
    mkdir -p "${KEYDIR}"
}

teardown() { rm -rf "${TMP}"; }

# mk_key <type> <content> — drop a fake host key public file.
mk_key() {
    local type="$1" content="$2"
    printf '%s\n' "${content}" > "${KEYDIR}/ssh_host_${type}_key.pub"
}

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_HOSTKEY_PROFILE="${PROFILE:-report}" \
    SELFDEF_HOSTKEY_BASELINE="${BASELINE}" \
    SELFDEF_HOSTKEY_DIR="${KEYDIR}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

@test "first run captures the host-key inventory + chmod 0600" {
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    mk_key rsa     "ssh-rsa     BBBBBBBB root@host"
    run_wd
    [ -f "${BASELINE}" ]
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"host_keys":2'
}

@test "unchanged keys on second run → ok / hostkeys_intact" {
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hostkeys_intact"'
    cap | grep -q '"severity":"ok"'
    cap | grep -qE '"changed":0'
}

@test "EXISTING key-type's fingerprint CHANGED → alert / hostkey_changed (the MITM signature)" {
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    run_wd
    # Same keyfile present but different content → different fingerprint
    # → comm shows the same filename in both added and removed, watchdog
    # classifies as "changed".
    mk_key ed25519 "ssh-ed25519 SWAPPED root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hostkey_changed"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"changed":1'
}

@test "new key-type ADDED (e.g. enabled ed25519) → warn / hostkey_set_changed" {
    mk_key rsa "ssh-rsa BBBBBBBB root@host"
    run_wd                          # baseline = {rsa}
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"   # added new type
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hostkey_set_changed"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"added":1'
    cap | grep -qE '"changed":0'
}

@test "key-type REMOVED (retired) → warn / hostkey_set_changed" {
    mk_key rsa     "ssh-rsa     BBBBBBBB root@host"
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    run_wd
    rm -f "${KEYDIR}/ssh_host_rsa_key.pub"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hostkey_set_changed"'
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"removed":1'
    cap | grep -qE '"changed":0'
}

@test "CHANGED takes precedence over warn-tier add/remove when both happen" {
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    mk_key rsa     "ssh-rsa     BBBBBBBB root@host"
    run_wd
    # Swap the ed25519 key (changed) AND retire rsa (removed)
    mk_key ed25519 "ssh-ed25519 SWAPPED root@host"
    rm -f "${KEYDIR}/ssh_host_rsa_key.pub"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hostkey_changed"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"changed":1'
}

@test "the emitted JSON carries every promised schema field" {
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_key ed25519 "ssh-ed25519 SWAPPED root@host"
    run_wd
    line="$(cap)"
    printf '%s' "${line}" | grep -q '"tag":"selfdef-ssh-hostkey"'
    printf '%s' "${line}" | grep -q '"severity":'
    printf '%s' "${line}" | grep -q '"event":'
    printf '%s' "${line}" | grep -q '"profile":'
    printf '%s' "${line}" | grep -qE '"added":[0-9]+'
    printf '%s' "${line}" | grep -qE '"removed":[0-9]+'
    printf '%s' "${line}" | grep -qE '"changed":[0-9]+'
    printf '%s' "${line}" | grep -q '"changed_sample":'
    printf '%s' "${line}" | grep -q '"added_sample":'
    printf '%s' "${line}" | grep -q '"removed_sample":'
}

@test "changed_sample carries 'keyfile:type' rows" {
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    run_wd
    mk_key ed25519 "ssh-ed25519 SWAPPED root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q 'ssh_host_ed25519_key.pub:ED25519'
}

@test "enforce profile + fingerprint changed → exit 1" {
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    run_wd
    mk_key ed25519 "ssh-ed25519 SWAPPED root@host"
    run env PATH="${BIN}:${PATH}" \
        SELFDEF_HOSTKEY_PROFILE=enforce \
        SELFDEF_HOSTKEY_BASELINE="${BASELINE}" \
        SELFDEF_HOSTKEY_DIR="${KEYDIR}" \
        bash "${WD}"
    [ "$status" -ne 0 ]
}

@test "enforce profile + unchanged → exit 0" {
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run_wd
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (multi-key compound CHANGED: 2 key-types changed simultaneously → alert with changed:2)" {
    # Operator rotation typically rotates ALL key types together. A mass
    # change is the legit-rotate signature OR a re-image. Either way,
    # severity should still alert (the operator needs to ack the rotation).
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    mk_key rsa     "ssh-rsa     ORIGINAL root@host"
    run_wd
    mk_key ed25519 "ssh-ed25519 ROTATED root@host"
    mk_key rsa     "ssh-rsa     ROTATED root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"changed":2'
}

@test "INVARIANT (multiple key-types ADDED): warn-tier + reflects in added count" {
    mk_key rsa "ssh-rsa BBBBBBBB root@host"
    run_wd
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    mk_key ecdsa   "ssh-ecdsa   CCCCCCCC root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"added":2'
}

@test "INVARIANT (zero-host-keys initial — baseline initially empty): handled gracefully (no key-dir bug)" {
    # /etc/ssh might have no keys yet on a fresh host. Baseline initial
    # should still complete without crash.
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"host_keys":0'
}

@test "INVARIANT (REPLACED key-type — different fingerprint format): retired DSA, added ED25519 → warn-tier set change" {
    # Legit hardening migration: retire DSA (deprecated), add ed25519.
    mk_key dsa "ssh-dss BBBBBBBB root@host"
    run_wd
    rm -f "${KEYDIR}/ssh_host_dsa_key.pub"
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"warn"'
    cap | grep -qE '"removed":1'
    cap | grep -qE '"added":1'
}

@test "INVARIANT (architectural: ssh-hostkey-watchdog auto-trusts after alert — sister of pci-device family)" {
    # Architectural choice: hostkey-watchdog (like pci-device-watchdog)
    # auto-refreshes the baseline after alerting. Sister-pattern contrast
    # with dns-resolver-watchdog which is no-auto-trust. Hardware-class
    # events fire ONCE, then operator-ack via natural state observation;
    # dns-class events are persistent-alert because attackers can keep
    # tampering.
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    run_wd
    mk_key ed25519 "ssh-ed25519 SWAPPED root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                          # alerts the first time
    cap | grep -q '"severity":"alert"'
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                          # third run — baseline refreshed → ok
    cap | grep -q '"severity":"ok"'
    cap | grep -q '"event":"hostkeys_intact"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ssh-hostkey -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (profile field echoes operator-set SELFDEF_HOSTKEY_PROFILE)" {
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    PROFILE=report run_wd
    cap | grep -q '"profile":"report"'
}

@test "INVARIANT (ECDSA key-type detection: NIST P-256 family also tracked alongside RSA/Ed25519/DSA)" {
    # ECDSA host keys are common on hardened hosts. Lock that
    # they're captured + tracked alongside other algorithms.
    mk_key ecdsa "ssh-ecdsa CCCCCCCC root@host"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"host_keys":1'
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_key ecdsa "ssh-ecdsa SWAPPED root@host"
    run_wd
    cap | grep -q '"severity":"alert"'
    cap | grep -qE 'ECDSA'
}

@test "INVARIANT (severity precedence: changed wins over add+remove combined → alert with changed_sample populated)" {
    # When rotation produces BOTH net-new types AND changed-types,
    # severity must be alert (changed wins over add/remove).
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    mk_key rsa     "ssh-rsa     OLDONE root@host"
    run_wd
    # Swap ed25519 + retire rsa + add ecdsa.
    mk_key ed25519 "ssh-ed25519 SWAPPED root@host"
    rm -f "${KEYDIR}/ssh_host_rsa_key.pub"
    mk_key ecdsa "ssh-ecdsa CCCCCCCC root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hostkey_changed"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE '"changed":1'
}

@test "INVARIANT (host_keys count surfaces accurately — initial inventory baseline_count tracks N installed types)" {
    # Operator dashboard counts host keys via the host_keys field.
    # Lock that the count is accurate across 3 algorithm types.
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    mk_key rsa     "ssh-rsa     BBBBBBBB root@host"
    mk_key ecdsa   "ssh-ecdsa   CCCCCCCC root@host"
    run_wd
    cap | grep -qE '"host_keys":3'
}
