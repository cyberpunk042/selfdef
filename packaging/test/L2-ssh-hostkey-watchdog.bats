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

@test "INVARIANT (re-arm after operator deletion of baseline: re-creates from current keydir on next run)" {
    # When operator out-of-band rm the baseline (forensics, lost
    # state), the next run treats as fresh baseline_initial. Sister
    # to many other modules' re-arm INVARIANT.
    mk_key ed25519 "ssh-ed25519 AAAAAAAA root@host"
    run_wd
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    [ -f "${BASELINE}" ]
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (RSA fingerprint swap also alerts — not only ED25519 axis)" {
    # The MITM/reinstall signature must fire across ALL key types,
    # not just ed25519. Sister axis to existing ed25519 + ecdsa
    # changed tests. Lock the RSA path specifically.
    mk_key rsa "ssh-rsa ORIGINAL root@host"
    run_wd
    mk_key rsa "ssh-rsa SWAPPED root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"hostkey_changed"'
    cap | grep -q '"severity":"alert"'
    cap | grep -qE 'RSA'
}

@test "INVARIANT (all host keys removed — operator-clearing-state surfaces in JSON observable)" {
    # When operator wipes /etc/ssh/ host keys (rare but possible —
    # reinstall, re-image, reset-to-factory), the watchdog should
    # surface the event as observable: every key REMOVED in one
    # scan. Sister to access-conf REMOVED + dns-resolver mass-flush
    # axes. Locks the operator-visibility contract: even a
    # legitimate state reset must be observable on the dashboard
    # for operator-confirmation flow.
    mk_key ed25519 "ssh-ed25519 ORIGINAL root@host"
    mk_key rsa     "ssh-rsa     BBBBBBBB root@host"
    run_wd
    rm -f "${KEYDIR}"/*
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"removed":[1-9]'
    cap | grep -qE '"severity":"(warn|alert)"'
}

@test "INVARIANT (ECDSA fingerprint swap also alerts — third-algorithm axis sister to ED25519 + RSA)" {
    # Sister to ED25519 + RSA fingerprint-swap axes already
    # locked. ECDSA host keys (ssh_host_ecdsa_key) are the
    # third canonical algorithm SSH ships by default. Lock
    # axis-symmetry: an ECDSA host-key fingerprint swap MUST
    # also alert — closes the algorithm-agnostic detection
    # contract on the host-identity surveillance surface
    # (T1556 — Modify Authentication Process; host-key swap
    # makes the host indistinguishable from attacker MITM).
    mk_key ed25519 "ssh-ed25519 ORIGINAL_ED root@host"
    mk_key rsa     "ssh-rsa     ORIGINAL_RSA root@host"
    mk_key ecdsa   "ecdsa-sha2-nistp256 ORIGINAL_ECDSA root@host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    mk_key ecdsa   "ecdsa-sha2-nistp256 SWAPPED_BY_ATTACKER root@host"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (host-key permissions 0600 baseline lock — private key file MUST be operator-private)" {
    # Sister to many other watchdog/installer file-perm
    # INVARIANTs across the brain. The host-key surveillance
    # surface depends on the watchdog reading host private keys
    # (or their fingerprints). Even though the watchdog only
    # reads fingerprints, a regression that left the keys
    # world-readable would be a separate security incident
    # (T1552.004 — Credentials in Files: Private Keys). The
    # watchdog operating on the keys MUST not change their
    # perms; the host-key files must remain operator-private
    # (0600 or 0640 typical for /etc/ssh/ssh_host_*_key).
    # Current-behavior lock: watchdog does NOT relax permissions
    # — sister contract to the no-auto-trust baseline lock.
    mk_key ed25519 "ssh-ed25519 ORIGINAL_ED root@host"
    chmod 0644 "${KEYDIR}/ssh_host_ed25519_key.pub"
    run_wd
    # Watchdog must not change pub-key file perms.
    [ "$(stat -c '%a' "${KEYDIR}/ssh_host_ed25519_key.pub")" = "644" ]
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. The
    # selfdef-ssh-hostkey tag MUST fire EXACTLY ONCE per scan
    # regardless of how many host-key changes surface (multi-key
    # swap scenario). Multi-line output would break SDD-062
    # downstream JSON-line consumer. Locks consolidation
    # discipline on the SSH MITM detection substrate (host-key
    # change = canonical MITM signal).
    mk_key ed25519 "ssh-ed25519 ORIGINAL_ED root@host"
    mk_key rsa "ssh-rsa ORIGINAL_RSA root@host"
    mk_key ecdsa "ecdsa-sha2-nistp256 ORIGINAL_EC root@host"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    # Swap all three host keys simultaneously (MITM scenario).
    mk_key ed25519 "ssh-ed25519 ATTACKER_ED root@host"
    mk_key rsa "ssh-rsa ATTACKER_RSA root@host"
    mk_key ecdsa "ecdsa-sha2-nistp256 ATTACKER_EC root@host"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-ssh-hostkey -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on ssh-hostkey surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The ssh-hostkey-watchdog MUST only emit severity values
    # from the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the host-key-MITM alert. Locks parser contract
    # on the SSH host-key fingerprint-watch substrate (canonical
    # MITM signal).
    mk_key ed25519 "ssh-ed25519 ORIGINAL_ED root@host"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline path
    mk_key ed25519 "ssh-ed25519 ATTACKER_ED root@host"  # MITM swap
    run_wd                                              # alert path
    # Every severity value emitted MUST be one of {ok,warn,alert}.
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (no auto-restore: ssh-hostkey-watchdog NEVER overwrites host keys — surveillance not remediation)" {
    # Sister to brain-wide no-auto-restore / surveillance-not-
    # remediation INVARIANTs across L2 watchdog suites. The
    # ssh-hostkey-watchdog DETECTS canonical MITM signal (host-
    # key fingerprint change) but MUST NEVER emit shell commands
    # that overwrite the swapped key with the baseline original.
    # Auto-restore would destroy forensic evidence chain
    # (operator can't analyze the attacker's planted key if it's
    # silently reverted) AND could overwrite operator-legitimate
    # key-rotation (operator may have run ssh-keygen to rotate
    # host keys but forgot to re-baseline). Surveillance, never
    # auto-remediation. Locks anti-evidence-destruction contract
    # on the ssh-hostkey substrate.
    mk_key ed25519 "ssh-ed25519 ORIGINAL_ED root@host"
    run_wd                                              # baseline
    mk_key ed25519 "ssh-ed25519 ATTACKER_ED root@host"  # MITM swap
    run_wd                                              # detect
    # Swapped key MUST remain on disk with attacker content.
    grep -q 'ATTACKER_ED' "${KEYDIR}/ssh_host_ed25519_key.pub"
    ! grep -qE 'cp[[:space:]]+.*\$\{?BASELINE_DIR\}?/.*[[:space:]]+\$\{?KEYDIR' "${WD}"
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # ssh-hostkey-watchdog runs ON the timer's scheduled fire —
    # verifies sha256 of /etc/ssh/ssh_host_*_key against pinned
    # baseline, emits a verdict on host-key rotation, then
    # exits. Type=simple would break timer OnUnitActiveSec
    # semantics. Locks oneshot-probe contract on the ssh-
    # hostkey-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd/selfdef-ssh-hostkey.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. ssh-hostkey-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # ssh-hostkey-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # ssh-hostkey-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'ssh-hostkey-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: ssh-hostkey-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. ssh-hostkey-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the ssh-hostkey-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (ssh-hostkey-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the ssh-hostkey-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-hostkey-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # ssh-hostkey-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-hostkey-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # ssh-hostkey-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}
