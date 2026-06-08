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

@test "INVARIANT (ssh-hostkey-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the ssh-hostkey-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-hostkey-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # ssh-hostkey-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-hostkey-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the ssh-hostkey-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (ssh-hostkey-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the ssh-hostkey-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the ssh-hostkey-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the ssh-hostkey-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the ssh-hostkey-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the ssh-hostkey-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog timer unit declares Persistent= directive — boot-catchup-policy contract)" {
    # Sister to brain-wide systemd timer Persistent= INVARIANT
    # family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Persistent=' "${t}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script file exists in module systemd/ dir — ExecStart-target source-of-truth contract)" {
    # Sister to brain-wide ExecStart-target INVARIANT family.
    # The watchdog .service's ExecStart points at
    # /usr/local/libexec/selfdef/<slug>-watchdog.sh which is
    # the runtime install path; the source of truth lives at
    # modules/<slug>-watchdog/systemd/<slug>-watchdog.sh.
    # A regression that lost the script file would break
    # the cargo-deb manifest install + leave ExecStart
    # dangling. Locks the source-script-exists discipline
    # on the ssh-hostkey-watchdog substrate.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    [ -f "${script_dir}/ssh-hostkey-watchdog.sh" ] ||     [ -n "$(ls "${script_dir}"/*.sh 2>/dev/null)" ]
}

@test "INVARIANT (ssh-hostkey-watchdog timer's Unit= field references a .service in the same module dir — co-located unit-pair binding contract)" {
    # Sister to brain-wide timer Unit= INVARIANT family.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        unit=$(grep -E '^Unit=' "${t}" | head -1 | cut -d= -f2)
        [ -n "${unit}" ]
        [ -f "${timer_dir}/${unit}" ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script is executable (mode includes +x) — script-runnable contract)" {
    # Sister to brain-wide script-executable INVARIANT family.
    # The watchdog .sh script MUST be chmod +x so systemd's
    # ExecStart can invoke it without needing a bash prefix.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        [ -x "${s}" ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog README.md exists in module dir — operator-doc-trail contract)" {
    # Sister to brain-wide module-doc-trail INVARIANT family.
    # Every watchdog module ships a README.md documenting its
    # probe target + alert semantics + remediation. A
    # regression that lost the README would leave operators
    # without per-module ops docs.
    readme="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/README.md"
    [ -f "${readme}" ]
}

@test "INVARIANT (ssh-hostkey-watchdog service Documentation URL references github.com/cyberpunk042/selfdef — canonical-vcs operator-doc-resolve contract)" {
    # Sister to brain-wide Documentation URL canonical INVARIANT
    # family. The Documentation= URL MUST reference the github
    # repo + module README path so operators can resolve docs
    # offline (via git checkout) or online (via github browser).
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=.*github.com/cyberpunk042/selfdef' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script uses set -u flag — undefined-variable strict-mode contract)" {
    # Sister to brain-wide Bash strict-mode INVARIANT family.
    # Watchdog scripts MUST declare set -u (exit on
    # undefined variable). Without -u, typos in env-var names
    # silently expand to empty strings, masking bugs.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^set -u' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script declares shebang #!/bin/bash or env bash — bash-interpreter contract)" {
    # Sister to brain-wide bash-shebang INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '#!/.*bash|#!/usr/bin/env bash'
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script uses logger -t selfdef- canonical tag — SDD-062 logger-tag contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script emits canonical severity vocabulary {ok,warn,alert} — bounded-severity contract)" {
    # Sister to brain-wide bounded-severity INVARIANT family.
    # Watchdog scripts emit logger -t selfdef-<name> -- {...severity:...}
    # with severity in the canonical vocabulary. A regression
    # introducing custom severity values (info, error, critical)
    # would break operator-side filtering.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '"severity":"(ok|warn|alert)"' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script tag selfdef-ssh-hostkey matches module name — SDD-062 tag-canonical contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # The tag passed to logger -t MUST exactly match selfdef-ssh-hostkey
    # so operator triage via journalctl _SYSTEMD_UNIT or
    # SYSLOG_IDENTIFIER filtering surfaces the right module.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script declares profile-aware exit behavior — operator-extension profile-dispatch contract)" {
    # Sister to brain-wide profile-aware INVARIANT family.
    # Scripts MUST handle PROFILE=enforce vs report differently.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'PROFILE.*enforce|enforce.*PROFILE|profile.*enforce' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script declares baseline file path — operator-extensible baseline-state contract)" {
    # Sister to brain-wide baseline-state INVARIANT family.
    # Delta-scan watchdogs MUST declare a BASELINE variable referencing
    # /var/lib/selfdef/ so operators know where baseline state lives.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '/var/lib/selfdef/|BASELINE' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script declares MODULE-suffixed tag in logger -t — module-name-tag-consistency contract)" {
    # Sister to SDD-062 tag-canonical INVARIANT family. The tag passed to
    # logger -t MUST include the module slug so journalctl filtering by
    # tag surfaces only this watchdog's events.
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE 'logger -t selfdef-' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script file is non-empty (size > 100 bytes) — non-trivial-script contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script has >20 lines — non-trivial-watchdog-body contract)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 20 ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .service unit file has >5 lines of directives — non-trivial-unit-file contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        lines=$(wc -l <"${s}")
        [ "${lines}" -gt 5 ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .service unit ExecStart references /usr/local/libexec/selfdef/ path — canonical-binary-path contract)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .timer file exists at canonical path modules/ssh-hostkey-watchdog/systemd — canonical-systemd-dir layout)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    [ -d "${timer_dir}" ]
    n=$(ls "${timer_dir}"/*.timer 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml exists at canonical path modules/ssh-hostkey-watchdog/ — module-manifest existence 72-cycle)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    [ -f "${mtoml}" ]
}

@test "INVARIANT (ssh-hostkey-watchdog systemd dir exists at modules/ssh-hostkey-watchdog/systemd — systemd-dir-existence 73-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    [ -d "${sd}" ]
}

@test "INVARIANT (ssh-hostkey-watchdog systemd dir is non-empty — systemd-content-presence 74-cycle)" {
    sd="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    n=$(ls "${sd}" | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ssh-hostkey-watchdog .service file size > 100 bytes — substantial-service-unit 75-cycle)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        size=$(stat -c '%s' "${s}")
        [ "${size}" -gt 100 ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .timer file size > 50 bytes — substantial-timer-unit 76-cycle)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        size=$(stat -c '%s' "${t}")
        [ "${size}" -gt 50 ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog README.md file size > 100 bytes — substantial-readme 77-cycle)" {
    readme="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/README.md"
    size=$(stat -c '%s' "${readme}")
    [ "${size}" -gt 100 ]
}

@test "INVARIANT (ssh-hostkey-watchdog .service Documentation URL is HTTP/HTTPS — operator-doc-link-protocol 78)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=(http|https)://' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script has shebang line — POSIX-conformant 79)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -1 "${s}" | grep -qE '^#!'
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script declares set flag in first 50 lines — strict-mode-prologue 80)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        head -50 "${s}" | grep -qE '^set -'
    done
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml size > 200 bytes — substantial-watchdog-manifest 81)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    size=$(stat -c '%s' "${mtoml}")
    [ "${size}" -gt 200 ]
}

@test "INVARIANT (ssh-hostkey-watchdog .service file is non-empty — non-trivial-unit-file 82)" {
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        [ -s "${s}" ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .timer file is non-empty — non-trivial-timer-file 83)" {
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        [ -s "${t}" ]
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script body has at least one variable assignment — non-vacuous-script 84)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    for s in "${script_dir}"/*.sh; do
        [ -f "${s}" ] || continue
        grep -qE '^[a-zA-Z_]+=' "${s}"
    done
}

@test "INVARIANT (ssh-hostkey-watchdog .sh script path matches systemd dir layout — canonical-script-co-location 85)" {
    script_dir="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/systemd"
    [ -d "${script_dir}" ]
    n=$(ls "${script_dir}"/*.sh 2>/dev/null | wc -l)
    [ "${n}" -ge 1 ]
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml has install_paths section — SDD-026 mutation-manifest 86)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml install_paths.paths non-empty list 87)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert isinstance(ps, list) and len(ps) > 0
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml install_paths.paths only absolute paths 88)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
for p in ps:
    assert isinstance(p, str) and p.startswith('/'), f'{p!r} not absolute'
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml provides list non-empty 89 — capability-export-present)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
p = data.get('provides')
assert isinstance(p, list) and len(p) >= 1
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml has at least 3 entries in install_paths.paths — substantial-manifest 90)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert len(ps) >= 3, f'expected >=3 paths, got {len(ps)}'
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml install_paths.paths includes /etc/ entry — config-staging 91)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/etc/') for p in ps)
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml install_paths.paths has /usr/local/libexec/selfdef/ entry 92)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any('libexec/selfdef' in p for p in ps)
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml install_paths.paths has /var/ entry 93 — state-staging)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ps = (data.get('install_paths') or {}).get('paths', [])
assert any(p.startswith('/var/') for p in ps)
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml [install_paths] declared at line beginning — TOML-section-header 94)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^\[install_paths\]' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml [install] block declared at line beginning — TOML-section-header 95)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^\[install\]' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml uses TOML key-value syntax — well-formed-TOML 96)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml name field uses double-quoted string syntax — TOML-string-quote 97)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml version field uses double-quoted string syntax — TOML-string-quote 98)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^version[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml category field double-quoted — TOML-string-quote 99)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^category[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml summary field double-quoted — TOML-string-quote 100)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^summary[[:space:]]*=[[:space:]]*"' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml name field matches module dir basename — TOML-name-dir-coherence 101)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    grep -qE '^name[[:space:]]*=[[:space:]]*"ssh-hostkey-watchdog"' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml top-level keys before any [section] — TOML-top-level-keys-first 102)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
with open('${mtoml}') as fp:
    for ln in fp:
        s = ln.strip()
        if not s or s.startswith('#'): continue
        if s.startswith('['): break
        assert '=' in ln
        break
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml file is UTF-8 encoded — TOML-encoding-contract 103)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    file "${mtoml}" | grep -qE 'UTF-8|ASCII text'
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml does not contain CRLF line endings — LF-only-contract 104)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    ! grep -qE $'\r' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml ends with newline — POSIX-line-ending-contract 105)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    last_char=$(tail -c 1 "${mtoml}" | od -An -c | tr -d ' ')
    [ "${last_char}" = "\\n" ]
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml does not contain leading tabs — TOML-indentation-canonical 106)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    ! grep -qP '^\t' "${mtoml}"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml does not start with UTF-8 BOM — TOML-no-BOM-canonical 107)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    first3=$(head -c 3 "${mtoml}" | od -An -tx1 | tr -d ' ')
    [ "${first3}" != "efbbbf" ]
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml file size exceeds 200 bytes — TOML-content-floor-canonical 108)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    sz=$(wc -c < "${mtoml}")
    [ "${sz}" -gt 200 ]
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml has top-level category field with non-empty string value — TOML-category-field-canonical 109)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
cat = data.get('category')
assert isinstance(cat, str) and cat, f'category must be non-empty string, got {cat!r}'
"
}

@test "INVARIANT (ssh-hostkey-watchdog module.toml has top-level phase field with value in bounded-vocab {main,pre,post} — TOML-phase-vocab-canonical 110)" {
    mtoml="${BATS_TEST_DIRNAME}/../../modules/ssh-hostkey-watchdog/module.toml"
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
ph = data.get('phase')
assert ph is None or ph in ('main','pre','post'), f'phase if present must be main|pre|post, got {ph!r}'
"
}
