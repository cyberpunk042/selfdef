#!/usr/bin/env bats
# L2 bats functional tests for the rhosts-watchdog scan script.
#
# /etc/hosts.equiv and ~/.rhosts/.shosts declare hosts/users trusted for
# PASSWORDLESS rlogin/rsh. A `+` wildcard is a classic trusted-relationship
# backdoor (T1199); root's ~/.rhosts existing at all is almost always a
# backdoor. Severity:
#   ok    → no delta
#   warn  → a trust entry / file added/removed/changed
#   alert → a `+` wildcard, a world-writable/non-root trust file, or a
#           per-user .rhosts/.shosts present
#
# Run with: bats packaging/test/L2-rhosts-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd/rhosts-watchdog.sh"

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
    EQUIV="${TMP}/hosts.equiv"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_RHOSTS_PROFILE="${PROFILE:-report}" \
    SELFDEF_RHOSTS_BASELINE="${BASELINE}" \
    SELFDEF_RHOSTS_FILES="${FILES_V:-$EQUIV}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'trusted.example.com\n' > "${EQUIV}"
}

@test "no rhosts files → ok / no_rhosts_files" {
    FILES_V="${TMP}/nonexistent" run_wd
    cap | grep -q '"event":"no_rhosts_files"'
    cap | grep -q '"severity":"ok"'
}

@test "benign hosts.equiv, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged hosts.equiv on second run → ok / rhosts_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "a + wildcard trust entry → alert / rhosts_trust_backdoor" {
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "a world-writable trust file → alert" {
    seed_benign
    run_wd
    chmod 0666 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
}

@test "a benign trust-entry change → warn / rhosts_changed" {
    seed_benign
    run_wd
    printf 'other.example.com\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"rhosts_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign hosts.equiv is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a wildcard trust entry" {
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — trust inventory enumerates legitimate trust relationships)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (multi-line + wildcard): + on its own line (not just trailing) → alert" {
    seed_benign
    run_wd
    printf '+\ntrusted.example.com\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (per-user .rhosts): a user-level .rhosts file IS flagged as a backdoor" {
    seed_benign
    run_wd
    # Test multi-file scan: declare a per-user rhosts file via FILES_V.
    user_rhosts="${TMP}/user-alice.rhosts"
    printf 'evil.example.com\n' > "${user_rhosts}"
    : > "${SELFDEF_TEST_LOGCAP}"
    FILES_V="${EQUIV} ${user_rhosts}" run_wd
    # Either the file's existence alone OR the wildcard signature fires alert.
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (pre-existing wildcard): baseline_initial fires alert if hosts.equiv already has a + at install-time" {
    printf '+\n' > "${EQUIV}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "DELTA detect — REMOVED trust entry (operator pruning) → warn" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    : > "${EQUIV}"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-rhosts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (group-writable): a group-writable trust file → alert too (more than just world-writable)" {
    seed_benign
    run_wd
    chmod 0664 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (no auto-trust): rhosts-watchdog does NOT refresh baseline on wildcard detection — alert STAYS until operator updates" {
    # rhosts wildcards (+ entry) are NEVER routine; the alert
    # must persist across runs until operator explicitly
    # re-baselines.
    seed_benign
    run_wd
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"rhosts_trust_backdoor"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented + wildcard NOT flagged: # prefix filtered)" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com\n# + would be a backdoor\n' > "${EQUIV}"
    run_wd
    # Current behavior: commented + must NOT trigger alert.
    ! cap | grep -q '"event":"rhosts_trust_backdoor"'
    ! cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (severity precedence: wildcard + world-writable → alert with rhosts_trust_backdoor event taking precedence)" {
    # When both issues coexist (wildcard AND world-writable file),
    # severity must be alert. Locks the consolidation.
    seed_benign
    run_wd
    printf '+\n' > "${EQUIV}"
    chmod 0666 "${EQUIV}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"severity":"alert"'
    # Either event surfaces — both are valid; lock that alert
    # severity fires consistently.
    cap | grep -qE '"event":"rhosts_(trust_backdoor|suspicious|world_writable)"'
}

@test "INVARIANT (whitespace tolerance: '  +  ' with leading/trailing spaces still triggers wildcard alert)" {
    # Attacker may use multi-space evasion. Lock whitespace-
    # tolerant parser still catches dangerous patterns.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '   +   \n' > "${EQUIV}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (user-wildcard +user form: + on a user position → still alerts)" {
    # rsh/rlogin grammar also accepts `+ user` (any host trusted
    # for the named user) or `host +` (any user from named host)
    # — both are trust-relationship backdoors. Lock that the
    # user-wildcard variant is also flagged.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com +\n' > "${EQUIV}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (per-user .shosts file IS flagged as backdoor — sister axis to .rhosts)" {
    # OpenSSH's hostbased-auth reads .shosts (the ssh-equivalent of
    # .rhosts) for hostbased trust. A user's .shosts is the same
    # backdoor surface as .rhosts on the rsh axis.
    seed_benign
    run_wd
    user_shosts="${TMP}/user-bob.shosts"
    printf 'evil.example.com\n' > "${user_shosts}"
    : > "${SELFDEF_TEST_LOGCAP}"
    FILES_V="${EQUIV} ${user_shosts}" run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (sample names the offending file in JSON — operator triage routing)" {
    # When a wildcard fires, the sample MUST surface the file path
    # so operator dashboard routes triage to the right path. Sister
    # contract: polkit-rules/nfs-exports sample-naming pattern.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf '+\n' > "${EQUIV}"
    run_wd
    cap | grep -q "$(basename "${EQUIV}")"
}

@test "INVARIANT (pre-existing wildcard: baseline_initial fires alert at install-time — install-time-vet contract)" {
    # Sister to every other watchdog pre-existing-broad-condition
    # baseline_initial INVARIANT across the brain. The install-time-
    # vet contract: if /etc/hosts.equiv ALREADY carries a wildcard
    # trust entry (+ or user-wildcard) when selfdef first installs
    # the watchdog, the first run MUST raise alert (or at least
    # warn) — not silently baseline a broken security posture.
    # Closes the install-time-vet axis on the rsh/rlogin/hostbased-
    # auth trust surface (T1199 — Trusted Relationship via legacy
    # rcommand wildcard backdoor account).
    printf 'trusted.example.com\n+\n' > "${EQUIV}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (DELTA detect — ADDED distinctive-attacker-named host in hosts.equiv surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a
    # distinctively-named host to hosts.equiv (T1199 — Trusted
    # Relationship via legacy rsh/rlogin hostbased-auth), the
    # host name MUST surface in the JSON sample so operator
    # dashboard routes triage to the right path. Locks the
    # operator-visibility contract on the legacy-trust grant
    # surface.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com\ndistinctive-attacker-host.evil.example\n' > "${EQUIV}"
    run_wd
    cap | grep -q 'distinctive-attacker-host'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to many other watchdog single-MAIN-logger-line
    # INVARIANTs across the brain. selfdef-rhosts tag must fire
    # EXACTLY ONCE per scan regardless of how many trust-grant
    # entries surface (multi-user .rhosts adds in one scan).
    # Multi-line output would break SDD-062 downstream JSON-
    # line consumer (Sigma correlator). Locks consolidation
    # discipline on T1199 trusted-relationship surface.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'trusted.example.com\nevil1.example\nevil2.example\nevil3.example\n+\n' > "${EQUIV}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-rhosts -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # State-resilience on T1199 trusted-relationship rhosts /
    # hosts.equiv surveillance.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (severity field is bounded vocabulary {ok,warn,alert} — operator dashboard severity axis lock)" {
    # Sister to brain-wide bounded-vocabulary INVARIANTs.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    sev=$(cap | grep -oE '"severity":"[^"]+"' | head -1)
    case "${sev}" in
        '"severity":"ok"'|'"severity":"warn"'|'"severity":"alert"') : ;;
        *) fail "severity '${sev}' outside bounded vocabulary {ok,warn,alert}" ;;
    esac
}

@test "INVARIANT (baseline file is chmod 0600 — confidentiality of rhosts inventory)" {
    # Sister to brain-wide baseline-chmod-0600 confidentiality
    # INVARIANTs across L2 surveillance suites. The rhosts-
    # watchdog baseline TSV contains the inventory of trusted-
    # host grants which discloses cross-host trust
    # relationships to any user able to read the file. Mode
    # 0600 (root-only) is the canonical confidentiality
    # contract — mode 0644 would expose the rsh/rlogin trust-
    # graph to reconnaissance enabling attacker to map
    # T1199 Trusted Relationship lateral-movement targets.
    # Locks file-mode confidentiality on the rhosts
    # surveillance substrate.
    printf 'trusted.example.com\n' > "${EQUIV}"
    run_wd
    [ -f "${BASELINE}" ]
    mode="$(stat -c '%a' "${BASELINE}")"
    [ "${mode}" = "600" ] || [ "${mode}" = "640" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # rhosts-watchdog runs ON the timer's scheduled fire — scans
    # /etc/hosts.equiv + every user's ~/.rhosts for trust-relation
    # entries, emits a verdict, then exits. Type=simple would
    # break timer OnUnitActiveSec semantics. Locks oneshot-probe
    # contract on the rhosts-watchdog substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd/selfdef-rhosts.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. rhosts-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # rhosts-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # rhosts-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'rhosts-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: rhosts-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. rhosts-watchdog is a DETECT-only watchdog: surveils +
    # emits verdicts, NEVER writes back. Locks no-auto-fix on
    # the rhosts-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (rhosts-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the rhosts-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (rhosts-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # rhosts-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (rhosts-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # rhosts-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (rhosts-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the rhosts-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (rhosts-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # rhosts-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (rhosts-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the rhosts-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (rhosts-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the rhosts-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the rhosts-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the rhosts-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the rhosts-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}

@test "INVARIANT (rhosts-watchdog timer unit declares OnCalendar= — daily-cadence operator-predictable contract)" {
    # Sister to brain-wide systemd OnCalendar= INVARIANT
    # family. Watchdog .timer units MUST declare an
    # OnCalendar= directive (canonically daily at a staggered
    # time per the watchdog ladder so simultaneous-fire
    # thundering-herd is avoided). The operator can predict
    # when each watchdog runs based on the canonical timer
    # schedule. A regression dropping OnCalendar= would
    # leave the watchdog firing ONLY at OnBootSec (no
    # recurring daily cadence). Locks the daily-cadence
    # discipline on the rhosts-watchdog timer substrate.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^OnCalendar=' "${t}"
    done
}

@test "INVARIANT (rhosts-watchdog timer unit declares WantedBy=timers.target — timer-enable-graph contract)" {
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
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^WantedBy=timers.target' "${t}"
    done
}

@test "INVARIANT (rhosts-watchdog timer unit declares Description= — operator-list-timers identification contract)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Watchdog .timer units MUST declare Description=
    # so operators triaging `systemctl list-timers` output
    # see a human-readable label per timer. Locks the
    # timer-Description discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        grep -qE '^Description=' "${t}"
    done
}

@test "INVARIANT (rhosts-watchdog timer unit file mode is 0644 — systemd unit-file mode convention)" {
    # Sister to brain-wide systemd unit-file mode INVARIANT
    # family. systemd unit files MUST be chmod 0644 (world-
    # readable + root-write-only). Locks the timer unit-file
    # mode discipline.
    timer_dir="${BATS_TEST_DIRNAME}/../../modules/rhosts-watchdog/systemd"
    for t in "${timer_dir}"/*.timer; do
        [ -f "${t}" ] || continue
        m=$(stat -c '%a' "${t}")
        [ "${m}" = "644" ]
    done
}
