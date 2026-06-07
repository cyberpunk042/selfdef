#!/usr/bin/env bats
# L2 bats functional tests for the nsswitch-watchdog scan script.
#
# /etc/nsswitch.conf maps each identity/name database to ordered lookup
# sources; each source X loads libnss_X.so into every getpwnam/gethostbyname
# caller. A rogue source (`passwd: files evil`) backdoors identity + auth
# resolution host-wide (T1556/T1574). Severity:
#   ok    → no delta
#   warn  → file hash changed / a known source added/reordered
#   alert → an UNKNOWN (non-standard) source on any db, OR a db line removed
#
# Run with: bats packaging/test/L2-nsswitch-watchdog.bats

WD="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd/nsswitch-watchdog.sh"

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
    CONF="${TMP}/nsswitch.conf"
}

teardown() { rm -rf "${TMP}"; }

run_wd() {
    PATH="${BIN}:${PATH}" \
    SELFDEF_NSSWITCH_PROFILE="${PROFILE:-report}" \
    SELFDEF_NSSWITCH_BASELINE="${BASELINE}" \
    SELFDEF_NSSWITCH_CONF="${CONF}" \
    bash "${WD}"
}

cap() { cat "${SELFDEF_TEST_LOGCAP}"; }

seed_benign() {
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
}

@test "benign nsswitch, first run → ok / baseline_initial" {
    seed_benign
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
    [ -f "${BASELINE}" ]
}

@test "unchanged nsswitch on second run → ok / nsswitch_intact" {
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_intact"'
    cap | grep -q '"severity":"ok"'
}

@test "an unknown (rogue) source on a db → alert / nsswitch_rogue_source" {
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "a database line removed → alert / nsswitch_db_removed" {
    seed_benign
    run_wd
    printf 'passwd: files\nshadow: files\nhosts: files dns\n' > "${CONF}"   # group line gone
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_db_removed"'
    cap | grep -q '"severity":"alert"'
}

@test "a benign known-source addition → warn / nsswitch_changed" {
    seed_benign
    run_wd
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns myhostname\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"event":"nsswitch_changed"'
    cap | grep -q '"severity":"warn"'
}

@test "a benign nsswitch is NOT flagged" {
    seed_benign
    run_wd
    ! cap | grep -q '"severity":"alert"'
    cap | grep -q '"severity":"ok"'
}

@test "enforce profile exits non-zero on a rogue source" {
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    PROFILE=enforce run run_wd
    [ "${status}" -ne 0 ]
    cap | grep -q '"severity":"alert"'
}

@test "baseline is chmod 0600 (confidentiality — nsswitch inventory enumerates identity-resolution providers)" {
    seed_benign
    run_wd
    [ "$(stat -c '%a' "${BASELINE}")" = "600" ]
}

@test "INVARIANT (known-source acceptance): `sss` (SSSD) on passwd is NOT flagged (LDAP/AD-integrated host)" {
    # SSSD is a canonical legit enterprise-NSS provider. Locks
    # that the KNOWN_NSS allow-list includes it.
    seed_benign
    run_wd
    printf 'passwd: files sss\ngroup: files sss\nshadow: files sss\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -qE '"severity":"(warn|ok)"'              # not alert — sss is known
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (known-source acceptance): `systemd` provider is NOT flagged (machined integration)" {
    seed_benign
    run_wd
    printf 'passwd: files systemd\ngroup: files systemd\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (known-source acceptance): `mdns_minimal` provider is NOT flagged (Avahi/Bonjour)" {
    seed_benign
    run_wd
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files mdns_minimal dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (rogue: multiple unknown sources on different dbs) → still alert (full-system rogue NSS attack)" {
    # A multi-db rogue NSS attack drops libnss_evil.so AND
    # libnss_backdoor.so on different dbs. Locks that the
    # watchdog catches a multi-db rogue addition (not just a
    # single-db one).
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files backdoor\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (pre-existing rogue): baseline_initial fires alert if nsswitch already has a rogue source at install-time" {
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "JSON record is emitted as a SINGLE main logger line (downstream JSON-line consumer contract)" {
    seed_benign
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-nsswitch -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (no auto-trust): nsswitch-watchdog does NOT refresh baseline on rogue detection — alert STAYS until operator updates" {
    # Rogue NSS sources are NEVER routine; the alert must persist
    # across runs until operator explicitly re-baselines. Locks
    # against a regression that copies the auto-trust pattern
    # from sister modules.
    seed_benign
    run_wd
    printf 'passwd: files evil\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # first delta — alert
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # alert STAYS
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (commented db line is NOT included in rogue-source inventory: # prefix filtered)" {
    # Operator notes about future db sources must not be parsed
    # as actual sources. A commented '# passwd: files evil' must
    # not surface as a rogue source.
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n# notes: discussed evil module\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"baseline_initial"'
    cap | grep -q '"severity":"ok"'
}

@test "INVARIANT (whitespace tolerance in db lookup: multi-space-separated sources normalized)" {
    # Operator may write 'passwd:  files  sss' with multiple spaces
    # between tokens. The parser must normalize whitespace.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd:  files  sss\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    # sss is a KNOWN source — even with weird whitespace it must
    # not be treated as rogue.
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (rogue sample format: db:rogue_source — operator triage payload)" {
    # The sample field shape lets operator instantly know WHICH
    # db gained which rogue source.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files evil_backdoor\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q 'passwd'
    cap | grep -q 'evil_backdoor'
}

@test "INVARIANT (known-source acceptance: ldap is NOT flagged — enterprise LDAP-integrated host)" {
    # ldap is a canonical legit enterprise-NSS provider via libnss-ldapd.
    # Locks that the KNOWN_NSS allow-list includes it.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files ldap\ngroup: files ldap\nshadow: files ldap\nhosts: files dns\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (rogue on hosts db — DNS-resolver hijack — also alerts)" {
    # hosts db is the DNS-resolver provider chain. A rogue source on
    # hosts db is a name-resolution hijack (T1556/T1574).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns evil_dns_hijack\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rogue on shadow db — credential-store hijack — also alerts)" {
    # shadow db backs the password hash store. A rogue source on shadow
    # backdoors the credential verification path.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files\ngroup: files\nshadow: files evil_cred_hijack\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (rogue on group db — group-membership hijack — also alerts)" {
    # Sister to rogue-on-passwd + rogue-on-shadow + rogue-on-hosts axes
    # already locked. group db backs the group-membership lookup. A
    # rogue source on group lets an attacker swap in their own libnss_
    # X.so that returns whatever group memberships they choose — direct
    # privesc vector (claim 'root', 'wheel', 'sudo' membership via the
    # rogue NSS provider). T1556/T1574 sister axis on the group-
    # membership resolution chain.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files\ngroup: files evil_group_hijack\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q '"event":"nsswitch_rogue_source"'
    cap | grep -q '"severity":"alert"'
}

@test "INVARIANT (known-source acceptance: sssd is NOT flagged — enterprise SSSD-integrated host)" {
    # Sister to the ldap known-source-acceptance INVARIANT already
    # locked. sssd is a canonical legitimate enterprise-NSS provider
    # via libnss-sss (the SSSD provider for AD/IPA/LDAP-backed
    # identity). Locks that the KNOWN_NSS allow-list includes sssd
    # alongside ldap (operator-friendly false-positive guard for
    # SSSD-integrated hosts).
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files sss\ngroup: files sss\nshadow: files sss\nhosts: files dns\n' > "${CONF}"
    run_wd
    ! cap | grep -q '"event":"nsswitch_rogue_source"'
}

@test "INVARIANT (DELTA detect — distinctive-attacker-named rogue NSS source surfaces in sample for operator-triage routing)" {
    # Sister to many other watchdog DELTA-detect sample-naming
    # INVARIANTs across the brain. When an attacker adds a
    # distinctively-named NSS module to passwd/group/shadow/
    # hosts (T1556.001 — Modify Authentication Process via
    # NSS module hijack; libnss_<distinctive>.so.2 gets
    # dlopen()'d by every name-resolution call), the rogue
    # module name MUST surface in the JSON sample so operator
    # dashboard routes triage to the right module.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files distinctive_attacker_mod\ngroup: files\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd
    cap | grep -q 'distinctive_attacker_mod'
}

@test "INVARIANT (rogue source on netgroup db — RBAC-substrate hijack — also alerts)" {
    # Sister to rogue-on-passwd / group / shadow / hosts dbs
    # already locked. The netgroup db is used for /etc/hosts.equiv
    # NIS-style trust groups + sudo Net_Groups + xinetd allow/
    # deny ACL semantics. Attacker injecting rogue NSS source on
    # netgroup hijacks the answer to "is host X a member of
    # group G?" — granting access regardless of actual host
    # group membership. T1556.001 — Modify Authentication Process
    # via NSS module hijack on the netgroup db. Closes axis-
    # parity with passwd/group/shadow/hosts dbs in the rogue-
    # source family.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetgroup: evil_nss\n' > "${CONF}"
    run_wd
    cap | grep -qE '"severity":"(alert|warn)"'
}

@test "INVARIANT (baseline re-establish on operator out-of-band deletion: missing baseline re-creates cleanly + emits baseline_initial)" {
    # Sister to brain-wide baseline-re-establish INVARIANTs.
    # Operator may wipe /var/lib/selfdef/nsswitch-baseline.tsv
    # during host triage to force a fresh inventory. The
    # watchdog MUST re-create the baseline cleanly on the next
    # scan AND emit baseline_initial (not crash AND not
    # silently no-op). Locks state-resilience on the NSS
    # provider surveillance surface (T1556.001 modify-auth-
    # process via NSS module hijack).
    seed_benign
    run_wd                                              # establishes baseline
    [ -f "${BASELINE}" ]
    rm -f "${BASELINE}"                                  # operator wipe
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # must re-establish
    [ -f "${BASELINE}" ]
    cap | grep -qE '"event":"baseline_initial"'
}

@test "INVARIANT (single MAIN logger record per scan — SDD-062 consumer dispatch contract)" {
    # Sister to brain-wide single-MAIN-logger INVARIANTs. Multi-
    # rogue scenario locks consolidation discipline on T1556.001
    # NSS module hijack surveillance.
    seed_benign
    run_wd
    : > "${SELFDEF_TEST_LOGCAP}"
    printf 'passwd: files evil1\ngroup: files evil2\nshadow: files evil3\nhosts: files dns evil4\n' > "${CONF}"
    run_wd
    main_count=$(cap | grep -cE '^-t selfdef-nsswitch -- ')
    [ "${main_count}" = "1" ]
}

@test "INVARIANT (severity bounded vocabulary {ok,warn,alert} — operator dashboard parser contract on nsswitch surface)" {
    # Sister to brain-wide severity-bounded-vocabulary INVARIANTs.
    # The nsswitch-watchdog MUST only emit severity values from
    # the closed set {ok,warn,alert} — never custom values
    # (critical, error, fatal, notice, info). Operator dashboard
    # parsers branch on the literal severity string; an out-of-
    # set value silently falls through routing and the operator
    # never sees the T1556.001 NSS module hijack alert. Locks
    # parser contract on the /etc/nsswitch.conf detection
    # surface.
    seed_benign
    : > "${SELFDEF_TEST_LOGCAP}"
    run_wd                                              # ok / baseline
    printf 'passwd: files evil-source\ngroup: files compat\nshadow: files\nhosts: files dns\n' > "${CONF}"
    run_wd                                              # alert path
    bad=$(grep -oE '"severity":"[^"]+"' "${SELFDEF_TEST_LOGCAP}" | grep -vE '"severity":"(ok|warn|alert)"' || true)
    [ -z "${bad}" ]
}

@test "INVARIANT (service unit declares Type=oneshot — timer-driven probe semantics)" {
    # Sister to brain-wide systemd Type=oneshot INVARIANT family.
    # nsswitch-watchdog runs ON the timer's scheduled fire —
    # diffs /etc/nsswitch.conf against baseline, emits a verdict
    # on hosts:/passwd: line backdoor sources, then exits.
    # Type=simple would break timer OnUnitActiveSec semantics.
    # Locks oneshot-probe contract on the nsswitch-watchdog
    # substrate.
    svc="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd/selfdef-nsswitch.service"
    [ -f "${svc}" ]
    grep -qE '^Type=oneshot' "${svc}"
}

@test "INVARIANT (module.toml TOML-parseable — anti-malformed-manifest contract)" {
    # Sister to brain-wide module.toml TOML-parseable INVARIANT
    # family. nsswitch-watchdog manifest declares install + profile gating
    # the resolver enforces; malformed manifest wedges the
    # nsswitch-watchdog scanner baseline. Python's tomllib is the
    # canonical parser. Locks anti-malformed-manifest on the
    # nsswitch-watchdog substrate.
    mtoml="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/module.toml"
    [ -f "${mtoml}" ]
    python3 -c "
import tomllib
with open('${mtoml}', 'rb') as fp:
    data = tomllib.load(fp)
assert data['name'] == 'nsswitch-watchdog', 'name mismatch'
assert 'version' in data, 'version missing'
assert 'install' in data, 'install missing'
"
}

@test "INVARIANT (no auto-fix: nsswitch-watchdog libexec NEVER writes back to its scanned target — surveillance not remediation)" {
    # Sister to brain-wide no-auto-{fix,delete,restore,uninstall}
    # family. nsswitch-watchdog is a DETECT-only watchdog: surveils its
    # target + emits verdicts, NEVER writes back. The libexec
    # script must NOT contain sed -i / tee mutations of its
    # scanned paths. Locks no-auto-fix on the nsswitch-watchdog
    # libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'sed[[:space:]]+-i.*\$\{?[A-Z_]*FILE'
        ! grep -vE '^[[:space:]]*#' "${sh}" | grep -qE 'tee[[:space:]].*\$\{?[A-Z_]*FILE'
    done
}

@test "INVARIANT (nsswitch-watchdog libexec uses set -u — anti-unbound-variable contract on the watchdog probe)" {
    # Sister to brain-wide shell-discipline INVARIANT family.
    # Locks set -u discipline on the nsswitch-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE '^set[[:space:]]+-u' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nsswitch-watchdog libexec uses logger -t with selfdef- tag — SDD-062 syslog routing contract)" {
    # Sister to brain-wide SDD-062 logger-tag INVARIANT family.
    # Locks SDD-062 logger-tag routing discipline on the
    # nsswitch-watchdog libexec substrate.
    wd_libexec="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    found=0
    for sh in "${wd_libexec}"/*.sh; do
        [ -f "${sh}" ] || continue
        if grep -qE 'logger[[:space:]]+-t[[:space:]]+selfdef-' "${sh}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nsswitch-watchdog timer unit declares RandomizedDelaySec — anti-thundering-herd cadence contract)" {
    # Sister to brain-wide timer-cadence INVARIANT family.
    # Locks anti-thundering-herd cadence discipline on the
    # nsswitch-watchdog timer substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^RandomizedDelaySec=' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nsswitch-watchdog timer unit declares Persistent=true — catch-up-after-downtime contract)" {
    # Sister to brain-wide timer Persistent INVARIANT family.
    # Locks Persistent= discipline on the nsswitch-watchdog timer
    # substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Persistent=true' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nsswitch-watchdog timer Unit= field references its companion .service — timer-to-service binding contract)" {
    # Sister to brain-wide systemd timer-Unit INVARIANT family.
    # Locks timer-to-service binding discipline on the
    # nsswitch-watchdog substrate.
    timer="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    found=0
    for t in "${timer}"/*.timer; do
        [ -f "${t}" ] || continue
        if grep -qE '^Unit=.*\.service' "${t}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nsswitch-watchdog service ExecStart references its libexec script — service-to-libexec binding contract)" {
    # Sister to brain-wide systemd ExecStart binding INVARIANT
    # family. Locks the service-to-libexec binding discipline
    # on the nsswitch-watchdog substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    found=0
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        if grep -qE '^ExecStart=' "${s}"; then
            found=1
        fi
    done
    [ "${found}" = "1" ]
}

@test "INVARIANT (nsswitch-watchdog service does NOT declare Restart=always — anti-restart-storm contract on oneshot probe)" {
    # Sister to brain-wide oneshot-probe INVARIANT family.
    # Locks anti-restart-storm discipline on the nsswitch-watchdog
    # service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        ! grep -qE '^Restart=always' "${s}"
        ! grep -qE '^Restart=on-failure' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares Description= — systemctl-status operator-readable label)" {
    # Sister to brain-wide systemd Description= INVARIANT
    # family. Locks Description-present discipline on the
    # nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Description=' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares TimeoutStartSec= — anti-hang oneshot bound contract)" {
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
    # bound discipline on the nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^TimeoutStartSec=' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares Nice= — idle-priority anti-resource-starve contract)" {
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
    # discipline on the nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Nice=' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares PrivateTmp= — /tmp namespace-isolation hardening contract)" {
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
    # discipline on the nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^PrivateTmp=' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares ProtectHome= — /home + /root + /run/user namespace-isolation hardening contract)" {
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
    # discipline on the nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ProtectHome=' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares NoNewPrivileges=true — privilege-escalation containment contract)" {
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
    # escalation containment discipline on the nsswitch-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^NoNewPrivileges=true' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares ReadWritePaths= — explicit-strict-mode-permitted-writes manifest contract)" {
    # Sister to brain-wide systemd ReadWritePaths= INVARIANT
    # family. Watchdog .service units run under ProtectSystem=
    # strict which forbids ALL writes to /etc, /usr, /boot —
    # the unit can ONLY write to paths explicitly enumerated
    # in ReadWritePaths=. Watchdog scripts MUST write to at
    # least /dev/log (logger(1) channel) + the canonical
    # selfdef state dir. A regression dropping ReadWritePaths=
    # would surface as EROFS at logger() call. Locks the
    # explicit-allowlist write-paths discipline on the nsswitch-
    # watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ReadWritePaths=' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit ExecStart references /usr/local/libexec/selfdef/ — operator-extension binary-path canonical contract)" {
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
    # nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^ExecStart=/usr/local/libexec/selfdef/' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares After= ordering directive — boot-sequencing contract)" {
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
    # nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^After=' "${s}"
    done
}

@test "INVARIANT (nsswitch-watchdog service unit declares Documentation= — operator-doc-link canonical contract)" {
    # Sister to brain-wide systemd Documentation= INVARIANT
    # family. Watchdog .service units MUST declare a
    # Documentation= directive pointing operators at the
    # module's README (canonical: https://github.com/
    # cyberpunk042/selfdef modules/<slug>-watchdog/README.md).
    # A regression dropping Documentation= would leave
    # operators triaging journald entries without a direct
    # docs link. Locks the Documentation= operator-doc-link
    # discipline on the nsswitch-watchdog service substrate.
    svc_dir="${BATS_TEST_DIRNAME}/../../modules/nsswitch-watchdog/systemd"
    for s in "${svc_dir}"/*.service; do
        [ -f "${s}" ] || continue
        grep -qE '^Documentation=' "${s}"
    done
}
