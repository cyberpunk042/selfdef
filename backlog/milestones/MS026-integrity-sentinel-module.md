# MS026 — Integrity-sentinel module

> Parent: `backlog/milestones/INDEX.md` row MS026 (source ref `modules/integrity-sentinel`).
> Source: `modules/integrity-sentinel/` (655 lines across README.md, module.toml, paths.txt.default, profiles/strict.toml, profiles/warn-only.toml, install/apply.sh, install/check.sh, install/lib.sh, install/uninstall.sh).
> All entries below extract verbatim. No invention.

## Epics (E0261–E0270)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0261 | Module identity — `integrity-sentinel` v0.1.1, category=hardening, summary "SHA256 baseline verification for policy artifacts. Fail-closed on drift."; "Records a SHA256 baseline of selfdef's policy artifacts and verifies the host still matches"; "Fail-closed by default: any drift in a baselined file (modified, removed, or a new file matching a tracked glob) makes `selfdefctl modules apply` exit non-zero"; "This is the answer to 'did anyone tamper with my rules / configs / module install scripts since I sealed the host?' — not as a crypto-anchored attestation (no signing, no remote attestation), but as a tripwire the operator owns the keys to" | `module.toml` 1–4 + `README.md` 1–11 |
| E0262 | What gets baselined — set of paths to track is OPERATOR-DEFINED in plain text file (one absolute path per line; globs and `**` expanded); default set shipped at `paths.txt.default` covers 6 categories of selfdef's own integrity artifacts: `/etc/selfdef/selfdef.toml` daemon config / `/etc/selfdef/modules.toml` host modules list / `/etc/selfdef/modules/*.toml` per-module configs / `/etc/selfdef/rules.d/**/*.yml` + .yaml correlator rules / `/usr/share/selfdef/modules/*/module.toml` module manifests / `/usr/share/selfdef/modules/*/install/*.sh` + `install/profiles/*.sh` every executable selfdef's runner can `bash <script>` against ("tampering here would let an attacker substitute their own apply.sh and have selfdef execute it"); "Copy the default to /etc/selfdef/integrity-sentinel/paths.txt and edit. The module deliberately does not install the file to that path automatically — picking what to baseline is a security decision the operator makes" | `README.md` 13–31 + `paths.txt.default` 1–24 |
| E0263 | Two profiles — `strict` (default; Drift behavior: "Exit non-zero on any drift. `selfdefctl modules apply` halts"; When to use: "Production. The whole point of the module"; severity default high) + `warn-only` (Drift behavior: "Report ok with 'DRIFT detected (warn-only: not blocking)' in the status message"; When to use: "Bring-up — while you stabilise what's in the baseline. Flip to strict once the noise is gone"; severity default low so doesn't trip is_actionable filter); "In both modes the full diff (`diff -u <baseline> <current>`) is written to stderr so the operator can triage immediately" | `README.md` 33–41 + `profiles/strict.toml` 1–32 + `profiles/warn-only.toml` 1–24 |
| E0264 | Lifecycle — 4-step happy path: 1) Set up paths file once (`mkdir -p /etc/selfdef/integrity-sentinel` + `cp /usr/share/selfdef/modules/integrity-sentinel/paths.txt.default /etc/selfdef/integrity-sentinel/paths.txt` + `nano /etc/selfdef/integrity-sentinel/paths.txt`); 2) Activate module in `/etc/selfdef/modules.toml`; 3) First apply seals baseline (`selfdefctl modules apply --only integrity-sentinel` → "ok: baseline created (N entries) at /var/lib/selfdef/integrity-sentinel/baseline.sha256"); 4) Subsequent applies verify (`selfdefctl modules apply` → "ok: baseline matches (N entries)") | `README.md` 43–62 |
| E0265 | Re-sealing after intentional changes — when operator legitimately updates a config/rule/module-script, existing baseline is stale and apply will refuse; canonical re-seal = `selfdefctl modules uninstall` + `selfdefctl modules apply --only integrity-sentinel`; "This is intentional friction: re-sealing is a deliberate act, never a silent side-effect of a routine apply"; one-shot operator alternative = `rm /var/lib/selfdef/integrity-sentinel/baseline.sha256` + `selfdefctl modules apply --only integrity-sentinel` (equivalent to uninstall+apply pair) | `README.md` 64–85 |
| E0266 | Baseline format — `sha256sum(1)` format (`<sha256-hex>  <abs-path>` record per line, sorted by path); "Both because it's the standard format on Linux and because it's directly verifiable without going through selfdef" via `sha256sum -c /var/lib/selfdef/integrity-sentinel/baseline.sha256`; "That gives operators a useful out-of-band path if `selfdefctl` itself is in doubt" | `README.md` 87–99 |
| E0267 | Config schema — `profile = "strict"` (strict|warn-only) / `paths_file = "/etc/selfdef/integrity-sentinel/paths.txt"` / `baseline_path = "/var/lib/selfdef/integrity-sentinel/baseline.sha256"` / `on_missing = "create"` (create|fail); optional notifier-wiring keys: `event_stream_path = "/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"` / `event_severity_strict = "high"` / `event_severity_warn = "low"` | `README.md` 101–113 |
| E0268 | Notifying on drift — out of box drift surfaces only in structured-status JSON; wiring drift into notifier chain (ntfy / Signal) by setting `event_stream_path` to JSONL the daemon's `eventstream` collector tails; OCSF Detection Finding class 2004 appended via `selfdefctl events emit`; "The daemon picks it up, the responder routes any `Findings`-category event through the notifier chain, and the operator gets a Signal / ntfy ping"; "Leave `event_stream_path` unset to suppress emission entirely — the structured-status surface is unaffected"; `on_missing = "fail"` rationale — "right answer once you've sealed the initial baseline through an out-of-band channel"; "It refuses to silently create a new baseline if the expected one is missing — which would otherwise be an exploitable race: an attacker who deleted the baseline file and triggered an apply could re-baseline a host they'd already tampered with" | `README.md` 115–151 |
| E0269 | Scope owned/not-owned — Owns: 1) baseline file at `baseline_path` (default `/var/lib/selfdef/integrity-sentinel/baseline.sha256`); 2) reading `paths_file` and computing current view of every matched regular file. Does NOT own: paths file itself (operator-managed) / integrity of baseline file (operator should `0600` it; module sets that on creation but doesn't enforce it on each apply) / cryptographic signing of baseline ("SHA256 is integrity, not authenticity — if an attacker has write access to both the tracked files AND the baseline, this module can't help. Pair with filesystem-level immutability (`chattr +i`) or out-of-band baseline storage if you need stronger guarantees") | `README.md` 153–172 |
| E0270 | Caveats + manifest properties — Symlinks (module follows; sha256sum default; tracked symlink target's hash is baselined; replacing symlink to point elsewhere DETECTED; replacing target's content DETECTED; replacing symlink with copy of target NOT detected — same hash) + Globs (`*` and `**` with bash globstar+nullglob; non-matching contribute zero entries) + Directories and special files skipped (only regular files hashed) + Ordering vs rest of `modules apply` (manifest declares `phase = "pre"` so runs before any `main`-phase module; drift detection in strict halts apply before anything else mutates host state — "intended security posture"); manifest properties — single-instance (`instanced = false`) + provides=baseline-attestation + 2 required binaries (sha256sum + diff) + [daemon_requires] block declares `collectors.eventstream.enabled=true` + `collectors.eventstream.paths=["${event_stream_path}"]` per SDD-002 D-1 + F-2026-018 | `README.md` 173–189 + `module.toml` 1–45 |

## Modules (M00655–M00680)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00655 | `module.toml` — 44-line manifest (single-instance, phase=pre, [daemon_requires]) | `module.toml` 1–44 | E0261 + E0270 |
| M00656 | `README.md` — 189-line operator doc with full lifecycle + caveats | `README.md` 1–189 | E0261 |
| M00657 | `paths.txt.default` — 24-line default paths set (6 category groups) | `paths.txt.default` 1–24 | E0262 |
| M00658 | `profiles/strict.toml` — 32-line default profile (fail-closed + high severity) | `profiles/strict.toml` 1–32 | E0263 |
| M00659 | `profiles/warn-only.toml` — 24-line bring-up profile (report ok + low severity) | `profiles/warn-only.toml` 1–24 | E0263 |
| M00660 | `install/apply.sh` — 107-line idempotent applier (first-run seals + subsequent verifies + drift summary + event emission) | `install/apply.sh` 1–107 | E0264 + E0268 |
| M00661 | `install/check.sh` — 61-line side-effect-free verifier (missing-baseline → fail; never creates) | `install/check.sh` 1–61 | E0264 |
| M00662 | `install/lib.sh` — 150-line module-specific helper lib (expand_paths + compute_baseline + emit_drift_event) | `install/lib.sh` 1–150 | E0264 + E0268 |
| M00663 | `install/uninstall.sh` — 46-line tear-down (manifest-walked + legacy-path fallback; preserves paths_file) | `install/uninstall.sh` 1–46 | E0265 |
| M00664 | Provided surface — `baseline-attestation` (the SHA256-baseline + verify capability) | `module.toml` 8 | E0270 |
| M00665 | Required binary — `sha256sum` | `module.toml` 12 | E0270 |
| M00666 | Required binary — `diff` | `module.toml` 13 | E0270 |
| M00667 | Single-instance constraint — `instanced = false` (host has exactly one integrity baseline) | `module.toml` 20 | E0270 |
| M00668 | Lifecycle phase — `phase = "pre"` (runs before any `main` module) | `module.toml` 25 | E0270 |
| M00669 | [daemon_requires] block — `collectors.eventstream.enabled = true` + `collectors.eventstream.paths = ["${event_stream_path}"]` per SDD-002 D-1 + F-2026-018 | `module.toml` 42–45 | E0270 |
| M00670 | Helper — `expand_paths` (globstar+nullglob subshell; refuses non-absolute paths; only baselines regular files; sorts NUL-separated deduped) | `install/lib.sh` 35–84 | M00662 |
| M00671 | Helper — `compute_baseline` (xargs -0 sha256sum + LC_ALL=C sort -k 2) | `install/lib.sh` 86–94 | M00662 |
| M00672 | Helper — `emit_drift_event` (OCSF class 2004 Detection Finding via `selfdefctl events emit`; gated on event_stream_path; DRY_RUN-aware; best-effort failures don't fail the pipeline) | `install/lib.sh` 96–150 | M00662 |
| M00673 | F-2027-024 manifest integration — `module_record_file` / `module_render_files` / `module_clear_manifest` replaces hand-curated BASELINE_PATH duplication | `install/lib.sh` 9–14 + `apply.sh` 69–72 + `uninstall.sh` 14–25 | M00660 + M00663 |
| M00674 | Profile `strict` — default; fail-closed; severity high; event emission ON by default per SDD-002 + F-2026-018 | `profiles/strict.toml` 1–32 | E0263 |
| M00675 | Profile `warn-only` — bring-up; report ok with DRIFT prefix; severity low; doesn't trip is_actionable filter | `profiles/warn-only.toml` 1–24 | E0263 |
| M00676 | Path category — daemon + host configs (selfdef.toml + modules.toml + modules/*.toml) | `paths.txt.default` 8–10 | E0262 |
| M00677 | Path category — correlator rules (/etc/selfdef/rules.d/**/*.yml + .yaml) | `paths.txt.default` 13–14 | E0262 |
| M00678 | Path category — module manifests (/usr/share/selfdef/modules/*/module.toml) | `paths.txt.default` 17 | E0262 |
| M00679 | Path category — module install scripts (/usr/share/selfdef/modules/*/install/*.sh + install/profiles/*.sh) | `paths.txt.default` 20–24 | E0262 |
| M00680 | OCSF event emission — class_uid=2004 (Detection Finding) + activity_id=1 + severity=high|low + source=selfdef.integrity-sentinel + message=SUMMARY + out=$stream_path | `install/lib.sh` 138–148 | E0268 |

## Features (F03001–F03120)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F03001 | module.toml `name = "integrity-sentinel"` | `module.toml` 1 | M00655 |
| F03002 | module.toml `version = "0.1.1"` | `module.toml` 2 | M00655 |
| F03003 | module.toml `summary = "SHA256 baseline verification for policy artifacts. Fail-closed on drift."` | `module.toml` 3 | M00655 |
| F03004 | module.toml `category = "hardening"` | `module.toml` 4 | M00655 |
| F03005 | module.toml `depends_on = []` | `module.toml` 6 | M00655 |
| F03006 | module.toml `conflicts = []` | `module.toml` 7 | M00655 |
| F03007 | module.toml `provides = ["baseline-attestation"]` | `module.toml` 8 | M00664 |
| F03008 | module.toml `consumes = []` | `module.toml` 9 | M00655 |
| F03009 | module.toml `requires` — binary sha256sum | `module.toml` 12 | M00665 |
| F03010 | module.toml `requires` — binary diff | `module.toml` 13 | M00666 |
| F03011 | module.toml `instanced = false` | `module.toml` 20 | M00667 |
| F03012 | module.toml `instanced` rationale — "a host has exactly one integrity baseline" | `module.toml` 16 | M00667 |
| F03013 | module.toml `instanced` rationale — multi-instance only useful for separate baselines for separate path sets | `module.toml` 17 | M00667 |
| F03014 | module.toml `instanced` rationale — `paths_file` knob covers separate sets by composition | `module.toml` 18–19 | M00667 |
| F03015 | module.toml `phase = "pre"` | `module.toml` 25 | M00668 |
| F03016 | module.toml phase rationale — gates rest of apply on baseline being intact | `module.toml` 22–23 | M00668 |
| F03017 | module.toml phase cross-ref — docs/src/modules-roadmap.md § Lifecycle surface | `module.toml` 23–24 | M00668 |
| F03018 | module.toml `[install] kind = "script"` | `module.toml` 27–28 | M00655 |
| F03019 | module.toml `apply = "install/apply.sh"` | `module.toml` 29 | M00660 |
| F03020 | module.toml `check = "install/check.sh"` | `module.toml` 30 | M00661 |
| F03021 | module.toml `uninstall = "install/uninstall.sh"` | `module.toml` 31 | M00663 |
| F03022 | module.toml `[profiles] default = "strict"` | `module.toml` 33–34 | E0263 |
| F03023 | module.toml `available = ["strict", "warn-only"]` | `module.toml` 35 | E0263 |
| F03024 | module.toml `[daemon_requires]` block | `module.toml` 42 | M00669 |
| F03025 | module.toml `collectors.eventstream.enabled = true` | `module.toml` 43 | M00669 |
| F03026 | module.toml `collectors.eventstream.paths = ["${event_stream_path}"]` | `module.toml` 44 | M00669 |
| F03027 | module.toml [daemon_requires] rationale — SDD-002 D-1 + emission on by default per F-2026-018 | `module.toml` 37–40 | M00669 |
| F03028 | module.toml [daemon_requires] — daemon must tail JSONL stream the module writes to | `module.toml` 38 | M00669 |
| F03029 | module.toml [daemon_requires] — `${event_stream_path}` substitution resolves against module's host config | `module.toml` 39–40 | M00669 |
| F03030 | README — fail-closed by default doctrine | `README.md` 4 | E0261 |
| F03031 | README — drift definition (modified, removed, or new file matching tracked glob) | `README.md` 5–6 | E0261 |
| F03032 | README — "tripwire the operator owns the keys to" | `README.md` 10–11 | E0261 |
| F03033 | README — NOT crypto-anchored attestation (no signing, no remote attestation) | `README.md` 10 | E0261 |
| F03034 | README — paths_file operator-defined plain text | `README.md` 15 | E0262 |
| F03035 | README — globs and `**` expanded | `README.md` 16 | E0262 |
| F03036 | README — default set shipped at `paths.txt.default` | `README.md` 17 | M00657 |
| F03037 | README path — /etc/selfdef/selfdef.toml (daemon config) | `README.md` 20 | M00676 |
| F03038 | README path — /etc/selfdef/modules.toml (host modules list) | `README.md` 21 | M00676 |
| F03039 | README path — /etc/selfdef/modules/*.toml (per-module configs) | `README.md` 22 | M00676 |
| F03040 | README path — /etc/selfdef/rules.d/**/*.yml (correlator rules) | `README.md` 23 | M00677 |
| F03041 | README path — /usr/share/selfdef/modules/*/module.toml (module manifests) | `README.md` 24 | M00678 |
| F03042 | README path — /usr/share/selfdef/modules/*/install/*.sh + install/profiles/*.sh | `README.md` 25–26 | M00679 |
| F03043 | README — module deliberately does NOT install paths.txt automatically | `README.md` 29–30 | E0262 |
| F03044 | README — "picking what to baseline is a security decision the operator makes" | `README.md` 30–31 | E0262 |
| F03045 | README profile strict — exit non-zero on any drift | `README.md` 37 | E0263 |
| F03046 | README profile strict — `selfdefctl modules apply` halts | `README.md` 37 | E0263 |
| F03047 | README profile strict — "Production. The whole point of the module" | `README.md` 37 | E0263 |
| F03048 | README profile warn-only — report ok with "DRIFT detected (warn-only: not blocking)" | `README.md` 38 | E0263 |
| F03049 | README profile warn-only — "Bring-up — while you stabilise what's in the baseline" | `README.md` 38 | E0263 |
| F03050 | README profile warn-only — "Flip to strict once the noise is gone" | `README.md` 38 | E0263 |
| F03051 | README — "In both modes the full diff (`diff -u <baseline> <current>`) is written to stderr" | `README.md` 40–41 | E0263 |
| F03052 | README lifecycle step 1 — `mkdir -p /etc/selfdef/integrity-sentinel` | `README.md` 47 | E0264 |
| F03053 | README lifecycle step 1 — `cp paths.txt.default /etc/selfdef/integrity-sentinel/paths.txt` | `README.md` 48–49 | E0264 |
| F03054 | README lifecycle step 1 — `nano /etc/selfdef/integrity-sentinel/paths.txt` | `README.md` 50 | E0264 |
| F03055 | README lifecycle step 2 — activate via `[modules.integrity-sentinel]` in /etc/selfdef/modules.toml | `README.md` 52–53 | E0264 |
| F03056 | README lifecycle step 3 — first apply seals baseline (`selfdefctl modules apply --only integrity-sentinel`) | `README.md` 55–57 | E0264 |
| F03057 | README lifecycle step 3 — success msg "ok: baseline created (N entries) at /var/lib/selfdef/integrity-sentinel/baseline.sha256" | `README.md` 57 | E0264 |
| F03058 | README lifecycle step 4 — subsequent applies verify | `README.md` 59 | E0264 |
| F03059 | README lifecycle step 4 — success msg "ok: baseline matches (N entries)" | `README.md` 61 | E0264 |
| F03060 | README re-seal — uninstall+apply canonical re-seal | `README.md` 70–73 | E0265 |
| F03061 | README re-seal — "This is intentional friction" | `README.md` 75 | E0265 |
| F03062 | README re-seal — "re-sealing is a deliberate act, never a silent side-effect of a routine apply" | `README.md` 75–76 | E0265 |
| F03063 | README re-seal — one-shot alternative `rm /var/lib/selfdef/integrity-sentinel/baseline.sha256` + apply | `README.md` 80–83 | E0265 |
| F03064 | README — baseline file in sha256sum(1) format | `README.md` 89 | E0266 |
| F03065 | README — `<sha256-hex>  <abs-path>` record per line | `README.md` 89–90 | E0266 |
| F03066 | README — sorted by path | `README.md` 90 | E0266 |
| F03067 | README — "directly verifiable without going through selfdef" | `README.md` 91–92 | E0266 |
| F03068 | README — `sha256sum -c /var/lib/selfdef/integrity-sentinel/baseline.sha256` works | `README.md` 95 | E0266 |
| F03069 | README — "useful out-of-band path if selfdefctl itself is in doubt" | `README.md` 98–99 | E0266 |
| F03070 | README config — profile (strict | warn-only) | `README.md` 104 | E0267 |
| F03071 | README config — paths_file = /etc/selfdef/integrity-sentinel/paths.txt | `README.md` 105 | E0267 |
| F03072 | README config — baseline_path = /var/lib/selfdef/integrity-sentinel/baseline.sha256 | `README.md` 106 | E0267 |
| F03073 | README config — on_missing (create | fail) default create | `README.md` 107 | E0267 |
| F03074 | README config — optional event_stream_path | `README.md` 110 | E0267 |
| F03075 | README config — optional event_severity_strict = "high" | `README.md` 111 | E0267 |
| F03076 | README config — optional event_severity_warn = "low" | `README.md` 112 | E0267 |
| F03077 | README — out of box drift only surfaces in structured-status JSON | `README.md` 117–118 | E0268 |
| F03078 | README — wiring via event_stream_path JSONL daemon tail | `README.md` 119–121 | E0268 |
| F03079 | README — eventstream collector configured to tail | `README.md` 132 | E0268 |
| F03080 | README — collectors.eventstream.enabled = true | `README.md` 131 | M00669 |
| F03081 | README — collectors.eventstream.paths = ["/var/lib/selfdef/eventstream/integrity-sentinel.jsonl"] | `README.md` 132 | M00669 |
| F03082 | README — read_from = "end" | `README.md` 133 | E0268 |
| F03083 | README — module appends Detection Finding (OCSF class 2004) | `README.md` 136 | M00680 |
| F03084 | README — emission via `selfdefctl events emit` | `README.md` 137 | M00680 |
| F03085 | README — daemon picks up, responder routes Findings-category through notifier chain | `README.md` 138 | E0268 |
| F03086 | README — operator gets Signal/ntfy ping | `README.md` 139 | E0268 |
| F03087 | README — "Leave event_stream_path unset to suppress emission entirely" | `README.md` 141 | E0268 |
| F03088 | README — "structured-status surface is unaffected" by leaving event_stream_path unset | `README.md` 142–143 | E0268 |
| F03089 | README — on_missing="fail" right after sealing baseline out-of-band | `README.md` 145–148 | E0268 |
| F03090 | README — "refuses to silently create a new baseline if the expected one is missing" | `README.md` 148–149 | E0268 |
| F03091 | README — exploit-race rationale ("attacker who deleted the baseline file and triggered an apply could re-baseline a host they'd already tampered with") | `README.md` 149–151 | E0268 |
| F03092 | README scope OWNS — baseline file at baseline_path | `README.md` 157 | E0269 |
| F03093 | README scope OWNS — reading paths_file + computing current view of every matched regular file | `README.md` 159–160 | E0269 |
| F03094 | README scope NOT-OWNS — paths_file (operator-managed) | `README.md` 164 | E0269 |
| F03095 | README scope NOT-OWNS — integrity of baseline file (operator should 0600; module sets on creation but doesn't enforce on each apply) | `README.md` 165–167 | E0269 |
| F03096 | README scope NOT-OWNS — cryptographic signing of baseline | `README.md` 168 | E0269 |
| F03097 | README — "SHA256 is integrity, not authenticity" | `README.md` 168–169 | E0269 |
| F03098 | README — "if attacker has write access to both tracked files AND baseline, this module can't help" | `README.md` 169–170 | E0269 |
| F03099 | README — "Pair with filesystem-level immutability (chattr +i)" | `README.md` 170–171 | E0269 |
| F03100 | README — "or out-of-band baseline storage if you need stronger guarantees" | `README.md` 171 | E0269 |
| F03101 | README caveat — Symlinks (module follows; sha256sum default) | `README.md` 175 | E0270 |
| F03102 | README caveat — symlink target's hash is baselined | `README.md` 175–177 | E0270 |
| F03103 | README caveat — replacing symlink to point elsewhere DETECTED | `README.md` 177–178 | E0270 |
| F03104 | README caveat — replacing target's content DETECTED | `README.md` 178 | E0270 |
| F03105 | README caveat — replacing symlink with copy of target NOT detected (same hash) | `README.md` 178–179 | E0270 |
| F03106 | README caveat — Globs `*` and `**` with bash globstar+nullglob | `README.md` 180 | E0270 |
| F03107 | README caveat — non-matching patterns contribute zero entries (NOT failure) | `README.md` 181–182 | E0270 |
| F03108 | README caveat — Directories and special files skipped (only regular files hashed) | `README.md` 183–184 | E0270 |
| F03109 | README caveat — phase="pre" runs before any main-phase module | `README.md` 185–187 | M00668 |
| F03110 | README caveat — strict drift halts apply BEFORE anything else mutates host state | `README.md` 187–188 | E0270 |
| F03111 | README caveat — "intended security posture" | `README.md` 188–189 | E0270 |
| F03112 | apply.sh — first-run path (no baseline + on_missing=create) | `apply.sh` 4–7 | M00660 |
| F03113 | apply.sh — subsequent-run path (recompute + diff + status) | `apply.sh` 9–13 | M00660 |
| F03114 | apply.sh — strict drift → status failed exit 1 | `apply.sh` 100–103 | M00660 |
| F03115 | apply.sh — warn-only drift → status ok with "(warn-only: not blocking)" suffix | `apply.sh` 105–107 | M00660 |
| F03116 | check.sh — never creates baseline; missing baseline always reported failed (regardless of on_missing) | `check.sh` 5–7 + 24 | M00661 |
| F03117 | lib.sh expand_paths — globstar+nullglob + non-absolute path refusal + regular-file-only filter + NUL-sep sorted output | `lib.sh` 42–84 | M00670 |
| F03118 | lib.sh compute_baseline — xargs -0 sha256sum + LC_ALL=C sort -k 2 | `lib.sh` 86–94 | M00671 |
| F03119 | lib.sh emit_drift_event — OCSF 2004 + severity routing + DRY_RUN-aware + best-effort + gated on event_stream_path | `lib.sh` 96–150 | M00672 + M00680 |
| F03120 | uninstall.sh — manifest-walked + legacy-path fallback (config-file resolution of baseline_path) + preserves paths_file | `uninstall.sh` 14–46 | M00663 + M00673 |

## Requirements (R06001–R06240)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R06001 | Module name MUST be `integrity-sentinel` | `module.toml` 1 | F03001 | non-negotiable | false | 10 |
| R06002 | Module version MUST be 0.1.1 | `module.toml` 2 | F03002 | non-negotiable | false | 10 |
| R06003 | Module summary MUST be "SHA256 baseline verification for policy artifacts. Fail-closed on drift." | `module.toml` 3 | F03003 | non-negotiable | false | 10 |
| R06004 | Module category MUST be `hardening` | `module.toml` 4 | F03004 | non-negotiable | false | 10 |
| R06005 | depends_on = [] | `module.toml` 6 | F03005 | non-negotiable | false | 10 |
| R06006 | conflicts = [] | `module.toml` 7 | F03006 | non-negotiable | false | 10 |
| R06007 | provides = ["baseline-attestation"] | `module.toml` 8 | F03007 | non-negotiable | false | 10 |
| R06008 | consumes = [] | `module.toml` 9 | F03008 | non-negotiable | false | 10 |
| R06009 | Required binary — sha256sum | `module.toml` 12 | F03009 | non-negotiable | false | 10 |
| R06010 | Required binary — diff | `module.toml` 13 | F03010 | non-negotiable | false | 10 |
| R06011 | instanced = false | `module.toml` 20 | F03011 | non-negotiable | false | 10 |
| R06012 | Rationale — "a host has exactly one integrity baseline" | `module.toml` 16 | F03012 | non-negotiable | false | 10 |
| R06013 | Rationale — multi-instance only useful for separate baselines for separate path sets | `module.toml` 17 | F03013 | non-negotiable | false | 10 |
| R06014 | Rationale — paths_file knob covers separate sets by composition | `module.toml` 18–19 | F03014 | non-negotiable | false | 10 |
| R06015 | phase = "pre" | `module.toml` 25 | F03015 | non-negotiable | false | 10 |
| R06016 | phase=pre — runs before any `main`-phase module | `module.toml` 22 | F03016 | non-negotiable | false | 10 |
| R06017 | phase rationale — gates rest of apply on baseline being intact | `module.toml` 22–23 | F03016 | non-negotiable | false | 10 |
| R06018 | phase cross-ref — docs/src/modules-roadmap.md § Lifecycle surface | `module.toml` 23–24 | F03017 | non-negotiable | false | 10 |
| R06019 | [install] kind = "script" | `module.toml` 28 | F03018 | non-negotiable | false | 10 |
| R06020 | [install] apply = "install/apply.sh" | `module.toml` 29 | F03019 | non-negotiable | false | 10 |
| R06021 | [install] check = "install/check.sh" | `module.toml` 30 | F03020 | non-negotiable | false | 10 |
| R06022 | [install] uninstall = "install/uninstall.sh" | `module.toml` 31 | F03021 | non-negotiable | false | 10 |
| R06023 | [profiles] default = "strict" | `module.toml` 34 | F03022 | non-negotiable | false | 10 |
| R06024 | [profiles] available = ["strict", "warn-only"] | `module.toml` 35 | F03023 | non-negotiable | false | 10 |
| R06025 | [daemon_requires] block exists | `module.toml` 42 | F03024 | non-negotiable | false | 10 |
| R06026 | [daemon_requires] collectors.eventstream.enabled = true | `module.toml` 43 | F03025 | non-negotiable | false | 10 |
| R06027 | [daemon_requires] collectors.eventstream.paths = ["${event_stream_path}"] | `module.toml` 44 | F03026 | non-negotiable | false | 10 |
| R06028 | [daemon_requires] rationale — SDD-002 D-1 + F-2026-018 | `module.toml` 37–40 | F03027 | non-negotiable | false | 10 |
| R06029 | [daemon_requires] — daemon must tail JSONL when emission is on | `module.toml` 38 | F03028 | non-negotiable | false | 10 |
| R06030 | [daemon_requires] — emission ON by default per F-2026-018 | `module.toml` 37–38 | F03028 | non-negotiable | false | 10 |
| R06031 | [daemon_requires] — `${event_stream_path}` substitution resolves against module's host config | `module.toml` 39–40 | F03029 | non-negotiable | false | 10 |
| R06032 | README — fail-closed by default | `README.md` 4 | F03030 | non-negotiable | false | 10 |
| R06033 | README — drift = modified file | `README.md` 5 | F03031 | non-negotiable | false | 10 |
| R06034 | README — drift = removed file | `README.md` 5 | F03031 | non-negotiable | false | 10 |
| R06035 | README — drift = new file matching tracked glob | `README.md` 5–6 | F03031 | non-negotiable | false | 10 |
| R06036 | README — drift makes `selfdefctl modules apply` exit non-zero | `README.md` 6 | F03031 | non-negotiable | false | 10 |
| R06037 | README — tripwire doctrine — "did anyone tamper with my rules / configs / module install scripts since I sealed the host?" | `README.md` 8–9 | E0261 | non-negotiable | false | 10 |
| R06038 | README — NOT crypto-anchored attestation (no signing) | `README.md` 10 | F03033 | non-negotiable | false | 10 |
| R06039 | README — NOT crypto-anchored attestation (no remote attestation) | `README.md` 10 | F03033 | non-negotiable | false | 10 |
| R06040 | README — "tripwire the operator owns the keys to" | `README.md` 10–11 | F03032 | non-negotiable | false | 10 |
| R06041 | README — paths to track operator-defined | `README.md` 15 | F03034 | non-negotiable | false | 10 |
| R06042 | README — plain text file | `README.md` 15 | F03034 | non-negotiable | false | 10 |
| R06043 | README — one absolute path per line | `README.md` 16 | F03034 | non-negotiable | false | 10 |
| R06044 | README — globs and `**` expanded | `README.md` 16 | F03035 | non-negotiable | false | 10 |
| R06045 | README — default set shipped at paths.txt.default | `README.md` 17 | F03036 | non-negotiable | false | 10 |
| R06046 | README path — /etc/selfdef/selfdef.toml | `README.md` 20 | F03037 | non-negotiable | false | 10 |
| R06047 | README path — /etc/selfdef/modules.toml | `README.md` 21 | F03038 | non-negotiable | false | 10 |
| R06048 | README path — /etc/selfdef/modules/*.toml | `README.md` 22 | F03039 | non-negotiable | false | 10 |
| R06049 | README path — /etc/selfdef/rules.d/**/*.yml | `README.md` 23 | F03040 | non-negotiable | false | 10 |
| R06050 | README path — /usr/share/selfdef/modules/*/module.toml | `README.md` 24 | F03041 | non-negotiable | false | 10 |
| R06051 | README path — /usr/share/selfdef/modules/*/install/*.sh | `README.md` 25 | F03042 | non-negotiable | false | 10 |
| R06052 | README path — /usr/share/selfdef/modules/*/install/profiles/*.sh | `README.md` 25 | F03042 | non-negotiable | false | 10 |
| R06053 | README path rationale — "tampering here would let an attacker substitute their own apply.sh and have selfdef execute it" | `paths.txt.default` 19–20 | M00679 | non-negotiable | false | 10 |
| R06054 | README — operator copies default to /etc/selfdef/integrity-sentinel/paths.txt and edits | `README.md` 28 | E0262 | non-negotiable | false | 10 |
| R06055 | README — module deliberately does NOT install paths.txt automatically | `README.md` 29–30 | F03043 | non-negotiable | false | 10 |
| R06056 | README — "picking what to baseline is a security decision the operator makes" | `README.md` 30–31 | F03044 | non-negotiable | false | 10 |
| R06057 | Profile strict — exit non-zero on any drift | `README.md` 37 | F03045 | non-negotiable | false | 10 |
| R06058 | Profile strict — `selfdefctl modules apply` halts | `README.md` 37 | F03046 | non-negotiable | false | 10 |
| R06059 | Profile strict — "Production. The whole point of the module" | `README.md` 37 | F03047 | non-negotiable | false | 10 |
| R06060 | Profile warn-only — report ok | `README.md` 38 | F03048 | non-negotiable | false | 10 |
| R06061 | Profile warn-only — "DRIFT detected (warn-only: not blocking)" suffix | `README.md` 38 | F03048 | non-negotiable | false | 10 |
| R06062 | Profile warn-only — "Bring-up — while you stabilise what's in the baseline" | `README.md` 38 | F03049 | non-negotiable | false | 10 |
| R06063 | Profile warn-only — "Flip to strict once the noise is gone" | `README.md` 38 | F03050 | non-negotiable | false | 10 |
| R06064 | In both modes — full diff (`diff -u <baseline> <current>`) written to stderr | `README.md` 40–41 | F03051 | non-negotiable | false | 10 |
| R06065 | Lifecycle — operator runs `mkdir -p /etc/selfdef/integrity-sentinel` | `README.md` 47 | F03052 | non-negotiable | false | 10 |
| R06066 | Lifecycle — copy paths.txt.default to /etc/selfdef/integrity-sentinel/paths.txt | `README.md` 48–49 | F03053 | non-negotiable | false | 10 |
| R06067 | Lifecycle — `nano /etc/selfdef/integrity-sentinel/paths.txt` (edit to taste) | `README.md` 50 | F03054 | non-negotiable | false | 10 |
| R06068 | Lifecycle — activate `[modules.integrity-sentinel]` in /etc/selfdef/modules.toml | `README.md` 52–53 | F03055 | non-negotiable | false | 10 |
| R06069 | Lifecycle — first apply (`selfdefctl modules apply --only integrity-sentinel`) seals baseline | `README.md` 55–56 | F03056 | non-negotiable | false | 10 |
| R06070 | Lifecycle — first-apply success message format: "ok: baseline created (N entries) at /var/lib/selfdef/integrity-sentinel/baseline.sha256" | `README.md` 57 | F03057 | non-negotiable | false | 10 |
| R06071 | Lifecycle — subsequent applies verify | `README.md` 59 | F03058 | non-negotiable | false | 10 |
| R06072 | Lifecycle — subsequent-apply success message format: "ok: baseline matches (N entries)" | `README.md` 61 | F03059 | non-negotiable | false | 10 |
| R06073 | Re-seal — canonical procedure = `selfdefctl modules uninstall` + `selfdefctl modules apply --only integrity-sentinel` | `README.md` 70–73 | F03060 | non-negotiable | false | 10 |
| R06074 | Re-seal — "uninstall removes the baseline file only" | `README.md` 71 | F03060 | non-negotiable | false | 10 |
| R06075 | Re-seal — "This is intentional friction" | `README.md` 75 | F03061 | non-negotiable | false | 10 |
| R06076 | Re-seal — "re-sealing is a deliberate act, never a silent side-effect of a routine apply" | `README.md` 75–76 | F03062 | non-negotiable | false | 10 |
| R06077 | Re-seal — one-shot alternative `rm /var/lib/selfdef/integrity-sentinel/baseline.sha256` | `README.md` 81 | F03063 | non-negotiable | false | 10 |
| R06078 | Re-seal — followed by `selfdefctl modules apply --only integrity-sentinel` | `README.md` 82 | F03063 | non-negotiable | false | 10 |
| R06079 | Re-seal — one-shot equivalent to uninstall+apply pair | `README.md` 85 | F03063 | non-negotiable | false | 10 |
| R06080 | Baseline format — sha256sum(1) format | `README.md` 89 | F03064 | non-negotiable | false | 10 |
| R06081 | Baseline format — `<sha256-hex>  <abs-path>` record per line | `README.md` 89–90 | F03065 | non-negotiable | false | 10 |
| R06082 | Baseline format — sorted by path | `README.md` 90 | F03066 | non-negotiable | false | 10 |
| R06083 | Baseline format rationale — standard format on Linux | `README.md` 91 | E0266 | non-negotiable | false | 10 |
| R06084 | Baseline format rationale — directly verifiable without going through selfdef | `README.md` 91–92 | F03067 | non-negotiable | false | 10 |
| R06085 | Baseline format — `sha256sum -c /var/lib/selfdef/integrity-sentinel/baseline.sha256` works | `README.md` 95 | F03068 | non-negotiable | false | 10 |
| R06086 | Baseline format — useful out-of-band path if selfdefctl in doubt | `README.md` 98–99 | F03069 | non-negotiable | false | 10 |
| R06087 | Config — profile (strict|warn-only) | `README.md` 104 | F03070 | non-negotiable | false | 10 |
| R06088 | Config — paths_file default /etc/selfdef/integrity-sentinel/paths.txt | `README.md` 105 | F03071 | non-negotiable | false | 10 |
| R06089 | Config — baseline_path default /var/lib/selfdef/integrity-sentinel/baseline.sha256 | `README.md` 106 | F03072 | non-negotiable | false | 10 |
| R06090 | Config — on_missing default "create" (create|fail) | `README.md` 107 | F03073 | non-negotiable | false | 10 |
| R06091 | Config — optional event_stream_path | `README.md` 110 | F03074 | non-negotiable | false | 10 |
| R06092 | Config — optional event_severity_strict default "high" | `README.md` 111 | F03075 | non-negotiable | false | 10 |
| R06093 | Config — optional event_severity_warn default "low" | `README.md` 112 | F03076 | non-negotiable | false | 10 |
| R06094 | Notifying — drift surfaces in structured-status JSON | `README.md` 117–118 | F03077 | non-negotiable | false | 10 |
| R06095 | Notifying — set event_stream_path to JSONL daemon tails | `README.md` 119–121 | F03078 | non-negotiable | false | 10 |
| R06096 | Notifying — daemon collectors.eventstream.enabled = true | `README.md` 131 | F03080 | non-negotiable | false | 10 |
| R06097 | Notifying — daemon collectors.eventstream.paths includes JSONL | `README.md` 132 | F03081 | non-negotiable | false | 10 |
| R06098 | Notifying — daemon collectors.eventstream.read_from = "end" | `README.md` 133 | F03082 | non-negotiable | false | 10 |
| R06099 | Drift event — Detection Finding (OCSF class 2004) | `README.md` 136 | F03083 | non-negotiable | false | 10 |
| R06100 | Drift event — emission via `selfdefctl events emit` | `README.md` 137 | F03084 | non-negotiable | false | 10 |
| R06101 | Drift event — daemon picks up + responder routes Findings-category through notifier chain | `README.md` 138 | F03085 | non-negotiable | false | 10 |
| R06102 | Drift event — operator gets Signal/ntfy ping | `README.md` 139 | F03086 | non-negotiable | false | 10 |
| R06103 | Notifying — "Leave event_stream_path unset to suppress emission entirely" | `README.md` 141 | F03087 | non-negotiable | false | 10 |
| R06104 | Notifying — structured-status surface unaffected by leaving event_stream_path unset | `README.md` 142–143 | F03088 | non-negotiable | false | 10 |
| R06105 | on_missing=fail — right answer once initial baseline sealed out-of-band | `README.md` 145–148 | F03089 | non-negotiable | false | 10 |
| R06106 | on_missing=fail — refuses to silently create new baseline if expected one missing | `README.md` 148–149 | F03090 | non-negotiable | false | 10 |
| R06107 | on_missing=fail — exploit-race rationale (attacker who deleted baseline could re-baseline tampered host) | `README.md` 149–151 | F03091 | non-negotiable | false | 10 |
| R06108 | Scope OWNS — baseline file at baseline_path | `README.md` 157 | F03092 | non-negotiable | false | 10 |
| R06109 | Scope OWNS — default baseline_path /var/lib/selfdef/integrity-sentinel/baseline.sha256 | `README.md` 157–158 | F03092 | non-negotiable | false | 10 |
| R06110 | Scope OWNS — reading paths_file | `README.md` 159 | F03093 | non-negotiable | false | 10 |
| R06111 | Scope OWNS — computing current view of every matched regular file | `README.md` 159–160 | F03093 | non-negotiable | false | 10 |
| R06112 | Scope NOT-OWNS — paths_file (operator-managed) | `README.md` 164 | F03094 | non-negotiable | false | 10 |
| R06113 | Scope NOT-OWNS — integrity of baseline file | `README.md` 165 | F03095 | non-negotiable | false | 10 |
| R06114 | Scope NOT-OWNS — operator should 0600 baseline | `README.md` 166 | F03095 | non-negotiable | false | 10 |
| R06115 | Scope NOT-OWNS — module sets 0600 on creation but doesn't enforce on each apply | `README.md` 166–167 | F03095 | non-negotiable | false | 10 |
| R06116 | Scope NOT-OWNS — cryptographic signing of baseline | `README.md` 168 | F03096 | non-negotiable | false | 10 |
| R06117 | Doctrine — "SHA256 is integrity, not authenticity" | `README.md` 168–169 | F03097 | non-negotiable | false | 10 |
| R06118 | Doctrine — module can't help if attacker has write access to both tracked files AND baseline | `README.md` 169–170 | F03098 | non-negotiable | false | 10 |
| R06119 | Mitigation — pair with filesystem-level immutability (`chattr +i`) | `README.md` 170–171 | F03099 | non-negotiable | false | 10 |
| R06120 | Mitigation — pair with out-of-band baseline storage for stronger guarantees | `README.md` 171 | F03100 | non-negotiable | false | 10 |
| R06121 | Caveat — module follows symlinks (sha256sum default) | `README.md` 175 | F03101 | non-negotiable | false | 10 |
| R06122 | Caveat — tracked symlink → target's hash is baselined | `README.md` 175–177 | F03102 | non-negotiable | false | 10 |
| R06123 | Caveat — replacing symlink to point elsewhere DETECTED | `README.md` 177–178 | F03103 | non-negotiable | false | 10 |
| R06124 | Caveat — replacing target's content DETECTED | `README.md` 178 | F03104 | non-negotiable | false | 10 |
| R06125 | Caveat — replacing symlink with copy of target NOT detected (same hash) | `README.md` 178–179 | F03105 | non-negotiable | false | 10 |
| R06126 | Caveat — `*` and `**` expanded with bash globstar+nullglob | `README.md` 180 | F03106 | non-negotiable | false | 10 |
| R06127 | Caveat — non-matching patterns contribute zero entries (NOT failure) | `README.md` 181–182 | F03107 | non-negotiable | false | 10 |
| R06128 | Caveat — Directories skipped | `README.md` 183 | F03108 | non-negotiable | false | 10 |
| R06129 | Caveat — Special files skipped | `README.md` 183 | F03108 | non-negotiable | false | 10 |
| R06130 | Caveat — only regular files hashed | `README.md` 183–184 | F03108 | non-negotiable | false | 10 |
| R06131 | Caveat — phase=pre runs before any main-phase module | `README.md` 185–187 | F03109 | non-negotiable | false | 10 |
| R06132 | Caveat — strict drift halts apply before anything else mutates host state | `README.md` 187–188 | F03110 | non-negotiable | false | 10 |
| R06133 | Caveat — "intended security posture" | `README.md` 188–189 | F03111 | non-negotiable | false | 10 |
| R06134 | apply.sh — first-run no-baseline + on_missing=create computes SHA256 of every path resolved from paths_file | `apply.sh` 4–5 | F03112 | non-negotiable | false | 10 |
| R06135 | apply.sh — first-run writes baseline to baseline_path in sha256sum format | `apply.sh` 6 | F03112 | non-negotiable | false | 10 |
| R06136 | apply.sh — first-run status ok | `apply.sh` 7 | F03112 | non-negotiable | false | 10 |
| R06137 | apply.sh — subsequent recomputes SHA256 over same expansion | `apply.sh` 10 | F03113 | non-negotiable | false | 10 |
| R06138 | apply.sh — subsequent diffs against stored baseline | `apply.sh` 11 | F03113 | non-negotiable | false | 10 |
| R06139 | apply.sh — subsequent clean → status ok | `apply.sh` 12 | F03113 | non-negotiable | false | 10 |
| R06140 | apply.sh — subsequent drift strict → status failed | `apply.sh` 13 | F03113 | non-negotiable | false | 10 |
| R06141 | apply.sh — subsequent drift warn-only → status ok-with-DRIFT | `apply.sh` 13 | F03113 | non-negotiable | false | 10 |
| R06142 | apply.sh MUST set -euo pipefail | `apply.sh` 15 | M00660 | non-negotiable | false | 10 |
| R06143 | apply.sh MODULE = "integrity-sentinel" | `apply.sh` 17 | M00660 | non-negotiable | false | 10 |
| R06144 | apply.sh DRY_RUN from SELFDEF_DRY_RUN env (default 0) | `apply.sh` 18 | M00660 | non-negotiable | false | 10 |
| R06145 | apply.sh CONFIG_FILE default /etc/selfdef/modules/integrity-sentinel.toml | `apply.sh` 19 | M00660 | non-negotiable | false | 10 |
| R06146 | apply.sh CONFIG_FILE override via SELFDEF_INTEGRITY_SENTINEL_CONFIG | `apply.sh` 19 | M00660 | non-negotiable | false | 10 |
| R06147 | apply.sh sources install/lib.sh via LIB_DIR | `apply.sh` 20–23 | M00660 | non-negotiable | false | 10 |
| R06148 | apply.sh preflight — `command -v sha256sum` | `apply.sh` 25 | M00665 | non-negotiable | false | 10 |
| R06149 | apply.sh preflight — `command -v diff` | `apply.sh` 26 | M00666 | non-negotiable | false | 10 |
| R06150 | apply.sh preflight — config readable | `apply.sh` 28 | M00660 | non-negotiable | false | 10 |
| R06151 | apply.sh — PROFILE read via toml_get (default strict) | `apply.sh` 30 | M00660 | non-negotiable | false | 10 |
| R06152 | apply.sh — PATHS_FILE read via toml_get | `apply.sh` 31 | M00660 | non-negotiable | false | 10 |
| R06153 | apply.sh — BASELINE_PATH read via toml_get | `apply.sh` 32 | M00660 | non-negotiable | false | 10 |
| R06154 | apply.sh — ON_MISSING read via toml_get (default create) | `apply.sh` 33 | M00660 | non-negotiable | false | 10 |
| R06155 | apply.sh — PROFILE validation (strict|warn-only or die) | `apply.sh` 35–38 | M00660 | non-negotiable | false | 10 |
| R06156 | apply.sh — ON_MISSING validation (create|fail or die) | `apply.sh` 39–42 | M00660 | non-negotiable | false | 10 |
| R06157 | apply.sh — paths_file required (die if empty) | `apply.sh` 43 | M00660 | non-negotiable | false | 10 |
| R06158 | apply.sh — baseline_path required (die if empty) | `apply.sh` 44 | M00660 | non-negotiable | false | 10 |
| R06159 | apply.sh — always recomputes current baseline view | `apply.sh` 46–47 | M00660 | non-negotiable | false | 10 |
| R06160 | apply.sh — uses mktemp for TMP_CURRENT + trap cleanup | `apply.sh` 48–49 | M00660 | non-negotiable | false | 10 |
| R06161 | apply.sh — expand_paths | compute_baseline > TMP_CURRENT | `apply.sh` 50 | M00670 + M00671 | non-negotiable | false | 10 |
| R06162 | apply.sh — COUNT = wc -l TMP_CURRENT | `apply.sh` 51 | M00660 | non-negotiable | false | 10 |
| R06163 | apply.sh — first-run path (no baseline) + on_missing=fail → die | `apply.sh` 53–56 | M00660 | non-negotiable | false | 10 |
| R06164 | apply.sh — die message format: "no baseline at $BASELINE_PATH and on_missing=fail" | `apply.sh` 55 | M00660 | non-negotiable | false | 10 |
| R06165 | apply.sh — first-run path creates baseline dir if absent | `apply.sh` 58–61 | M00660 | non-negotiable | false | 10 |
| R06166 | apply.sh — first-run path DRY_RUN=1 logs intent without writing | `apply.sh` 62–63 | M00660 | non-negotiable | false | 10 |
| R06167 | apply.sh — first-run install -m 0600 /dev/null + cp + chmod 0600 | `apply.sh` 65–67 | M00660 | non-negotiable | false | 10 |
| R06168 | apply.sh — first-run baseline_path created with 0600 mode | `apply.sh` 65–67 | M00660 | non-negotiable | false | 10 |
| R06169 | apply.sh — F-2027-024 module_record_file baseline_path | `apply.sh` 69–72 | M00673 | non-negotiable | false | 10 |
| R06170 | apply.sh — first-run emit_status "ok" "baseline created (COUNT entries) at BASELINE_PATH" | `apply.sh` 73 | M00660 | non-negotiable | false | 10 |
| R06171 | apply.sh — first-run exit 0 | `apply.sh` 74 | M00660 | non-negotiable | false | 10 |
| R06172 | apply.sh — verify path: diff -u BASELINE_PATH TMP_CURRENT (|| true to capture) | `apply.sh` 78 | M00660 | non-negotiable | false | 10 |
| R06173 | apply.sh — empty diff → emit_status "ok" "baseline matches (COUNT entries)" + exit 0 | `apply.sh` 79–82 | M00660 | non-negotiable | false | 10 |
| R06174 | apply.sh — non-empty diff → drift detected | `apply.sh` 84 | M00660 | non-negotiable | false | 10 |
| R06175 | apply.sh — ADDED = grep -c '^+[^+]' DIFF_OUT | `apply.sh` 85 | M00660 | non-negotiable | false | 10 |
| R06176 | apply.sh — REMOVED = grep -c '^-[^-]' DIFF_OUT | `apply.sh` 86 | M00660 | non-negotiable | false | 10 |
| R06177 | apply.sh — SUMMARY format: "DRIFT detected: +X new/changed lines, -Y missing/changed lines vs baseline" | `apply.sh` 87 | M00660 | non-negotiable | false | 10 |
| R06178 | apply.sh — always logs full diff to stderr for triage | `apply.sh` 89–93 | M00660 | non-negotiable | false | 10 |
| R06179 | apply.sh — calls emit_drift_event with PROFILE + SUMMARY | `apply.sh` 98 | M00672 | non-negotiable | false | 10 |
| R06180 | apply.sh — strict → emit_status "failed" SUMMARY + exit 1 | `apply.sh` 100–103 | F03114 | non-negotiable | false | 10 |
| R06181 | apply.sh — warn-only → emit_status "ok" "SUMMARY (warn-only: not blocking)" | `apply.sh` 107 | F03115 | non-negotiable | false | 10 |
| R06182 | check.sh — no state changes | `check.sh` 3 | M00661 | non-negotiable | false | 10 |
| R06183 | check.sh — same comparison as apply but never creates/overwrites baseline | `check.sh` 4–5 | M00661 | non-negotiable | false | 10 |
| R06184 | check.sh — missing baseline ALWAYS reported failed (regardless of on_missing) | `check.sh` 5–7 | F03116 | non-negotiable | false | 10 |
| R06185 | check.sh — rationale: "check is read-only and 'no baseline yet' is a legitimate failure to surface" | `check.sh` 6–7 | F03116 | non-negotiable | false | 10 |
| R06186 | check.sh MUST set -euo pipefail | `check.sh` 9 | M00661 | non-negotiable | false | 10 |
| R06187 | check.sh DRY_RUN=0 forced (read-only contract) | `check.sh` 12 | M00661 | non-negotiable | false | 10 |
| R06188 | check.sh — config readable check (die if not) | `check.sh` 22 | M00661 | non-negotiable | false | 10 |
| R06189 | check.sh — die if no baseline at BASELINE_PATH ("run apply first") | `check.sh` 28 | M00661 | non-negotiable | false | 10 |
| R06190 | check.sh — recomputes current via expand_paths | compute_baseline > TMP_CURRENT | `check.sh` 32 | M00661 | non-negotiable | false | 10 |
| R06191 | check.sh — empty diff → emit_status "ok" "baseline matches (COUNT entries)" + exit 0 | `check.sh` 36–39 | M00661 | non-negotiable | false | 10 |
| R06192 | check.sh — drift → same SUMMARY format as apply | `check.sh` 41–44 | M00661 | non-negotiable | false | 10 |
| R06193 | check.sh — drift logs full diff to stderr (same as apply) | `check.sh` 46–49 | M00661 | non-negotiable | false | 10 |
| R06194 | check.sh — drift calls emit_drift_event (same wiring as apply) | `check.sh` 53 | M00672 | non-negotiable | false | 10 |
| R06195 | check.sh — warn-only drift → emit_status "ok" with warn-only suffix + exit 0 | `check.sh` 55–58 | M00661 | non-negotiable | false | 10 |
| R06196 | check.sh — strict drift → emit_status "failed" + exit 1 | `check.sh` 59–60 | M00661 | non-negotiable | false | 10 |
| R06197 | lib.sh — F-2027-024 v2 opt-in | `lib.sh` 9–14 | M00662 | non-negotiable | false | 10 |
| R06198 | lib.sh — 3-tier lookup precedence (env / workspace / installed) | `lib.sh` 16–32 | M00662 | non-negotiable | false | 10 |
| R06199 | lib.sh expand_paths — stdin paths_file contents | `lib.sh` 43 | M00670 | non-negotiable | false | 10 |
| R06200 | lib.sh expand_paths — stdout NUL-separated absolute paths sorted deduped | `lib.sh` 43–44 | M00670 | non-negotiable | false | 10 |
| R06201 | lib.sh expand_paths — paths_file readable check (die if not) | `lib.sh` 46 | M00670 | non-negotiable | false | 10 |
| R06202 | lib.sh expand_paths — globstar+nullglob in subshell so flags don't leak | `lib.sh` 48–50 | M00670 | non-negotiable | false | 10 |
| R06203 | lib.sh expand_paths — trims trailing CR | `lib.sh` 52 | M00670 | non-negotiable | false | 10 |
| R06204 | lib.sh expand_paths — trims leading whitespace | `lib.sh` 53 | M00670 | non-negotiable | false | 10 |
| R06205 | lib.sh expand_paths — trims trailing whitespace | `lib.sh` 54 | M00670 | non-negotiable | false | 10 |
| R06206 | lib.sh expand_paths — skips blank lines | `lib.sh` 55 | M00670 | non-negotiable | false | 10 |
| R06207 | lib.sh expand_paths — skips `#`-comments | `lib.sh` 55 | M00670 | non-negotiable | false | 10 |
| R06208 | lib.sh expand_paths — refuses non-absolute paths (exit 2) | `lib.sh` 58–62 | M00670 | non-negotiable | false | 10 |
| R06209 | lib.sh expand_paths — non-absolute refusal message format: "[integrity-sentinel] refusing non-absolute path: $line" | `lib.sh` 60 | M00670 | non-negotiable | false | 10 |
| R06210 | lib.sh expand_paths — uses `for match in $line` for glob expansion | `lib.sh` 66 | M00670 | non-negotiable | false | 10 |
| R06211 | lib.sh expand_paths — nullglob: non-matching globs produce zero iterations | `lib.sh` 67–73 | M00670 | non-negotiable | false | 10 |
| R06212 | lib.sh expand_paths — only baselines regular files (`-f` test) | `lib.sh` 78 | M00670 | non-negotiable | false | 10 |
| R06213 | lib.sh expand_paths — skips dirs / symlinks-to-dirs / sockets | `lib.sh` 76–77 | M00670 | non-negotiable | false | 10 |
| R06214 | lib.sh expand_paths — emits NUL-separated via `printf '%s\0' "$match"` | `lib.sh` 79 | M00670 | non-negotiable | false | 10 |
| R06215 | lib.sh expand_paths — final pipe `LC_ALL=C sort -zu` for sorted deduped output | `lib.sh` 84 | M00670 | non-negotiable | false | 10 |
| R06216 | lib.sh compute_baseline — `xargs -0 -r sha256sum 2>/dev/null` | `lib.sh` 90 | M00671 | non-negotiable | false | 10 |
| R06217 | lib.sh compute_baseline — `LC_ALL=C sort -k 2` for stable path-sorted output | `lib.sh` 91 | M00671 | non-negotiable | false | 10 |
| R06218 | lib.sh emit_drift_event — gated on event_stream_path being set | `lib.sh` 119–120 | M00672 | non-negotiable | false | 10 |
| R06219 | lib.sh emit_drift_event — no-op return 0 if event_stream_path empty | `lib.sh` 120 | M00672 | non-negotiable | false | 10 |
| R06220 | lib.sh emit_drift_event — strict severity default high | `lib.sh` 124–125 | M00672 | non-negotiable | false | 10 |
| R06221 | lib.sh emit_drift_event — warn-only severity default low | `lib.sh` 127 | M00672 | non-negotiable | false | 10 |
| R06222 | lib.sh emit_drift_event — uses SELFDEF_CTL_BIN env (default `selfdefctl`) | `lib.sh` 131 | M00672 | non-negotiable | false | 10 |
| R06223 | lib.sh emit_drift_event — DRY_RUN=1 logs intent without emission | `lib.sh` 137–139 | M00672 | non-negotiable | false | 10 |
| R06224 | lib.sh emit_drift_event — best-effort: notifier hiccup never fails the pipeline | `lib.sh` 141–143 | M00672 | non-negotiable | false | 10 |
| R06225 | lib.sh emit_drift_event — OCSF class_uid=2004 | `lib.sh` 145 | M00680 | non-negotiable | false | 10 |
| R06226 | lib.sh emit_drift_event — activity_id=1 | `lib.sh` 146 | M00680 | non-negotiable | false | 10 |
| R06227 | lib.sh emit_drift_event — source="selfdef.integrity-sentinel" | `lib.sh` 148 | M00680 | non-negotiable | false | 10 |
| R06228 | uninstall.sh — removes recorded baseline so fresh apply can re-seal | `uninstall.sh` 4 | M00663 | non-negotiable | false | 10 |
| R06229 | uninstall.sh — does NOT touch paths_file | `uninstall.sh` 5 | M00663 | non-negotiable | false | 10 |
| R06230 | uninstall.sh — walks manifest via module_render_files | `uninstall.sh` 22 | M00673 | non-negotiable | false | 10 |
| R06231 | uninstall.sh — legacy fallback if manifest_count=0 | `uninstall.sh` 28–37 | M00663 | non-negotiable | false | 10 |
| R06232 | uninstall.sh — legacy fallback default baseline path /var/lib/selfdef/integrity-sentinel/baseline.sha256 | `uninstall.sh` 30 | M00663 | non-negotiable | false | 10 |
| R06233 | uninstall.sh — legacy fallback reads baseline_path from CONFIG_FILE if present | `uninstall.sh` 31–33 | M00663 | non-negotiable | false | 10 |
| R06234 | uninstall.sh — clears manifest via module_clear_manifest | `uninstall.sh` 39 | M00663 | non-negotiable | false | 10 |
| R06235 | uninstall.sh — emit_status "ok" "uninstalled (paths_file preserved, N file(s) removed)" | `uninstall.sh` 41 | M00663 | non-negotiable | false | 10 |
| R06236 | profiles/strict.toml — event emission ON by default | `profiles/strict.toml` 22–24 | M00674 | non-negotiable | false | 10 |
| R06237 | profiles/warn-only.toml — event_severity_warn=low so doesn't trip is_actionable filter | `profiles/warn-only.toml` 17–18 | M00675 | non-negotiable | false | 10 |
| R06238 | paths.txt.default — comment notes "Copy this file to /etc/selfdef/integrity-sentinel/paths.txt and edit to taste" | `paths.txt.default` 2–3 | M00657 | non-negotiable | false | 10 |
| R06239 | paths.txt.default — comment notes "globstar is enabled when this file is expanded" | `paths.txt.default` 4 | M00657 | non-negotiable | false | 10 |
| R06240 | Composite — MS026 (10 epics / 26 modules / 120 features / 240 reqs) covers integrity-sentinel module v0.1.1 (655 lines): module.toml (44-line manifest with single-instance + phase=pre + [daemon_requires]) + README.md (189-line operator doc with full lifecycle + caveats + scope) + paths.txt.default (24-line default 6-category paths set) + 2 profiles (strict default fail-closed high-severity + warn-only bring-up low-severity) + apply.sh (107-line idempotent applier + first-run-seal + verify + OCSF 2004 drift event) + check.sh (61-line side-effect-free verifier + missing-baseline-always-fails) + lib.sh (150-line expand_paths + compute_baseline + emit_drift_event helpers) + uninstall.sh (46-line manifest-walked + legacy-fallback + paths_file-preserved); 1 provided surface (baseline-attestation); 2 required binaries (sha256sum + diff); fail-closed tripwire doctrine; "operator owns the keys to"; SHA256 integrity NOT authenticity; pair with chattr +i / out-of-band storage; on_missing=fail exploit-race prevention; phase=pre gates rest of apply on baseline intact; daemon_requires SDD-002 D-1 + F-2026-018; F-2027-024 manifest integration | `modules/integrity-sentinel/` 655 lines | E0261 + E0262 + E0263 + E0264 + E0265 + E0266 + E0267 + E0268 + E0269 + E0270 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module.toml full transcription including [daemon_requires] (R06001–R06031) + README fail-closed doctrine + 6 baselined paths + profiles + lifecycle (R06032–R06079) + baseline format + sha256sum -c verifiability (R06080–R06086) + config schema + notifying-on-drift OCSF 2004 wiring + on_missing=fail exploit-race rationale (R06087–R06107) + scope owned + not-owned + SHA256-is-integrity-not-authenticity + mitigations (R06108–R06120) + caveats (symlinks/globs/special-files/phase=pre) (R06121–R06133) + apply.sh full transcription including first-run-seal + verify + drift summary + strict-vs-warn-only branching + F-2027-024 manifest record (R06134–R06181) + check.sh full transcription including missing-baseline-always-fails + DRY_RUN-forced-0 (R06182–R06196) + lib.sh full transcription including expand_paths globstar+nullglob + compute_baseline xargs sha256sum sort + emit_drift_event OCSF 2004 + gating + best-effort (R06197–R06227) + uninstall.sh full transcription including manifest-walk + legacy-fallback + paths_file-preserved (R06228–R06235) + profile defaults + paths.txt.default comments (R06236–R06239) + composite (R06240)
- Source range 655 lines yields 240 R-rows representing ~37% line-coverage at the verbatim-citation level (commentary lines in lib.sh + apply.sh excluded; most non-trivial invariants captured)
- Project boundary — MS026 is selfdef IPS hardening scope; phase=pre semantic gates rest of apply on baseline being intact; cross-repo binding to sovereign-os routes through MS007 audit-manifest typed-mirror crate (the operator-trusted out-of-band baseline could surface in sovereign-os audit dashboards)

## Cross-references

- Adjacent INDEX rows: MS025 detect-host (substrate) / MS027 Observability module (selfdef-side)
- Lifecycle integration — integrity-sentinel runs phase=pre BEFORE any main-phase module; gates rest of apply on baseline being intact; strict drift halts before host state mutates
- Event integration — emits OCSF Detection Finding class 2004 via `selfdefctl events emit` to JSONL stream that detect-host's eventstream collector tails; daemon's responder routes to notifier chain (MS004 14-notifier-integrations) → ntfy/Signal/etc.
- daemon_requires integration — module.toml [daemon_requires] block (SDD-002 D-1 + F-2026-018) declares that selfdef-daemon's collectors.eventstream.enabled=true + paths includes the integrity-sentinel JSONL stream; module-loader SHALL enforce this contract before apply proceeds
- Test integration — MS020 L1-L5 layered harness covers module-script category (Category 3 of 4) for apply.sh + check.sh + uninstall.sh
- Shared module-script lib — MS021 shared module-script lib v2 provides log / emit_status / die / run / toml_get / module_record_file / module_render_files / module_clear_manifest used here
- SDD ledger integration — F-2026-018 (emission on by default) + SDD-002 D-1 ([daemon_requires] design point) + F-2027-024 (manifest helpers opt-in) + F-2027-027 (DRY_RUN-forced-0 in check.sh) all from selfdef SDD ledger (MS013 27-SDD charter)
- Cross-module — integrity-sentinel baselines per-module configs at /etc/selfdef/modules/*.toml + module manifests at /usr/share/selfdef/modules/*/module.toml + install scripts at /usr/share/selfdef/modules/*/install/*.sh; ALL other modules (MS023 polarproxy / MS024 bridge-l2 / MS025 detect-host etc.) are subject to this baseline
- Cross-repo binding — sovereign-os has no integrity-sentinel equivalent (host-hardening tripwire is IPS-only); cross-repo audit (if needed) routes through MS007 audit-manifest typed-mirror crate
- Operator references: sha256sum(1) manpage / OCSF Detection Finding class 2004 / `chattr +i` filesystem immutability / SDD-002 + F-2026-018 + F-2027-024 + F-2027-027 from selfdef SDD ledger
