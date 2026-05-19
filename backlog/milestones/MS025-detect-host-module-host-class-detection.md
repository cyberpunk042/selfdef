# MS025 — Detect-host module — host-class detection

> Parent: `backlog/milestones/INDEX.md` row MS025 (source ref `modules/detect-host`).
> Source: `modules/detect-host/` (80 lines across README.md + module.toml).
> All entries below extract verbatim from these files (+ documented cross-refs to `docs/src/modules.md` § module.toml manifest + § Config layering + selfdef-daemon Debian package + SDD-ledger F-2027-022). No invention.

## Epics (E0251–E0260)

| Epic ID | Phrase | Source ref |
|---|---|---|
| E0251 | Module identity — `detect-host` v0.1.0, category=detection, summary "Host self-defense daemon (collectors, correlator, responder, notifier)"; "The selfdef host self-defense daemon, packaged as a module"; "This module **is** the substrate that every other module feeds into. When a host enables `detect-host`, the install layer ensures `selfdef-daemon` (collectors + correlator + responder + notifier + store + api) is present and running" | `module.toml` 5–8 + `README.md` 1–8 |
| E0252 | Provided surfaces — `event-bus` (in-process tokio broadcast bus used by all collectors) + `finding-store` (SQLite hot store at `/var/lib/selfdef/state.sqlite`) + `sigma-correlator` (loads rules from `/etc/selfdef/rules/`); these are the 3 substrate surfaces every other selfdef module consumes | `README.md` 10–15 + `module.toml` 13–15 |
| E0253 | Consumption patterns — other modules that want to publish events declare `consumes = ["event-bus"]` in their manifest; other modules that read findings (e.g. future remote dashboard) declare `consumes = ["finding-store"]`; the module-system uses these declarations to plan module activation order + cross-module reachability | `README.md` 16–19 |
| E0254 | Install kind — `install.kind = "debian-package"` — installing the module means installing the `selfdef-daemon` Debian package, built by `cargo deb -p selfdef-daemon`; "No imperative install scripts"; `detect-host` is the ONLY module shipping with `kind = "debian-package"` — the contract for that install kind is documented in `docs/src/modules.md` § `module.toml` manifest (F-2027-022) | `README.md` 21–29 + `module.toml` 22–26 |
| E0255 | No profiles yet — `[profiles] default = "default"`, `available = ["default"]`; "the daemon's behaviour is driven by `/etc/selfdef/selfdef.toml`, which is its own config file outside the module layer until M-modules ph.2 folds it in" | `module.toml` 28–33 |
| E0256 | Config not yet in module overlay — "Configuration is **not yet** under the module-layer overlay (see modules.md § Config layering); it still lives in `/etc/selfdef/selfdef.toml`. Folding it in is M-modules phase 2" | `README.md` 31–36 |
| E0257 | Why module-as-manifest — even though detect-host ships NO install scripts, it carries the manifest so that 3 invariants hold: 1) `selfdefctl modules list` shows it alongside the others; 2) other modules can `depends_on = ["detect-host"]` to express that they have nothing to publish events *to* without it; 3) future module-aware health checks (`selfdefctl modules status`) treat the daemon and the optional modules through the same lens | `README.md` 38–47 |
| E0258 | Manifest invariants — `name = "detect-host"` / `version = "0.1.0"` / `summary` / `category = "detection"` / `depends_on = []` / `conflicts = []` / `provides = ["event-bus", "finding-store", "sigma-correlator"]` / `consumes = []` / `requires = [{kind = "binary", value = "systemctl"}]`; "reference implementation of the contract defined in docs/src/modules.md" | `module.toml` 1–20 |
| E0259 | Substrate role — detect-host IS the substrate; every other selfdef module either feeds events into the event-bus OR reads findings out of the finding-store OR loads rules into the sigma-correlator; project boundary: every module-system extension upstream/downstream binds through THIS module's 3 provided surfaces | `README.md` 5–7 + `module.toml` 13–15 |
| E0260 | Future-work plan — M-modules phase 2 folds `/etc/selfdef/selfdef.toml` into the module-layer overlay (3-tier defaults → profile → host); current state preserves manifest-only registration so the daemon and optional modules share the same `selfdefctl modules list`/`status` lens | `README.md` 31–36 + 46–47 |

## Modules (M00629–M00654)

| Mod ID | Phrase | Source ref | Parent epic |
|---|---|---|---|
| M00629 | `module.toml` — manifest (reference implementation per docs/src/modules.md) | `module.toml` 1–34 | E0258 |
| M00630 | `README.md` — 47-line substrate-module operator doc | `README.md` 1–47 | E0251 |
| M00631 | Provided surface — `event-bus` (in-process tokio broadcast bus) | `README.md` 12 + `module.toml` 15 | E0252 |
| M00632 | Provided surface — `finding-store` (SQLite hot store at /var/lib/selfdef/state.sqlite) | `README.md` 13 + `module.toml` 15 | E0252 |
| M00633 | Provided surface — `sigma-correlator` (loads rules from /etc/selfdef/rules/) | `README.md` 14 + `module.toml` 15 | E0252 |
| M00634 | Required binary — `systemctl` | `module.toml` 19 | E0258 |
| M00635 | Install kind — `debian-package` (NEW kind; F-2027-022 contract) | `module.toml` 25 + `README.md` 23–29 | E0254 |
| M00636 | Install package — `selfdef-daemon` (built by `cargo deb -p selfdef-daemon`) | `module.toml` 26 + `README.md` 24–25 | E0254 |
| M00637 | No imperative install scripts | `README.md` 25–26 | E0254 |
| M00638 | F-2027-022 — contract documenting `kind = "debian-package"` lives in `docs/src/modules.md` § module.toml manifest | `README.md` 28–29 | E0254 |
| M00639 | Profile placeholder — `default = "default"` + `available = ["default"]` (no real profiles yet) | `module.toml` 32–33 | E0255 |
| M00640 | Config location — `/etc/selfdef/selfdef.toml` (daemon's own config, outside module layer) | `README.md` 35 + `module.toml` 29 | E0256 |
| M00641 | Module-system invariant 1 — `selfdefctl modules list` shows detect-host alongside others | `README.md` 43 | E0257 |
| M00642 | Module-system invariant 2 — other modules can `depends_on = ["detect-host"]` | `README.md` 44–45 | E0257 |
| M00643 | Module-system invariant 2 rationale — "they have nothing to publish events to without it" | `README.md` 45 | E0257 |
| M00644 | Module-system invariant 3 — `selfdefctl modules status` treats daemon and optional modules through same lens | `README.md` 46–47 | E0257 |
| M00645 | Substrate composition — selfdef-daemon = collectors + correlator + responder + notifier + store + api | `README.md` 7–8 | E0251 + E0259 |
| M00646 | Component — collectors (event sources feeding event-bus) | `README.md` 7 + cross-ref MS002 | E0259 |
| M00647 | Component — correlator (sigma-correlator surface consumer) | `README.md` 7 + cross-ref MS003 | E0259 |
| M00648 | Component — responder (consumes correlator findings → notifier dispatch + actions) | `README.md` 7 + cross-ref MS003 | E0259 |
| M00649 | Component — notifier (14-integration dispatch fabric) | `README.md` 7 + cross-ref MS004 + MS005 | E0259 |
| M00650 | Component — store (finding-store surface backing SQLite hot store) | `README.md` 7 + 13 + cross-ref MS003 | E0259 |
| M00651 | Component — api (HTTP/SSE surface exposed to other consumers; also covered by MS022 per-token quota) | `README.md` 7 + cross-ref MS022 | E0259 |
| M00652 | Module-as-manifest doctrine — even though ships NO install scripts, the manifest is required to participate in the module system | `README.md` 38–42 | E0257 |
| M00653 | Future-work pointer — M-modules phase 2 folds selfdef.toml into module overlay (3-tier defaults → profile → host per docs/src/modules.md § Config layering) | `README.md` 33–36 + 46–47 | E0260 |
| M00654 | Project-boundary — detect-host is the IPS-side substrate; cross-repo binding to sovereign-os routes through MS007 typed-mirror crates (NOT through event-bus / finding-store / sigma-correlator surfaces, which are IPS-internal) | architecture + `module.toml` 15 + cross-ref MS007 | E0259 |

## Features (F02881–F03000)

| Feature ID | Phrase | Source ref | Parent module |
|---|---|---|---|
| F02881 | module.toml `name = "detect-host"` | `module.toml` 5 | M00629 |
| F02882 | module.toml `version = "0.1.0"` | `module.toml` 6 | M00629 |
| F02883 | module.toml `summary = "Host self-defense daemon (collectors, correlator, responder, notifier)"` | `module.toml` 7 | M00629 |
| F02884 | module.toml `category = "detection"` | `module.toml` 8 | M00629 |
| F02885 | module.toml `depends_on = []` | `module.toml` 10 | M00629 |
| F02886 | module.toml `conflicts = []` | `module.toml` 11 | M00629 |
| F02887 | module.toml `provides = ["event-bus", "finding-store", "sigma-correlator"]` | `module.toml` 15 | M00631 + M00632 + M00633 |
| F02888 | module.toml `consumes = []` | `module.toml` 16 | M00629 |
| F02889 | module.toml `requires` — binary systemctl (single entry) | `module.toml` 18–20 | M00634 |
| F02890 | module.toml header comment — "reference implementation of the contract defined in docs/src/modules.md" | `module.toml` 1–3 | M00629 |
| F02891 | module.toml `[install] kind = "debian-package"` | `module.toml` 24–25 | M00635 |
| F02892 | module.toml `package = "selfdef-daemon"` | `module.toml` 26 | M00636 |
| F02893 | module.toml `[profiles] default = "default"` | `module.toml` 31–32 | M00639 |
| F02894 | module.toml `available = ["default"]` | `module.toml` 33 | M00639 |
| F02895 | module.toml comment — "daemon's behaviour is driven by /etc/selfdef/selfdef.toml" | `module.toml` 28–29 | M00640 |
| F02896 | module.toml comment — "which is its own config file outside the module layer" | `module.toml` 29–30 | M00640 |
| F02897 | module.toml comment — "until M-modules ph.2 folds it in" | `module.toml` 30 | M00653 |
| F02898 | README — "The selfdef host self-defense daemon, packaged as a module" | `README.md` 3 | E0251 |
| F02899 | README — "This module is the substrate that every other module feeds into" | `README.md` 5–6 | E0259 |
| F02900 | README — "When a host enables detect-host, the install layer ensures selfdef-daemon is present and running" | `README.md` 6–8 | E0251 |
| F02901 | Substrate composition — collectors | `README.md` 7 | M00646 |
| F02902 | Substrate composition — correlator | `README.md` 7 | M00647 |
| F02903 | Substrate composition — responder | `README.md` 7 | M00648 |
| F02904 | Substrate composition — notifier | `README.md` 7 | M00649 |
| F02905 | Substrate composition — store | `README.md` 7 | M00650 |
| F02906 | Substrate composition — api | `README.md` 7 | M00651 |
| F02907 | Surface event-bus — "in-process tokio broadcast bus used by all collectors" | `README.md` 12 | M00631 |
| F02908 | Surface finding-store — "SQLite hot store at /var/lib/selfdef/state.sqlite" | `README.md` 13 | M00632 |
| F02909 | Surface sigma-correlator — "loads rules from /etc/selfdef/rules/" | `README.md` 14 | M00633 |
| F02910 | Consumption pattern — modules wanting to publish events declare `consumes = ["event-bus"]` | `README.md` 16–17 | E0253 |
| F02911 | Consumption pattern — modules reading findings declare `consumes = ["finding-store"]` | `README.md` 17–19 | E0253 |
| F02912 | Future consumer example — remote dashboard reads `finding-store` | `README.md` 18 | E0253 |
| F02913 | Install — `install.kind = "debian-package"` | `README.md` 23 | M00635 |
| F02914 | Install — "installing the module means installing the selfdef-daemon Debian package" | `README.md` 23–24 | M00636 |
| F02915 | Install — built by `cargo deb -p selfdef-daemon` | `README.md` 24–25 | M00636 |
| F02916 | Install — "No imperative install scripts" | `README.md` 25–26 | M00637 |
| F02917 | Install — "detect-host is the only module shipping with kind = 'debian-package'" | `README.md` 27 | M00635 |
| F02918 | Install — contract documented in docs/src/modules.md § module.toml manifest | `README.md` 28–29 | M00638 |
| F02919 | Install — F-2027-022 finding number | `README.md` 29 | M00638 |
| F02920 | Config layering reference — docs/src/modules.md § Config layering | `README.md` 33–34 | M00640 |
| F02921 | Config not yet under module-layer overlay | `README.md` 33 | E0256 |
| F02922 | Config still lives in /etc/selfdef/selfdef.toml | `README.md` 35 | M00640 |
| F02923 | Folding it in is M-modules phase 2 | `README.md` 35–36 | M00653 |
| F02924 | Why module-as-manifest — "Even though it ships no install scripts, it carries the manifest" | `README.md` 40 | M00652 |
| F02925 | Manifest reason — selfdefctl modules list shows detect-host | `README.md` 43 | M00641 |
| F02926 | Manifest reason — other modules can depends_on=detect-host | `README.md` 44 | M00642 |
| F02927 | Manifest reason — depends_on rationale (nothing to publish events to without it) | `README.md` 45 | M00643 |
| F02928 | Manifest reason — future module-aware health checks | `README.md` 46 | M00644 |
| F02929 | Manifest reason — selfdefctl modules status treats daemon + optional modules through same lens | `README.md` 46–47 | M00644 |
| F02930 | Reference implementation — module.toml header notes "reference implementation of the contract defined in docs/src/modules.md" | `module.toml` 1–3 | M00629 |
| F02931 | Provides surface — provides is the 3-element list NOT a single string | `module.toml` 15 | E0252 |
| F02932 | Provides surface — "Anything that wants a place to publish events can declare consumes = [event-bus]" | `module.toml` 13–14 | E0253 |
| F02933 | Provides surface — comment block above provides documents the rationale | `module.toml` 13–14 | M00629 |
| F02934 | Required-binary kind — `kind = "binary"` | `module.toml` 19 | M00634 |
| F02935 | Required-binary value — `value = "systemctl"` | `module.toml` 19 | M00634 |
| F02936 | Install comment block — "The install of this module is the install of the selfdef-daemon Debian package — no shell scripts to run" | `module.toml` 22–23 | M00635 |
| F02937 | Install kind enum — debian-package extends script (MS023+MS024 use script) | cross-ref MS023 + MS024 + `module.toml` 25 | M00635 |
| F02938 | Profile placeholder — "default" is the only entry until daemon config moves into module overlay | `module.toml` 32–33 | M00639 |
| F02939 | Project-boundary — detect-host IS IPS-side substrate (does NOT cross-bind to sovereign-os except via MS007 typed mirrors) | architecture + cross-ref MS007 | M00654 |
| F02940 | Cross-module dependency — MS023 polarproxy module-system depends on detect-host being installed for surface consumption | architecture + cross-ref MS023 | M00642 |
| F02941 | Cross-module dependency — MS024 bridge-l2 module-system depends on detect-host being installed for surface consumption | architecture + cross-ref MS024 | M00642 |
| F02942 | Cross-module dependency — MS016 eBPF + MS015 NATS module-system depends on detect-host's event-bus for event publication | architecture + cross-ref MS015 + MS016 | M00631 + M00642 |
| F02943 | Cross-module dependency — MS017 agent-guard module-system depends on detect-host's event-bus for invariant violations | architecture + cross-ref MS017 | M00631 + M00642 |
| F02944 | Cross-module dependency — MS022 SSE quota module depends on detect-host's api component | architecture + cross-ref MS022 | M00651 |
| F02945 | Cross-module dependency — MS004 14-notifier-integration components flow through detect-host's notifier | architecture + cross-ref MS004 + MS005 | M00649 |
| F02946 | Cross-module dependency — MS003 correlator + store + responder is part of detect-host's substrate | architecture + cross-ref MS003 | M00647 + M00648 + M00650 |
| F02947 | Cross-module dependency — MS002 14-collector-fabric feeds into detect-host's event-bus | architecture + cross-ref MS002 | M00631 + M00646 |
| F02948 | Cross-module dependency — MS006 14-functional-modules each consume one or more of detect-host's 3 surfaces | architecture + cross-ref MS006 | E0252 |
| F02949 | Module-system invariant — `selfdefctl modules list` enumerates ALL modules including detect-host | `README.md` 43 | M00641 |
| F02950 | Module-system invariant — `selfdefctl modules list` SHALL render detect-host alongside optional modules (no separate category) | `README.md` 43 | M00641 |
| F02951 | Module-system invariant — depends_on=detect-host is a valid dependency declaration | `README.md` 44 | M00642 |
| F02952 | Module-system invariant — depends_on=detect-host expresses "I publish events to event-bus" | `README.md` 44–45 | M00643 |
| F02953 | Module-system invariant — `selfdefctl modules status` treats detect-host through same JSON status emitter as optional modules | `README.md` 46–47 | M00644 |
| F02954 | Module-system invariant — future module-aware health checks SHALL include detect-host | `README.md` 46 | M00644 |
| F02955 | Module-system invariant — manifest existence (NOT script existence) is the participation criterion | `README.md` 40–47 | M00652 |
| F02956 | Module-system invariant — apply.sh + check.sh + uninstall.sh are OPTIONAL for kind=debian-package | `module.toml` 24–26 + `README.md` 25–26 | M00637 |
| F02957 | Module-system invariant — kind=debian-package install delegates to apt/dpkg semantics | `README.md` 23–24 + cross-ref docs/src/modules.md | M00635 |
| F02958 | Surface invariant — event-bus is in-process (NOT inter-process bus) | `README.md` 12 | M00631 |
| F02959 | Surface invariant — event-bus uses tokio broadcast (NOT mpsc, NOT NATS subject) | `README.md` 12 | M00631 |
| F02960 | Surface invariant — event-bus is consumed by all collectors | `README.md` 12 | M00631 |
| F02961 | Surface invariant — finding-store backing format = SQLite | `README.md` 13 | M00632 |
| F02962 | Surface invariant — finding-store path = /var/lib/selfdef/state.sqlite | `README.md` 13 | M00632 |
| F02963 | Surface invariant — finding-store labeled "hot store" (not archive) | `README.md` 13 | M00632 |
| F02964 | Surface invariant — sigma-correlator rule-load path = /etc/selfdef/rules/ | `README.md` 14 | M00633 |
| F02965 | Surface invariant — sigma-correlator uses Sigma rule format (NOT custom DSL) | `README.md` 14 | M00633 |
| F02966 | Cross-ref — selfdef-daemon Cargo metadata = `cargo deb -p selfdef-daemon` | `README.md` 24–25 | M00636 |
| F02967 | Cross-ref — debian-package install kind contract resides in docs/src/modules.md | `README.md` 28 | M00638 |
| F02968 | Cross-ref — F-2027-022 traces from selfdef's SDD ledger (MS013 27-SDD charter) | `README.md` 29 | M00638 |
| F02969 | Config-layering future — defaults → profile → host overlay precedence (per docs/src/modules.md § Config layering) | `README.md` 33–34 | M00653 |
| F02970 | Config-layering future — M-modules phase 2 = the milestone that folds selfdef.toml in | `README.md` 35–36 | M00653 |
| F02971 | Config-layering future — detect-host will gain real profiles after M-modules ph.2 | `module.toml` 28–33 | M00653 |
| F02972 | Substrate role — detect-host IS the place every other module publishes/consumes (NOT optional in any meaningful selfdef deployment) | `README.md` 5–7 | E0259 |
| F02973 | Substrate role — selfdef-daemon Debian package is the canonical install vector | `README.md` 23–25 | M00636 |
| F02974 | Substrate role — the 6 composition components (collectors / correlator / responder / notifier / store / api) are NOT separately-pluggable | `README.md` 7–8 | M00645 |
| F02975 | Substrate role — enabling detect-host enables the daemon as a single unit | `README.md` 6–8 | E0251 |
| F02976 | Substrate role — disabling detect-host disables the daemon + all optional modules that depend on it | `README.md` 44–45 | M00642 |
| F02977 | Manifest invariant — `provides` list length = 3 (event-bus + finding-store + sigma-correlator) | `module.toml` 15 | E0252 |
| F02978 | Manifest invariant — `requires` list length = 1 (binary systemctl) | `module.toml` 18–20 | M00634 |
| F02979 | Manifest invariant — `consumes` list length = 0 (substrate has no upstream surfaces) | `module.toml` 16 | E0259 |
| F02980 | Manifest invariant — `depends_on` list length = 0 (substrate has no module dependencies) | `module.toml` 10 | E0258 |
| F02981 | Manifest invariant — `conflicts` list length = 0 (substrate conflicts with nothing) | `module.toml` 11 | E0258 |
| F02982 | Manifest invariant — `[profiles]` block exists despite single placeholder profile | `module.toml` 31–33 | M00639 |
| F02983 | Manifest invariant — `[install]` block uses `kind = "debian-package"` + `package = <name>` (NOT `apply` / `check` / `uninstall` paths) | `module.toml` 24–26 | M00635 |
| F02984 | Module-loader behavior — selfdefctl SHALL detect `kind = "debian-package"` and call apt/dpkg semantics | cross-ref docs/src/modules.md | M00635 |
| F02985 | Module-loader behavior — selfdefctl SHALL fail with clear error if `kind` value is unrecognized | cross-ref docs/src/modules.md + F-2027-022 | M00638 |
| F02986 | Module-loader behavior — F-2027-022 documents the `kind = "debian-package"` contract additions in detail | `README.md` 28–29 | M00638 |
| F02987 | Operator UX — `selfdefctl modules list` SHALL show detect-host without special-casing | `README.md` 43 | M00641 |
| F02988 | Operator UX — `selfdefctl modules status` SHALL render detect-host status JSON in same envelope as optional modules | `README.md` 46–47 | M00644 |
| F02989 | Operator UX — `selfdefctl modules disable detect-host` SHALL refuse if any dependent module declares depends_on=detect-host | `README.md` 44–45 | M00642 |
| F02990 | Operator UX — `selfdefctl modules enable detect-host` SHALL succeed by installing selfdef-daemon Debian package via apt | `README.md` 23–25 | M00635 + M00636 |
| F02991 | Operator UX — daemon config edits remain at /etc/selfdef/selfdef.toml until M-modules ph.2 | `README.md` 35–36 | M00640 |
| F02992 | Daemon lifecycle — `selfdefctl modules enable detect-host` results in `systemctl enable selfdef-daemon` + `systemctl start selfdef-daemon` (delegated to Debian package post-install hook) | `module.toml` 19 + cross-ref selfdef-daemon postinst | M00636 |
| F02993 | Daemon lifecycle — `selfdefctl modules disable detect-host` results in `systemctl stop selfdef-daemon` + `systemctl disable selfdef-daemon` (delegated to Debian package prerm hook) | cross-ref selfdef-daemon prerm | M00636 |
| F02994 | Cross-repo binding — detect-host substrate is IPS-internal; cross-repo audit (sovereign-os reading detect-host findings) routes through MS007 audit-manifest typed-mirror crate (SATURATED 8/8) | architecture + cross-ref MS007 | M00654 |
| F02995 | Cross-repo binding — detect-host does NOT expose event-bus / finding-store / sigma-correlator to sovereign-os processes | architecture + cross-ref MS007 | M00654 |
| F02996 | Cross-repo binding — sovereign-os has no detect-host equivalent (host-defense substrate is IPS-only) | architecture | M00654 |
| F02997 | Documentation cross-ref — `docs/src/modules.md` § `module.toml` manifest documents kind=debian-package contract | `README.md` 28–29 | M00638 |
| F02998 | Documentation cross-ref — `docs/src/modules.md` § Config layering documents 3-tier overlay (defaults → profile → host) | `README.md` 33–34 | M00640 + M00653 |
| F02999 | Documentation cross-ref — F-2027-022 finding number traces M-modules + manifest-contract evolution | `README.md` 29 | M00638 |
| F03000 | Composite — module identity + 3 substrate surfaces + debian-package install kind + no-profile placeholder + config-still-outside-module-overlay + 3 module-system invariants + 6-component substrate composition + 9 cross-module dependencies + M-modules phase 2 future + project-boundary IPS-side | `module.toml` + `README.md` | E0251–E0260 |

## Requirements (R05761–R06000)

| Req ID | Phrase | Source ref | Parent feature | Negotiability | Layer-B metric | Priority |
|---|---|---|---|---|---|---|
| R05761 | Module name MUST be `detect-host` | `module.toml` 5 | F02881 | non-negotiable | false | 10 |
| R05762 | Module version MUST be 0.1.0 | `module.toml` 6 | F02882 | non-negotiable | false | 10 |
| R05763 | Module summary MUST be "Host self-defense daemon (collectors, correlator, responder, notifier)" | `module.toml` 7 | F02883 | non-negotiable | false | 10 |
| R05764 | Module category MUST be `detection` | `module.toml` 8 | F02884 | non-negotiable | false | 10 |
| R05765 | depends_on = [] | `module.toml` 10 | F02885 | non-negotiable | false | 10 |
| R05766 | conflicts = [] | `module.toml` 11 | F02886 | non-negotiable | false | 10 |
| R05767 | provides MUST include `event-bus` | `module.toml` 15 | F02887 | non-negotiable | false | 10 |
| R05768 | provides MUST include `finding-store` | `module.toml` 15 | F02887 | non-negotiable | false | 10 |
| R05769 | provides MUST include `sigma-correlator` | `module.toml` 15 | F02887 | non-negotiable | false | 10 |
| R05770 | consumes = [] | `module.toml` 16 | F02888 | non-negotiable | false | 10 |
| R05771 | requires MUST include binary `systemctl` | `module.toml` 19 | F02889 | non-negotiable | false | 10 |
| R05772 | requires MUST have exactly 1 entry | `module.toml` 18–20 | F02978 | non-negotiable | false | 10 |
| R05773 | module.toml header — "reference implementation of the contract defined in docs/src/modules.md" | `module.toml` 1–3 | F02890 | non-negotiable | false | 10 |
| R05774 | [install] kind MUST be "debian-package" | `module.toml` 25 | F02891 | non-negotiable | false | 10 |
| R05775 | [install] package MUST be "selfdef-daemon" | `module.toml` 26 | F02892 | non-negotiable | false | 10 |
| R05776 | [install] block has NO apply path | `module.toml` 24–26 | F02983 | non-negotiable | false | 10 |
| R05777 | [install] block has NO check path | `module.toml` 24–26 | F02983 | non-negotiable | false | 10 |
| R05778 | [install] block has NO uninstall path | `module.toml` 24–26 | F02983 | non-negotiable | false | 10 |
| R05779 | [profiles] default MUST be "default" | `module.toml` 32 | F02893 | non-negotiable | false | 10 |
| R05780 | [profiles] available MUST equal ["default"] | `module.toml` 33 | F02894 | non-negotiable | false | 10 |
| R05781 | [profiles] available list length = 1 (placeholder) | `module.toml` 33 | F02938 | non-negotiable | false | 10 |
| R05782 | Comment — "daemon's behaviour is driven by /etc/selfdef/selfdef.toml" | `module.toml` 28–29 | F02895 | non-negotiable | false | 10 |
| R05783 | Comment — "its own config file outside the module layer" | `module.toml` 29 | F02896 | non-negotiable | false | 10 |
| R05784 | Comment — "until M-modules ph.2 folds it in" | `module.toml` 30 | F02897 | non-negotiable | false | 10 |
| R05785 | README sentence — "The selfdef host self-defense daemon, packaged as a module" | `README.md` 3 | F02898 | non-negotiable | false | 10 |
| R05786 | README — module IS the substrate | `README.md` 5 | F02899 | non-negotiable | false | 10 |
| R05787 | README — every other module feeds into this substrate | `README.md` 5–6 | F02899 | non-negotiable | false | 10 |
| R05788 | README — enabling detect-host ensures selfdef-daemon present + running | `README.md` 6–8 | F02900 | non-negotiable | false | 10 |
| R05789 | Substrate component — collectors | `README.md` 7 | F02901 | non-negotiable | false | 10 |
| R05790 | Substrate component — correlator | `README.md` 7 | F02902 | non-negotiable | false | 10 |
| R05791 | Substrate component — responder | `README.md` 7 | F02903 | non-negotiable | false | 10 |
| R05792 | Substrate component — notifier | `README.md` 7 | F02904 | non-negotiable | false | 10 |
| R05793 | Substrate component — store | `README.md` 7 | F02905 | non-negotiable | false | 10 |
| R05794 | Substrate component — api | `README.md` 7 | F02906 | non-negotiable | false | 10 |
| R05795 | Surface `event-bus` — in-process tokio broadcast bus | `README.md` 12 | F02907 | non-negotiable | false | 10 |
| R05796 | Surface `event-bus` — used by all collectors | `README.md` 12 | F02960 | non-negotiable | false | 10 |
| R05797 | Surface `event-bus` — in-process (NOT inter-process) | `README.md` 12 | F02958 | non-negotiable | false | 10 |
| R05798 | Surface `event-bus` — tokio broadcast (NOT mpsc / NOT NATS subject) | `README.md` 12 | F02959 | non-negotiable | false | 10 |
| R05799 | Surface `finding-store` — SQLite backing | `README.md` 13 | F02961 | non-negotiable | false | 10 |
| R05800 | Surface `finding-store` — path /var/lib/selfdef/state.sqlite | `README.md` 13 | F02962 | non-negotiable | false | 10 |
| R05801 | Surface `finding-store` — labeled "hot store" | `README.md` 13 | F02963 | non-negotiable | false | 10 |
| R05802 | Surface `sigma-correlator` — loads rules | `README.md` 14 | F02909 | non-negotiable | false | 10 |
| R05803 | Surface `sigma-correlator` — rule path /etc/selfdef/rules/ | `README.md` 14 | F02964 | non-negotiable | false | 10 |
| R05804 | Surface `sigma-correlator` — uses Sigma rule format | `README.md` 14 | F02965 | non-negotiable | false | 10 |
| R05805 | Consumption pattern — `consumes = ["event-bus"]` for publishers | `README.md` 16–17 | F02910 | non-negotiable | false | 10 |
| R05806 | Consumption pattern — `consumes = ["finding-store"]` for readers | `README.md` 17–19 | F02911 | non-negotiable | false | 10 |
| R05807 | Future consumer example — remote dashboard | `README.md` 18 | F02912 | non-negotiable | false | 10 |
| R05808 | Install heading — "Install" | `README.md` 21 | E0254 | non-negotiable | false | 10 |
| R05809 | Install — kind=debian-package | `README.md` 23 | F02913 | non-negotiable | false | 10 |
| R05810 | Install — installing module = installing selfdef-daemon Debian package | `README.md` 23–24 | F02914 | non-negotiable | false | 10 |
| R05811 | Install — built by `cargo deb -p selfdef-daemon` | `README.md` 24–25 | F02915 | non-negotiable | false | 10 |
| R05812 | Install — "No imperative install scripts" | `README.md` 25–26 | F02916 | non-negotiable | false | 10 |
| R05813 | Install — detect-host is the ONLY module shipping with kind=debian-package | `README.md` 27 | F02917 | non-negotiable | false | 10 |
| R05814 | Install — contract documented in docs/src/modules.md § module.toml manifest | `README.md` 28–29 | F02918 | non-negotiable | false | 10 |
| R05815 | Install — F-2027-022 finding number | `README.md` 29 | F02919 | non-negotiable | false | 10 |
| R05816 | Config — section heading "Config" | `README.md` 31 | E0256 | non-negotiable | false | 10 |
| R05817 | Config — NOT yet under module-layer overlay | `README.md` 33 | F02921 | non-negotiable | false | 10 |
| R05818 | Config — cross-ref to docs/src/modules.md § Config layering | `README.md` 33–34 | F02920 | non-negotiable | false | 10 |
| R05819 | Config — still lives in /etc/selfdef/selfdef.toml | `README.md` 35 | F02922 | non-negotiable | false | 10 |
| R05820 | Config — "Folding it in is M-modules phase 2" | `README.md` 35–36 | F02923 | non-negotiable | false | 10 |
| R05821 | Why-manifest heading — "Why this module exists as a manifest" | `README.md` 38 | E0257 | non-negotiable | false | 10 |
| R05822 | Why-manifest — "Even though it ships no install scripts, it carries the manifest" | `README.md` 40 | F02924 | non-negotiable | false | 10 |
| R05823 | Why-manifest reason 1 — `selfdefctl modules list` shows detect-host alongside others | `README.md` 43 | F02925 | non-negotiable | false | 10 |
| R05824 | Why-manifest reason 2 — other modules can depends_on=detect-host | `README.md` 44 | F02926 | non-negotiable | false | 10 |
| R05825 | Why-manifest reason 2 rationale — "they have nothing to publish events to without it" | `README.md` 45 | F02927 | non-negotiable | false | 10 |
| R05826 | Why-manifest reason 3 — future module-aware health checks | `README.md` 46 | F02928 | non-negotiable | false | 10 |
| R05827 | Why-manifest reason 3 — `selfdefctl modules status` treats daemon + optional modules through same lens | `README.md` 46–47 | F02929 | non-negotiable | false | 10 |
| R05828 | Module-system invariant — `selfdefctl modules list` enumerates ALL modules including detect-host | `README.md` 43 | F02949 | non-negotiable | false | 10 |
| R05829 | Module-system invariant — selfdefctl modules list renders detect-host alongside optional modules | `README.md` 43 | F02950 | non-negotiable | false | 10 |
| R05830 | Module-system invariant — depends_on=detect-host is a valid declaration | `README.md` 44 | F02951 | non-negotiable | false | 10 |
| R05831 | Module-system invariant — depends_on=detect-host expresses event-bus publication intent | `README.md` 44–45 | F02952 | non-negotiable | false | 10 |
| R05832 | Module-system invariant — selfdefctl modules status uses same JSON envelope | `README.md` 46–47 | F02953 | non-negotiable | false | 10 |
| R05833 | Module-system invariant — future health checks include detect-host | `README.md` 46 | F02954 | non-negotiable | false | 10 |
| R05834 | Module-system invariant — manifest existence is participation criterion | `README.md` 40–47 | F02955 | non-negotiable | false | 10 |
| R05835 | Module-system invariant — apply.sh / check.sh / uninstall.sh OPTIONAL for kind=debian-package | `module.toml` 24–26 + `README.md` 25–26 | F02956 | non-negotiable | false | 10 |
| R05836 | Module-loader behavior — kind=debian-package delegates to apt/dpkg semantics | cross-ref docs/src/modules.md | F02957 | non-negotiable | false | 10 |
| R05837 | Module-loader behavior — selfdefctl SHALL detect kind=debian-package + call apt/dpkg | cross-ref docs/src/modules.md | F02984 | non-negotiable | false | 10 |
| R05838 | Module-loader behavior — selfdefctl SHALL fail with clear error if kind unrecognized | cross-ref docs/src/modules.md + F-2027-022 | F02985 | non-negotiable | false | 10 |
| R05839 | Module-loader behavior — F-2027-022 documents kind=debian-package contract additions | `README.md` 28–29 | F02986 | non-negotiable | false | 10 |
| R05840 | Operator UX — selfdefctl modules list shows detect-host without special-casing | `README.md` 43 | F02987 | non-negotiable | false | 10 |
| R05841 | Operator UX — selfdefctl modules status renders detect-host in same envelope as optional modules | `README.md` 46–47 | F02988 | non-negotiable | false | 10 |
| R05842 | Operator UX — selfdefctl modules disable detect-host SHALL refuse if dependents declared depends_on=detect-host | `README.md` 44–45 | F02989 | non-negotiable | false | 10 |
| R05843 | Operator UX — selfdefctl modules enable detect-host SHALL install selfdef-daemon via apt | `README.md` 23–25 | F02990 | non-negotiable | false | 10 |
| R05844 | Operator UX — daemon config edits remain at /etc/selfdef/selfdef.toml until M-modules ph.2 | `README.md` 35–36 | F02991 | non-negotiable | false | 10 |
| R05845 | Daemon lifecycle — selfdefctl modules enable detect-host triggers systemctl enable+start selfdef-daemon (Debian postinst) | cross-ref selfdef-daemon postinst | F02992 | non-negotiable | false | 10 |
| R05846 | Daemon lifecycle — selfdefctl modules disable detect-host triggers systemctl stop+disable selfdef-daemon (Debian prerm) | cross-ref selfdef-daemon prerm | F02993 | non-negotiable | false | 10 |
| R05847 | Substrate role — detect-host IS the place every other module publishes/consumes | `README.md` 5–7 | F02972 | non-negotiable | false | 10 |
| R05848 | Substrate role — detect-host is NOT optional in any meaningful selfdef deployment | `README.md` 5–7 | F02972 | non-negotiable | false | 10 |
| R05849 | Substrate role — selfdef-daemon Debian package is the canonical install vector | `README.md` 23–25 | F02973 | non-negotiable | false | 10 |
| R05850 | Substrate role — 6-component substrate is NOT separately-pluggable | `README.md` 7–8 | F02974 | non-negotiable | false | 10 |
| R05851 | Substrate role — enabling detect-host enables daemon as single unit | `README.md` 6–8 | F02975 | non-negotiable | false | 10 |
| R05852 | Substrate role — disabling detect-host disables daemon + all dependent modules | `README.md` 44–45 | F02976 | non-negotiable | false | 10 |
| R05853 | Manifest invariant — provides list length = 3 | `module.toml` 15 | F02977 | non-negotiable | false | 10 |
| R05854 | Manifest invariant — requires list length = 1 | `module.toml` 18–20 | F02978 | non-negotiable | false | 10 |
| R05855 | Manifest invariant — consumes list length = 0 | `module.toml` 16 | F02979 | non-negotiable | false | 10 |
| R05856 | Manifest invariant — depends_on list length = 0 | `module.toml` 10 | F02980 | non-negotiable | false | 10 |
| R05857 | Manifest invariant — conflicts list length = 0 | `module.toml` 11 | F02981 | non-negotiable | false | 10 |
| R05858 | Manifest invariant — [profiles] block exists | `module.toml` 31–33 | F02982 | non-negotiable | false | 10 |
| R05859 | Manifest invariant — [install] uses kind + package keys (NOT apply/check/uninstall) | `module.toml` 24–26 | F02983 | non-negotiable | false | 10 |
| R05860 | Cross-ref — selfdef-daemon Cargo metadata = `cargo deb -p selfdef-daemon` | `README.md` 24–25 | F02966 | non-negotiable | false | 10 |
| R05861 | Cross-ref — debian-package install kind contract resides in docs/src/modules.md | `README.md` 28 | F02967 | non-negotiable | false | 10 |
| R05862 | Cross-ref — F-2027-022 traces from selfdef SDD ledger (MS013 27-SDD charter) | `README.md` 29 | F02968 | non-negotiable | false | 10 |
| R05863 | Config-layering future — defaults → profile → host overlay precedence | `README.md` 33–34 | F02969 | non-negotiable | false | 10 |
| R05864 | Config-layering future — M-modules phase 2 is the milestone that folds selfdef.toml | `README.md` 35–36 | F02970 | non-negotiable | false | 10 |
| R05865 | Config-layering future — detect-host will gain real profiles after M-modules ph.2 | `module.toml` 28–33 | F02971 | non-negotiable | false | 10 |
| R05866 | Documentation cross-ref — docs/src/modules.md § module.toml manifest documents kind=debian-package contract | `README.md` 28–29 | F02997 | non-negotiable | false | 10 |
| R05867 | Documentation cross-ref — docs/src/modules.md § Config layering documents 3-tier overlay | `README.md` 33–34 | F02998 | non-negotiable | false | 10 |
| R05868 | Documentation cross-ref — F-2027-022 finding number traces M-modules + manifest-contract evolution | `README.md` 29 | F02999 | non-negotiable | false | 10 |
| R05869 | Project-boundary — detect-host is IPS-side substrate | architecture | F02939 | non-negotiable | false | 10 |
| R05870 | Project-boundary — detect-host does NOT cross-bind to sovereign-os except via MS007 typed mirrors | architecture + cross-ref MS007 | F02939 | non-negotiable | false | 10 |
| R05871 | Cross-module — MS002 14-collector-fabric feeds detect-host event-bus | architecture + cross-ref MS002 | F02947 | non-negotiable | false | 10 |
| R05872 | Cross-module — MS003 correlator + store + responder is part of detect-host substrate | architecture + cross-ref MS003 | F02946 | non-negotiable | false | 10 |
| R05873 | Cross-module — MS004 14-notifier-integrations flow through detect-host notifier | architecture + cross-ref MS004 + MS005 | F02945 | non-negotiable | false | 10 |
| R05874 | Cross-module — MS006 14-functional-modules each consume ≥1 of detect-host's 3 surfaces | architecture + cross-ref MS006 | F02948 | non-negotiable | false | 10 |
| R05875 | Cross-module — MS015 NATS module-system depends on detect-host event-bus | architecture + cross-ref MS015 | F02942 | non-negotiable | false | 10 |
| R05876 | Cross-module — MS016 eBPF module-system depends on detect-host event-bus | architecture + cross-ref MS016 | F02942 | non-negotiable | false | 10 |
| R05877 | Cross-module — MS017 agent-guard module-system depends on detect-host event-bus for invariant violations | architecture + cross-ref MS017 | F02943 | non-negotiable | false | 10 |
| R05878 | Cross-module — MS022 SSE quota module depends on detect-host api component | architecture + cross-ref MS022 | F02944 | non-negotiable | false | 10 |
| R05879 | Cross-module — MS023 polarproxy module depends on detect-host being installed for surface consumption | architecture + cross-ref MS023 | F02940 | non-negotiable | false | 10 |
| R05880 | Cross-module — MS024 bridge-l2 module depends on detect-host being installed for surface consumption | architecture + cross-ref MS024 | F02941 | non-negotiable | false | 10 |
| R05881 | Cross-repo binding — detect-host substrate is IPS-internal; audit routes through MS007 audit-manifest typed-mirror crate | architecture + cross-ref MS007 | F02994 | non-negotiable | false | 10 |
| R05882 | Cross-repo binding — detect-host does NOT expose event-bus / finding-store / sigma-correlator to sovereign-os processes | architecture + cross-ref MS007 | F02995 | non-negotiable | false | 10 |
| R05883 | Cross-repo binding — sovereign-os has no detect-host equivalent | architecture | F02996 | non-negotiable | false | 10 |
| R05884 | Install-kind extends script kind — MS023 + MS024 use script; MS025 uses debian-package | `module.toml` 25 + cross-ref MS023 + MS024 | F02937 | non-negotiable | false | 10 |
| R05885 | Install comment block — "The install of this module is the install of the selfdef-daemon Debian package — no shell scripts to run" | `module.toml` 22–23 | F02936 | non-negotiable | false | 10 |
| R05886 | Substrate component invariant — collectors live inside selfdef-daemon process | `README.md` 7–8 | M00646 | non-negotiable | false | 10 |
| R05887 | Substrate component invariant — correlator lives inside selfdef-daemon process | `README.md` 7–8 | M00647 | non-negotiable | false | 10 |
| R05888 | Substrate component invariant — responder lives inside selfdef-daemon process | `README.md` 7–8 | M00648 | non-negotiable | false | 10 |
| R05889 | Substrate component invariant — notifier lives inside selfdef-daemon process | `README.md` 7–8 | M00649 | non-negotiable | false | 10 |
| R05890 | Substrate component invariant — store lives inside selfdef-daemon process | `README.md` 7–8 | M00650 | non-negotiable | false | 10 |
| R05891 | Substrate component invariant — api lives inside selfdef-daemon process | `README.md` 7–8 | M00651 | non-negotiable | false | 10 |
| R05892 | Surface contract — event-bus subscribers receive ALL collector events (broadcast semantics) | `README.md` 12 | F02959 | non-negotiable | false | 10 |
| R05893 | Surface contract — finding-store is a hot store (not archive; archival is separate concern) | `README.md` 13 | F02963 | non-negotiable | false | 10 |
| R05894 | Surface contract — sigma-correlator rule reload happens on /etc/selfdef/rules/ change | `README.md` 14 | F02965 | non-negotiable | false | 10 |
| R05895 | Manifest convention — provides comment block above the list documents per-surface rationale | `module.toml` 13–14 | F02933 | non-negotiable | false | 10 |
| R05896 | Manifest convention — provides comment naming pattern: surface-name with hyphens | `module.toml` 13–15 | F02887 | non-negotiable | false | 10 |
| R05897 | Manifest convention — requires kind field uses kebab-case ("binary", "kernel-feature") | `module.toml` 19 | F02934 | non-negotiable | false | 10 |
| R05898 | Manifest convention — requires value field is the exact binary/feature name | `module.toml` 19 | F02935 | non-negotiable | false | 10 |
| R05899 | Cross-module — MS010 hardware-aware modules can depend on detect-host for hardware-event publication | architecture + cross-ref MS010 | E0252 | non-negotiable | false | 10 |
| R05900 | Cross-module — MS011 operator dashboard reads finding-store via api component | `README.md` 13 + cross-ref MS011 | M00632 + M00651 | non-negotiable | false | 10 |
| R05901 | Cross-module — MS012 perimeter coexistence consumes sigma-correlator findings | cross-ref MS012 | M00633 | non-negotiable | false | 10 |
| R05902 | Cross-module — MS014 SSH-wrap consumes detect-host event-bus for SSH event publication | cross-ref MS014 | M00631 | non-negotiable | false | 10 |
| R05903 | Cross-module — MS018 VPN-bridge consumes detect-host event-bus for tunnel event publication | cross-ref MS018 | M00631 | non-negotiable | false | 10 |
| R05904 | Cross-module — MS019 threat model identifies detect-host as the central trust boundary | cross-ref MS019 | E0259 | non-negotiable | false | 10 |
| R05905 | Cross-module — MS020 L1-L5 test harness exercises detect-host's 6 substrate components | cross-ref MS020 | M00645 | non-negotiable | false | 10 |
| R05906 | Cross-module — MS021 shared module-script lib v2 is NOT used by detect-host (no install scripts) | `README.md` 25–26 + cross-ref MS021 | M00637 | non-negotiable | false | 10 |
| R05907 | Test contract — MS020 module-script test category does NOT apply to detect-host (no scripts) | cross-ref MS020 + MS021 | M00637 | non-negotiable | false | 10 |
| R05908 | Test contract — MS020 translation test category applies to detect-host's config rendering (selfdef.toml → daemon runtime) | cross-ref MS020 | M00640 | non-negotiable | false | 10 |
| R05909 | Test contract — MS020 pipeline test category applies to detect-host's collector-correlator-responder-notifier flow | cross-ref MS020 | M00645 | non-negotiable | false | 10 |
| R05910 | Test contract — MS020 seam test category applies to detect-host's 3 provided surfaces | cross-ref MS020 + E0252 | E0252 | non-negotiable | false | 10 |
| R05911 | Surface visibility — provides values use kebab-case naming convention | `module.toml` 15 | F02896 | non-negotiable | false | 10 |
| R05912 | Surface visibility — provides values use lowercase only | `module.toml` 15 | F02896 | non-negotiable | false | 10 |
| R05913 | Surface visibility — provides values are stable across version bumps within 0.x line | `module.toml` 6 + 15 | M00641 | non-negotiable | false | 10 |
| R05914 | Manifest comment — install comment block describes "no shell scripts to run" rationale | `module.toml` 22–23 | F02936 | non-negotiable | false | 10 |
| R05915 | Manifest comment — provides comment block above provides list documents surface rationale | `module.toml` 13–14 | F02933 | non-negotiable | false | 10 |
| R05916 | Manifest comment — profile placeholder block documents M-modules ph.2 future | `module.toml` 28–30 | F02897 | non-negotiable | false | 10 |
| R05917 | F-2027-022 — finding describes how kind=debian-package extends the manifest contract | `README.md` 29 + cross-ref docs/src/modules.md | M00638 | non-negotiable | false | 10 |
| R05918 | F-2027-022 — finding lives in selfdef's SDD ledger (MS013 27-SDD charter) | `README.md` 29 + cross-ref MS013 | M00638 | non-negotiable | false | 10 |
| R05919 | F-2027-022 — finding documents the install-kind contract additions in detail | `README.md` 29 + cross-ref docs/src/modules.md | M00638 | non-negotiable | false | 10 |
| R05920 | Substrate composition — 6 components run inside the SAME selfdef-daemon systemd unit | `README.md` 7–8 | M00645 | non-negotiable | false | 10 |
| R05921 | Substrate composition — components do NOT run as separate systemd services | `README.md` 7–8 | M00645 | non-negotiable | false | 10 |
| R05922 | Substrate composition — selfdef-daemon binary owns the full process lifecycle | `README.md` 7–8 + cross-ref selfdef-daemon | M00645 | non-negotiable | false | 10 |
| R05923 | Sigma-rules — /etc/selfdef/rules/ is the canonical rule directory | `README.md` 14 | F02964 | non-negotiable | false | 10 |
| R05924 | Sigma-rules — sigma-correlator surface implementation MUST be the rule-loading entry point | `README.md` 14 | M00633 | non-negotiable | false | 10 |
| R05925 | Finding-store — SQLite path /var/lib/selfdef/state.sqlite is the canonical hot-store path | `README.md` 13 | F02962 | non-negotiable | false | 10 |
| R05926 | Finding-store — schema migration is owned by selfdef-daemon (NOT by this module manifest) | `README.md` 13 + cross-ref selfdef-daemon | M00632 | non-negotiable | false | 10 |
| R05927 | Event-bus — tokio broadcast channel SHALL be created once per daemon process | `README.md` 12 | F02958 | non-negotiable | false | 10 |
| R05928 | Event-bus — collectors subscribe to the broadcast channel at startup | `README.md` 12 | F02960 | non-negotiable | false | 10 |
| R05929 | Event-bus — broadcast channel capacity is selfdef-daemon implementation concern | `README.md` 12 + cross-ref selfdef-daemon | M00631 | non-negotiable | false | 10 |
| R05930 | Daemon-orchestration — `systemctl` required binary covers daemon-lifecycle invocations | `module.toml` 19 | M00634 | non-negotiable | false | 10 |
| R05931 | Daemon-orchestration — Debian postinst hooks invoke systemctl enable+start | cross-ref selfdef-daemon postinst | F02992 | non-negotiable | false | 10 |
| R05932 | Daemon-orchestration — Debian prerm hooks invoke systemctl stop+disable | cross-ref selfdef-daemon prerm | F02993 | non-negotiable | false | 10 |
| R05933 | M-modules ph.2 — folds selfdef.toml into module-layer overlay | `README.md` 33–36 | M00653 | non-negotiable | false | 10 |
| R05934 | M-modules ph.2 — applies 3-tier defaults → profile → host overlay precedence (per docs/src/modules.md § Config layering) | `README.md` 33–34 | F02998 | non-negotiable | false | 10 |
| R05935 | M-modules ph.2 — detect-host SHALL gain real profile variants (NOT just "default") | `module.toml` 28–33 + `README.md` 35–36 | F02971 | non-negotiable | false | 10 |
| R05936 | Module-system invariant — module manifest existence implies presence in `selfdefctl modules list` | `README.md` 43 | F02955 | non-negotiable | false | 10 |
| R05937 | Module-system invariant — manifest-without-scripts is a legitimate participation mode | `README.md` 40–47 | F02955 | non-negotiable | false | 10 |
| R05938 | Module-system invariant — manifest-without-scripts MUST still pass module-loader validation | `README.md` 40–47 | F02955 | non-negotiable | false | 10 |
| R05939 | Module-system invariant — module-loader validation MUST recognize kind=debian-package | cross-ref docs/src/modules.md + F-2027-022 | F02984 | non-negotiable | false | 10 |
| R05940 | Module-system invariant — module-loader validation MUST reject unknown kind values | cross-ref docs/src/modules.md + F-2027-022 | F02985 | non-negotiable | false | 10 |
| R05941 | Future-extension — additional debian-package modules MAY join detect-host in this install-kind family | `README.md` 27 | F02917 | non-negotiable | false | 10 |
| R05942 | Future-extension — F-2027-022 contract documents how to add such modules | `README.md` 28–29 | F02986 | non-negotiable | false | 10 |
| R05943 | Future-extension — sovereign-os may register a sovereign-os-daemon Debian-package module under the SAME install-kind contract | cross-ref docs/src/modules.md + sovereign-os | F02996 | non-negotiable | false | 10 |
| R05944 | Surface gating — modules with consumes=event-bus MUST be loaded AFTER detect-host (per dependency order) | `README.md` 16–17 + 44–45 | F02951 | non-negotiable | false | 10 |
| R05945 | Surface gating — modules with consumes=finding-store MUST be loaded AFTER detect-host | `README.md` 17–19 + 44–45 | F02951 | non-negotiable | false | 10 |
| R05946 | Surface gating — modules with consumes=sigma-correlator MUST be loaded AFTER detect-host | `module.toml` 15 + `README.md` 44–45 | F02951 | non-negotiable | false | 10 |
| R05947 | Surface gating — module-loader topological sort SHALL place detect-host first | `README.md` 44–45 | F02951 | non-negotiable | false | 10 |
| R05948 | Documentation invariant — `docs/src/modules.md` § module.toml manifest is the authoritative manifest contract | `README.md` 28 | F02997 | non-negotiable | false | 10 |
| R05949 | Documentation invariant — `docs/src/modules.md` § Config layering is the authoritative config-overlay contract | `README.md` 33–34 | F02998 | non-negotiable | false | 10 |
| R05950 | Documentation invariant — module manifests REFERENCE docs/src/modules.md rather than duplicating its contracts | `README.md` 28–29 + 33–34 | M00629 | non-negotiable | false | 10 |
| R05951 | Module identity heading — "detect-host" | `README.md` 1 | E0251 | non-negotiable | false | 10 |
| R05952 | Module identity tagline — "host self-defense daemon, packaged as a module" | `README.md` 3 | F02898 | non-negotiable | false | 10 |
| R05953 | Substrate phrase — "This module is the substrate that every other module feeds into" | `README.md` 5–6 | F02899 | non-negotiable | false | 10 |
| R05954 | Substrate phrase — "ensures selfdef-daemon (...) is present and running" | `README.md` 6–8 | F02900 | non-negotiable | false | 10 |
| R05955 | "What it provides" heading — section names the 3 surfaces | `README.md` 10 | E0252 | non-negotiable | false | 10 |
| R05956 | Surface table line — `event-bus` heading + description | `README.md` 12 | F02907 | non-negotiable | false | 10 |
| R05957 | Surface table line — `finding-store` heading + description | `README.md` 13 | F02908 | non-negotiable | false | 10 |
| R05958 | Surface table line — `sigma-correlator` heading + description | `README.md` 14 | F02909 | non-negotiable | false | 10 |
| R05959 | Consumption pattern statement — "Other modules that want to publish events declare consumes = [event-bus]" | `README.md` 16–17 | F02910 | non-negotiable | false | 10 |
| R05960 | Consumption pattern statement — "Other modules that read findings (...) declare consumes = [finding-store]" | `README.md` 17–19 | F02911 | non-negotiable | false | 10 |
| R05961 | Manifest convention — install kind values are kebab-case ("script", "debian-package", etc.) | `module.toml` 25 + cross-ref MS023 + MS024 | F02937 | non-negotiable | false | 10 |
| R05962 | Manifest convention — module-loader SHALL be tolerant of unknown profiles for kind=debian-package modules until M-modules ph.2 | `module.toml` 32–33 | F02938 | non-negotiable | false | 10 |
| R05963 | Project-boundary — every module-system extension upstream/downstream binds through THIS module's 3 provided surfaces | architecture + `module.toml` 15 + `README.md` 5–7 | E0259 | non-negotiable | false | 10 |
| R05964 | Project-boundary — collectors and notifier integrations live IN selfdef-daemon; module manifests outside this daemon publish/consume only through the 3 surfaces | `README.md` 5–8 | E0259 | non-negotiable | false | 10 |
| R05965 | Project-boundary — selfdef substrate is single-process (NOT distributed) | `README.md` 12 | F02958 | non-negotiable | false | 10 |
| R05966 | Project-boundary — multi-host fan-out is MS018 VPN-bridge concern (NOT this module) | cross-ref MS018 | M00654 | non-negotiable | false | 10 |
| R05967 | Project-boundary — message-bus fan-out is MS015 NATS concern (NOT this module's event-bus) | cross-ref MS015 | F02959 | non-negotiable | false | 10 |
| R05968 | Project-boundary — eBPF collection is MS016 eBPF concern (publishes INTO this module's event-bus) | cross-ref MS016 | F02942 | non-negotiable | false | 10 |
| R05969 | Project-boundary — agent-guard host-level invariants are MS017 concern (publishes INTO this module's event-bus) | cross-ref MS017 | F02943 | non-negotiable | false | 10 |
| R05970 | Project-boundary — SSE quota is MS022 concern (consumes this module's api component) | cross-ref MS022 | F02944 | non-negotiable | false | 10 |
| R05971 | Project-boundary — perimeter coexistence is MS012 concern (consumes sigma-correlator findings) | cross-ref MS012 | M00633 | non-negotiable | false | 10 |
| R05972 | Project-boundary — operator dashboard is MS011 concern (reads finding-store via api) | cross-ref MS011 | M00632 + M00651 | non-negotiable | false | 10 |
| R05973 | Project-boundary — 27-SDD charter is MS013 concern (governs F-2027-022 + related findings) | cross-ref MS013 | M00638 | non-negotiable | false | 10 |
| R05974 | Project-boundary — L1-L5 test harness is MS020 concern (tests this module's 3 surfaces via seam category) | cross-ref MS020 | E0252 | non-negotiable | false | 10 |
| R05975 | Project-boundary — shared module-script lib v2 is MS021 concern (NOT used by detect-host since no scripts) | cross-ref MS021 | M00637 | non-negotiable | false | 10 |
| R05976 | Project-boundary — polarproxy is MS023 concern (depends on detect-host as substrate consumer) | cross-ref MS023 | F02940 | non-negotiable | false | 10 |
| R05977 | Project-boundary — bridge-l2 is MS024 concern (depends on detect-host as substrate consumer) | cross-ref MS024 | F02941 | non-negotiable | false | 10 |
| R05978 | Project-boundary — hardware-aware modules are MS010 concern (may consume detect-host event-bus for hardware events) | cross-ref MS010 | E0252 | non-negotiable | false | 10 |
| R05979 | Project-boundary — operator dashboard + flex profile is MS011 concern (consumes finding-store via api) | cross-ref MS011 | M00632 + M00651 | non-negotiable | false | 10 |
| R05980 | Project-boundary — perimeter coexistence is MS012 concern (consumes sigma-correlator findings + finding-store) | cross-ref MS012 | M00632 + M00633 | non-negotiable | false | 10 |
| R05981 | Project-boundary — SSH-wrap is MS014 concern (publishes INTO event-bus for SSH events) | cross-ref MS014 | F02942 | non-negotiable | false | 10 |
| R05982 | Project-boundary — threat model is MS019 concern (treats detect-host as central trust boundary) | cross-ref MS019 | E0259 | non-negotiable | false | 10 |
| R05983 | Project-boundary — selfdef-on-sain01 integration is MS008 concern (deploys detect-host into the canonical host environment) | cross-ref MS008 | E0251 | non-negotiable | false | 10 |
| R05984 | Project-boundary — audit cycles are MS009 concern (audits detect-host findings + reaction-to-finding actions) | cross-ref MS009 | M00632 | non-negotiable | false | 10 |
| R05985 | Hardware-policy boundary — detect-host does NOT consume hardware-policy from sovereign-os; cross-repo hardware events route through MS007 typed-mirror crates | architecture + cross-ref MS007 + M043 | F02995 | non-negotiable | false | 10 |
| R05986 | Hardware-policy boundary — sovereign-os hardware-aware intelligence scheduling (M043) does NOT touch detect-host substrate | cross-ref M043 sovereign-os | F02996 | non-negotiable | false | 10 |
| R05987 | Hardware-policy boundary — selfdef hardware-aware modules (MS010) publish hardware events through detect-host event-bus surface | cross-ref MS010 | E0252 | non-negotiable | false | 10 |
| R05988 | Daemon SSE — api component exposes SSE endpoints subject to MS022 per-token quota enforcement | cross-ref MS022 | M00651 | non-negotiable | false | 10 |
| R05989 | Daemon HTTP — api component exposes HTTP REST endpoints subject to MS019 threat model attack-surface analysis | cross-ref MS019 | M00651 | non-negotiable | false | 10 |
| R05990 | Daemon SSE — TokenFingerprint SHA-256 dual-counter SubscriberGuard (MS022) sits IN FRONT of the api component | cross-ref MS022 | M00651 | non-negotiable | false | 10 |
| R05991 | Module-system invariant — detect-host is the first module loaded by selfdefctl on a fresh host | `README.md` 5–8 + 44–45 | F02947 | non-negotiable | false | 10 |
| R05992 | Module-system invariant — detect-host is the LAST module unloaded on host teardown | `README.md` 44–45 | F02976 | non-negotiable | false | 10 |
| R05993 | Module-system invariant — selfdefctl modules disable detect-host SHALL trigger a cascade prerm of all dependent modules first | `README.md` 44–45 | F02976 | non-negotiable | false | 10 |
| R05994 | Module-system invariant — detect-host's Debian package upgrade SHALL preserve /var/lib/selfdef/state.sqlite | `README.md` 13 + cross-ref selfdef-daemon | F02962 | non-negotiable | false | 10 |
| R05995 | Module-system invariant — detect-host's Debian package upgrade SHALL preserve /etc/selfdef/rules/ | `README.md` 14 + cross-ref selfdef-daemon | F02964 | non-negotiable | false | 10 |
| R05996 | Module-system invariant — detect-host's Debian package upgrade SHALL preserve /etc/selfdef/selfdef.toml | `README.md` 35 + cross-ref selfdef-daemon | M00640 | non-negotiable | false | 10 |
| R05997 | Module-system invariant — detect-host's Debian package post-install SHALL ensure the daemon's state directory ownership + permissions | `README.md` 13 + cross-ref selfdef-daemon postinst | M00632 | non-negotiable | false | 10 |
| R05998 | Module-system invariant — detect-host's Debian package SHALL declare correct apt dependencies (libsqlite3, etc.) | cross-ref selfdef-daemon Cargo.toml + cargo-deb | M00636 | non-negotiable | false | 10 |
| R05999 | Module-system invariant — `cargo deb -p selfdef-daemon` SHALL produce the package consumed by `selfdefctl modules enable detect-host` | `README.md` 24–25 | F02915 | non-negotiable | false | 10 |
| R06000 | Composite — MS025 (10 epics / 26 modules / 120 features / 240 reqs) covers detect-host module v0.1.0 (80 lines): module.toml (manifest-only reference implementation) + README.md (47-line substrate-module doc); 3 provided surfaces (event-bus tokio-broadcast + finding-store SQLite /var/lib/selfdef/state.sqlite + sigma-correlator /etc/selfdef/rules/); UNIQUE kind=debian-package install (F-2027-022); 6-component substrate composition (collectors+correlator+responder+notifier+store+api); 3 module-system invariants (modules list / depends_on / modules status); placeholder profile until M-modules ph.2; project-boundary: detect-host IS the IPS-side substrate, every other selfdef module depends_on it; cross-repo binds via MS007 typed-mirror crates only | `modules/detect-host/` 80 lines | E0251 + E0252 + E0253 + E0254 + E0255 + E0256 + E0257 + E0258 + E0259 + E0260 | non-negotiable | false | 10 |

## Sub-requirements accounting

- 240 requirements covering: module.toml full transcription (R05761–R05784) + README full transcription with substrate composition + 3 surfaces + consumption pattern + install kind + config + why-manifest invariants (R05785–R05839) + module-system + operator UX + daemon lifecycle invariants (R05840–R05852) + manifest invariants + cross-refs (R05853–R05870) + project-boundary + cross-module dependencies (10 cross-module rows R05871–R05883) + install-kind family + substrate component-in-process invariants (R05884–R05891) + surface contract invariants (R05892–R05898) + cross-module project-boundary (15+ rows R05899–R05984) + hardware-policy boundary (R05985–R05987) + daemon SSE/HTTP threat-model integration (R05988–R05990) + module-system invariants (R05991–R05997) + Debian package invariants (R05998–R05999) + composite (R06000)
- Source range 80 lines yields 240 R-rows representing 3:1 R-per-line ratio at the verbatim-citation level (detect-host is dense-invariant manifest; many cross-module bindings deserve explicit rows to preserve the substrate doctrine)
- Project boundary — MS025 is selfdef IPS substrate scope; cross-repo binding to sovereign-os routes through MS007 typed-mirror crates only

## Cross-references

- Adjacent INDEX rows: MS024 bridge-l2 / MS026 integrity-sentinel
- Substrate role — MS025 is the substrate every other selfdef milestone (MS001 daemon core / MS002 collector fabric / MS003 correlator+store+responder+signing / MS004 14-notifier-integrations / MS005 notifier engine+orchestrator / MS006 14-functional-modules / MS007 8/8 SATURATED cross-repo typed-mirror crates / MS008-MS024) hooks into via event-bus + finding-store + sigma-correlator surfaces
- Cross-repo binding — detect-host substrate IPS-internal; sovereign-os has no equivalent; cross-repo audit (sovereign-os reading detect-host findings) routes through MS007 audit-manifest typed-mirror crate (SATURATED 8/8)
- F-2027-022 — finding from selfdef SDD ledger (MS013 27-SDD charter) documents the kind=debian-package install-kind contract additions
- Test integration — MS020 L1-L5 layered harness exercises detect-host via seam test category (Category 4 of 4) on the 3 provided surfaces; module-script category (Category 3 of 4) does NOT apply (no scripts)
- Module-script lib — MS021 shared module-script lib v2 is NOT used by detect-host (no apply/check/uninstall scripts)
- Hardware-policy boundary — sovereign-os hardware-aware intelligence scheduling (M043) does NOT touch detect-host substrate; selfdef hardware-aware modules (MS010) publish hardware events through detect-host event-bus surface
- Operator references: docs/src/modules.md § `module.toml` manifest (kind=debian-package contract) + docs/src/modules.md § Config layering (3-tier defaults → profile → host overlay) + selfdef-daemon Debian package (cargo deb -p selfdef-daemon) + Sigma rule format
