//! selfdefctl — admin CLI for the selfdef daemon.
//!
//! M3 implements `events tail` and `status` by reading the SQLite hot store
//! directly. A future milestone replaces this with an IPC channel to the
//! running daemon (UNIX socket), keeping the same UX.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod alerts;
mod audit_chains;
mod authority;
mod capability_tokens;
mod capability_tokens_registry;
mod commit_authority;
mod communication_boundary;
mod dashboard_prefs;
mod dashboards;
mod doctor;
mod emit;
mod filesystem_boundary;
mod flex_profile;
mod follow;
mod friction_audit;
mod grants;
mod guardian;
mod hardware;
mod health;
mod inference_backends;
mod init;
mod mcp;
mod models;
mod modules;
mod nats;
mod network_boundary;
mod notify;
mod paths;
mod perimeter;
mod policy;
mod repl;
mod sandbox_tiers;
mod scheduler;
mod ssh_wrap;
mod tool_authority;
mod trio;
mod wizard;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use selfdef_config::Config;
use selfdef_core::Event;
use selfdef_store::SqliteStore;

#[derive(Debug, Parser)]
#[command(name = "selfdefctl", version, about = "selfdef admin CLI")]
struct Cli {
    #[arg(
        short,
        long,
        env = "SELFDEF_CONFIG",
        default_value = paths::DAEMON_CONFIG,
        global = true
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show daemon status (event count, store path).
    Status,
    /// Inspect or replay events from the hot store.
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },
    /// Reload rules without restarting (SIGHUP). Not implemented in M3.
    Reload,
    /// Manage detection rules. Not implemented in M3.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Trigger panic mode. Not implemented in M3.
    Panic {
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Inspect or manually create forensic bundles.
    Forensics {
        #[command(subcommand)]
        action: ForensicsAction,
    },
    /// Inspect the module catalog (list / info). Read-only.
    Modules {
        #[command(subcommand)]
        action: ModulesAction,
    },
    /// SD-R34: 1-bit / ternary / quantised model registry. List
    /// registered models or dry-run "would this land on THIS
    /// host?" via the SD-R14 + SD-R26 + SD-R32 predicate engine.
    Models {
        #[command(subcommand)]
        action: ModelsAction,
    },
    /// Manage the API surface (token rotation, etc).
    Api {
        #[command(subcommand)]
        action: ApiAction,
    },
    /// SDD-008 D-4: acknowledge, forget, or list pending
    /// notification escalations. Talks directly to the persistent
    /// escalation engine (`[notifier].escalations_path`); WAL mode
    /// handles concurrent daemon reads.
    Notify {
        #[command(subcommand)]
        action: NotifyAction,
    },
    /// Detection-rule signing tools (operator-side).
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Kubernetes RBAC posture checks (SDD-004 F-2026-025
    /// follow-up). Useful for verifying that the cluster's
    /// RBAC doesn't allow unintended subjects to defeat
    /// `agent-guard`'s pod-label scope.
    Rbac {
        #[command(subcommand)]
        action: RbacAction,
    },
    /// Holistic operator health check. Runs cross-cutting
    /// audit-shipped state verifications (rule signing,
    /// API token mode, eventstream integrity, RBAC posture
    /// summary) in one go. Complementary to
    /// `selfdefctl modules check`, which covers per-module
    /// health via each module's `check.sh`.
    ///
    /// Env overrides (F-2027-018):
    ///   - `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG=<path>` — when set,
    ///     the rbac category reads the agent-guard scope from
    ///     `<path>` instead of `/etc/selfdef/modules/agent-guard.toml`.
    ///     Test-only — used by the integration suite to stage a
    ///     fake config in a tempdir.
    Doctor {
        /// JSON-lines output instead of the human report —
        /// for CI / monitoring integration.
        #[arg(long)]
        json: bool,
    },
    /// First-run bootstrap. Writes starter config files +
    /// prints the operator checklist. Non-destructive by
    /// default (refuses to overwrite existing files).
    Init {
        #[command(subcommand)]
        action: InitAction,
    },
    /// SDD-015: Tetragon perimeter coexistence — inspect / verify
    /// the boundary between selfdef-authored `agent-guard-*`
    /// TracingPolicies and sovereign-os's host-scoped
    /// `sovereign-kernel-fence.yaml`.
    Perimeter {
        #[command(subcommand)]
        action: PerimeterAction,
    },
    /// SD-R11: first-time-operator setup walkthrough — probes
    /// hardware, surfaces Sain01Match verdict, recommends a config
    /// snippet, prints next-step commands. Pure-read; never writes
    /// config (operator copy-pastes — authority always wins).
    Wizard {
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// SDD-017: SAIN-01 hardware inventory + Sain01Match verdict.
    /// Probes the host for CPU features, memory, GPU device nodes,
    /// motherboard ID + PCIe state, and compares to the SAIN-01
    /// target. Read-only; safe on any host (graceful on missing
    /// kernel surfaces).
    Hardware {
        #[command(subcommand)]
        action: Option<HardwareAction>,
        /// Machine-readable JSON output (alternative to subverb).
        #[arg(long)]
        json: bool,
    },
    /// SDD-027 / MS046: boot-time hardware-integrity gate operator
    /// surface. Reads the verdict ring buffer that the friction-audit
    /// boot script writes; surfaces gate verdicts (pcie / zfs /
    /// memory / immutability / signature / timeout) and operator-
    /// signed overrides. Read-only by default; mutating actions
    /// require Ring 0 authority + MS003 multi-sig (deferred).
    FrictionAudit {
        #[command(subcommand)]
        action: Option<FrictionAuditAction>,
        /// Machine-readable JSON output (alternative to subverb).
        #[arg(long)]
        json: bool,
    },
    /// SDD-029 / MS044: Guardian Daemon (sain-01 §10 guardian-core)
    /// operator surface. Read-only by default; mutating actions
    /// (replay / rollback) require Ring 0 authority + MS003 multi-sig.
    Guardian {
        #[command(subcommand)]
        action: Option<GuardianAction>,
        /// Machine-readable JSON output (alternative to subverb).
        #[arg(long)]
        json: bool,
    },
    /// SDD-031 / MS048: Goldilocks Scheduler operator surface
    /// (avx-plus-plus dump tail 18000-18250). Read-only by default;
    /// mutating actions (force / audit-cycle replay) require Ring 0
    /// authority + MS003 multi-sig.
    Scheduler {
        #[command(subcommand)]
        action: SchedulerAction,
    },
    /// MS043 R10081 + F05081: consolidated four-watchdog-set operator
    /// view. Renders friction-audit (hardware frame, MS046) + perimeter
    /// (kernel syscall, MS047) + guardian (supervisor tier, MS044) +
    /// scheduler (routing layer, MS048) state in one read-only snapshot.
    /// The single-command analog of the dashboard's main page —
    /// useful when no GUI / no browser available.
    Trio {
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
        /// Watch-mode: repeat every N seconds until Ctrl-C. In human
        /// mode (default), clear+redraw between cycles. With --json,
        /// emit one JSON line per cycle (JSONL stream — pipe into jq /
        /// Loki / your monitoring pipeline). 0 (default) means render once.
        #[arg(long, default_value_t = 0)]
        watch: u32,
        /// Quiet mode: single-line aggregate summary suitable for PS1
        /// prompt embedding or terminal-multiplexer status bars. Format:
        /// 'selfdef: fa=OK perim=ALERT guard=OK sched=OK'. Exit code 0
        /// when all aggregates are OK; 1 otherwise (so `selfdefctl trio
        /// --quiet && cmd` works as a gate).
        #[arg(long)]
        quiet: bool,
    },
    /// MS027 + four-watchdog set: unified tail of all four watchdog
    /// OCSF jsonl logs (friction-audit + perimeter + guardian + scheduler).
    /// Cross-cutting operator visibility — see what's happening across
    /// the entire IPS boundary-enforcement stack in real time.
    TrioTail {
        /// Poll interval in milliseconds (default 1000).
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        /// Emit each event as a JSON line prefixed with source-tag (default
        /// is human-readable). Useful for piping into jq / log shippers.
        #[arg(long)]
        json: bool,
    },
    /// MS027 alerts CLI parity with the dashboard PWA "Alerts overview"
    /// 6th panel. Reads `/metrics` from the local daemon (UNIX socket
    /// at /run/selfdef.sock by default; SELFDEF_API_URL + token over
    /// TCP), parses the 9 alert-relevant series, and renders one row
    /// per alert with NAME · MS · series · threshold · current value
    /// · STATE. Exit code 0 iff every alert is OK or UNKNOWN; 1 if any
    /// is WARN or CRITICAL. Pair with shell gates:
    ///   selfdefctl alerts --quiet && deploy.sh
    Alerts {
        /// Machine-readable JSON output (jq-friendly).
        #[arg(long)]
        json: bool,
        /// Single-line `selfdef-alerts: WORST` mode for PS1 / status
        /// bars + as a gate-friendly exit-code-only invocation.
        #[arg(long)]
        quiet: bool,
    },
    /// MS011 Z-6 composite health CLI parity with the dashboard's
    /// "Composite health" top panel + GET /v1/health. One-command
    /// answer to "is the box OK?". Aggregates alerts + network +
    /// storage + raid + gpu + cpu into 6 rows + a composite worst.
    /// Exit code 0 iff worst is OK or UNKNOWN; 1 if WARN or
    /// CRITICAL. Pair with shell gates:
    ///   selfdefctl health --quiet && safe-action.sh
    Health {
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
        /// Single-line `selfdef-health: WORST` for PS1 / status bars.
        #[arg(long)]
        quiet: bool,
    },
    /// MS009 composite audit-chain replay across the 3 chained-audit
    /// watchdogs (perimeter / guardian / scheduler). Calls
    /// GET /v1/audit-chains which runs each watchdog's
    /// audit_chain_check on its OCSF JSONL file. Renders one row per
    /// chain with EVENTS_VERIFIED + STATE + DETAIL (error message
    /// with line number when broken). Exit 0 iff every chain
    /// verified; 1 otherwise.
    AuditChains {
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
        /// Single-line `selfdef-audit-chains: WORST` for status bars.
        #[arg(long)]
        quiet: bool,
    },
    /// MS041 / SDD-043 commit-authority operator surface. Offline
    /// validation + classification of CommitEnvelope drafts against
    /// the `selfdef-commit-authority` crate's contract (8 commit
    /// types + 5 mandatory fields + 3 high-risk gates + F04871..
    /// F04875 classifier). No daemon round-trip — the crate is the
    /// authoritative source.
    CommitAuthority {
        #[command(subcommand)]
        action: CommitAuthorityAction,
    },
    /// MS042 / SDD-050 tool-authority operator surface. Offline
    /// discovery of the 11-crate tool-policy pipeline (8 ToolId
    /// variants × 7 ExecutionMode × 6 Profile) + per-triple
    /// permits check.
    ToolAuthority {
        #[command(subcommand)]
        action: ToolAuthorityAction,
    },
    /// MS035 / SDD-044 capability-tokens operator surface. Offline
    /// discovery of the typed authority-handle schema (Token shape +
    /// 5-verdict CheckVerdict ladder + 5-companion-crate ecosystem).
    /// Mutation surface (issue / revoke) intentionally not exposed
    /// — the store is in-memory per SDD-044 D-3 and operator-token
    /// minting goes through MS003-signed config today.
    CapabilityTokens {
        #[command(subcommand)]
        action: CapabilityTokensAction,
    },
    /// MS037 / SDD-045 filesystem-boundary operator surface.
    /// Discovery of the explicit-exchange directory discipline
    /// (3-dir layout + 6-step import pipeline + 5-field patch
    /// schema + 6 application predicates + 2 verbatim doctrines).
    FilesystemBoundary {
        #[command(subcommand)]
        action: FilesystemBoundaryAction,
    },
    /// MS038 / SDD-046 network-boundary operator surface. Discovery
    /// of the 5-profile egress ladder + cross-cycle bindings to
    /// MS032 sandbox tiers + MS039 authority rings.
    NetworkBoundary {
        #[command(subcommand)]
        action: NetworkBoundaryAction,
    },
    /// MS032 / SDD-047 sandbox-tiers operator surface. Discovery of
    /// the 5-tier capability ladder + 4 PromotionGate variants + 5
    /// companion crates.
    SandboxTiers,
    /// MS034 / SDD-048 communication-boundary operator surface.
    /// Discovery of the 4-transport ladder + 8-message-type schema +
    /// proposal→commit mapping + 2 verbatim doctrines.
    CommunicationBoundary,
    /// MS039 + MS040 / SDD-049 authority operator surface. Discovery
    /// of the 7-level authority ladder + 5 trust rings + 6-profile
    /// envelope matrix + 4 TransitionGate variants + 5 authority
    /// crates.
    Authority,
    /// MS033 / SDD-051 policy-and-trace operator surface. Cluster +
    /// crate discovery for the 36-crate `selfdef-policy-*` ecosystem.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// MS014 / SDD-052 selfdef-ssh-wrap operator surface. Doctrine +
    /// install discovery for the drop-in `ssh` replacement.
    SshWrap {
        #[command(subcommand)]
        action: SshWrapAction,
    },
    /// MS015 / SDD-053 selfdef-nats bridge operator surface.
    /// Discovery of the two-way pump subject schema + modes +
    /// echo-defense rule + cross-host invariants.
    Nats,
    /// MS011 Z-3 / `selfdef-flex-profile` operator surface.
    /// 2 subverbs: `schema` (offline doctrine) + `show` (live state
    /// via GET /v1/flex-profile).
    FlexProfile {
        #[command(subcommand)]
        action: FlexProfileAction,
    },
    /// M060 D-13 — grant registry operator surface. `show` reads the
    /// resident snapshot; `issue`/`revoke` are the IPS-side write path
    /// (via the daemon API) the mirror-export republishes for sovereign-os.
    Grants {
        #[command(subcommand)]
        action: GrantsAction,
    },
    /// MS043 UX — list the 5 operator-named dashboard view presets
    /// (compact / default / inference / performance / security) via
    /// `GET /v1/dashboards`. Operator deep-links each via
    /// `/dashboard/#preset=<name>` OR via
    /// `selfdefctl dashboard-prefs set active_preset <name>`.
    Dashboards {
        /// JSON pass-through for jq.
        #[arg(long)]
        json: bool,
    },
    /// MS043 UX / SDD-060 — operator-pull view of the dashboard-
    /// prefs surface. `show` GETs the persisted prefs from the
    /// daemon; `set <field> <value>` PUTs a mutation for one of
    /// refresh_rate | active_preset | hidden_panels.
    DashboardPrefs {
        #[command(subcommand)]
        action: Option<DashboardPrefsAction>,
        /// JSON pass-through for the default `show` action (jq-friendly).
        #[arg(long)]
        json: bool,
    },
    /// MS011 Z-2 / SDD-026 inference-backend surface. `show` calls
    /// `GET /v1/inference-backends` + renders the 4-backend install
    /// state. `version <backend>` shells out directly to the local
    /// binary's `--version` — no daemon round-trip needed.
    InferenceBackends {
        #[command(subcommand)]
        action: Option<InferenceBackendsAction>,
        /// Machine-readable JSON output for the default `show` action
        /// (passes through the raw daemon body). Ignored for `version`.
        #[arg(long)]
        json: bool,
    },
    /// SD-R84 (SDD-026 Z-11 foundation): operator-facing MCP tool
    /// manifest surface. The future selfdef-mcp-server consumes the
    /// SAME manifest the operator's `claude-code` (or any MCP client)
    /// reads to learn what selfdef verbs are exposable as tools.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// SD-R85 (SDD-026 Z-12 foundation): operator-facing REPL surface.
    /// Multi-tier programming layer per the operator directive:
    ///   Tier 0  Programming        (Rust crates linked to selfdef-core)
    ///   Tier 1  Proto-Programming  (Python REPL atop selfdef-cli verbs;
    ///                               THIS round seeds Tier 1)
    ///   Tier 2  Proto-Proto-Prog   (operator-defined macros + custom CoT
    ///                               loops compiling to Tier 1 calls;
    ///                               future round)
    Repl {
        #[command(subcommand)]
        action: ReplAction,
    },
    /// Print version and build info.
    Version,
}

#[derive(Debug, clap::Subcommand)]
enum McpAction {
    /// Print the JSON tool manifest the future MCP server would
    /// expose. Operator-readable schema for every selfdef verb that
    /// is safe to expose as a stateless MCP tool call.
    Tools {
        /// Emit machine-readable JSON (default) or human-readable
        /// table.
        #[arg(long)]
        human: bool,
    },
    /// SD-R91 (SDD-026 Z-11 closure): stdio JSON-RPC MCP server that
    /// exposes the SD-R84 read-only tool manifest. Implements
    /// `initialize`, `tools/list`, `tools/call`. Each `tools/call`
    /// invokes the matching `selfdefctl …` subprocess + returns its
    /// JSON output as a single text content block.
    ///
    /// Wire format: line-delimited JSON-RPC 2.0 (one request per
    /// line, one response per line). Cycle-8 read-only doctrine:
    /// only tools with `category == "read-only"` are callable;
    /// requests for write tools return JSON-RPC error -32601.
    Serve {
        /// Handle exactly N requests then exit (used by L3 tests).
        #[arg(long)]
        exit_after: Option<u32>,
        /// SD-R92: select wire framing.
        ///
        ///   line       SD-R91 line-delimited JSON-RPC (testable, jq-able)
        ///   lsp        SD-R92 LSP-style Content-Length framing (spec MCP)
        ///
        /// Default is `line` for backwards compat with SD-R91. Real
        /// MCP clients (claude-code et al.) speak `lsp`.
        #[arg(long, default_value = "line")]
        framing: String,
        /// SD-R94: bind a TCP listener instead of reading from stdin.
        /// HOST:PORT form, e.g. `127.0.0.1:8444`. Each accepted
        /// connection runs the same per-line/per-LSP-message dispatch
        /// loop, then closes. Cycle-8 doctrine: read-only tools only;
        /// `--token-env VAR` enforces a per-connection Bearer-style
        /// preamble (first line MUST be `Authorization: Bearer
        /// <env-value>` for the connection to handle requests).
        #[arg(long)]
        tcp: Option<String>,
        /// SD-R94: name of env var holding the connection token.
        /// When set with `--tcp`, every connection MUST send the
        /// Authorization preamble before its first JSON-RPC message.
        /// Operator-supplied tokens NEVER live in-repo (SDD-009).
        #[arg(long)]
        token_env: Option<String>,
    },
}

#[derive(Debug, clap::Subcommand)]
enum ReplAction {
    /// SD-R85: print the REPL bootstrap script the operator dumps
    /// into their Python session (or `python3 -i -c "$(selfdefctl
    /// repl bootstrap)"`). Imports the selfdef-cli subprocess
    /// wrappers + sets up the operator namespace. Tier 1
    /// (Proto-Programming) seed.
    Bootstrap,
    /// SD-R85: print the manifest describing the REPL tiers + which
    /// callables each tier exposes. JSON by default; --human for
    /// banner.
    Tiers {
        #[arg(long)]
        human: bool,
    },
    /// SD-R90 (SDD-026 Z-12 follow-up): print ready-to-paste example
    /// Tier 2 (Proto-Proto-Programming) macros built on top of the
    /// Tier 1 callable surface. Operators copy-paste OR import into
    /// their Python session — these are starting-point demonstrations
    /// of the operator-extension layer the SD-R85 manifest names.
    /// Operator-named: "you do you own things and you even have
    /// custom CoT or such and advanced tailored features".
    Tier2Examples {
        /// Show only one example (by name); without --name, prints all.
        #[arg(long)]
        name: Option<String>,
        /// Emit JSON inventory instead of the example source.
        #[arg(long)]
        json: bool,
    },
    /// SD-R95 (SDD-026 Z-12 audit): read back the JSONL audit trail
    /// the REPL bootstrap writes when SELFDEF_REPL_HISTORY is set.
    /// Operator-pull surface: shows every Tier 1 + Tier 2 invocation
    /// with argv + rc + duration_ms so the operator can audit what
    /// their session (or an integrated-intelligence module) executed.
    History {
        /// Override the history file path.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Cap the number of rows rendered (default = 50; --all overrides).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Show every row regardless of --limit.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, clap::Subcommand)]
enum HardwareAction {
    /// Probe + render the full snapshot + Sain01Match verdict (default).
    Probe,
    /// Only render the Sain01Match verdict label (FullMatch /
    /// PartialMatch / NoMatch). Exit code reflects verdict.
    Match,
    /// SD-R10: emit the HardwareCapabilities JSON to stdout (default)
    /// or to `--output PATH` atomically. Consumed by sovereign-os
    /// Wasm-AOT pipeline + future hardware-aware policies; schema is
    /// operator-stable. Exit code reflects verdict.
    Export {
        /// Optional destination path. When set, the file is written
        /// atomically (tempfile + rename) instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// SD-R17: per-sensor temperature readout from /sys/class/hwmon
    /// + nvidia-smi (GPU temps). Read-only. Exit code 0 always.
    Thermals {
        /// Output JSON instead of human-readable rows.
        #[arg(long)]
        json: bool,
    },
    /// SD-R19: emit host-specific compile flags (CFLAGS / KCFLAGS /
    /// `-march=`) in a format the operator can `source` or `eval`
    /// before invoking their build pipeline. Direct enabler for the
    /// Wasm-to-AVX-512 AOT + bitnet.cpp paths.
    Tune {
        /// Output format. `sh` (default) emits POSIX shell assignments
        /// suitable for `source <(...)`. `env-file` emits the same
        /// without the `export` prefix (for systemd EnvironmentFile=).
        /// `make` emits Makefile assignments. `json` emits a structured
        /// document with each field as a key.
        #[arg(long, default_value = "sh")]
        format: String,
        /// Optional output path. When set, writes atomically to the
        /// file (tempfile + rename) instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// SD-R67: one-screen operator-readable hardware-exploit posture
    /// summary. Composes SD-R64 (ternary_aot_capable +
    /// zmm_int8_lane_capacity) + SD-R66 (ternary_kernel_hint) into
    /// a "at-a-glance: can this box run 1-bit models at the hot-path
    /// lane width?" report. Exit code reflects Sain01Match verdict.
    Posture {
        /// Emit JSON instead of the human-readable banner.
        #[arg(long)]
        json: bool,
    },
    /// SD-R70: emit a complete host-tuned `wasmtime compile` script
    /// for a given .wasm module. Pipes to `bash` to produce a
    /// .cwasm against this host's exact target_cpu + target_features
    /// (the SD-R30 wasm_aot surface). One-command Wasm-to-AVX-512
    /// AOT — direct operator-verbatim directive closure.
    AotScript {
        /// Input .wasm module path (operator-supplied).
        #[arg(value_name = "WASM_PATH")]
        wasm: PathBuf,
        /// Optional output .cwasm path. When unset the script defaults
        /// the output to the wasm path with `.cwasm` extension.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

/// SDD-027 / MS046 friction-audit subcommand action set.
///
/// Default (no subverb) renders the latest verdict per gate from the
/// ring buffer at `/var/cache/selfdef/friction-audit/ring/`. The buffer
/// is written by `/usr/local/bin/friction-audit` on every boot via
/// `sovereign-guard.service`.
#[derive(Debug, clap::Subcommand)]
enum FrictionAuditAction {
    /// Render the latest verdict for each gate (default action when
    /// no subverb is supplied).
    Show,
    /// Render the last N verdicts (oldest-first). Capped at the ring
    /// buffer size (256).
    History {
        /// How many entries to render (default: 32).
        #[arg(long, default_value_t = 32)]
        limit: u32,
    },
    /// Re-run the gate now (does not require reboot). Operator-
    /// triggered per MS046 R10927 — never automatic.
    Replay,
}

#[derive(Debug, clap::Subcommand)]
enum SchedulerAction {
    /// Current state + last 16 decisions + backpressure snapshot.
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Decision history (newest-first; default 32, hard-max 256).
    History {
        #[arg(long, default_value_t = 32)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Single-decision detail by request_id.
    Explain {
        request_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Counterfactual replay against a different profile (read-only).
    Replay {
        request_id: String,
        /// Replay against this profile (default: original profile).
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Per-profile 7-axis weight matrix readout.
    Weights {
        /// Profile name (fast / careful / private / autonomous /
        /// experimental / production). When omitted, prints all six.
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Operator-force-override a request's route (Ring 0 + MS003).
    Force {
        request_id: String,
        /// Route to force (blackwell / rtx3090 / cpu / hybrid / hibernate).
        #[arg(long)]
        route: String,
        #[arg(long)]
        json: bool,
    },
    /// Audit-cycle replay — re-evaluate audit chain integrity.
    AuditCycle {
        #[command(subcommand)]
        action: SchedulerAuditCycleAction,
    },
}

#[derive(Debug, clap::Subcommand)]
enum SchedulerAuditCycleAction {
    /// Verify the SHA-256 chain integrity of the scheduler audit log.
    Replay {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, clap::Subcommand)]
enum SshWrapAction {
    /// Print the doctrine (per-host policy + OCSF events +
    /// refuse-to-connect + PATH-shadow drop-in).
    Doctrine,
    /// Print step-by-step install instructions.
    Install,
}

#[derive(Debug, clap::Subcommand)]
enum PolicyAction {
    /// Print the 8 functional clusters with their member crates
    /// per SDD-051 § Recommended design.
    Clusters,
    /// Print every shipped `selfdef-policy-*` crate organized
    /// under its cluster.
    Crates,
}

#[derive(Debug, clap::Subcommand)]
enum FlexProfileAction {
    /// Print the static schema (DeltaOp variants, Delta fields,
    /// RevertRecord shape, refusal rules). Offline — no daemon
    /// needed.
    Schema,
    /// Fetch live state via GET /v1/flex-profile and print
    /// baseline + delta count + revert count + latest delta.
    Show {
        /// Pass through the raw JSON body (jq-friendly).
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, clap::Subcommand)]
enum GrantsAction {
    /// Read the current resident grant snapshot via GET /v1/grants.
    Show {
        /// Pass through the raw JSON body (jq-friendly).
        #[arg(long)]
        json: bool,
    },
    /// Issue an operator-signed grant via POST /v1/grants/issue.
    Issue {
        /// Grant kind: filesystem|network|capability|communication|sandbox.
        #[arg(long)]
        kind: String,
        /// Scope: path glob / FQDN / CIDR / capability tag (kind-dependent).
        #[arg(long)]
        scope: String,
        /// Operator-authored reason (non-empty).
        #[arg(long)]
        reason: String,
        /// Active profile at issuance time.
        #[arg(long, default_value = "careful")]
        profile: String,
        /// Requesting actor MS003 fingerprint.
        #[arg(long)]
        actor: String,
        /// Desired TTL in seconds (≤ 86400).
        #[arg(long, default_value_t = 60)]
        ttl_seconds: u32,
        /// MS003 signature over the request (sign with the `minisign` CLI).
        #[arg(long)]
        signature: String,
        /// Pass through the raw JSON response (jq-friendly).
        #[arg(long)]
        json: bool,
    },
    /// Revoke a grant by id via POST /v1/grants/revoke.
    Revoke {
        /// Grant id to revoke.
        grant_id: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum InferenceBackendsAction {
    /// Default: fetch live state via GET /v1/inference-backends and
    /// render the 4-backend install table.
    Show,
    /// Shell out to the local backend binary's `--version` directly
    /// (no daemon round-trip). Exit 0 on success, 1 if not installed,
    /// 2 on subprocess error.
    Version {
        /// One of: llama.cpp, vllm, bitnet.cpp, unsloth.
        backend: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum DashboardPrefsAction {
    /// Default: fetch the current prefs via GET /v1/dashboard-prefs
    /// and render the human table (or JSON with --json).
    Show,
    /// PUT a mutation. `field` is one of:
    ///   - refresh_rate ∈ {fast, normal, slow, paused}
    ///   - active_preset ∈ {default, security, performance, inference, compact}
    ///   - hidden_panels — comma-separated section IDs (empty string clears)
    Set {
        /// refresh_rate | active_preset | hidden_panels
        field: String,
        /// New value for the field.
        value: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum FilesystemBoundaryAction {
    /// Print the 3-dir layout + 6-step pipeline + 5-field schema +
    /// 6 predicates + verbatim doctrines.
    Doctrine,
    /// Print the full SDD-045 contract including the caller-side
    /// 9-step sequence.
    Schema,
}

#[derive(Debug, clap::Subcommand)]
enum NetworkBoundaryAction {
    /// Print the 5-profile NetworkProfile ladder with bit values +
    /// cross-cycle bindings.
    Profiles,
    /// Parse a u8 (decimal or 0bXXXX) and report which NetworkProfile
    /// it encodes. Exit 0 if recognized; 1 otherwise.
    Classify {
        /// policy bits — `5` or `0b101` etc.
        bits: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum CapabilityTokensAction {
    /// Print the 5 CheckVerdict variants + their semantics.
    Verdicts,
    /// Print the full SDD-044 schema (Token shape + companion
    /// crates + caller contract + refusal rules).
    Schema,
    /// Read the live daemon-resident token snapshot via
    /// GET /v1/capability-tokens/snapshot.
    Show {
        /// Pass through the raw JSON body (jq-friendly).
        #[arg(long)]
        json: bool,
    },
    /// Issue an operator-signed MS035 capability token via
    /// POST /v1/capability-tokens/issue.
    Issue {
        /// Active profile at issuance time (MS040).
        #[arg(long, default_value = "careful")]
        profile: String,
        /// Requesting actor MS003 fingerprint.
        #[arg(long)]
        actor: String,
        /// Allowed tool tokens (repeat the flag; e.g.
        /// `--tool tests --tool builds`).
        #[arg(long = "tool", required = true)]
        tools: Vec<String>,
        /// MS039 trust ring: ring0|ring1|ring2|ring3|ring4.
        #[arg(long)]
        trust_ring: String,
        /// MS039 authority level: l0_observe|l1_suggest|l2_simulate|
        /// l3_prepare|l4_execute|l5_commit|l6_persist.
        #[arg(long)]
        authority_level: String,
        /// MS036 sandbox tier: A|B|C|D.
        #[arg(long)]
        sandbox_tier: String,
        /// Parent token id for F04146 inheritance (empty = root).
        #[arg(long, default_value = "")]
        parent_token_id: String,
        /// TTL in seconds (≤ 86400).
        #[arg(long, default_value_t = 60)]
        ttl_seconds: u32,
        /// MS003 signature over the request (sign with the `minisign` CLI).
        #[arg(long)]
        signature: String,
        /// Pass through the raw JSON response (jq-friendly).
        #[arg(long)]
        json: bool,
    },
    /// Revoke a capability token by id via POST /v1/capability-tokens/revoke.
    Revoke {
        /// Capability-token id to revoke.
        token_id: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum ToolAuthorityAction {
    /// Print the 8 canonical ToolId variants + the 9-gate
    /// composition pipeline + per-gate decision vocabulary +
    /// refusal rules. Operator + agent discovery of the SDD-050
    /// contract.
    Tools,
    /// Call `selfdef_tool_capability_policy::is_authorized(tool,
    /// mode, profile)` and print Allow / NotAuthorized. Exit 0 if
    /// allowed; 1 otherwise (shell-gate friendly).
    Permits {
        /// Tool id (shell | fs-read | fs-write | web-fetch |
        /// model-inference | mcp-bridge | replay-control |
        /// cli-bridge).
        tool: String,
        /// Execution mode (plan | dry-run | shadow | sandbox |
        /// execute | replay | debug).
        mode: String,
        /// Profile (private | fast | careful | autonomous |
        /// experimental | production).
        profile: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum CommitAuthorityAction {
    /// Print the 8 commit types + 5 mandatory fields + 3 high-risk
    /// gates + classifier rules + refusal rules. Operator + agent
    /// discovery of the SDD-043 contract.
    Types,
    /// Read a JSON CommitEnvelope from disk and run
    /// `selfdef_commit_authority::validate`. Exit 0 if valid; 1 if
    /// any mandatory field / signature / high-risk gate / rollback
    /// constraint fails.
    Validate {
        /// Path to the JSON envelope file.
        file: std::path::PathBuf,
    },
    /// Read a JSON CommitEnvelope and report whether it's classified
    /// high-risk per F04871..F04875. Exit 0 if low-risk; 1 if high-
    /// risk (so operators can shell-gate elevated workflows behind
    /// `selfdefctl commit-authority classify <file>`).
    Classify {
        /// Path to the JSON envelope file.
        file: std::path::PathBuf,
    },
}

#[derive(Debug, clap::Subcommand)]
enum GuardianAction {
    /// Daemon state + last N events processed (default: 16).
    Show,
    /// Render the last N verdicts (newest-first).
    History {
        /// How many entries to render (default: 32).
        #[arg(long, default_value_t = 32)]
        limit: u32,
    },
    /// Re-classify a stored event by id (MS009 replay invariant;
    /// operator-triggered, never automatic).
    Replay {
        /// Event id (Tetragon UUID) to re-classify.
        event_id: String,
    },
    /// Operator-signed false-positive rollback (Ring 0 + MS003).
    Rollback {
        /// Event id (Tetragon UUID) of the verdict being rolled back.
        event_id: String,
    },
}

#[derive(Debug, clap::Subcommand)]
enum PerimeterAction {
    /// Inspect the cross-author overlap between selfdef + sovereign-os
    /// Tetragon TracingPolicies. Exit 0 on pass, 1 on overlap.
    CheckOverlap,
    /// Show the coexistence configuration + per-author policy counts
    /// on disk. Read-only.
    Status,
    /// SDD-028 / MS047: active sovereign-kernel-fence policy summary +
    /// last N Sigkill verdicts + currently-loaded allowlist extensions.
    /// Read-only.
    Show {
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// SDD-028 / MS047: Sigkill verdict history (newest-first).
    History {
        /// How many entries to render (default: 32).
        #[arg(long, default_value_t = 32)]
        limit: u32,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// SDD-028 / MS047: install a new operator-signed allowlist
    /// extension manifest. Requires Ring 0 + MS003 multi-sig. The
    /// `--signed` argument must point at a `.json` manifest with a
    /// detached `.minisig` signature alongside.
    Extend {
        /// Path to the MS003-signed extension manifest (`.json`).
        /// Its `<path>.minisig` sibling MUST exist.
        #[arg(long)]
        signed: PathBuf,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// SDD-028 / MS047: revoke a currently-loaded extension by id.
    /// Requires Ring 0 + MS003 signature.
    Revoke {
        /// Extension id (kebab-case) as written in the manifest.
        extension_id: String,
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// SDD-028 / MS047: re-evaluate the perimeter baseline against the
    /// current TracingPolicy. Operator-triggered audit cycle (replay
    /// only; never automatic).
    AuditCycle {
        #[command(subcommand)]
        action: AuditCycleAction,
    },
}

#[derive(Debug, clap::Subcommand)]
enum AuditCycleAction {
    /// Re-evaluate baseline against current policy. Cross-ref MS009.
    Replay {
        /// Machine-readable JSON output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum InitAction {
    /// Write a starter `selfdef.toml` daemon config. The
    /// template ships with every audit-shipped opt-in
    /// security feature OFF; the operator turns each on after
    /// reading the matching `docs/dev/<feature>.md` runbook.
    Config {
        /// Where to write the starter config. Default:
        /// `/etc/selfdef/selfdef.toml`.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Overwrite an existing file. By default, init
        /// refuses to clobber on-disk state.
        #[arg(long)]
        force: bool,
        /// SDD-013: pin the deployment target in the generated
        /// config. `generic` (default) uses /var/lib/selfdef paths;
        /// `sain01` routes state to /mnt/vault/context per
        /// sovereign-os `profiles/sain-01.yaml § hardware.storage`.
        /// Operator typos fail-loud — no silent fallback.
        #[arg(long, value_parser = parse_deployment_target, default_value = "generic")]
        target: selfdef_config::DeploymentTarget,
    },
    /// Write a starter `modules.toml` listing every shipped
    /// module commented out with a short description.
    /// Operator uncomments the modules they want activated.
    Modules {
        /// Where to write. Default: `/etc/selfdef/modules.toml`.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Print the first-run operator checklist (config write,
    /// systemctl enable, module apply, opt-in security
    /// features, periodic doctor timer). Read-only — no
    /// filesystem effects.
    Checklist,
}

#[derive(Debug, Subcommand)]
enum RbacAction {
    /// SDD-004 F-2026-025 follow-up: print the recommended RBAC
    /// posture for `agent-guard`'s `scope = "pod-label"`. Reads
    /// the agent-guard module config to determine the configured
    /// label key/value; if scope != "pod-label", reports the
    /// check as not-applicable and exits 0.
    ///
    /// With `--probe`, additionally shells out to `kubectl auth
    /// can-i patch pods --subresource=labels --as=<subject>`
    /// for a built-in set of common-mistake subjects
    /// (system:authenticated, system:unauthenticated,
    /// system:masters, system:serviceaccount:default:default,
    /// plus operator-supplied `--as`) and reports each as
    /// ok / overly-permissive. F-2027-007: the expanded set
    /// catches kubeadm-style bootstrap superuser bindings and
    /// the common "PATCH pods to default SA" anti-pattern.
    Check {
        /// Override the agent-guard module config path.
        /// Default: `/etc/selfdef/modules/agent-guard.toml`.
        #[arg(long)]
        module_config: Option<PathBuf>,
        /// Probe the cluster via `kubectl auth can-i ...`. Without
        /// this flag, the verb is read-only documentation —
        /// prints the recommended posture + the exact kubectl
        /// commands the operator should run.
        #[arg(long)]
        probe: bool,
        /// Additional subjects to probe via `kubectl auth can-i
        /// --as=<value>`. Repeatable.
        #[arg(long = "as", value_name = "SUBJECT")]
        as_subjects: Vec<String>,
        /// Namespace to scope the probe to. Default: all
        /// namespaces (`kubectl auth can-i ... --all-namespaces`
        /// equivalent — omits `-n`).
        #[arg(long)]
        namespace: Option<String>,
        /// Don't fail the command on overly-permissive findings;
        /// just print them.
        #[arg(long)]
        warn_only: bool,
    },
}

#[derive(Debug, Subcommand)]
enum KeysAction {
    /// SDD-004 rule-signing follow-up: verify a detached
    /// minisign signature against a target file. Useful for
    /// operator debugging — "did this rule really get signed by
    /// the key I think it did?" — without invoking the daemon's
    /// load path. Uses `[security].signing_public_key_file` from
    /// the daemon config unless `--public-key` is given.
    Verify {
        /// File to verify. The signature must live at
        /// `<file>.minisig` (minisign's default sidecar layout).
        target: PathBuf,
        /// Override the public-key path (default: from
        /// `[security].signing_public_key_file`).
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
    /// F-2027-006 follow-up: batch-verify every `.yml`/`.yaml`
    /// file under a directory in one process. Replaces N
    /// `selfdefctl keys verify <p>` invocations from
    /// `modules/tetragon/install/apply.sh`. Exits 0 iff every
    /// file verifies; prints one line per file with the
    /// pass/fail outcome.
    VerifyDir {
        /// Directory to walk. Non-recursive — checks the
        /// immediate `*.yml` / `*.yaml` files in `dir`.
        dir: PathBuf,
        /// Override the public-key path (default: from
        /// `[security].signing_public_key_file`).
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ApiAction {
    /// SDD-004 F-2026-023 follow-up: rotate the API bearer token.
    /// Generates a new high-entropy token, writes it atomically
    /// to the path configured in `[api].token_file`, and
    /// optionally signals the daemon (SIGUSR2) to reload from
    /// disk. The previous token continues to work until the
    /// signal is delivered.
    RotateToken {
        /// Override the token-file path (default: read from the
        /// daemon config's `[api].token_file`). Useful when
        /// rotating the control token instead of the read
        /// token — pass the path to `control_token_file`.
        #[arg(long)]
        token_file: Option<PathBuf>,
        /// Number of random bytes in the new token (base64-url
        /// encoded). Default 32 → 43-char token.
        #[arg(long, default_value_t = 32)]
        bytes: usize,
        /// PID of the running selfdefd to signal with SIGUSR2
        /// after writing the new token. Defaults to no signal —
        /// the operator runs `systemctl kill --signal=SIGUSR2
        /// selfdefd` separately. Passing `--pid auto` looks for
        /// the daemon via `systemctl show -p MainPID
        /// selfdefd.service`.
        #[arg(long)]
        pid: Option<String>,
        /// Print the new token to stdout instead of just the
        /// path it was written to. Default: omit (the token is
        /// only on disk, where the next scrape config reads it).
        #[arg(long)]
        print: bool,
    },
}

#[derive(Debug, Subcommand)]
enum NotifyAction {
    /// SDD-008 D-4: mark an in-flight escalation as acknowledged.
    /// The wake task short-circuits any further rungs — the operator
    /// has seen the event. Idempotent: re-acking an already-acked
    /// event reports "already acked" and exits 0.
    Ack {
        /// Event ID (UUID) to ack. Matches `EventId` in the
        /// escalation engine; the same id the operator sees in
        /// the notification body.
        event_id: String,
    },
    /// SDD-008 D-4: forget a pending escalation entirely (DELETE
    /// the row). Use when the operator wants to suppress further
    /// rungs WITHOUT recording an ack — e.g. when the alert was a
    /// false positive and the audit trail should reflect that.
    Forget {
        /// Event ID (UUID) to forget.
        event_id: String,
    },
    /// SDD-008 D-4: print the pending escalation queue. Read-only.
    /// Useful for "what's in flight right now?" triage.
    List {
        /// Maximum rows to print. Default 50.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// JSON-lines output for scripting. Default is a human
        /// table with severity emoji.
        #[arg(long)]
        json: bool,
    },
    /// Pull the next wake-task action forward to "right now" by
    /// setting the row's `deadline_at = now`. The daemon's wake task
    /// then fires the current rung's channels at its next poll
    /// (typically within 60s). Use when an operator wants to re-fire
    /// a notification without waiting for the rung's natural ack
    /// window — e.g. testing a freshly-configured channel, or
    /// believing the previous delivery failed silently. Does NOT
    /// reset rung state or bypass profile limits; the row's
    /// rung_index keeps marching forward exactly as the wake task
    /// would have advanced it at the natural deadline. Idempotent;
    /// re-sending an already-acked event reports "noop" and exits 0.
    Resend {
        /// Event ID (UUID) to resend.
        event_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ModelsAction {
    /// SD-R34: list every model.toml under the registry dir.
    List {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// SD-R34: dry-run the hardware gate on this host — shows
    /// which registered models WOULD apply and which WOULD SKIP.
    /// Read-only.
    CheckHardware {
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
    },
    /// SD-R57 (closes SDD-019 T-3 fetch-side): download a model
    /// artifact + verify sha256 against the manifest. Operator
    /// pins artifact_sha256 in model.toml; fetcher refuses to
    /// rename on mismatch.
    Fetch {
        /// Model slug (the directory name under --dir).
        slug: String,
        /// Destination path for the downloaded artifact.
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Env-var name carrying a Bearer token (e.g.
        /// HUGGINGFACE_HUB_TOKEN). Operator-supplied tokens
        /// NEVER live in-repo; only env-var references.
        #[arg(long, value_name = "ENV_NAME")]
        token_env: Option<String>,
    },
    /// SD-R81 (SDD-025 Y-2): LoRA-adapter state surface (foundation
    /// brick for the X-4 LoRA lifecycle arc). For now: a single
    /// `list` subverb that reads the operator-owned state file at
    /// `/var/lib/selfdef/loras.json` (overridable via
    /// SELFDEF_LORA_STATE or --state) and renders the active
    /// adapter set. attach/detach verbs land in subsequent rounds.
    Lora {
        #[command(subcommand)]
        action: LoraAction,
    },
}

#[derive(Debug, clap::Subcommand)]
enum LoraAction {
    /// SD-R81: list every adapter recorded in the state file.
    List {
        /// Override the LoRA state file path (default:
        /// `/var/lib/selfdef/loras.json`, env `SELFDEF_LORA_STATE`).
        #[arg(long)]
        state: Option<PathBuf>,
        /// Emit JSON (the raw state shape) instead of the tabular view.
        #[arg(long)]
        json: bool,
    },
    /// SD-R89 (SDD-025 Y-2 extension): record a LoRA attachment in
    /// the operator state file.
    ///
    /// Atomic update: read existing state, append/upsert the entry,
    /// write atomically via tempfile + rename. Idempotent — attaching
    /// the same adapter_id twice upserts the base_model + status
    /// fields rather than duplicating the row.
    Attach {
        adapter_id: String,
        base_model: String,
        /// Override status (default: "active").
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// SD-R89: remove a LoRA attachment by adapter_id. Atomic update.
    /// rc=1 when the adapter wasn't present (operator should re-check).
    Detach {
        adapter_id: String,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// SD-R89: flip an attached LoRA's status (active / disabled /
    /// errored). Doesn't remove the row — useful for "I want to keep
    /// the binding metadata but stop loading this adapter".
    SetStatus {
        adapter_id: String,
        /// One of: active / disabled / errored.
        status: String,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ModulesAction {
    /// List every module manifest found in the modules directory.
    List {
        /// Override the modules directory (default: /usr/share/selfdef/modules,
        /// falling back to the workspace `modules/` in dev runs).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// SD-R63: machine-readable JSON instead of the tabular view.
        #[arg(long)]
        json: bool,
        /// SD-R75 (SDD-024 X-6): filter to modules whose `category`
        /// field matches exactly. Operator-stable string;
        /// currently in use: hardening / inference / network /
        /// detection / hardware / observability.
        #[arg(long)]
        category: Option<String>,
        /// SD-R75 (SDD-024 X-6): filter to modules whose `phase`
        /// field matches exactly. Operator-stable string;
        /// currently in use: pre-install / during-install /
        /// post-install / main / recurrent.
        #[arg(long)]
        phase: Option<String>,
    },
    /// SD-R99 (E2.M6): show the effective per-module feature map —
    /// the module manifest's `[features]` defaults deep-merged with
    /// the operator's per-module overlay (`/etc/selfdef/modules/<slug>.toml`
    /// or `--config <path>` or `$SELFDEF_MODULE_FEATURES_<SLUG>` env).
    /// Always emits JSON: `{module, source, overlay_keys, features}`.
    /// Operator-overlay-doctrine (SDD-030 R283 vector) adopted here.
    Features {
        slug: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Explicit per-module overlay TOML; beats env + /etc.
        /// (Named `--overlay` rather than `--config` to avoid
        /// colliding with the global daemon-config flag.)
        #[arg(long)]
        overlay: Option<PathBuf>,
        /// SD-R100 (E2.M7): emit ONLY boolean leaves set to true
        /// (recursive). Tables with no surviving children are
        /// dropped. Operator-pull view of which features are
        /// currently *enabled* on this host.
        #[arg(long, conflicts_with = "disabled_only")]
        enabled_only: bool,
        /// SD-R100 (E2.M7): companion to `--enabled-only` — emit
        /// ONLY boolean leaves set to false.
        #[arg(long, conflicts_with = "enabled_only")]
        disabled_only: bool,
    },
    /// SD-R100 (E2.M7): set one feature key in the operator overlay
    /// file. Dotted keys walk/create nested tables. Value is parsed
    /// as a TOML scalar (`true`/`false`/`42`/`"foo"`/...). Writes to
    /// `--overlay <path>` (creating it if missing) or to the default
    /// `/etc/selfdef/modules/<slug>.toml` when no flag given.
    FeatureSet {
        slug: String,
        /// Dotted feature key (e.g. `auditd` or `limits.warn`).
        key: String,
        /// TOML scalar literal — `true`, `false`, `42`, `"text"`,
        /// `3.14`, `[1, 2]`, etc.
        value: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        overlay: Option<PathBuf>,
    },
    /// SD-R100 (E2.M7): remove one feature key from the operator
    /// overlay file. Idempotent: clearing an absent key reports
    /// `cleared = false` without error.
    FeatureClear {
        slug: String,
        key: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        overlay: Option<PathBuf>,
    },
    /// Show the full manifest for one module by slug.
    Info {
        slug: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// SD-R39: probe the host and surface "gate verdict on THIS
        /// host" inline (passes / unmet predicates). Same engine as
        /// `modules check-hardware` but for one module.
        #[arg(long)]
        with_host_status: bool,
        /// SD-R40: emit the manifest as structured JSON instead of
        /// the human-readable form. Tooling consumers
        /// (sovereign-osctl, future fleet dashboards) parse this
        /// directly without scraping. Implies `--with-host-status`
        /// when set alongside; the gate verdict lands under
        /// `host_status` in the JSON.
        #[arg(long)]
        json: bool,
        /// SD-R80 (SDD-025 Y-4): probe the host + render the
        /// RESOLVED requirement set — root predicates plus the
        /// `any_of` branch that matched (when applicable). Operators
        /// learn "this host would land via branch 1: VNNI + ternary
        /// path." Implies --with-host-status. Pure renderer over
        /// `HardwareRequirements::evaluate_resolved` (SD-R79).
        #[arg(long)]
        resolved: bool,
    },
    /// Apply every active module's install/apply.sh in dependency order.
    Apply {
        /// Override the host modules config (default: /etc/selfdef/modules.toml).
        #[arg(long)]
        host_config: Option<PathBuf>,
        /// Override the catalog directory.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Skip mutations — set SELFDEF_DRY_RUN=1 for each script.
        #[arg(long)]
        dry_run: bool,
        /// Only apply these modules (comma-separated).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Skip these modules (comma-separated).
        #[arg(long, value_delimiter = ',')]
        except: Vec<String>,
        /// SDD-002: skip the pre-apply check that every active
        /// module's `[daemon_requires]` is satisfied by the
        /// daemon's `/etc/selfdef/selfdef.toml`. Use only when
        /// you know what you're doing.
        #[arg(long)]
        ignore_daemon_requires: bool,
        /// SDD-018 D-2 (SD-R42): force-apply gated modules even
        /// when their `[requires_hardware]` predicates fail on
        /// this host. Equivalent to deleting the
        /// `[requires_hardware]` block from each manifest, but
        /// without editing files. Use for one-off testing on
        /// near-match hosts. Production should rely on the gate.
        #[arg(long, conflicts_with = "strict_hardware")]
        ignore_hardware: bool,
        /// SD-R44 (companion to --ignore-hardware): turn gate-SKIP
        /// into gate-FAIL. When any module would silently skip due
        /// to unmet `[requires_hardware]` predicates, apply EXITS
        /// non-zero with the unmet predicate list. Use on SAIN-01
        /// production to refuse incomplete installs. Cannot be
        /// combined with --ignore-hardware (the two flags express
        /// opposite intents).
        #[arg(long, conflicts_with = "ignore_hardware")]
        strict_hardware: bool,
        /// SD-R76 (SDD-024 X-5): force a FRESH hardware probe
        /// before the `[requires_hardware]` gate evaluates, instead
        /// of using the cached selfdef-hardware snapshot. Use when
        /// the operator has changed BIOS settings (enabled AVX-512,
        /// swapped GPUs in/out) and the cached snapshot diverges
        /// from physical reality. Default OFF — most apply runs
        /// happen on a stable host where the cached snapshot is
        /// current.
        #[arg(long)]
        reprobe_hardware: bool,
    },
    /// Run check.sh for every active module (no mutations).
    Check {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        except: Vec<String>,
        /// SDD-002: same flag as `apply` — skip the pre-check
        /// against the daemon's selfdef.toml.
        #[arg(long)]
        ignore_daemon_requires: bool,
    },
    /// Status summary of every active module (alias of `check`).
    Status {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// SD-R45: emit a structured JSON document with per-module
        /// status rows instead of the human-readable summary.
        /// Tooling consumers (sovereign-osctl overview, fleet
        /// dashboards) parse this directly.
        #[arg(long)]
        json: bool,
    },
    /// SD-R83 (SDD-026 Z-13 partial): show installed / available /
    /// orphaned modules in one table, partitioning the catalog ×
    /// host-config join:
    ///   INSTALLED  — slug present in both catalog AND host-config
    ///                ([modules.X] entry in /etc/selfdef/modules.toml)
    ///   AVAILABLE  — slug present in catalog, NOT activated in
    ///                host-config (operator could `apply --only X`)
    ///   ORPHANED   — slug in host-config but NOT in catalog (stale
    ///                entry — operator should prune or restore the
    ///                manifest)
    /// Read-only. Composes with the future Z-1 dashboard's "Browse
    /// available" sub-tab.
    Diff {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Emit JSON instead of the tabular partition.
        #[arg(long)]
        json: bool,
    },
    /// SD-R86 (SDD-026 Z-13): surface uninstalled-but-available
    /// catalog modules with operator-actionable recommendations.
    ///
    /// Walks the AVAILABLE partition from `modules diff` and decorates
    /// each row with hardware-gate verdict, per-dependency installed
    /// flag, and a roll-up `recommendation` field (ready /
    /// blocked-by-hardware / blocked-by-missing-deps / needs-review).
    /// The dashboard's "Install options" tab consumes the JSON
    /// directly. Operator-named "modules options-to-install".
    InstallOptions {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Restrict to one category.
        #[arg(long)]
        category: Option<String>,
        /// Show only `recommendation = "ready"` rows.
        #[arg(long)]
        only_ready: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// SD-R87 (SDD-026 Z-13): topologically-ordered install plan over
    /// the SD-R86 AVAILABLE-and-READY set.
    ///
    /// Resolves the dep graph + emits a numbered sequence of
    /// `selfdefctl modules apply --only <slug>` commands the operator
    /// runs in order. NOT-READY modules are reported in a separate
    /// "skipped" section with their blocking reason. Dep cycles fail
    /// the plan with rc=1 (manifests must be corrected).
    InstallPlan {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Restrict to one category.
        #[arg(long)]
        category: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// SD-R88 (SDD-026 Z-13 follow-up): emit a copy-pasteable config
    /// scaffold for one catalog module — the operator's next step
    /// AFTER `install-plan` tells them WHAT to install.
    ///
    /// Renders a ready-to-paste `[modules."<slug>"]` block + the
    /// matching `[daemon.*]` entries the manifest declares as
    /// daemon_requires. Hardware-gate predicates surface as comments.
    ConfigScaffold {
        slug: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Required when the module is instanced
        /// (e.g. `--instance wg0` for the tunnel module).
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// SD-R93 (SDD-026 Z-13 execution): apply the SD-R87 install-plan
    /// end-to-end. Walks each step of the topologically-ordered plan,
    /// invoking `apply --only <slug>` per step. Per-step outcome is
    /// reported. DRY-RUN by default; `--apply` actually executes. Step
    /// failures HALT the rest of the plan unless `--continue-on-failure`
    /// is set.
    ApplyPlan {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        category: Option<String>,
        /// Actually execute (default is DRY-RUN preview).
        #[arg(long)]
        apply: bool,
        /// Don't halt on first failure — keep trying every step.
        #[arg(long)]
        continue_on_failure: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run uninstall.sh for every active module in reverse dependency order.
    ///
    /// Destructive: requires `--confirm <hostname>` matching this host
    /// unless `--dry-run` is set. Modules without an uninstall script
    /// are reported as `skipped` rather than failing the run.
    Uninstall {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Skip mutations — set SELFDEF_DRY_RUN=1 for each script.
        /// When set, `--confirm` is not required.
        #[arg(long)]
        dry_run: bool,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        except: Vec<String>,
        /// Required for non-dry-run runs: must match this host's hostname.
        #[arg(long)]
        confirm: Option<String>,
    },
    /// SDD-002 D-5: print every active module's
    /// `[daemon_requires]` block as a copy-pasteable TOML
    /// snippet. Read-only; doesn't touch the daemon config.
    ShowRequires {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// SD-R15: dry-run the SD-R14 hardware gate on this host —
    /// shows which active modules WOULD apply and which WOULD SKIP
    /// based on each manifest's `[requires_hardware]` block.
    /// Read-only; no module scripts run.
    CheckHardware {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Emit JSON instead of human-readable output.
        #[arg(long)]
        json: bool,
        /// SD-R38: dry-run the gate against a SAVED capabilities
        /// JSON instead of probing the local host. Lets operators
        /// preview "would this catalog land on a SAIN-01 box?" from
        /// a dev workstation. The file shape matches the SD-R10
        /// `selfdefctl hardware export --output <path>` output.
        #[arg(long, value_name = "PATH")]
        caps: Option<PathBuf>,
    },
    /// SD-R36: emit the active modules' dependency graph in
    /// Graphviz DOT format. Operators pipe to `dot -Tsvg` for a
    /// visual layout, or read the text directly for a quick
    /// audit of how modules compose. Read-only.
    Graph {
        #[arg(long)]
        host_config: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Annotate node colour by SD-R14 gate verdict (green =
        /// kept, red = skipped). Requires a hardware probe;
        /// default is off (graph alone is operator-readable
        /// without colour).
        #[arg(long)]
        with_hardware_gate: bool,
        /// SD-R41: emit the graph as structured JSON (nodes +
        /// edges) instead of DOT. Tooling consumers
        /// (sovereign-osctl, fleet dashboards) consume this
        /// directly without parsing DOT.
        #[arg(long)]
        json: bool,
    },
    /// SD-R50: pretty-print the SD-R47 `--ignore-hardware` audit
    /// trail (one operator-readable line per recorded override).
    /// Reads the file at SELFDEF_MODULES_AUDIT_PATH or --audit-path.
    AuditLog {
        /// Path to the audit JSONL file. Defaults to
        /// $SELFDEF_MODULES_AUDIT_PATH if set, else
        /// /var/log/selfdef/modules-audit.jsonl.
        #[arg(long)]
        audit_path: Option<PathBuf>,
        /// Show the last N entries (default: 20).
        #[arg(short, long, default_value_t = 20)]
        n: usize,
        /// Emit raw JSONL instead of the human-readable form.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ForensicsAction {
    /// List forensic bundles in the configured forensics directory.
    List,
    /// Collect a bundle now for an event by id (must exist in the hot store).
    Collect {
        /// Event UUID. Use `selfdefctl events alerts --json` to find ids.
        event_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum EventsAction {
    /// Tail recent events.
    Tail {
        #[arg(short, long, default_value_t = 20)]
        n: u32,

        /// Output as JSON-lines instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Tail recent findings (alerts) only — category_uid = 2.
    Alerts {
        #[arg(short, long, default_value_t = 20)]
        n: u32,

        #[arg(long)]
        json: bool,
    },
    /// Live-tail events as they hit the daemon's bus, via the
    /// `/events/stream` SSE endpoint. Reads the UNIX socket the
    /// daemon binds (no TCP / no bearer-token required). Prints
    /// each event one per line to stdout — defaults to JSON.
    ///
    /// Useful for incident response and live debugging — pair
    /// with `selfdefctl events tail` (which reads the SQLite
    /// store) for historical context.
    ///
    /// F-2028-010: flag constraints (also enforced by clap):
    /// `--url` and `--unix-socket` are mutually exclusive;
    /// `--token-file` requires `--url`. Pass exactly one of
    /// `--unix-socket` (default) or `--url`; pair `--url` with
    /// `--token-file` when the daemon's TCP transport requires
    /// bearer-auth (it does by default).
    Follow {
        /// Path to the daemon's UNIX socket. Default:
        /// `/run/selfdef.sock` (matches the daemon's
        /// `[api].unix_socket` default). Ignored when `--url`
        /// is set.
        #[arg(long, default_value = "/run/selfdef.sock")]
        unix_socket: PathBuf,
        /// F-2027-010: base URL of the daemon's TCP transport
        /// (e.g. `https://selfdef.example.com:7443`). When set,
        /// `--unix-socket` is ignored and the live-tail goes
        /// over HTTP/HTTPS instead of the local socket. Pair
        /// with `--token-file` if the daemon's TCP transport
        /// requires bearer-auth (it does by default).
        #[arg(long, conflicts_with = "unix_socket")]
        url: Option<String>,
        /// F-2027-010: path to a file holding the bearer token
        /// the daemon's TCP transport accepts (one line, the
        /// raw token — same shape `selfdefctl api rotate-token`
        /// produces). Only meaningful with `--url`. Reading
        /// the token from a file (vs `--token` on the command
        /// line) keeps it out of `ps` / shell history.
        #[arg(long, requires = "url")]
        token_file: Option<PathBuf>,
        /// Filter to only category_uid = 2 (Findings / alerts).
        /// Default: every event on the bus.
        #[arg(long)]
        alerts_only: bool,
        /// Stop after N events (default: stream forever).
        #[arg(short, long)]
        n: Option<usize>,
    },
    /// Append a single pre-formed event to a JSONL stream that the
    /// daemon's `eventstream` collector tails. Lets modules and
    /// helper scripts surface findings onto the bus without
    /// hand-rolling the OCSF envelope.
    Emit {
        /// OCSF class UID (e.g. `2004` for Detection Finding).
        #[arg(long)]
        class_uid: u32,
        /// OCSF activity_id within the class. Defaults to `1` ("the
        /// thing happened") which matches what most class-specific
        /// rules look for.
        #[arg(long, default_value_t = 1)]
        activity_id: u32,
        /// One of: informational, low, medium, high, critical.
        #[arg(long)]
        severity: String,
        /// `source` field on the event — typically
        /// `selfdef.<module-slug>`.
        #[arg(long)]
        source: String,
        /// Free-text message attached to the event.
        #[arg(long)]
        message: Option<String>,
        /// Override the host_tag (defaults to $HOSTNAME / /etc/hostname).
        #[arg(long)]
        host_tag: Option<String>,
        /// JSONL file to append to. The daemon's `eventstream` collector
        /// should be configured to tail this path.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RulesAction {
    /// List installed rules.
    List,
    /// Validate rule files without loading them.
    Validate { path: PathBuf },
    /// Test rules against a JSONL replay corpus.
    Test {
        #[arg(long)]
        corpus: PathBuf,
    },
    /// Run the rule linter (catches missing metadata, unreachable conditions).
    Lint,
    /// Print ATT&CK coverage of the loaded rules.
    Coverage,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let daemon_config_path = cli.config.clone();
    let cfg = Config::load(Some(&cli.config)).context("loading configuration")?;

    match cli.command {
        Command::Version => {
            println!(
                "selfdefctl {} (core {} · schema v{})",
                env!("CARGO_PKG_VERSION"),
                selfdef_core::version(),
                selfdef_core::SCHEMA_VERSION,
            );
        }
        Command::Mcp { action } => match action {
            McpAction::Tools { human } => {
                if human {
                    print!("{}", mcp::render_tools_human());
                } else {
                    println!("{}", mcp::render_tools_json());
                }
            }
            McpAction::Serve {
                exit_after,
                framing,
                tcp,
                token_env,
            } => {
                let code = if let Some(bind) = tcp {
                    mcp::serve_tcp(&bind, &framing, token_env.as_deref(), exit_after)?
                } else {
                    mcp::serve_stdio(exit_after, &framing)?
                };
                if code != 0 {
                    std::process::exit(code);
                }
            }
        },
        Command::Repl { action } => match action {
            ReplAction::Bootstrap => {
                print!("{}", repl::bootstrap_script());
            }
            ReplAction::Tiers { human } => {
                if human {
                    print!("{}", repl::render_tiers_human());
                } else {
                    println!("{}", repl::render_tiers_json());
                }
            }
            ReplAction::Tier2Examples { name, json } => {
                let code = repl::cmd_tier2_examples(name.as_deref(), json)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ReplAction::History {
                path,
                limit,
                all,
                json,
            } => {
                let code = repl::cmd_history(path.as_deref(), limit, all, json)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
        },
        Command::Api {
            action:
                ApiAction::RotateToken {
                    token_file,
                    bytes,
                    pid,
                    print,
                },
        } => {
            api_rotate_token(&cfg, token_file, bytes, pid, print)?;
        }
        Command::Notify {
            action: NotifyAction::Ack { event_id },
        } => {
            notify::ack(&cfg, &event_id)?;
        }
        Command::Notify {
            action: NotifyAction::Forget { event_id },
        } => {
            notify::forget(&cfg, &event_id)?;
        }
        Command::Notify {
            action: NotifyAction::List { limit, json },
        } => {
            notify::list(&cfg, limit, json)?;
        }
        Command::Notify {
            action: NotifyAction::Resend { event_id },
        } => {
            notify::resend(&cfg, &event_id)?;
        }
        Command::Keys {
            action: KeysAction::Verify { target, public_key },
        } => {
            keys_verify(&cfg, &target, public_key)?;
        }
        Command::Keys {
            action: KeysAction::VerifyDir { dir, public_key },
        } => {
            keys_verify_dir(&cfg, &dir, public_key)?;
        }
        Command::Rbac {
            action:
                RbacAction::Check {
                    module_config,
                    probe,
                    as_subjects,
                    namespace,
                    warn_only,
                },
        } => {
            rbac_check(
                module_config,
                probe,
                &as_subjects,
                namespace.as_deref(),
                warn_only,
            )?;
        }
        Command::Doctor { json } => {
            let results = doctor::run(&cfg);
            let (rendered, exit) = if json {
                doctor::render_json(&results)?
            } else {
                doctor::render_human(&results)
            };
            print!("{rendered}");
            std::process::exit(exit);
        }
        Command::Init { action } => match action {
            InitAction::Config {
                output,
                force,
                target,
            } => {
                let path = output.unwrap_or_else(|| PathBuf::from(init::DEFAULT_DAEMON_CONFIG));
                init::write_starter_config_with_target(&path, force, target)?;
            }
            InitAction::Modules { output, force } => {
                let path = output.unwrap_or_else(|| PathBuf::from(init::DEFAULT_MODULES_CONFIG));
                init::write_starter_modules(&path, force)?;
            }
            InitAction::Checklist => {
                init::print_checklist();
            }
        },
        Command::Perimeter { action } => match action {
            PerimeterAction::CheckOverlap => {
                let exit = perimeter::run_check_overlap(&cfg).context("perimeter check-overlap")?;
                std::process::exit(exit);
            }
            PerimeterAction::Status => {
                let exit = perimeter::run_status(&cfg).context("perimeter status")?;
                std::process::exit(exit);
            }
            PerimeterAction::Show { json } => {
                let exit = perimeter::run_show(json).context("perimeter show")?;
                std::process::exit(exit);
            }
            PerimeterAction::History { limit, json } => {
                let exit = perimeter::run_history(limit, json).context("perimeter history")?;
                std::process::exit(exit);
            }
            PerimeterAction::Extend { signed, json } => {
                let exit = perimeter::run_extend(&signed, json).context("perimeter extend")?;
                std::process::exit(exit);
            }
            PerimeterAction::Revoke { extension_id, json } => {
                let exit =
                    perimeter::run_revoke(&extension_id, json).context("perimeter revoke")?;
                std::process::exit(exit);
            }
            PerimeterAction::AuditCycle { action } => match action {
                AuditCycleAction::Replay { json } => {
                    let exit = perimeter::run_audit_cycle_replay(json)
                        .context("perimeter audit-cycle replay")?;
                    std::process::exit(exit);
                }
            },
        },
        Command::Wizard { json } => {
            let exit = if json {
                wizard::run_json()?
            } else {
                wizard::run_human()?
            };
            std::process::exit(exit);
        }
        Command::Hardware { action, json } => {
            let exit = match action {
                Some(HardwareAction::Match) => hardware::run_match()?,
                Some(HardwareAction::Export { output }) => hardware::run_export(output)?,
                Some(HardwareAction::Thermals { json: tj }) => hardware::run_thermals(tj)?,
                Some(HardwareAction::Posture { json: pj }) => hardware::run_posture(pj)?,
                Some(HardwareAction::AotScript { wasm, output }) => {
                    hardware::run_aot_script(&wasm, output.as_deref())?
                }
                Some(HardwareAction::Tune { format, output }) => {
                    hardware::run_tune(&format, output)?
                }
                Some(HardwareAction::Probe) if json => hardware::run_json()?,
                None if json => hardware::run_json()?,
                _ => hardware::run_human()?,
            };
            std::process::exit(exit);
        }
        Command::Scheduler { action } => {
            let exit = match action {
                SchedulerAction::Show { json } => scheduler::run_show(json)?,
                SchedulerAction::History { limit, json } => scheduler::run_history(limit, json)?,
                SchedulerAction::Explain { request_id, json } => {
                    scheduler::run_explain(&request_id, json)?
                }
                SchedulerAction::Replay {
                    request_id,
                    profile,
                    json,
                } => scheduler::run_replay(&request_id, profile.as_deref(), json)?,
                SchedulerAction::Weights { profile, json } => {
                    scheduler::run_weights(profile.as_deref(), json)?
                }
                SchedulerAction::Force {
                    request_id,
                    route,
                    json,
                } => scheduler::run_force(&request_id, &route, json)?,
                SchedulerAction::AuditCycle { action } => match action {
                    SchedulerAuditCycleAction::Replay { json } => {
                        scheduler::run_audit_cycle_replay(json)?
                    }
                },
            };
            std::process::exit(exit);
        }
        Command::Trio { json, watch, quiet } => {
            let exit = trio::run(json, watch, quiet).context("trio")?;
            std::process::exit(exit);
        }
        Command::TrioTail { interval_ms, json } => {
            let exit = trio::run_tail(interval_ms, json).context("trio-tail")?;
            std::process::exit(exit);
        }
        Command::Alerts { json, quiet } => {
            let exit = alerts::run(json, quiet).context("alerts")?;
            std::process::exit(exit);
        }
        Command::Health { json, quiet } => {
            let exit = health::run(json, quiet).context("health")?;
            std::process::exit(exit);
        }
        Command::AuditChains { json, quiet } => {
            let exit = audit_chains::run(json, quiet).context("audit-chains")?;
            std::process::exit(exit);
        }
        Command::CommitAuthority { action } => {
            let exit = match action {
                CommitAuthorityAction::Types => commit_authority::run_types()?,
                CommitAuthorityAction::Validate { file } => {
                    commit_authority::run_validate(&file).context("commit-authority validate")?
                }
                CommitAuthorityAction::Classify { file } => {
                    commit_authority::run_classify(&file).context("commit-authority classify")?
                }
            };
            std::process::exit(exit);
        }
        Command::ToolAuthority { action } => {
            let exit = match action {
                ToolAuthorityAction::Tools => tool_authority::run_tools()?,
                ToolAuthorityAction::Permits {
                    tool,
                    mode,
                    profile,
                } => tool_authority::run_permits_cli(&tool, &mode, &profile)?,
            };
            std::process::exit(exit);
        }
        Command::CapabilityTokens { action } => {
            let exit = match action {
                CapabilityTokensAction::Verdicts => capability_tokens::run_verdicts()?,
                CapabilityTokensAction::Schema => capability_tokens::run_schema()?,
                CapabilityTokensAction::Show { json } => {
                    capability_tokens_registry::run_show(json).context("capability-tokens show")?
                }
                CapabilityTokensAction::Issue {
                    profile,
                    actor,
                    tools,
                    trust_ring,
                    authority_level,
                    sandbox_tier,
                    parent_token_id,
                    ttl_seconds,
                    signature,
                    json,
                } => capability_tokens_registry::run_issue(
                    &actor,
                    &profile,
                    &tools,
                    &trust_ring,
                    &authority_level,
                    &sandbox_tier,
                    &parent_token_id,
                    ttl_seconds,
                    &signature,
                    json,
                )
                .context("capability-tokens issue")?,
                CapabilityTokensAction::Revoke { token_id } => {
                    capability_tokens_registry::run_revoke(&token_id)
                        .context("capability-tokens revoke")?
                }
            };
            std::process::exit(exit);
        }
        Command::FilesystemBoundary { action } => {
            let exit = match action {
                FilesystemBoundaryAction::Doctrine => filesystem_boundary::run_doctrine()?,
                FilesystemBoundaryAction::Schema => filesystem_boundary::run_schema()?,
            };
            std::process::exit(exit);
        }
        Command::NetworkBoundary { action } => {
            let exit = match action {
                NetworkBoundaryAction::Profiles => network_boundary::run_profiles()?,
                NetworkBoundaryAction::Classify { bits } => network_boundary::run_classify(&bits)?,
            };
            std::process::exit(exit);
        }
        Command::SandboxTiers => {
            let exit = sandbox_tiers::run_tiers()?;
            std::process::exit(exit);
        }
        Command::CommunicationBoundary => {
            let exit = communication_boundary::run_schema()?;
            std::process::exit(exit);
        }
        Command::Authority => {
            let exit = authority::run_matrix()?;
            std::process::exit(exit);
        }
        Command::Policy { action } => {
            let exit = match action {
                PolicyAction::Clusters => policy::run_clusters()?,
                PolicyAction::Crates => policy::run_crates()?,
            };
            std::process::exit(exit);
        }
        Command::SshWrap { action } => {
            let exit = match action {
                SshWrapAction::Doctrine => ssh_wrap::run_doctrine()?,
                SshWrapAction::Install => ssh_wrap::run_install_help()?,
            };
            std::process::exit(exit);
        }
        Command::Nats => {
            let exit = nats::run_doctrine()?;
            std::process::exit(exit);
        }
        Command::FlexProfile { action } => {
            let exit = match action {
                FlexProfileAction::Schema => flex_profile::run_schema()?,
                FlexProfileAction::Show { json } => {
                    flex_profile::run_show(json).context("flex-profile show")?
                }
            };
            std::process::exit(exit);
        }
        Command::Grants { action } => {
            let exit = match action {
                GrantsAction::Show { json } => grants::run_show(json).context("grants show")?,
                GrantsAction::Issue {
                    kind,
                    scope,
                    reason,
                    profile,
                    actor,
                    ttl_seconds,
                    signature,
                    json,
                } => grants::run_issue(
                    &kind,
                    &scope,
                    &reason,
                    &profile,
                    &actor,
                    ttl_seconds,
                    &signature,
                    json,
                )
                .context("grants issue")?,
                GrantsAction::Revoke { grant_id } => {
                    grants::run_revoke(&grant_id).context("grants revoke")?
                }
            };
            std::process::exit(exit);
        }
        Command::Dashboards { json } => {
            let exit = dashboards::run(json).context("dashboards")?;
            std::process::exit(exit);
        }
        Command::DashboardPrefs { action, json } => {
            let exit = match action {
                Some(DashboardPrefsAction::Set { field, value }) => {
                    dashboard_prefs::run_set(&field, &value).context("dashboard-prefs set")?
                }
                Some(DashboardPrefsAction::Show) | None => {
                    dashboard_prefs::run_show(json).context("dashboard-prefs show")?
                }
            };
            std::process::exit(exit);
        }
        Command::InferenceBackends { action, json } => {
            let exit = match action {
                Some(InferenceBackendsAction::Version { backend }) => {
                    inference_backends::run_version(&backend)
                        .context("inference-backends version")?
                }
                Some(InferenceBackendsAction::Show) | None => {
                    inference_backends::run(json).context("inference-backends")?
                }
            };
            std::process::exit(exit);
        }
        Command::Guardian { action, json } => {
            let exit = match action {
                Some(GuardianAction::Show) | None => guardian::run_show(json)?,
                Some(GuardianAction::History { limit }) => guardian::run_history(limit, json)?,
                Some(GuardianAction::Replay { event_id }) => guardian::run_replay(&event_id, json)?,
                Some(GuardianAction::Rollback { event_id }) => {
                    guardian::run_rollback(&event_id, json)?
                }
            };
            std::process::exit(exit);
        }
        Command::FrictionAudit { action, json } => {
            let exit = match action {
                Some(FrictionAuditAction::Show) | None => friction_audit::run_show(json)?,
                Some(FrictionAuditAction::History { limit }) => {
                    friction_audit::run_history(limit, json)?
                }
                Some(FrictionAuditAction::Replay) => friction_audit::run_replay(json)?,
            };
            std::process::exit(exit);
        }
        Command::Status => {
            let store = SqliteStore::open(&cfg.store.hot_path).context("opening hot store")?;
            let count = store.count().await.context("counting events")?;
            println!("store:  {}", cfg.store.hot_path.display());
            println!("events: {count}");
        }
        Command::Events {
            action: EventsAction::Tail { n, json },
        } => {
            let store = SqliteStore::open(&cfg.store.hot_path).context("opening hot store")?;
            let events = store.recent(n).await.context("querying events")?;
            for event in events.iter().rev() {
                if json {
                    println!("{}", serde_json::to_string(event)?);
                } else {
                    print_event_human(event);
                }
            }
        }
        Command::Events {
            action:
                EventsAction::Follow {
                    unix_socket,
                    url,
                    token_file,
                    alerts_only,
                    n,
                },
        } => match url {
            Some(base_url) => {
                // F-2027-010: TCP/HTTP(S) transport. Token comes
                // from `--token-file`; the file's contents flow
                // straight into the `Authorization: Bearer ...`
                // header.
                let token = match token_file {
                    Some(path) => Some(follow::read_token_file(&path)?),
                    None => None,
                };
                follow::events_follow_tcp(&base_url, token.as_deref(), alerts_only, n).await?;
            }
            None => {
                follow::events_follow_unix(&unix_socket, alerts_only, n).await?;
            }
        },
        Command::Events {
            action:
                EventsAction::Emit {
                    class_uid,
                    activity_id,
                    severity,
                    source,
                    message,
                    host_tag,
                    out,
                },
        } => {
            emit::emit_event(emit::EmitArgs {
                class_uid,
                activity_id,
                severity: &severity,
                source: &source,
                message: message.as_deref(),
                host_tag: host_tag.as_deref(),
                out: &out,
            })?;
        }
        Command::Events {
            action: EventsAction::Alerts { n, json },
        } => {
            let store = SqliteStore::open(&cfg.store.hot_path).context("opening hot store")?;
            let events = store
                .recent_findings(n)
                .await
                .context("querying findings")?;
            if events.is_empty() {
                println!("(no findings yet)");
            }
            for event in events.iter().rev() {
                if json {
                    println!("{}", serde_json::to_string(event)?);
                } else {
                    print_event_human(event);
                }
            }
        }
        Command::Reload => {
            // Find selfdefd by reading /run/selfdefd.pid (a future addition);
            // for now, advise the user.
            eprintln!("selfdefctl: to reload rules, send SIGHUP to selfdefd:");
            eprintln!("           sudo systemctl reload selfdefd");
            eprintln!("           # or: sudo kill -HUP $(pidof selfdefd)");
            std::process::exit(2);
        }
        Command::Rules { action } => match action {
            RulesAction::List => {
                let engine = selfdef_correlator::Engine::load_dir(&cfg.correlator.rules_dir)
                    .context("loading rules directory")?;
                if engine.rule_count() == 0 {
                    println!("(no rules in {})", cfg.correlator.rules_dir.display());
                }
                for r in engine.rules() {
                    println!(
                        "{:<40}  {:<10}  {}",
                        r.id,
                        format!("{:?}", r.level).to_lowercase(),
                        r.title
                    );
                }
            }
            RulesAction::Validate { path } => {
                let engine = selfdef_correlator::Engine::load_dir(&path)
                    .with_context(|| format!("loading rules from {}", path.display()))?;
                println!("OK: {} rules", engine.rule_count());
                for r in engine.rules() {
                    println!("  - {} ({})", r.id, r.title);
                }
            }
            RulesAction::Test { corpus } => {
                let engine = selfdef_correlator::Engine::load_dir(&cfg.correlator.rules_dir)
                    .context("loading rules")?;
                let content = std::fs::read_to_string(&corpus)
                    .with_context(|| format!("reading corpus {}", corpus.display()))?;
                let seq = std::sync::atomic::AtomicU64::new(0);
                let mut total = 0;
                let mut fired = 0;
                for line in content.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let event: selfdef_core::Event =
                        serde_json::from_str(line).context("parsing corpus event")?;
                    total += 1;
                    let findings = engine.process(&event, "replay", &seq);
                    fired += findings.len();
                }
                println!("Processed {total} events; rules fired {fired} times.");
            }
            RulesAction::Lint => {
                let engine = selfdef_correlator::Engine::load_dir(&cfg.correlator.rules_dir)
                    .context("loading rules")?;
                let issues = selfdef_correlator::lint::lint_rules(engine.rules());
                let mut errors = 0;
                let mut warns = 0;
                for issue in &issues {
                    match issue.severity {
                        selfdef_correlator::lint::Severity::Error => errors += 1,
                        selfdef_correlator::lint::Severity::Warn => warns += 1,
                    }
                    println!("{issue}");
                }
                println!();
                println!(
                    "{} rule(s), {} error(s), {} warning(s)",
                    engine.rule_count(),
                    errors,
                    warns
                );
                if errors > 0 {
                    std::process::exit(1);
                }
            }
            RulesAction::Coverage => {
                let engine = selfdef_correlator::Engine::load_dir(&cfg.correlator.rules_dir)
                    .context("loading rules")?;
                let coverage = engine.attack_coverage();
                println!("ATT&CK coverage across {} rules:", engine.rule_count());
                println!("  techniques: {}", coverage.techniques.len());
                println!("  tactics:    {}", coverage.tactics.len());
                if !coverage.rules_per_tactic.is_empty() {
                    println!();
                    println!("  By tactic:");
                    for (tactic, count) in &coverage.rules_per_tactic {
                        println!("    {tactic:>22?}  {count}");
                    }
                }
                if !coverage.techniques.is_empty() {
                    println!();
                    println!("  Techniques:");
                    for t in &coverage.techniques {
                        println!("    {t}");
                    }
                }
            }
        },
        Command::Forensics { action } => match action {
            ForensicsAction::List => {
                let dir = &cfg.responder.forensics_dir;
                if !dir.exists() {
                    println!("(no bundles — {} does not exist)", dir.display());
                } else {
                    let mut entries: Vec<_> = std::fs::read_dir(dir)
                        .with_context(|| format!("reading {}", dir.display()))?
                        .filter_map(Result::ok)
                        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                        .collect();
                    entries.sort_by_key(std::fs::DirEntry::file_name);
                    if entries.is_empty() {
                        println!("(no bundles in {})", dir.display());
                    }
                    for entry in entries {
                        let name = entry.file_name();
                        let path = entry.path();
                        let size = dir_size_bytes(&path).unwrap_or(0);
                        println!(
                            "{:<40}  {:>10} bytes  {}",
                            name.to_string_lossy(),
                            size,
                            path.display()
                        );
                    }
                }
            }
            ForensicsAction::Collect { event_id } => {
                use selfdef_responder::actions::{Action, ForensicsBundleAction};
                let id = uuid::Uuid::parse_str(&event_id)
                    .with_context(|| format!("not a valid event id: {event_id}"))?;
                let store = SqliteStore::open(&cfg.store.hot_path).context("opening hot store")?;
                let event = store
                    .get(id)
                    .await
                    .context("looking up event")?
                    .with_context(|| format!("no event with id {event_id} in store"))?;
                let action = ForensicsBundleAction::new(cfg.responder.forensics_dir.clone());
                let outcome = action.execute(&event, /* dry_run */ false).await?;
                println!("{}", outcome.notes);
            }
        },
        Command::Models { action } => match action {
            ModelsAction::List { dir } => {
                let code = models::cmd_list(dir.as_deref())?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModelsAction::CheckHardware { dir, json } => {
                let code = models::cmd_check_hardware(dir.as_deref(), json)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModelsAction::Fetch {
                slug,
                to,
                dir,
                token_env,
            } => {
                let code =
                    models::cmd_fetch(dir.as_deref(), &slug, &to, token_env.as_deref()).await?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModelsAction::Lora { action } => match action {
                LoraAction::List { state, json } => {
                    let code = models::cmd_lora_list(state.as_deref(), json)?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
                LoraAction::Attach {
                    adapter_id,
                    base_model,
                    status,
                    state,
                    json,
                } => {
                    let code = models::cmd_lora_attach(
                        state.as_deref(),
                        &adapter_id,
                        &base_model,
                        status.as_deref(),
                        json,
                    )?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
                LoraAction::Detach {
                    adapter_id,
                    state,
                    json,
                } => {
                    let code = models::cmd_lora_detach(state.as_deref(), &adapter_id, json)?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
                LoraAction::SetStatus {
                    adapter_id,
                    status,
                    state,
                    json,
                } => {
                    let code =
                        models::cmd_lora_set_status(state.as_deref(), &adapter_id, &status, json)?;
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
            },
        },
        Command::Modules { action } => match action {
            ModulesAction::List {
                dir,
                json,
                category,
                phase,
            } => {
                let resolved = modules::resolve_dir(dir.as_deref());
                if json {
                    modules::cmd_list_json_filtered(
                        &resolved,
                        category.as_deref(),
                        phase.as_deref(),
                    )?;
                } else {
                    modules::cmd_list_filtered(&resolved, category.as_deref(), phase.as_deref())?;
                }
            }
            ModulesAction::Features {
                slug,
                dir,
                overlay,
                enabled_only,
                disabled_only,
            } => {
                let resolved = modules::resolve_dir(dir.as_deref());
                let filter = match (enabled_only, disabled_only) {
                    (true, false) => modules::FeatureFilter::EnabledOnly,
                    (false, true) => modules::FeatureFilter::DisabledOnly,
                    _ => modules::FeatureFilter::All,
                };
                let rc = modules::cmd_features_json_filtered(
                    &resolved,
                    &slug,
                    overlay.as_deref(),
                    filter,
                )?;
                std::process::exit(rc);
            }
            ModulesAction::FeatureSet {
                slug,
                key,
                value,
                dir,
                overlay,
            } => {
                let resolved = modules::resolve_dir(dir.as_deref());
                let rc =
                    modules::cmd_feature_set(&resolved, &slug, &key, &value, overlay.as_deref())?;
                std::process::exit(rc);
            }
            ModulesAction::FeatureClear {
                slug,
                key,
                dir,
                overlay,
            } => {
                let resolved = modules::resolve_dir(dir.as_deref());
                let rc = modules::cmd_feature_clear(&resolved, &slug, &key, overlay.as_deref())?;
                std::process::exit(rc);
            }
            ModulesAction::Info {
                slug,
                dir,
                with_host_status,
                json,
                resolved: resolved_flag,
            } => {
                let resolved = modules::resolve_dir(dir.as_deref());
                if json {
                    // SD-R40: --json implies host_status (the field
                    // is cheap to compute + tooling almost always
                    // wants both).
                    modules::cmd_info_json(&resolved, &slug)?;
                } else {
                    modules::cmd_info(&resolved, &slug)?;
                    if with_host_status || resolved_flag {
                        modules::cmd_info_host_status(&resolved, &slug)?;
                    }
                    if resolved_flag {
                        // SD-R80 (SDD-025 Y-4) — render the resolved
                        // requirement set (root + matched any_of branch).
                        modules::cmd_info_resolved(&resolved, &slug)?;
                    }
                }
            }
            ModulesAction::Apply {
                host_config,
                dir,
                dry_run,
                only,
                except,
                ignore_daemon_requires,
                ignore_hardware,
                strict_hardware,
                reprobe_hardware,
            } => {
                let opts = modules::LifecycleOpts {
                    host_config,
                    dir,
                    only,
                    except,
                    dry_run,
                    ignore_daemon_requires,
                    ignore_hardware,
                    strict_hardware,
                    reprobe_hardware,
                    daemon_config_path: Some(daemon_config_path.clone()),
                };
                let code = modules::cmd_apply(&opts)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::Check {
                host_config,
                dir,
                only,
                except,
                ignore_daemon_requires,
            } => {
                let opts = modules::LifecycleOpts {
                    host_config,
                    dir,
                    only,
                    except,
                    dry_run: false,
                    ignore_daemon_requires,
                    ignore_hardware: false,
                    strict_hardware: false,
                    reprobe_hardware: false,
                    daemon_config_path: Some(daemon_config_path.clone()),
                };
                let code = modules::cmd_check(&opts)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::Status {
                host_config,
                dir,
                json,
            } => {
                let opts = modules::LifecycleOpts {
                    host_config,
                    dir,
                    only: Vec::new(),
                    except: Vec::new(),
                    dry_run: false,
                    ..Default::default()
                };
                let code = if json {
                    modules::cmd_status_json(&opts)?
                } else {
                    modules::cmd_status(&opts)?
                };
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::Diff {
                host_config,
                dir,
                json,
            } => {
                let host_path = modules::resolve_host_config_path(host_config.as_deref());
                let dir_path = modules::resolve_dir(dir.as_deref());
                let code = modules::cmd_diff(&host_path, &dir_path, json)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::InstallOptions {
                host_config,
                dir,
                category,
                only_ready,
                json,
            } => {
                let host_path = modules::resolve_host_config_path(host_config.as_deref());
                let dir_path = modules::resolve_dir(dir.as_deref());
                let code = modules::cmd_install_options(
                    &host_path,
                    &dir_path,
                    json,
                    category.as_deref(),
                    only_ready,
                )?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::InstallPlan {
                host_config,
                dir,
                category,
                json,
            } => {
                let host_path = modules::resolve_host_config_path(host_config.as_deref());
                let dir_path = modules::resolve_dir(dir.as_deref());
                let code =
                    modules::cmd_install_plan(&host_path, &dir_path, json, category.as_deref())?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::ConfigScaffold {
                slug,
                dir,
                instance,
                json,
            } => {
                let dir_path = modules::resolve_dir(dir.as_deref());
                let code =
                    modules::cmd_config_scaffold(&dir_path, &slug, instance.as_deref(), json)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::ApplyPlan {
                host_config,
                dir,
                category,
                apply,
                continue_on_failure,
                json,
            } => {
                let host_path = modules::resolve_host_config_path(host_config.as_deref());
                let dir_path = modules::resolve_dir(dir.as_deref());
                let code = modules::cmd_apply_plan(
                    &host_path,
                    &dir_path,
                    category.as_deref(),
                    apply,
                    continue_on_failure,
                    json,
                )?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::ShowRequires { host_config, dir } => {
                let opts = modules::LifecycleOpts {
                    host_config,
                    dir,
                    ..Default::default()
                };
                let code = modules::cmd_show_requires(&opts)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::CheckHardware {
                host_config,
                dir,
                json,
                caps,
            } => {
                let opts = modules::LifecycleOpts {
                    host_config,
                    dir,
                    ..Default::default()
                };
                let code = modules::cmd_check_hardware_with_caps(&opts, json, caps.as_deref())?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::Graph {
                host_config,
                dir,
                with_hardware_gate,
                json,
            } => {
                let opts = modules::LifecycleOpts {
                    host_config,
                    dir,
                    ..Default::default()
                };
                let code = if json {
                    modules::cmd_graph_json(&opts, with_hardware_gate)?
                } else {
                    modules::cmd_graph(&opts, with_hardware_gate)?
                };
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::AuditLog {
                audit_path,
                n,
                json,
            } => {
                let resolved = audit_path
                    .or_else(|| {
                        std::env::var("SELFDEF_MODULES_AUDIT_PATH")
                            .ok()
                            .map(PathBuf::from)
                    })
                    .unwrap_or_else(|| PathBuf::from("/var/log/selfdef/modules-audit.jsonl"));
                let code = modules::cmd_audit_log(&resolved, n, json)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
            ModulesAction::Uninstall {
                host_config,
                dir,
                dry_run,
                only,
                except,
                confirm,
            } => {
                if !dry_run
                    && let Err(refusal) =
                        check_confirm_hostname("uninstall modules", confirm.as_deref())
                {
                    refusal.print();
                    if matches!(refusal, ConfirmRefusal::Missing { .. }) {
                        eprintln!("(or pass --dry-run to preview)");
                    }
                    std::process::exit(2);
                }
                let opts = modules::LifecycleOpts {
                    host_config,
                    dir,
                    only,
                    except,
                    dry_run,
                    ..Default::default()
                };
                let code = modules::cmd_uninstall(&opts)?;
                if code != 0 {
                    std::process::exit(code);
                }
            }
        },
        Command::Panic { confirm } => {
            let actual_host = match check_confirm_hostname("engage panic mode", confirm.as_deref())
            {
                Ok(host) => host,
                Err(refusal) => {
                    refusal.print();
                    std::process::exit(2);
                }
            };

            use selfdef_responder::actions::{Action, LockdownEgressAction, NotifyAction};
            use std::sync::Arc;

            let event = selfdef_core::Event::new(
                selfdef_core::category::ClassUid::DETECTION_FINDING,
                1,
                selfdef_core::severity::SeverityId::Critical,
                &actual_host,
                "selfdef.panic",
                0,
            )
            .with_message("PANIC: manual lockdown requested via selfdefctl");

            // Build a notifier chain from config.
            let mut chain: Vec<Box<dyn selfdef_notifier::Notifier>> = Vec::new();
            for ch in &cfg.notifier.channels {
                if ch == "ntfy"
                    && !cfg.notifier.ntfy.url.is_empty()
                    && !cfg.notifier.ntfy.topic.is_empty()
                {
                    chain.push(Box::new(
                        selfdef_integration_ntfy::NtfyNotifier::from_config(
                            &cfg.notifier.ntfy.url,
                            &cfg.notifier.ntfy.topic,
                            cfg.notifier.ntfy.token_file.as_ref(),
                        ),
                    ));
                }
            }
            let notifier: Arc<dyn selfdef_notifier::Notifier> =
                Arc::new(selfdef_notifier::NotifierChain::new(chain));

            let actions: Vec<Arc<dyn Action>> = vec![
                Arc::new(NotifyAction::new(notifier)),
                Arc::new(LockdownEgressAction::new(
                    cfg.responder.lockdown_script.clone(),
                )),
            ];
            let responder = selfdef_responder::Responder::new(
                actions,
                vec!["notify".into(), "lockdown_egress".into()],
                cfg.responder.dry_run,
            );

            eprintln!(
                "Engaging panic mode (dry_run={}). Notifying and invoking lockdown script.",
                cfg.responder.dry_run
            );
            responder.fire(&event).await;
            eprintln!("Panic dispatch complete.");
        }
    }
    Ok(())
}

fn dir_size_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        } else if ft.is_dir() {
            total = total.saturating_add(dir_size_bytes(&entry.path()).unwrap_or(0));
        }
    }
    Ok(total)
}

fn print_event_human(e: &Event) {
    let time = e
        .time_dt
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    println!(
        "{time}  [{:>8}] {:<24} {:<14} {} {}",
        e.severity_id,
        e.class_uid.name(),
        e.source,
        e.host_tag,
        e.message.as_deref().unwrap_or(""),
    );
}

/// Outcome of a destructive-op hostname confirmation check. Used by
/// `panic` and `modules uninstall` to gate their respective dangerous
/// paths. Closes F-2026-059 — the two sites duplicated this logic
/// before; this helper is the single source of truth.
fn check_confirm_hostname(op_label: &str, confirm: Option<&str>) -> Result<String, ConfirmRefusal> {
    let actual_host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default();
    let provided = confirm.unwrap_or("").trim();
    if provided.is_empty() {
        return Err(ConfirmRefusal::Missing {
            op_label: op_label.to_string(),
        });
    }
    if provided != actual_host {
        return Err(ConfirmRefusal::Mismatch {
            provided: provided.to_string(),
            actual_host,
        });
    }
    Ok(actual_host)
}

enum ConfirmRefusal {
    Missing {
        op_label: String,
    },
    Mismatch {
        provided: String,
        actual_host: String,
    },
}

impl ConfirmRefusal {
    fn print(&self) {
        match self {
            Self::Missing { op_label } => {
                eprintln!("Refusing to {op_label} without --confirm <hostname>.");
                eprintln!("Provide --confirm with this host's name to proceed.");
            }
            Self::Mismatch {
                provided,
                actual_host,
            } => {
                eprintln!("Confirm mismatch: provided '{provided}', host is '{actual_host}'.");
            }
        }
    }
}

/// SDD-004 F-2026-023 follow-up: rotate the API bearer token.
/// Writes a fresh high-entropy token to the configured token
/// file atomically (write tempfile → fsync → rename → chmod
/// 0600), then optionally signals the daemon (SIGUSR2) to
/// re-read it.
fn api_rotate_token(
    cfg: &selfdef_config::Config,
    override_path: Option<PathBuf>,
    bytes: usize,
    pid: Option<String>,
    print: bool,
) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    if bytes == 0 || bytes > 256 {
        anyhow::bail!("--bytes must be in 1..=256 (got {bytes})");
    }

    let target = match override_path {
        Some(p) => p,
        None => PathBuf::from(cfg.api.token_file.as_str()),
    };
    if target.as_os_str().is_empty() {
        anyhow::bail!(
            "no token file configured: pass --token-file or set [api].token_file in selfdef.toml"
        );
    }

    // High-entropy token via /dev/urandom + base64-url (no
    // padding). Avoids pulling a `getrandom` workspace dep just
    // for this CLI verb; /dev/urandom is always seeded on
    // long-running Linux systems where the daemon runs.
    let mut buf = vec![0u8; bytes];
    {
        use std::io::Read as _;
        let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
        f.read_exact(&mut buf).context("reading /dev/urandom")?;
    }
    let token = base64_urlsafe(&buf);

    // Atomic write: tempfile in the same directory → fsync → rename → chmod.
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent).with_context(|| format!("creating {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.rotate.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("api.token")
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("opening tempfile {}", tmp.display()))?;
        f.write_all(token.as_bytes())
            .with_context(|| format!("writing tempfile {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync tempfile {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &target)
        .with_context(|| format!("rename {} → {}", tmp.display(), target.display(),))?;
    // Re-assert the mode in case the rename inherited umask
    // permissions on some filesystems.
    let mut perms = std::fs::metadata(&target)
        .with_context(|| format!("stat {}", target.display()))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&target, perms)
        .with_context(|| format!("chmod 0600 {}", target.display()))?;

    println!(
        "wrote {} ({} bytes, mode 0600)",
        target.display(),
        token.len()
    );
    if print {
        println!("{token}");
    }

    if let Some(pid_arg) = pid {
        let pid_num: i32 = if pid_arg == "auto" {
            discover_daemon_pid().context("--pid auto: discovering selfdefd via systemctl")?
        } else {
            pid_arg
                .parse()
                .context("--pid: expected an integer or `auto`")?
        };
        signal_sigusr2(pid_num).with_context(|| format!("sending SIGUSR2 to pid {pid_num}"))?;
        println!("sent SIGUSR2 to pid {pid_num} (daemon will reload tokens)");
    } else {
        println!("next step: run `systemctl kill --signal=SIGUSR2 selfdefd` (or pass --pid <pid>)",);
    }
    Ok(())
}

/// Discover the running selfdefd pid via `systemctl show -p MainPID
/// selfdefd.service`. Returns the parsed pid or an error if systemctl
/// isn't available or the unit isn't running.
fn discover_daemon_pid() -> Result<i32> {
    // F-2027-004: detect missing systemctl up front so the
    // error message is operator-actionable rather than a raw
    // "exited 127". Containerised dev, restricted distros, and
    // BSD compat layers all hit this.
    let out = match std::process::Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", "selfdefd.service"])
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "no `systemctl` on PATH — `--pid auto` can't discover the daemon. \
                 Pass `--pid <pid>` directly (find it with e.g. `pgrep selfdefd`)"
            );
        }
        Err(e) => return Err(e).context("spawn systemctl"),
    };
    if !out.status.success() {
        anyhow::bail!(
            "systemctl exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let pid: i32 = trimmed
        .parse()
        .with_context(|| format!("parsing MainPID '{trimmed}'"))?;
    if pid <= 0 {
        anyhow::bail!("selfdefd.service has no running MainPID (got {pid})");
    }
    Ok(pid)
}

/// Send SIGUSR2 to a pid. Uses /bin/kill (avoiding an unsafe libc
/// call to stay within the workspace's `unsafe_code = "forbid"`
/// lint).
fn signal_sigusr2(pid: i32) -> Result<()> {
    let out = std::process::Command::new("kill")
        .args(["-s", "USR2", &pid.to_string()])
        .output()
        .context("spawn kill")?;
    if !out.status.success() {
        anyhow::bail!(
            "kill exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Base64 URL-safe, no padding. Hand-rolled to avoid a base64
/// dependency for ~30 lines of CLI code.
fn base64_urlsafe(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(A[((b >> 18) & 0x3f) as usize] as char);
        out.push(A[((b >> 12) & 0x3f) as usize] as char);
        out.push(A[((b >> 6) & 0x3f) as usize] as char);
        out.push(A[(b & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b = u32::from(bytes[i]) << 16;
        out.push(A[((b >> 18) & 0x3f) as usize] as char);
        out.push(A[((b >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let b = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
        out.push(A[((b >> 18) & 0x3f) as usize] as char);
        out.push(A[((b >> 12) & 0x3f) as usize] as char);
        out.push(A[((b >> 6) & 0x3f) as usize] as char);
    }
    out
}

/// SDD-004 F-2026-025 follow-up: print the recommended k8s RBAC
/// posture for `agent-guard`'s `scope = "pod-label"`, optionally
/// probing the live cluster via `kubectl auth can-i`.
fn rbac_check(
    module_config_override: Option<PathBuf>,
    probe: bool,
    extra_subjects: &[String],
    namespace: Option<&str>,
    warn_only: bool,
) -> Result<()> {
    let module_cfg_path = module_config_override
        .unwrap_or_else(|| PathBuf::from("/etc/selfdef/modules/agent-guard.toml"));
    let module_cfg = std::fs::read_to_string(&module_cfg_path).with_context(|| {
        format!(
            "reading agent-guard module config from {}",
            module_cfg_path.display()
        )
    })?;
    let (scope, label_key, label_value) = parse_agent_guard_scope(&module_cfg);

    println!("# Agent-guard RBAC posture check");
    println!("# Module config: {}", module_cfg_path.display());
    println!();

    if scope != "pod-label" {
        println!(
            "rbac check not applicable: agent-guard scope = \"{scope}\". Pod-label \
             RBAC is only meaningful when scope = \"pod-label\"."
        );
        return Ok(());
    }

    println!("Configured boundary: pods carrying `{label_key}={label_value}`");
    println!();
    println!("Recommended posture:");
    println!("  - Only cluster-admin and any documented narrow ServiceAccount");
    println!("    may PATCH pod labels in namespaces where agent-guard runs.");
    println!("  - Specifically, none of these subjects should be granted");
    println!("    `patch` on `pods` (full or labels sub-resource):");
    println!("      • system:authenticated  (any cred-bearing principal)");
    println!("      • system:unauthenticated  (anonymous)");
    println!("      • system:masters  (kubeadm bootstrap superuser group)");
    println!("      • system:serviceaccount:default:default  (default-ns default SA)");
    println!();
    println!("Manual verification commands:");
    // F-2027-007: expanded built-in set. Beyond the two
    // public groups (authenticated / anonymous), include the
    // two common-mistake bindings auditors hit in the wild:
    //   • system:masters — the kubeadm bootstrap superuser
    //     group; clusters that grant this to humans (vs only
    //     the bootstrap admin.conf) bypass every cluster RBAC
    //     check by design.
    //   • system:serviceaccount:default:default — the default
    //     ServiceAccount in the default namespace; pods that
    //     forget to set serviceAccountName run as this and
    //     any RoleBinding on it leaks to every "I forgot to
    //     set it" pod in the cluster.
    let probe_subjects: Vec<String> = [
        "system:authenticated".to_string(),
        "system:unauthenticated".to_string(),
        "system:masters".to_string(),
        "system:serviceaccount:default:default".to_string(),
    ]
    .into_iter()
    .chain(extra_subjects.iter().cloned())
    .collect();
    // F-2027-060: validate every probe subject up front. The
    // built-in defaults are static strings under our control,
    // but `extra_subjects` come from operator-supplied `--as`
    // flags and could carry shell metacharacters or ANSI escapes
    // that would corrupt the daemon's logs + the operator's
    // terminal when we echo the subject back through error
    // paths. No shell-injection vector (we use `Command::new`,
    // not the shell) — this is a log-pollution mitigation.
    for subj in &probe_subjects {
        validate_rbac_subject(subj).with_context(|| {
            format!(
                "refusing to probe an unsafe subject (length {} bytes)",
                subj.len(),
            )
        })?;
    }
    let ns_arg: Vec<&str> = match namespace {
        Some(ns) => vec!["-n", ns],
        None => vec![],
    };
    for subj in &probe_subjects {
        let mut cmd_line = vec![
            "kubectl",
            "auth",
            "can-i",
            "patch",
            "pods",
            "--subresource=labels",
            "--as",
            subj.as_str(),
        ];
        cmd_line.extend(ns_arg.iter().copied());
        println!("  $ {}", cmd_line.join(" "));
    }

    if !probe {
        println!();
        println!("Skipping live probe (pass --probe to run the kubectl commands).");
        return Ok(());
    }

    println!();
    println!("Live probe:");
    let mut overly_permissive: Vec<String> = Vec::new();
    for subj in &probe_subjects {
        match rbac_probe_subject(subj, namespace)? {
            ProbeOutcome::Cannot => println!("  ok:     {subj} — kubectl reports CANNOT"),
            ProbeOutcome::Can => {
                println!("  WARN:   {subj} — kubectl reports CAN (overly permissive)");
                overly_permissive.push(subj.clone());
            }
            ProbeOutcome::KubectlMissing => {
                anyhow::bail!("--probe: `kubectl` is not on PATH");
            }
            ProbeOutcome::Other(stderr) => {
                println!("  skip:   {subj} — kubectl error: {}", stderr.trim());
            }
        }
    }
    println!();
    if overly_permissive.is_empty() {
        println!(
            "ok: no probed subject can patch pod labels — RBAC posture matches \
             agent-guard's pod-label scope assumption."
        );
        Ok(())
    } else {
        println!(
            "warn: {} subject(s) can patch pod labels: {}",
            overly_permissive.len(),
            overly_permissive.join(", "),
        );
        if warn_only {
            Ok(())
        } else {
            anyhow::bail!(
                "overly-permissive RBAC posture for agent-guard pod-label scope; \
                 fix or pass --warn-only to suppress"
            );
        }
    }
}

/// SDD-013: clap value-parser for `--target`. Routes through
/// [`DeploymentTarget::from_str`] so the CLI rejects unknown values
/// fail-loud, matching the config-loader contract (no silent
/// fallback, no case-insensitive variants).
fn parse_deployment_target(s: &str) -> Result<selfdef_config::DeploymentTarget, String> {
    use std::str::FromStr;
    selfdef_config::DeploymentTarget::from_str(s)
}

/// Parse the agent-guard module config TOML for `scope`,
/// `pod_label_key`, and `pod_label_value`. Hand-rolled to avoid
/// a toml-crate dependency hop just for three string scalars.
/// Returns `("container", "", "")` defaults when keys are
/// missing.
fn parse_agent_guard_scope(body: &str) -> (String, String, String) {
    let mut scope = String::from("container");
    let mut key = String::new();
    let mut value = String::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("scope") {
            if let Some(v) = extract_toml_scalar(rest) {
                scope = v;
            }
        } else if let Some(rest) = line.strip_prefix("pod_label_key") {
            if let Some(v) = extract_toml_scalar(rest) {
                key = v;
            }
        } else if let Some(rest) = line.strip_prefix("pod_label_value") {
            if let Some(v) = extract_toml_scalar(rest) {
                value = v;
            }
        }
    }
    (scope, key, value)
}

/// Extract a quoted-string scalar from a TOML `= "value"` tail.
/// Returns None for any line shape this helper doesn't
/// understand (the caller falls back to defaults).
fn extract_toml_scalar(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

enum ProbeOutcome {
    Cannot,
    Can,
    KubectlMissing,
    Other(String),
}

fn rbac_probe_subject(subject: &str, namespace: Option<&str>) -> Result<ProbeOutcome> {
    let mut cmd = std::process::Command::new("kubectl");
    cmd.args([
        "auth",
        "can-i",
        "patch",
        "pods",
        "--subresource=labels",
        "--as",
        subject,
    ]);
    if let Some(ns) = namespace {
        cmd.args(["-n", ns]);
    }
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProbeOutcome::KubectlMissing);
        }
        Err(e) => return Err(e).context("spawn kubectl"),
    };
    // `kubectl auth can-i` semantics: exit 0 + "yes" on stdout
    // means CAN; exit non-zero + "no" means CANNOT; anything
    // else is an error condition we surface to the operator.
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    match (out.status.success(), stdout.as_str()) {
        (true, "yes") => Ok(ProbeOutcome::Can),
        (false, "no") => Ok(ProbeOutcome::Cannot),
        _ => Ok(ProbeOutcome::Other(stderr)),
    }
}

/// F-2027-060: defense-in-depth validator for `--as <subject>`.
/// Subject strings flow to `kubectl` via `Command::new(...).args(...)`
/// (no shell, so no injection vector) and into the daemon's
/// own logs and stdout when the probe summarises results. An
/// operator passing an ANSI-escape-laden or otherwise malformed
/// string would corrupt those logs / terminals; this validator
/// rejects anything outside the safe Kubernetes-identifier
/// charset (`A-Z a-z 0-9 : . _ / @ -`) plus the 1..=253 char
/// length window k8s already enforces on subject names.
///
/// Returns `Ok(())` on a valid subject, an `anyhow::Error` whose
/// message names the offending byte (not the whole string — that
/// would re-introduce the very log-pollution this guards against).
fn validate_rbac_subject(subject: &str) -> Result<()> {
    if subject.is_empty() {
        anyhow::bail!("--as: subject is empty");
    }
    if subject.len() > 253 {
        anyhow::bail!(
            "--as: subject is {} bytes; Kubernetes caps subject names at 253",
            subject.len(),
        );
    }
    for (i, b) in subject.bytes().enumerate() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'/' | b'@' | b'-');
        if !ok {
            anyhow::bail!(
                "--as: subject contains disallowed byte 0x{b:02x} at position {i}; \
                 allowed charset is [A-Za-z0-9:._/@-]",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod rbac_subject_tests {
    use super::validate_rbac_subject;

    #[test]
    fn accepts_default_built_in_subjects() {
        validate_rbac_subject("system:authenticated").unwrap();
        validate_rbac_subject("system:unauthenticated").unwrap();
        validate_rbac_subject("system:masters").unwrap();
    }

    #[test]
    fn accepts_serviceaccount_form() {
        validate_rbac_subject("system:serviceaccount:kube-system:default").unwrap();
        validate_rbac_subject("alice@example.com").unwrap();
        validate_rbac_subject("group/team_a.v1-rc").unwrap();
    }

    #[test]
    fn rejects_empty() {
        let err = validate_rbac_subject("").unwrap_err().to_string();
        assert!(err.contains("subject is empty"), "got: {err}");
    }

    #[test]
    fn rejects_shell_metacharacters() {
        let err = validate_rbac_subject("system:masters$(whoami)")
            .unwrap_err()
            .to_string();
        assert!(err.contains("disallowed byte 0x24"), "got: {err}");
    }

    #[test]
    fn rejects_ansi_escape() {
        let err = validate_rbac_subject("alice\x1b[31m")
            .unwrap_err()
            .to_string();
        assert!(err.contains("0x1b"), "got: {err}");
    }

    #[test]
    fn rejects_whitespace() {
        let err = validate_rbac_subject("alice bob").unwrap_err().to_string();
        assert!(err.contains("0x20"), "got: {err}");
    }

    #[test]
    fn rejects_over_length() {
        let s = "a".repeat(254);
        let err = validate_rbac_subject(&s).unwrap_err().to_string();
        assert!(err.contains("254 bytes"), "got: {err}");
    }
}

/// SDD-004 rule-signing follow-up: verify a detached minisign
/// signature for a target file. Wraps `selfdef_signing::Verifier`
/// with operator-friendly error messages.
fn keys_verify(
    cfg: &selfdef_config::Config,
    target: &std::path::Path,
    override_pubkey: Option<PathBuf>,
) -> Result<()> {
    let pubkey = match override_pubkey {
        Some(p) => p,
        None => cfg.security.signing_public_key_file.clone().context(
            "no public key configured: pass --public-key or set \
                 [security].signing_public_key_file in selfdef.toml",
        )?,
    };
    let verifier = selfdef_signing::Verifier::load(&pubkey)
        .with_context(|| format!("loading public key from {}", pubkey.display()))?;
    verifier.verify_detached_file(target).with_context(|| {
        format!(
            "verifying {} against {}",
            target.display(),
            pubkey.display(),
        )
    })?;
    println!(
        "ok: {} verifies against {}",
        target.display(),
        pubkey.display(),
    );
    Ok(())
}

/// F-2027-006 follow-up: batch-verify every `.yml`/`.yaml` file
/// in `dir` against one public key in a single process. Used
/// by `modules/tetragon/install/apply.sh` instead of spawning
/// `selfdefctl keys verify` per policy file.
///
/// Walks `dir` non-recursively (matches the tetragon
/// `policy_dir` shape — operators drop policy YAMLs flat).
/// Exits 0 iff every file's `.minisig` verifies; prints one
/// line per file as `ok: <path>` or `fail: <path>: <reason>`,
/// then a summary line.
fn keys_verify_dir(
    cfg: &selfdef_config::Config,
    dir: &std::path::Path,
    override_pubkey: Option<PathBuf>,
) -> Result<()> {
    let pubkey = match override_pubkey {
        Some(p) => p,
        None => cfg.security.signing_public_key_file.clone().context(
            "no public key configured: pass --public-key or set \
                 [security].signing_public_key_file in selfdef.toml",
        )?,
    };
    let verifier = selfdef_signing::Verifier::load(&pubkey)
        .with_context(|| format!("loading public key from {}", pubkey.display()))?;
    if !dir.is_dir() {
        anyhow::bail!("not a directory: {}", dir.display());
    }
    let mut total = 0usize;
    let mut failed = 0usize;
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    // Sort for stable output across runs.
    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|e| e == "yml" || e == "yaml")
        })
        .collect();
    paths.sort();
    for path in &paths {
        total += 1;
        match verifier.verify_detached_file(path) {
            Ok(()) => println!("ok:   {}", path.display()),
            Err(e) => {
                failed += 1;
                println!("fail: {}: {e}", path.display());
            }
        }
    }
    println!(
        "summary: {total} file(s), {} ok, {failed} fail (key: {})",
        total - failed,
        pubkey.display(),
    );
    if failed > 0 {
        anyhow::bail!("{failed} of {total} file(s) failed verification");
    }
    Ok(())
}

#[cfg(test)]
mod rotate_tests {
    use super::base64_urlsafe;

    #[test]
    fn base64_urlsafe_matches_known_vectors() {
        // Standard RFC 4648 §5 vectors, padding stripped.
        assert_eq!(base64_urlsafe(b""), "");
        assert_eq!(base64_urlsafe(b"f"), "Zg");
        assert_eq!(base64_urlsafe(b"fo"), "Zm8");
        assert_eq!(base64_urlsafe(b"foo"), "Zm9v");
        assert_eq!(base64_urlsafe(b"foob"), "Zm9vYg");
        assert_eq!(base64_urlsafe(b"fooba"), "Zm9vYmE");
        assert_eq!(base64_urlsafe(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_urlsafe_emits_only_url_safe_chars() {
        let bytes: Vec<u8> = (0..=255).collect();
        let s = base64_urlsafe(&bytes);
        for c in s.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-url-safe char {c:?} in output: {s}",
            );
        }
    }
}
