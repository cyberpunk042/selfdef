//! selfdefctl — admin CLI for the selfdef daemon.
//!
//! M3 implements `events tail` and `status` by reading the SQLite hot store
//! directly. A future milestone replaces this with an IPC channel to the
//! running daemon (UNIX socket), keeping the same UX.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod modules;

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
        default_value = "/etc/selfdef/selfdef.toml",
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
    /// Print version and build info.
    Version,
}

#[derive(Debug, Subcommand)]
enum ModulesAction {
    /// List every module manifest found in the modules directory.
    List {
        /// Override the modules directory (default: /usr/share/selfdef/modules,
        /// falling back to the workspace `modules/` in dev runs).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show the full manifest for one module by slug.
    Info {
        slug: String,
        #[arg(long)]
        dir: Option<PathBuf>,
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
        Command::Modules { action } => match action {
            ModulesAction::List { dir } => {
                let resolved = modules::resolve_dir(dir.as_deref());
                modules::cmd_list(&resolved)?;
            }
            ModulesAction::Info { slug, dir } => {
                let resolved = modules::resolve_dir(dir.as_deref());
                modules::cmd_info(&resolved, &slug)?;
            }
        },
        Command::Panic { confirm } => {
            let actual_host = std::env::var("HOSTNAME")
                .ok()
                .or_else(|| {
                    std::fs::read_to_string("/etc/hostname")
                        .ok()
                        .map(|s| s.trim().to_string())
                })
                .unwrap_or_default();
            let provided = confirm.as_deref().unwrap_or("").trim();
            if provided.is_empty() {
                eprintln!("Refusing to engage panic mode without --confirm <hostname>.");
                eprintln!("Provide --confirm with this host's name to proceed.");
                std::process::exit(2);
            }
            if provided != actual_host {
                eprintln!("Confirm mismatch: provided '{provided}', host is '{actual_host}'.");
                std::process::exit(2);
            }

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
                    chain.push(Box::new(selfdef_notifier::NtfyNotifier::from_config(
                        &cfg.notifier.ntfy.url,
                        &cfg.notifier.ntfy.topic,
                        cfg.notifier.ntfy.token_file.as_ref(),
                    )));
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
