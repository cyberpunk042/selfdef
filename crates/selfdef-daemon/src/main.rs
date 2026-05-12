//! selfdef daemon entry point — M4.
//!
//! Adds the correlator and responder alongside the M3 collector + store sink.
//! Subscribers (3 of them now) each see the bus independently.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use selfdef_bus::{Bus, BusError};
use selfdef_collector_auditd::{AuditdCollector, host_tag_from_env_or_hostname};
use selfdef_config::Config;
use selfdef_correlator::Correlator;
use selfdef_notifier::{Notifier, NotifierChain, NtfyNotifier, SignalCliNotifier};
use selfdef_responder::Responder;
use selfdef_store::SqliteStore;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Parser)]
#[command(name = "selfdefd", version, about = "selfdef daemon")]
struct Args {
    #[arg(
        short,
        long,
        env = "SELFDEF_CONFIG",
        default_value = "/etc/selfdef/selfdef.toml"
    )]
    config: PathBuf,
    #[arg(long, env = "SELFDEF_LOG")]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(args.log_level.as_deref())?;

    let cfg = Config::load(Some(&args.config)).context("loading configuration")?;
    let host_tag = cfg
        .daemon
        .host_tag
        .clone()
        .unwrap_or_else(host_tag_from_env_or_hostname);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        schema = selfdef_core::SCHEMA_VERSION,
        config = %args.config.display(),
        host_tag = %host_tag,
        "selfdefd starting"
    );

    let bus = Bus::new(cfg.bus.inproc_capacity);
    let publisher = bus.publisher();

    let store = SqliteStore::open(&cfg.store.hot_path).context("opening hot store")?;
    info!(path = %store.path().display(), "store ready");
    let count_at_start = store.count().await.unwrap_or(0);

    let shutdown = CancellationToken::new();

    // ---- store sink ----
    let store_sub = bus.subscribe();
    let sink_task = {
        let sd = shutdown.clone();
        tokio::spawn(async move { run_store_sink(store, store_sub, sd).await })
    };

    // ---- correlator ----
    let (correlator_task, correlator) = if cfg.correlator.enabled {
        let sub = bus.subscribe();
        let corr = Arc::new(Correlator::new(
            publisher.clone(),
            host_tag.clone(),
            cfg.correlator.rules_dir.clone(),
        ));
        match corr.load_rules() {
            Ok(n) => info!(rules = n, "correlator loaded rules"),
            Err(e) => warn!(error = %e, "initial rule load failed; running with empty ruleset"),
        }
        let sd = shutdown.clone();
        let c = Arc::clone(&corr);
        let h = tokio::spawn(async move { c.run(sub, sd).await });
        (Some(h), Some(corr))
    } else {
        warn!("correlator disabled in config");
        (None, None)
    };

    // ---- notifier chain ----
    let notifier = build_notifier_chain(&cfg);
    if notifier.is_empty() {
        warn!("no notification channels configured");
    }

    // ---- responder ----
    let responder_task = {
        let sub = bus.subscribe();
        let notifier_arc: Arc<dyn selfdef_notifier::Notifier> = Arc::new(notifier);
        let actions: Vec<Arc<dyn selfdef_responder::actions::Action>> = vec![
            Arc::new(selfdef_responder::actions::NotifyAction::new(notifier_arc)),
            Arc::new(selfdef_responder::actions::SnapshotProcAction::new(
                cfg.responder.snapshot_dir.clone(),
            )),
            Arc::new(selfdef_responder::actions::KillPidAction::new()),
            Arc::new(selfdef_responder::actions::LockdownEgressAction::new(
                cfg.responder.lockdown_script.clone(),
            )),
            Arc::new(selfdef_responder::actions::RevokeSessionAction::new(
                cfg.responder.revoke_session_script.clone(),
            )),
            Arc::new(selfdef_responder::actions::ForensicsBundleAction::new(
                cfg.responder.forensics_dir.clone(),
            )),
            Arc::new(selfdef_responder::actions::VelociraptorEscalateAction::new(
                cfg.responder.velociraptor_binary.clone(),
                cfg.responder.velociraptor_args.clone(),
            )),
        ];
        let resp = Arc::new(Responder::new(
            actions,
            cfg.responder.allowed_actions.clone(),
            cfg.responder.dry_run,
        ));
        let sd = shutdown.clone();
        tokio::spawn(async move { resp.run(sub, sd).await })
    };

    // ---- collectors ----
    let mut collector_handles: Vec<(&str, tokio::task::JoinHandle<()>)> = Vec::new();
    if cfg.collectors.auditd.enabled {
        let coll = AuditdCollector::new(
            cfg.collectors.auditd.input_path.clone(),
            selfdef_collector_auditd::ReadFrom::parse(&cfg.collectors.auditd.read_from),
            publisher.clone(),
            host_tag.clone(),
        );
        let coll_shutdown = shutdown.clone();
        let h = tokio::spawn(async move {
            if let Err(e) = coll.run(coll_shutdown).await {
                error!(error = %e, "auditd collector failed");
            }
        });
        collector_handles.push(("auditd", h));
        info!("auditd collector enabled");
    }

    if cfg.collectors.journald.enabled {
        use selfdef_collector_journald::{InputMode, JournaldCollector, ReadFrom as JReadFrom};
        let mode = if cfg.collectors.journald.mode == "file" {
            InputMode::File {
                path: cfg
                    .collectors
                    .journald
                    .input_path
                    .clone()
                    .unwrap_or_else(|| std::path::PathBuf::from("/var/log/journal.jsonl")),
                read_from: JReadFrom::parse(&cfg.collectors.journald.read_from),
            }
        } else {
            InputMode::Journalctl {
                binary: cfg.collectors.journald.journalctl_path.clone(),
                units: cfg.collectors.journald.units.clone(),
            }
        };
        let coll = JournaldCollector::new(mode, publisher.clone(), host_tag.clone());
        let sd = shutdown.clone();
        let h = tokio::spawn(async move {
            if let Err(e) = coll.run(sd).await {
                error!(error = %e, "journald collector failed");
            }
        });
        collector_handles.push(("journald", h));
        info!("journald collector enabled");
    }

    if cfg.collectors.tetragon.enabled {
        use selfdef_collector_tetragon::{ReadFrom as TReadFrom, TetragonCollector};
        let coll = TetragonCollector::new(
            cfg.collectors.tetragon.input_path.clone(),
            TReadFrom::parse(&cfg.collectors.tetragon.read_from),
            publisher.clone(),
            host_tag.clone(),
        );
        let sd = shutdown.clone();
        let h = tokio::spawn(async move {
            if let Err(e) = coll.run(sd).await {
                error!(error = %e, "tetragon collector failed");
            }
        });
        collector_handles.push(("tetragon", h));
        info!("tetragon collector enabled");
    }

    if cfg.collectors.suricata.enabled {
        use selfdef_collector_suricata::{ReadFrom as SReadFrom, SuricataCollector};
        let coll = SuricataCollector::new(
            cfg.collectors.suricata.input_path.clone(),
            SReadFrom::parse(&cfg.collectors.suricata.read_from),
            publisher.clone(),
            host_tag.clone(),
        );
        let sd = shutdown.clone();
        let h = tokio::spawn(async move {
            if let Err(e) = coll.run(sd).await {
                error!(error = %e, "suricata collector failed");
            }
        });
        collector_handles.push(("suricata", h));
        info!("suricata collector enabled");
    }

    if cfg.collectors.canary.enabled {
        use selfdef_collector_canary::CanaryCollector;
        let coll = CanaryCollector::new(
            cfg.collectors.canary.paths.clone(),
            publisher.clone(),
            host_tag.clone(),
        );
        let sd = shutdown.clone();
        let h = tokio::spawn(async move {
            if let Err(e) = coll.run(sd).await {
                error!(error = %e, "canary collector failed");
            }
        });
        collector_handles.push(("canary", h));
        info!(
            count = cfg.collectors.canary.paths.len(),
            "canary collector enabled"
        );
    }

    if cfg.collectors.eventstream.enabled {
        use selfdef_collector_eventstream::{EventstreamCollector, ReadFrom as EReadFrom};
        let read_from = EReadFrom::parse(&cfg.collectors.eventstream.read_from);
        for path in cfg.collectors.eventstream.paths.clone() {
            let coll = EventstreamCollector::new(path.clone(), read_from, publisher.clone());
            let sd = shutdown.clone();
            let h = tokio::spawn(async move {
                if let Err(e) = coll.run(sd).await {
                    error!(error = %e, path = %path.display(), "eventstream collector failed");
                }
            });
            collector_handles.push(("eventstream", h));
        }
        info!(
            count = cfg.collectors.eventstream.paths.len(),
            "eventstream collector(s) enabled"
        );
    }

    if cfg.collectors.ebpf.enabled {
        use selfdef_collector_ebpf::EbpfCollector;
        let collector = EbpfCollector::new(
            cfg.collectors.ebpf.program_path.clone(),
            publisher.clone(),
            host_tag.clone(),
        );
        let sd = shutdown.clone();
        let h = tokio::spawn(async move {
            if let Err(e) = collector.run(sd).await {
                error!(error = %e, "eBPF collector failed");
            }
        });
        collector_handles.push(("ebpf", h));
        info!(
            path = %cfg.collectors.ebpf.program_path.display(),
            "eBPF collector enabled"
        );
    }

    if collector_handles.is_empty() {
        warn!("no collectors enabled — daemon will observe nothing");
    }

    // ---- ready ----
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    info!(events_at_start = count_at_start, "selfdefd ready");

    tokio::select! {
        () = wait_for_shutdown_or_reload(correlator.as_ref()) => info!("shutdown signal received"),
        () = run_heartbeat() => warn!("heartbeat task exited unexpectedly"),
    }

    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
    shutdown.cancel();

    for (name, h) in collector_handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        info!(collector = name, "collector stopped");
    }
    if let Some(h) = correlator_task {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        info!("correlator stopped");
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), responder_task).await;
    info!("responder stopped");

    drop(publisher);
    match tokio::time::timeout(Duration::from_secs(5), sink_task).await {
        Ok(Ok((written, lagged))) => info!(written, lagged, "store sink stopped"),
        Ok(Err(e)) => warn!(error = %e, "sink task panicked"),
        Err(_) => warn!("sink task did not stop within timeout"),
    }

    info!("selfdefd stopped cleanly");
    Ok(())
}

async fn run_store_sink(
    store: SqliteStore,
    mut sub: selfdef_bus::Subscriber,
    shutdown: CancellationToken,
) -> (u64, u64) {
    let mut written: u64 = 0;
    let mut lagged: u64 = 0;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!(written, lagged, "store sink shutting down");
                return (written, lagged);
            }
            res = sub.recv() => match res {
                Ok(event) => {
                    if let Err(e) = store.insert(&event).await {
                        error!(error = %e, "store insert failed");
                    } else {
                        written += 1;
                    }
                }
                Err(BusError::Lagged(n)) => {
                    lagged = lagged.saturating_add(n);
                    warn!(missed = n, "store sink lagged");
                }
                Err(BusError::Closed) => {
                    info!(written, lagged, "store sink: bus closed");
                    return (written, lagged);
                }
                Err(e) => error!(error = %e, "store sink: unexpected bus error"),
            }
        }
    }
}

fn build_notifier_chain(cfg: &Config) -> NotifierChain {
    let mut inner: Vec<Box<dyn Notifier>> = Vec::new();
    for channel in &cfg.notifier.channels {
        match channel.as_str() {
            "ntfy" if !cfg.notifier.ntfy.url.is_empty() && !cfg.notifier.ntfy.topic.is_empty() => {
                inner.push(Box::new(NtfyNotifier::from_config(
                    &cfg.notifier.ntfy.url,
                    &cfg.notifier.ntfy.topic,
                    cfg.notifier.ntfy.token_file.as_ref(),
                )));
                info!(channel, "notifier channel enabled");
            }
            "signal"
                if !cfg.notifier.signal.account.is_empty()
                    && !cfg.notifier.signal.recipient.is_empty() =>
            {
                inner.push(Box::new(SignalCliNotifier::new(
                    cfg.notifier.signal.binary.clone(),
                    cfg.notifier.signal.account.clone(),
                    cfg.notifier.signal.recipient.clone(),
                )));
                info!(channel, "notifier channel enabled");
            }
            other => warn!(channel = other, "notifier channel skipped (missing config)"),
        }
    }
    NotifierChain::new(inner)
}

fn init_tracing(level_override: Option<&str>) -> Result<()> {
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

    let filter = level_override.map_or_else(EnvFilter::from_default_env, |lvl| {
        EnvFilter::try_new(lvl).unwrap_or_else(|_| EnvFilter::new("info"))
    });

    if let Ok(journald) = tracing_journald::layer() {
        tracing_subscriber::registry()
            .with(filter)
            .with(journald)
            .try_init()
            .context("initialize journald tracing")?;
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .try_init()
            .context("initialize stderr tracing")?;
    }
    Ok(())
}

async fn wait_for_shutdown_or_reload(correlator: Option<&Arc<Correlator>>) {
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGTERM handler");
            std::future::pending::<()>().await;
            return;
        }
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to install SIGINT handler");
            std::future::pending::<()>().await;
            return;
        }
    };
    let mut hup = signal(SignalKind::hangup()).ok();

    loop {
        tokio::select! {
            _ = term.recv() => {
                info!("SIGTERM received");
                return;
            }
            _ = int.recv() => {
                info!("SIGINT received");
                return;
            }
            _ = async {
                if let Some(h) = hup.as_mut() {
                    h.recv().await;
                } else {
                    std::future::pending::<Option<()>>().await;
                }
            } => {
                info!("SIGHUP received");
                if let Some(corr) = correlator {
                    match corr.load_rules() {
                        Ok(n) => info!(rules = n, "rules reloaded"),
                        Err(e) => warn!(error = %e, "rule reload failed; keeping previous ruleset"),
                    }
                }
                // continue the loop — don't exit on SIGHUP
            }
        }
    }
}

async fn run_heartbeat() {
    let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
    }
}
