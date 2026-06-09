//! selfdef daemon entry point — M4.
//!
//! Adds the correlator and responder alongside the M3 collector + store sink.
//! Subscribers (3 of them now) each see the bus independently.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

mod cli_mirror_publisher;
mod dispatcher_adapter;
mod hardware_probe_loop;
mod mirror_export_loop;
mod retention_sweep_loop;
mod rules_collector_loop;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use selfdef_bus::{Bus, BusError};
use selfdef_collector_auditd::{AuditdCollector, host_tag_from_env_or_hostname};
use selfdef_config::Config;
use selfdef_correlator::Correlator;
use selfdef_integration_ntfy::NtfyNotifier;
use selfdef_integration_signal::SignalCliNotifier;
use selfdef_notifier::{Notifier, NotifierChain, Subscription};
use selfdef_notifier_engine::{EscalationEngine, Mode, PayloadDispatcher, Profile, wake_task};
use selfdef_notifier_orchestrator::{Channel, Subscription as OrchestratorSubscription};
use selfdef_responder::Responder;
use selfdef_store::SqliteStore;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

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
    /// Load + validate the config and exit (0 = valid, non-zero =
    /// invalid). Runs every startup check `Config::load` performs (TOML
    /// parse + the semantic fail-fast rules) without starting the daemon
    /// or touching any host state — a safe pre-flight for operators.
    #[arg(long)]
    validate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // Honor [daemon].log_format for the stderr fallback logger. Best-effort
    // peek: the authoritative config load + error handling happens below;
    // default to "text" if the file is missing/invalid so logging still
    // initialises (and the real load reports the error properly).
    let log_format = Config::load(Some(&args.config))
        .map(|c| c.daemon.log_format)
        .unwrap_or_else(|_| "text".to_string());
    init_tracing(args.log_level.as_deref(), &log_format)?;

    // SDD-002 follow-up: `--validate` is a pure pre-flight. Load the config
    // (which runs the TOML parse + every semantic fail-fast rule) and exit
    // WITHOUT starting the daemon or touching host state (no hardware probe,
    // no state-fork check, no listeners). Print a clean one-line result —
    // not an anyhow backtrace — so operators get an actionable message.
    if args.validate {
        // Config::load(Some(missing)) silently falls back to defaults — fine
        // for the daemon's normal boot, but for a pre-flight of a NAMED file
        // the operator is asking "is THIS file valid", so a missing file is
        // a failure, not a silent defaults-pass.
        if !args.config.exists() {
            eprintln!("INVALID: {} — config file not found", args.config.display());
            std::process::exit(1);
        }
        return match Config::load(Some(&args.config)) {
            Ok(_) => {
                println!("OK: {} is valid", args.config.display());
                Ok(())
            }
            Err(e) => {
                eprintln!("INVALID: {} — {e}", args.config.display());
                std::process::exit(1);
            }
        };
    }

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

    // SDD-013 § 5: surface the active deployment target + resolved state
    // paths in a single greppable log line. Operators check posture via
    // `journalctl -u selfdefd | grep deployment.target`.
    let dep_target = cfg.deployment.target;
    info!(
        "deployment.target" = %dep_target,
        state_dir = %selfdef_config::state_dir(dep_target).display(),
        audit_log = %selfdef_config::audit_log_path(dep_target).display(),
        escalations = %selfdef_config::escalations_path(dep_target).display(),
        "deployment: target = {dep_target}; state paths resolved",
    );
    // SDD-013 § Q13-C: refuse to start when target mismatches state-dir
    // contents — explicit operator migration is safer than silent fork.
    if let Err(e) = check_q13c_state_fork(dep_target) {
        return Err(e.context("Q13-C state-fork pre-flight"));
    }

    // SDD-017: hardware probe at startup. Best-effort + informational
    // — never blocks the daemon unless [deployment].sain01_strict is
    // set AND target=sain01 AND the verdict is not FullMatch. Logs the
    // Sain01Match verdict so operators see hardware drift in
    // `journalctl -u selfdefd | grep sain01_match`.
    match selfdef_hardware::probe() {
        Ok(snap) => {
            let m = selfdef_hardware::matches_sain01(&snap);
            info!(
                overall = ?m.overall,
                cpu_avx512_vnni = m.cpu_avx512_vnni,
                cpu_avx512_bf16 = m.cpu_avx512_bf16,
                memory_at_least_256gb = m.memory_at_least_256gb,
                gpu_count_at_least_2 = m.gpu_count_at_least_2,
                pcie_dual_x8_present = m.pcie_dual_x8_present,
                motherboard_proart_x870e = ?m.motherboard_proart_x870e,
                logical_threads = snap.cpu.logical_threads,
                memory_total_bytes = snap.memory.total_bytes,
                gpu_count = snap.gpus.len(),
                "sain01_match (SDD-017)",
            );
            // SDD-017 § 6: Layer B textfile-collector emission.
            if !cfg.deployment.hardware_metrics_path.is_empty() {
                let p = std::path::Path::new(&cfg.deployment.hardware_metrics_path);
                if let Err(e) = selfdef_hardware::write_layer_b_metrics(p, &snap, &m) {
                    warn!(
                        path = %p.display(),
                        error = %e,
                        "SDD-017 § 6: writing Layer B hardware metrics failed; continuing"
                    );
                } else {
                    info!(
                        path = %p.display(),
                        "SDD-017 § 6: Layer B hardware metrics emitted"
                    );
                }
            }
            // SDD-017 § 7 (SD-R10): HardwareCapabilities JSON export.
            // Consumed by sovereign-os Wasm-AOT pipeline + future
            // hardware-aware policies. Atomic tempfile+rename inside
            // the helper.
            if !cfg.deployment.hardware_capabilities_path.is_empty() {
                let p = std::path::Path::new(&cfg.deployment.hardware_capabilities_path);
                if let Err(e) = selfdef_hardware::write_capabilities_json(p, &snap) {
                    warn!(
                        path = %p.display(),
                        error = %e,
                        "SDD-017 § 7 (SD-R10): writing HardwareCapabilities JSON failed; continuing"
                    );
                } else {
                    info!(
                        path = %p.display(),
                        "SDD-017 § 7 (SD-R10): HardwareCapabilities JSON emitted"
                    );
                }
            }
            // SDD-017 § 5: strict-mode gate. Only fires when target=sain01
            // AND sain01_strict=true AND overall != FullMatch.
            if matches!(dep_target, selfdef_config::DeploymentTarget::Sain01)
                && cfg.deployment.sain01_strict
                && !matches!(m.overall, selfdef_hardware::Sain01Verdict::FullMatch)
            {
                anyhow::bail!(
                    "SDD-017 § 5 sain01_strict: refusing to start — \
                     deployment.target = sain01 + sain01_strict = true \
                     but hardware verdict = {:?}. \
                     Either fix the missing dimension(s), set sain01_strict = false \
                     to downgrade to warn-only, or switch target = generic. \
                     Run `selfdefctl hardware` for the per-dimension breakdown.",
                    m.overall
                );
            }
        }
        Err(e) => {
            warn!(error = %e, "hardware probe failed (SDD-017); daemon continues");
        }
    }

    // SDD-027 / MS046 — friction-audit observability at daemon boot.
    //
    // We don't EVALUATE the gate here (sovereign-guard.service has
    // already done that at boot ordering — Before=podman.service /
    // docker.service / containerd.service). We just surface the
    // verdict + active operator overrides for operator visibility.
    // Non-fatal: a friction-audit fail without an override means the
    // operator has either signed an override OR systemd boot ordering
    // is mis-wired (the daemon shouldn't even be running). Either way,
    // we log it.
    match selfdef_friction_audit::load_default_overrides(selfdef_friction_audit::now_ms()) {
        Ok((store, report)) => {
            let active = store.active_gates(selfdef_friction_audit::now_ms());
            info!(
                "friction-audit.overrides" = active.len(),
                "friction-audit: {} operator override(s) active at startup",
                active.len()
            );
            for gate in &active {
                info!(?gate, "friction-audit: gate operator-override-active");
            }
            // Surface per-file load errors so operators can see when a
            // manifest failed to verify (e.g. signature mismatch, TTL
            // expired).
            for entry in report {
                if let Err(e) = entry {
                    warn!(error = %e, "friction-audit: override manifest rejected");
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "friction-audit: override store load failed; daemon continues");
        }
    }
    match selfdef_friction_audit::read_ring_buffer(std::path::Path::new(
        selfdef_friction_audit::DEFAULT_RING_DIR,
    )) {
        Ok(verdicts) if verdicts.is_empty() => {
            info!("friction-audit: no boot-time verdicts recorded yet (ring buffer empty)");
        }
        Ok(verdicts) => {
            let failing = verdicts.iter().filter(|v| v.is_failing()).count();
            info!(
                "friction-audit.verdicts" = verdicts.len(),
                "friction-audit.failing" = failing,
                "friction-audit: {} ring-buffer verdict(s), {} currently failing",
                verdicts.len(),
                failing
            );
        }
        Err(e) => {
            warn!(error = %e, "friction-audit: ring buffer read failed; daemon continues");
        }
    }

    // SDD-028 / MS047 — perimeter observability at daemon boot.
    //
    // Sister-observability point to friction-audit above. The actual
    // enforcement is in-kernel via Tetragon's `sovereign-kernel-fence`
    // TracingPolicy (loaded from /etc/tetragon/tracing-policies/). The
    // daemon surfaces the policy presence + currently-loaded operator-
    // signed allowlist extensions + the latest verdicts so operators
    // can see the state at start. Non-fatal — if Tetragon isn't running
    // the perimeter isn't enforcing; that's a watchdog concern for
    // selfdef-guardian-daemon (MS044), not a reason to refuse to boot.
    match selfdef_perimeter::load_default_extensions(selfdef_perimeter::now_ms()) {
        Ok((store, report)) => {
            let now = selfdef_perimeter::now_ms();
            let active = store.active(now);
            info!(
                "perimeter.extensions" = active.len(),
                "perimeter: {} operator allowlist extension(s) active at startup",
                active.len()
            );
            for m in &active {
                info!(
                    extension_id = %m.extension_id,
                    paths = m.binary_paths.len(),
                    "perimeter: extension active"
                );
            }
            for entry in report {
                if let Err(e) = entry {
                    warn!(error = %e, "perimeter: extension manifest rejected");
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "perimeter: extension store load failed; daemon continues");
        }
    }
    let policy_path = std::path::Path::new(selfdef_perimeter::DEFAULT_POLICY_PATH);
    if policy_path.exists() {
        info!(
            policy = %policy_path.display(),
            "perimeter: sovereign-kernel-fence TracingPolicy present"
        );
    } else {
        warn!(
            policy = %policy_path.display(),
            "perimeter: sovereign-kernel-fence TracingPolicy NOT present — kernel-fence is OFF"
        );
    }
    match selfdef_perimeter::read_ring_buffer(std::path::Path::new(
        selfdef_perimeter::DEFAULT_RING_DIR,
    )) {
        Ok(verdicts) if verdicts.is_empty() => {
            info!("perimeter: no Tetragon verdicts recorded yet (ring buffer empty)");
        }
        Ok(verdicts) => {
            let sigkills = verdicts.iter().filter(|v| v.is_sigkill()).count();
            let extensions_used = verdicts.iter().filter(|v| v.is_extension_allowed()).count();
            info!(
                "perimeter.verdicts" = verdicts.len(),
                "perimeter.sigkills" = sigkills,
                "perimeter.extension_allowed" = extensions_used,
                "perimeter: {} ring-buffer verdict(s), {} SIGKILL, {} extension-allowed",
                verdicts.len(),
                sigkills,
                extensions_used
            );
        }
        Err(e) => {
            warn!(error = %e, "perimeter: ring buffer read failed; daemon continues");
        }
    }

    // SDD-029 / MS044 — Guardian Daemon observability at daemon boot.
    //
    // Third leg of the three-watchdog trio (friction-audit at hardware
    // frame, perimeter at kernel syscall, guardian at supervisor tier).
    // selfdefd does NOT run Guardian itself — that's selfdef-guardian.service
    // (a separate systemd unit). selfdefd just surfaces the boot-time
    // state for operator visibility.
    let guardian_socket = std::path::Path::new(selfdef_guardian::DEFAULT_SOCKET_PATH);
    if guardian_socket.exists() {
        info!(
            socket = %guardian_socket.display(),
            "guardian: Tetragon UNIX socket present"
        );
    } else {
        info!(
            socket = %guardian_socket.display(),
            "guardian: Tetragon UNIX socket not present yet (Tetragon may not be running)"
        );
    }
    match selfdef_guardian::read_ring_buffer(std::path::Path::new(
        selfdef_guardian::DEFAULT_RING_DIR,
    )) {
        Ok(verdicts) if verdicts.is_empty() => {
            info!("guardian: no events recorded yet (ring buffer empty)");
        }
        Ok(verdicts) => {
            let failed = verdicts.iter().filter(|v| !v.all_steps_ok()).count();
            info!(
                "guardian.verdicts" = verdicts.len(),
                "guardian.failed_responses" = failed,
                "guardian: {} event(s) recorded, {} with step failures",
                verdicts.len(),
                failed
            );
        }
        Err(e) => {
            warn!(error = %e, "guardian: ring buffer read failed; daemon continues");
        }
    }

    // SDD-031 / MS048 — Goldilocks Scheduler observability at daemon boot.
    //
    // Fourth member of the four-watchdog set: hardware frame (friction-
    // audit) + kernel syscall (perimeter) + supervisor tier (guardian)
    // + routing layer (scheduler). selfdefd does NOT run the scheduler
    // itself — selfdef-scheduler.service is a separate systemd unit.
    // selfdefd surfaces boot-time state for operator visibility.
    let scheduler_audit_log = std::path::Path::new(selfdef_scheduler::DEFAULT_AUDIT_LOG_PATH);
    match selfdef_scheduler::audit_chain_check(scheduler_audit_log) {
        Ok(n) => info!(
            "scheduler.audit_chain_events" = n,
            "scheduler: audit chain intact, {} event(s)", n
        ),
        Err(e) => warn!(error = %e, "scheduler: audit chain check failed; daemon continues"),
    }
    match selfdef_scheduler::read_ring_buffer(std::path::Path::new(
        selfdef_scheduler::DEFAULT_RING_DIR,
    )) {
        Ok(decisions) if decisions.is_empty() => {
            info!("scheduler: no decisions recorded yet (ring buffer empty)");
        }
        Ok(decisions) => {
            let backpressured = decisions
                .iter()
                .filter(|d| d.backpressure.any_pressure())
                .count();
            info!(
                "scheduler.decisions" = decisions.len(),
                "scheduler.backpressured_decisions" = backpressured,
                "scheduler: {} decision(s) recorded, {} under backpressure",
                decisions.len(),
                backpressured
            );
        }
        Err(e) => {
            warn!(error = %e, "scheduler: ring buffer read failed; daemon continues");
        }
    }

    let bus = Arc::new(Bus::new(cfg.bus.inproc_capacity));
    let publisher = bus.publisher();

    let store = Arc::new(SqliteStore::open(&cfg.store.hot_path).context("opening hot store")?);
    info!(path = %store.path().display(), "store ready");
    let count_at_start = store.count().await.unwrap_or(0);

    let shutdown = CancellationToken::new();

    // ---- store sink ----
    let store_sub = bus.subscribe();
    let sink_task = {
        let sd = shutdown.clone();
        let s = Arc::clone(&store);
        tokio::spawn(async move { run_store_sink(s, store_sub, sd).await })
    };

    // F-2026-094: shared bus-lag counters for the two consequential consumers.
    // The same Arc is handed to each consumer (which bumps it on a broadcast
    // lag) and to the Metrics handle (which renders it live), so dropped-before-
    // action findings / missed detections become observable instead of living
    // only in a warn log. Created here so both the metrics wiring below and the
    // correlator + responder constructions further down can clone them.
    let responder_lag = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let correlator_lag = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // The shared Metrics handle. Constructed here (before the retention +
    // mirror loops) so every producer records into the SAME Arc that the
    // API /metrics surface renders. Cheap + Arc'd; only the /metrics scrape
    // endpoint + bus-ingest task are gated by [api].enabled, so when the
    // API is off there is no handle and producers simply skip recording.
    let metrics_handle: Option<Arc<selfdef_api::Metrics>> = if cfg.api.enabled {
        Some(Arc::new(selfdef_api::Metrics::new(host_tag.clone())))
    } else {
        None
    };
    if let Some(m) = &metrics_handle {
        // SDD-081: surface retention on/off so a consumer alert can tell
        // "operator opted out" from "retention stalled".
        m.set_retention_enabled(cfg.store.hot_retention_days > 0);
        // F-2026-092: surface the responder's autonomous-response severity
        // floor (0 = none) so a dashboard can chart suppression against
        // selfdef_findings_by_severity_total instead of guessing the config.
        let floor_repr = match cfg.responder.min_severity.trim().to_ascii_lowercase().as_str() {
            "" | "none" | "unknown" => 0,
            other => parse_severity_floor(other).map_or(0, |s| s as u32),
        };
        m.set_responder_min_severity_floor(floor_repr);
        // F-2026-094: hand the consumers' live lag counters to /metrics.
        m.set_lag_sources(Arc::clone(&responder_lag), Arc::clone(&correlator_lag));
    }

    // SD-R retention sweep (SDD-081): enforce StoreConfig::hot_retention_days.
    // Without it the knob is dead config and the hot store grows unbounded
    // (F-2026-016). Disabled when hot_retention_days==0 (operator opt-out).
    // Records selfdef_store_retention_{sweeps,pruned}_total (SDD-081 D-1).
    let _retention_task = {
        let s = Arc::clone(&store);
        let sd = shutdown.clone();
        let days = cfg.store.hot_retention_days;
        let m = metrics_handle.clone();
        tokio::spawn(
            async move { retention_sweep_loop::run_retention_sweep_loop(s, days, sd, m).await },
        )
    };

    // SD-R22: periodic hardware probe + thermal-event emission loop.
    // Opt-in via [hardware_probe].enabled. The task lives for the
    // daemon's lifetime + observes the same shutdown signal as the
    // other background tasks.
    let _hardware_probe_task = if cfg.hardware_probe.enabled {
        let metrics_path: Option<std::path::PathBuf> =
            if cfg.deployment.hardware_metrics_path.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(
                    &cfg.deployment.hardware_metrics_path,
                ))
            };
        let probe_cfg = cfg.hardware_probe.clone();
        let pubr = publisher.clone();
        let sd = shutdown.clone();
        let ht = host_tag.clone();
        Some(tokio::spawn(async move {
            hardware_probe_loop::run_hardware_probe_loop(probe_cfg, metrics_path, pubr, ht, sd)
                .await
        }))
    } else {
        None
    };

    // M060 D-02 (R10063-R10068): cross-repo mirror export. Opt-in via
    // [deployment].selfdef_mirror_dir. Publishes the active authority-
    // profile snapshot READ-ONLY for the sovereign-os cockpit. Lives for
    // the daemon's lifetime + observes the same shutdown signal.
    //
    // Reuse the shared Metrics handle constructed above (retention + mirror
    // + the API ingest task all record into the SAME Arc, so /metrics shows
    // a single coherent view). The mirror loop bumps per-artifact publish
    // counters; when the API is disabled the handle is None and the loop
    // simply skips recording.
    let mirror_metrics = metrics_handle.clone();
    let _mirror_export_task = if cfg.deployment.selfdef_mirror_dir.is_empty() {
        None
    } else {
        let mirror_dir = std::path::PathBuf::from(&cfg.deployment.selfdef_mirror_dir);
        let flex_path = std::path::PathBuf::from(selfdef_flex_profile::DEFAULT_STATE_PATH);
        // Honor the same overrides the API write paths use, so relocated
        // resident stores are read + republished consistently.
        let grants_store = std::env::var("SELFDEF_GRANTS_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(selfdef_grant_registry::DEFAULT_STATE_PATH)
            });
        let capability_tokens_store = std::env::var("SELFDEF_CAPABILITY_TOKENS_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(selfdef_capability_registry::DEFAULT_STATE_PATH)
            });
        let sandboxes_store = std::env::var("SELFDEF_SANDBOXES_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(selfdef_sandbox_registry::DEFAULT_STATE_PATH)
            });
        let quarantine_store = std::env::var("SELFDEF_QUARANTINE_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(selfdef_quarantine_registry::DEFAULT_STATE_PATH)
            });
        let trust_scores_store = std::env::var("SELFDEF_TRUST_SCORES_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(selfdef_trust_score_registry::DEFAULT_STATE_PATH)
            });
        let audit_store = std::env::var("SELFDEF_AUDIT_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(selfdef_audit_registry::DEFAULT_STATE_PATH)
            });
        let rules_store = std::env::var("SELFDEF_RULES_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(selfdef_rules_registry::DEFAULT_STATE_PATH)
            });
        let rules_collector_store = rules_store.clone();
        let rules_collector_shutdown = shutdown.clone();
        // M060 D-12: poll `nft -j list ruleset` on its own cadence and
        // persist into the resident rules registry. Decoupled from the
        // mirror-export loop so a slow nft call cannot stall the other
        // 7 mirror domains. The export loop reads the registry file.
        tokio::spawn(async move {
            rules_collector_loop::run_rules_collector_loop(
                rules_collector_store,
                rules_collector_shutdown,
            )
            .await
        });
        let sd = shutdown.clone();
        let metrics_for_mirror = mirror_metrics.clone();
        info!(
            mirror_dir = %mirror_dir.display(),
            "M060: mirror export enabled (active-profile + grants + capability-tokens + sandboxes + quarantine + trust-scores + audit + rules, read-only)"
        );
        Some(tokio::spawn(async move {
            mirror_export_loop::run_mirror_export_loop(
                mirror_dir,
                flex_path,
                grants_store,
                capability_tokens_store,
                sandboxes_store,
                quarantine_store,
                trust_scores_store,
                audit_store,
                rules_store,
                metrics_for_mirror,
                sd,
            )
            .await
        }))
    };

    // ---- correlator ----
    let (correlator_task, correlator) = if cfg.correlator.enabled {
        let sub = bus.subscribe();
        // SDD-004 rule-signing follow-up: if [security] turns it
        // on, load the public key now. Refuse to start when the
        // operator opted in but the key path is missing/broken —
        // running unsigned-trusted is worse than failing loudly.
        let mut corr = Correlator::new(
            publisher.clone(),
            host_tag.clone(),
            cfg.correlator.rules_dir.clone(),
        )
        .with_lag_counter(Arc::clone(&correlator_lag));
        if cfg.security.require_signed_rules {
            let key_path = cfg.security.signing_public_key_file.as_ref().context(
                "[security].require_signed_rules = true but \
                     [security].signing_public_key_file is unset",
            )?;
            let verifier = selfdef_signing::Verifier::load(key_path).with_context(|| {
                format!(
                    "loading rule-signing public key from {}",
                    key_path.display()
                )
            })?;
            info!(
                key = %key_path.display(),
                "correlator: rule-signing verification enabled"
            );
            corr = corr.with_verifier(verifier);
        }
        let corr = Arc::new(corr);
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

    // ---- notifier path: M4 chain OR SDD-008 D-5d engine ----
    // When [notifier].escalations_path is set, we open the
    // persistent EscalationEngine, build a Vec<Arc<dyn Channel>>,
    // wrap them in a PayloadDispatcher, and spawn the wake task.
    // The responder gets a DispatcherAdapter (impl Notifier) so
    // existing call sites are unchanged. When unset, we fall back
    // to the M4 NotifierChain — no persistence, no escalation.
    let (notifier_arc, wake_task_handle, escalation_engine_for_api) =
        build_notifier_path(&cfg, &shutdown);
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
    let responder = {
        let base = Responder::new(
            actions,
            cfg.responder.allowed_actions.clone(),
            cfg.responder.dry_run,
        )
        .with_lag_counter(Arc::clone(&responder_lag));
        // F-2026-092: apply the optional autonomous-response severity floor.
        // `none`/`unknown`/empty means no floor (process every finding, the
        // default). A recognized grade raises the floor; an unrecognized token
        // is logged and treated as no floor rather than silently dropping.
        let token = cfg.responder.min_severity.trim();
        let floored = match token.to_ascii_lowercase().as_str() {
            "" | "none" | "unknown" => base,
            other => match parse_severity_floor(other) {
                Some(floor) => {
                    info!(floor = %floor, "responder autonomous-response severity floor enabled");
                    base.with_min_severity(floor)
                }
                None => {
                    warn!(
                        token = %token,
                        "unrecognized responder.min_severity; no floor applied (every finding processed)"
                    );
                    base
                }
            },
        };
        Arc::new(floored)
    };

    let responder_task = {
        let sub = bus.subscribe();
        let resp = Arc::clone(&responder);
        let sd = shutdown.clone();
        tokio::spawn(async move { resp.run(sub, sd).await })
    };

    // ---- api ----
    // The API holds an Arc clone of the same responder so its
    // `dispatch_single` / `fire` calls hit the same action set the bus
    // task runs.
    // ---- metrics ----
    // One process-wide Metrics handle, shared between the API (which
    // serves /metrics) and the ingest task (which subscribes to the
    // bus and bumps counters per event). The ingest task is gated on
    // the API being enabled — without a scrape surface, the counters
    // are dead weight.
    // mirror_metrics was constructed earlier so the M060 mirror-export
    // loop could bump per-artifact publish counters from startup. Reuse
    // the same Arc so /metrics + the mirror loop + the bus-ingest task
    // all share one set of counters.
    let (metrics_handle, metrics_task) = if cfg.api.enabled {
        let metrics = mirror_metrics
            .clone()
            .unwrap_or_else(|| Arc::new(selfdef_api::Metrics::new(host_tag.clone())));
        let m = Arc::clone(&metrics);
        let b = Arc::clone(&bus);
        let sd = shutdown.clone();
        let task = tokio::spawn(async move {
            selfdef_api::run_metrics_ingest(m, b, sd).await;
        });
        (Some(metrics), Some(task))
    } else {
        (None, None)
    };

    let (api_task, api_token_reloader) = if cfg.api.enabled {
        use selfdef_api::{ApiServer, ApiState, SseCaps};
        let cfg_api = build_api_config(&cfg.api);
        let mut state = ApiState::new(Arc::clone(&store), Arc::clone(&bus), host_tag.clone())
            .with_publisher(publisher.clone())
            // SDD-007 D-4: thread the operator-overrideable SSE
            // caps into ApiState. Empty/None falls back to the
            // compiled-in defaults (64 global, 8 per-token).
            .with_sse_caps(SseCaps {
                global: cfg.api.max_sse_subscribers,
                per_token: cfg.api.max_sse_subscribers_per_token,
            });
        if let Some(m) = metrics_handle.clone() {
            state = state.with_metrics(m);
        }
        if let Some(c) = correlator.clone() {
            state = state.with_correlator(c);
        }
        state = state.with_responder(Arc::clone(&responder));
        // SDD-008 D-4 HTTP ack: thread the escalation engine handle
        // into ApiState so `/notify/ack/:token` can record acks.
        // When the daemon is on the legacy chain path (no
        // escalations_path), the handle is None and the route
        // returns 503.
        if let Some(engine) = escalation_engine_for_api.clone() {
            state = state.with_escalation_engine(engine);
        }
        let server = ApiServer::new(state, cfg_api);
        // SDD-004 F-2026-023 follow-up: stash the reloader so SIGUSR2
        // can hot-rotate tokens. The reloader's Arc<RwLock<>> is
        // shared with the server's auth middleware.
        let reloader = server.token_reloader();
        let sd = shutdown.clone();
        info!("api: starting");
        let task = tokio::spawn(async move {
            if let Err(e) = server.run(sd).await {
                error!(error = %e, "api server failed");
            }
        });
        (Some(task), Some(reloader))
    } else {
        (None, None)
    };

    // ---- nats bridge ----
    let nats_task = if cfg.bus.nats.enabled && !cfg.bus.nats.url.trim().is_empty() {
        let nats_cfg = selfdef_nats::NatsConfig {
            url: cfg.bus.nats.url.clone(),
            subject_prefix: cfg.bus.nats.subject_prefix.clone(),
            jetstream: selfdef_nats::JetStreamConfig {
                enabled: cfg.bus.nats.jetstream.enabled,
                stream_name: cfg.bus.nats.jetstream.stream_name.clone(),
                durable_consumer_prefix: cfg.bus.nats.jetstream.durable_consumer_prefix.clone(),
                max_age_secs: cfg.bus.nats.jetstream.max_age_secs,
                max_bytes: cfg.bus.nats.jetstream.max_bytes,
                max_msgs: cfg.bus.nats.jetstream.max_msgs,
            },
        };
        let sub = bus.subscribe();
        let pub_ = publisher.clone();
        let ht = host_tag.clone();
        let sd = shutdown.clone();
        info!(url = %nats_cfg.url, "nats bridge: starting");
        Some(tokio::spawn(async move {
            if let Err(e) = selfdef_nats::run_bridge(nats_cfg, ht, pub_, sub, sd).await {
                error!(error = %e, "nats bridge failed");
            }
        }))
    } else {
        None
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
        use selfdef_collector_eventstream::{
            EventstreamCollector, IntegrityCheck, ReadFrom as EReadFrom,
        };
        let read_from = EReadFrom::parse(&cfg.collectors.eventstream.read_from);
        // SDD-004 F-2026-026 follow-up: build the integrity check
        // once and clone it per path. Disabled by default so
        // operator-owned emitter paths keep working unchanged.
        let integrity = IntegrityCheck {
            enabled: cfg.collectors.eventstream.integrity_check,
            allowed_owners: cfg.collectors.eventstream.allowed_owners.clone(),
        };
        for path in cfg.collectors.eventstream.paths.clone() {
            let coll = EventstreamCollector::new(path.clone(), read_from, publisher.clone())
                .with_integrity_check(integrity.clone());
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
            integrity_check = cfg.collectors.eventstream.integrity_check,
            "eventstream collector(s) enabled"
        );
    }

    if cfg.collectors.ebpf.enabled {
        use selfdef_collector_ebpf::{EbpfCollector, EbpfProbes};
        let probes = EbpfProbes {
            execve: cfg.collectors.ebpf.enable_execve,
            lsm_file_open: cfg.collectors.ebpf.enable_lsm_open,
            kprobe_unlinkat: cfg.collectors.ebpf.enable_kprobe_unlink,
        };
        let collector = EbpfCollector::with_probes(
            cfg.collectors.ebpf.program_path.clone(),
            publisher.clone(),
            host_tag.clone(),
            probes,
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
        () = wait_for_shutdown_or_reload(correlator.as_ref(), api_token_reloader.as_ref()) => info!("shutdown signal received"),
        () = run_heartbeat() => warn!("heartbeat task exited unexpectedly"),
    }

    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]);
    shutdown.cancel();

    for (name, h) in collector_handles {
        match tokio::time::timeout(Duration::from_secs(5), h).await {
            Ok(Ok(())) => info!(collector = name, "collector stopped"),
            // The handle was already finished with a JoinError — the collector
            // task panicked at some earlier point in the run, NOT during this
            // shutdown. Nothing was watching it live, so events from this
            // source were silently lost until now. Report the truth instead of
            // logging a clean "stopped" (the old `let _ = …` swallowed this).
            Ok(Err(e)) => warn!(
                collector = name, error = %e,
                "collector task terminated abnormally (panicked) before shutdown \
                 — events from this source were silently lost while the daemon ran"
            ),
            Err(_) => warn!(collector = name, "collector did not stop within 5s"),
        }
    }
    if let Some(h) = correlator_task {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        info!("correlator stopped");
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), responder_task).await;
    info!("responder stopped");
    if let Some(h) = wake_task_handle {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        info!("escalation wake_task stopped");
    }
    if let Some(h) = api_task {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        info!("api stopped");
    }
    if let Some(h) = metrics_task {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        info!("metrics ingest stopped");
    }
    if let Some(h) = nats_task {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        info!("nats bridge stopped");
    }

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
    store: Arc<SqliteStore>,
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

/// Translate the string-shaped `[api]` config into the typed `ApiConfig`
/// the api crate consumes. Parse failures fall back to "transport not
/// enabled" rather than crash the daemon — a typo in the TOML shouldn't
/// take selfdef down.
/// SDD-013 Q13-C pre-flight: refuse to start when the operator's
/// chosen target mismatches what's on disk in either candidate
/// state-dir. State-fork is a silent corruption hazard (two daemons
/// writing two audit logs feels like everything works until the
/// operator pulls one of them and discovers half the timeline is in
/// the other). Fail-loud at startup with a clear migration directive.
///
/// Detects:
/// - target = Generic but /mnt/vault/context/selfdef-audit.jsonl OR
///   /mnt/vault/context/selfdef-escalations.sqlite exists
/// - target = Sain01 but /var/lib/selfdef/selfdef-audit.jsonl OR
///   /var/lib/selfdef/selfdef-escalations.sqlite exists
///
/// Operator must migrate state files (or rm them, with eyes open)
/// before the daemon will start. No silent fork, no silent merge.
fn check_q13c_state_fork(target: selfdef_config::DeploymentTarget) -> Result<()> {
    use selfdef_config::DeploymentTarget;
    let opposite = match target {
        DeploymentTarget::Generic => DeploymentTarget::Sain01,
        DeploymentTarget::Sain01 => DeploymentTarget::Generic,
    };
    let opposite_dir = selfdef_config::state_dir(opposite);
    if !opposite_dir.exists() {
        return Ok(());
    }
    let opposite_audit = selfdef_config::audit_log_path(opposite);
    let opposite_esc = selfdef_config::escalations_path(opposite);
    let mut conflicts: Vec<std::path::PathBuf> = Vec::new();
    if opposite_audit.exists() {
        conflicts.push(opposite_audit);
    }
    if opposite_esc.exists() {
        conflicts.push(opposite_esc);
    }
    if conflicts.is_empty() {
        return Ok(());
    }
    let conflicts_str = conflicts
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "SDD-013 Q13-C state-fork hazard detected:\n\
         configured target = {target}, but selfdef state exists at the {opposite} location ({conflicts_str}).\n\
         Migrate or remove the conflicting state file(s) before starting the daemon — silent state-fork can lose events.\n\
         For migration guidance see docs/sdd/013-deployment-target-config.md § Q13-C.",
    );
}

fn build_api_config(cfg: &selfdef_config::ApiConfig) -> selfdef_api::ApiConfig {
    use selfdef_api::ApiConfig as Out;
    let unix_socket = if cfg.unix_socket.trim().is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(&cfg.unix_socket))
    };
    let unix_socket_mode =
        u32::from_str_radix(cfg.unix_socket_mode.trim_start_matches('0'), 8).unwrap_or(0o660);
    let tcp_addr = if cfg.tcp_addr.trim().is_empty() {
        None
    } else {
        match cfg.tcp_addr.parse() {
            Ok(addr) => Some(addr),
            Err(e) => {
                warn!(addr = %cfg.tcp_addr, error = %e, "api: tcp_addr parse failed; tcp transport disabled");
                None
            }
        }
    };
    let token_file = if cfg.token_file.trim().is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(&cfg.token_file))
    };
    let control_token_file = if cfg.control_token_file.trim().is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(&cfg.control_token_file))
    };
    let tls = if cfg.tls.cert_path.trim().is_empty() || cfg.tls.key_path.trim().is_empty() {
        None
    } else {
        Some(selfdef_api::TlsConfig {
            cert_path: std::path::PathBuf::from(&cfg.tls.cert_path),
            key_path: std::path::PathBuf::from(&cfg.tls.key_path),
            client_ca: if cfg.tls.client_ca.trim().is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(&cfg.tls.client_ca))
            },
        })
    };
    Out {
        enabled: cfg.enabled,
        unix_socket,
        unix_socket_mode,
        tcp_addr,
        token_file,
        control_token_file,
        tls,
    }
}

fn build_notifier_chain(cfg: &Config) -> NotifierChain {
    // Surface orphaned channel configs: a `[notifier.ntfy]` block
    // with non-default values but no matching `"ntfy"` entry in
    // `cfg.notifier.channels` is almost always an operator
    // mistake — the channel is silently inert. Warn before
    // building the chain so the operator sees it on a normal
    // restart, not just on the first event. (F-2026-054)
    let configured_ntfy = !cfg.notifier.ntfy.url.is_empty() || !cfg.notifier.ntfy.topic.is_empty();
    let configured_signal =
        !cfg.notifier.signal.account.is_empty() || !cfg.notifier.signal.recipient.is_empty();
    let lists_ntfy = cfg.notifier.channels.iter().any(|c| c == "ntfy");
    let lists_signal = cfg.notifier.channels.iter().any(|c| c == "signal");
    if configured_ntfy && !lists_ntfy {
        warn!(
            "notifier: [notifier.ntfy] is configured but \"ntfy\" is not in \
             [notifier].channels; the channel is inert. Add \"ntfy\" to \
             channels or clear the [notifier.ntfy] block."
        );
    }
    if configured_signal && !lists_signal {
        warn!(
            "notifier: [notifier.signal] is configured but \"signal\" is not in \
             [notifier].channels; the channel is inert. Add \"signal\" to \
             channels or clear the [notifier.signal] block."
        );
    }

    let mut inner: Vec<(Box<dyn Notifier>, Subscription)> = Vec::new();
    for channel in &cfg.notifier.channels {
        match channel.as_str() {
            "ntfy" if !cfg.notifier.ntfy.url.is_empty() && !cfg.notifier.ntfy.topic.is_empty() => {
                inner.push((
                    Box::new(NtfyNotifier::from_config(
                        &cfg.notifier.ntfy.url,
                        &cfg.notifier.ntfy.topic,
                        cfg.notifier.ntfy.token_file.as_ref(),
                    )),
                    build_subscription(channel, cfg),
                ));
                info!(channel, "notifier channel enabled");
            }
            "signal"
                if !cfg.notifier.signal.account.is_empty()
                    && !cfg.notifier.signal.recipient.is_empty() =>
            {
                inner.push((
                    Box::new(SignalCliNotifier::new(
                        cfg.notifier.signal.binary.clone(),
                        cfg.notifier.signal.account.clone(),
                        cfg.notifier.signal.recipient.clone(),
                    )),
                    build_subscription(channel, cfg),
                ));
                info!(channel, "notifier channel enabled");
            }
            "smtp"
                if !cfg.notifier.smtp.relay_host.is_empty() && !cfg.notifier.smtp.to.is_empty() =>
            {
                let tls = match cfg.notifier.smtp.tls.as_str() {
                    "implicit_tls" => selfdef_integration_smtp::TlsProfile::ImplicitTls,
                    "plain" => selfdef_integration_smtp::TlsProfile::Plain,
                    _ => selfdef_integration_smtp::TlsProfile::StartTls,
                };
                match selfdef_integration_smtp::SmtpNotifier::from_config(
                    &cfg.notifier.smtp.relay_host,
                    cfg.notifier.smtp.relay_port,
                    tls,
                    cfg.notifier.smtp.username.as_deref(),
                    cfg.notifier.smtp.password_file.as_ref(),
                    &cfg.notifier.smtp.from,
                    &cfg.notifier.smtp.to,
                    std::time::Duration::from_secs(cfg.notifier.smtp.timeout_secs),
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "smtp channel skipped (config rejected by builder)",
                    ),
                }
            }
            "discord" if cfg.notifier.discord.webhook_url_file.is_some() => {
                let Some(url_path) = cfg.notifier.discord.webhook_url_file.as_ref() else {
                    continue;
                };
                match selfdef_integration_discord::DiscordNotifier::from_config(
                    url_path,
                    &cfg.notifier.discord.username,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "discord channel skipped (config rejected by builder)",
                    ),
                }
            }
            "pagerduty" if cfg.notifier.pagerduty.routing_key_file.is_some() => {
                let Some(key_path) = cfg.notifier.pagerduty.routing_key_file.as_ref() else {
                    continue;
                };
                match selfdef_integration_pagerduty::PagerDutyNotifier::from_config(
                    key_path,
                    &cfg.notifier.pagerduty.endpoint,
                    &cfg.notifier.pagerduty.source,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "pagerduty channel skipped (config rejected by builder)",
                    ),
                }
            }
            "loki" if !cfg.notifier.loki.endpoint.is_empty() => {
                match selfdef_integration_loki::LokiNotifier::from_config(
                    &cfg.notifier.loki.endpoint,
                    &cfg.notifier.loki.tenant_id,
                    cfg.notifier.loki.auth_token_file.as_ref(),
                    &cfg.notifier.loki.source,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "loki channel skipped (config rejected by builder)",
                    ),
                }
            }
            "opensearch" if !cfg.notifier.opensearch.endpoint.is_empty() => {
                match selfdef_integration_opensearch::OpenSearchNotifier::from_config(
                    &cfg.notifier.opensearch.endpoint,
                    &cfg.notifier.opensearch.index,
                    &cfg.notifier.opensearch.auth_kind,
                    &cfg.notifier.opensearch.username,
                    cfg.notifier.opensearch.auth_token_file.as_ref(),
                    &cfg.notifier.opensearch.source,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "opensearch channel skipped (config rejected by builder)",
                    ),
                }
            }
            "thehive"
                if !cfg.notifier.thehive.endpoint.is_empty()
                    && cfg.notifier.thehive.api_key_file.is_some() =>
            {
                let Some(key_path) = cfg.notifier.thehive.api_key_file.as_ref() else {
                    continue;
                };
                match selfdef_integration_thehive::TheHiveNotifier::from_config(
                    &cfg.notifier.thehive.endpoint,
                    key_path,
                    &cfg.notifier.thehive.source,
                    &cfg.notifier.thehive.alert_type,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "thehive channel skipped (config rejected by builder)",
                    ),
                }
            }
            "slack" if cfg.notifier.slack.webhook_url_file.is_some() => {
                let Some(url_path) = cfg.notifier.slack.webhook_url_file.as_ref() else {
                    // Unreachable given the guard above, but keep
                    // the destructure explicit for clarity.
                    continue;
                };
                match selfdef_integration_slack::SlackNotifier::from_config(
                    url_path,
                    &cfg.notifier.slack.username,
                    &cfg.notifier.slack.icon_emoji,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "slack channel skipped (config rejected by builder)",
                    ),
                }
            }
            "twilio"
                if !cfg.notifier.twilio.account_sid.is_empty()
                    && !cfg.notifier.twilio.to.is_empty() =>
            {
                let Some(token_path) = cfg.notifier.twilio.auth_token_file.as_ref() else {
                    warn!(channel, "twilio channel skipped (auth_token_file not set)");
                    continue;
                };
                match selfdef_integration_twilio::TwilioNotifier::from_config(
                    &cfg.notifier.twilio.account_sid,
                    token_path,
                    &cfg.notifier.twilio.from,
                    &cfg.notifier.twilio.to,
                    std::time::Duration::from_secs(cfg.notifier.twilio.timeout_secs),
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "twilio channel skipped (config rejected by builder)",
                    ),
                }
            }
            "wall" if !cfg.notifier.wall.binary.as_os_str().is_empty() => {
                let floor = if cfg.notifier.wall.severity_floor.is_empty() {
                    None
                } else {
                    Some(cfg.notifier.wall.severity_floor.as_str())
                };
                match selfdef_integration_wall::WallChannel::from_config(
                    &cfg.notifier.wall.binary,
                    floor,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "wall channel skipped (config rejected by builder)",
                    ),
                }
            }
            "write"
                if !cfg.notifier.write.binary.as_os_str().is_empty()
                    && !cfg.notifier.write.users.is_empty() =>
            {
                let floor = if cfg.notifier.write.severity_floor.is_empty() {
                    None
                } else {
                    Some(cfg.notifier.write.severity_floor.as_str())
                };
                match selfdef_integration_write::WriteChannel::from_config(
                    &cfg.notifier.write.binary,
                    floor,
                    &cfg.notifier.write.users,
                ) {
                    Ok(n) => {
                        inner.push((Box::new(n), build_subscription(channel, cfg)));
                        info!(channel, "notifier channel enabled");
                    }
                    Err(e) => warn!(
                        channel,
                        error = %e,
                        "write channel skipped (config rejected by builder)",
                    ),
                }
            }
            "shared-audit-summary" if selfdef_config::resolve_shared_audit_summary_enabled(cfg) => {
                let Some(path) = selfdef_config::resolve_shared_audit_summary_path(cfg) else {
                    warn!(
                        channel,
                        "shared-audit-summary channel needs a path; \
                         disable explicitly via [notifier.shared_audit_summary] enabled=false \
                         on generic deployments without an override"
                    );
                    continue;
                };
                let pointer = selfdef_config::resolve_shared_audit_summary_pointer(cfg);
                let jsonl_twin = selfdef_config::resolve_shared_audit_summary_jsonl_twin(cfg);
                let ch =
                    selfdef_integration_shared_audit_summary::SharedAuditSummaryChannel::with_paths_and_jsonl_twin(
                        path.clone(),
                        pointer.clone(),
                        jsonl_twin,
                    );
                inner.push((Box::new(ch), build_subscription(channel, cfg)));
                info!(
                    channel,
                    path = %path.display(),
                    pointer = %pointer.display(),
                    "notifier channel enabled (SDD-014)"
                );
            }
            "oracle-triage" if cfg.notifier.oracle_triage.enabled => {
                match build_oracle_triage_channel(cfg) {
                    Ok(ch) => {
                        inner.push((Box::new(ch), build_subscription(channel, cfg)));
                        info!(
                            channel,
                            endpoint = %cfg.notifier.oracle_triage.endpoint,
                            model = %cfg.notifier.oracle_triage.model,
                            "notifier channel enabled (SDD-016)"
                        );
                    }
                    Err(e) => warn!(channel, error = %e, "oracle-triage build failed"),
                }
            }
            other => warn!(channel = other, "notifier channel skipped (missing config)"),
        }
    }
    NotifierChain::with_subscriptions(inner)
}

/// SDD-016: build the oracle-triage Channel from [notifier.oracle_triage]
/// config. Threads severity-floor parsing + env-var key loading.
fn build_oracle_triage_channel(
    cfg: &Config,
) -> Result<selfdef_integration_oracle_triage::OracleTriageChannel, anyhow::Error> {
    use selfdef_integration_oracle_triage::{OracleTriageChannel, OutputTarget, TriageFilter};
    let c = &cfg.notifier.oracle_triage;
    let min_severity = parse_severity_token(&c.filter.min_severity)
        .unwrap_or(selfdef_core::severity::SeverityId::Medium);
    let filter = TriageFilter {
        min_severity,
        kinds: c.filter.kinds.clone(),
    };
    let output_target = match c.output_target.as_str() {
        "operator-dashboard" => OutputTarget::OperatorDashboard,
        "shared-audit-summary" => OutputTarget::SharedAuditSummary,
        "both" => OutputTarget::Both,
        other => {
            warn!(
                output_target = other,
                "oracle-triage: unknown output_target, defaulting to operator-dashboard"
            );
            OutputTarget::OperatorDashboard
        }
    };
    OracleTriageChannel::from_config(
        &c.endpoint,
        &c.model,
        c.timeout_seconds,
        c.api_key_env.as_deref(),
        filter,
        output_target,
        c.system_prompt_path.as_ref(),
        c.max_events_per_hour,
    )
    .map_err(anyhow::Error::from)
}

/// SDD-016: parse the severity_floor token used by the oracle-triage
/// filter. Returns None on unknown — caller falls back to Medium.
fn parse_severity_token(token: &str) -> Option<selfdef_core::severity::SeverityId> {
    use selfdef_core::severity::SeverityId;
    match token.to_ascii_lowercase().as_str() {
        "informational" | "info" => Some(SeverityId::Informational),
        "low" => Some(SeverityId::Low),
        "medium" | "warn" => Some(SeverityId::Medium),
        "high" => Some(SeverityId::High),
        "critical" | "error" => Some(SeverityId::Critical),
        "fatal" => Some(SeverityId::Fatal),
        _ => None,
    }
}

/// SDD-008 D-3: build the [`Subscription`] for a channel slug by
/// looking up `[notifier.subscriptions.<channel>]` in the config and
/// translating string-shaped fields into the typed
/// [`selfdef_notifier::Subscription`]. Missing entry returns the
/// default (accept-all) subscription.
/// SDD-008 D-5d: choose between the M4 fire-and-forget chain and
/// the persistent-engine dispatcher based on whether the operator
/// set `[notifier].escalations_path`.
///
/// - Path unset → build the existing `NotifierChain` (M4 path).
/// - Path set, engine opens OK → build `Vec<Arc<dyn Channel>>`,
///   wrap in `PayloadDispatcher`, spawn `wake_task::run` on the
///   shutdown token, return a `DispatcherAdapter` so the responder
///   sees an `Arc<dyn Notifier>` regardless.
/// - Path set, engine fails to open → log + fall back to M4. Daemon
///   startup never fails on a notifier misconfiguration.
#[allow(clippy::type_complexity)]
fn build_notifier_path(
    cfg: &Config,
    shutdown: &tokio_util::sync::CancellationToken,
) -> (
    Arc<dyn selfdef_notifier::Notifier>,
    Option<tokio::task::JoinHandle<()>>,
    Option<Arc<EscalationEngine>>,
) {
    let Some(escalations_path) = cfg.notifier.escalations_path.as_ref() else {
        let chain = build_notifier_chain(cfg);
        if chain.is_empty() {
            warn!("no notification channels configured");
        }
        return (Arc::new(chain), None, None);
    };

    match EscalationEngine::open(escalations_path) {
        Ok(engine) => {
            let engine = Arc::new(engine);
            let engine_for_api = Arc::clone(&engine);
            let channels = build_channel_set(cfg);
            if channels.is_empty() {
                warn!(
                    "no notification channels configured (escalation engine still active; \
                     wake task will run and clean up timed-out rows)",
                );
            }
            // SDD-008 D-5e: per-channel subscription filter now
            // applies on the engine path too. The pre-D-5e stopgap
            // warn (F-2031-009) is removed; the dispatcher consults
            // build_channel_subscriptions() before each channel.send.
            let channel_subscriptions = build_channel_subscriptions(cfg);
            if !channel_subscriptions.is_empty() {
                info!(
                    subscription_channels = ?channel_subscriptions.keys().collect::<Vec<_>>(),
                    "per-channel subscription filters loaded (D-5e)",
                );
            }
            let mode = parse_dispatcher_mode(&cfg.notifier.mode);
            let profile = parse_dispatcher_profile(&cfg.notifier.profile, cfg);
            let panic_floor = cfg.notifier.panic_floor.as_deref().and_then(|raw| {
                let parsed = parse_severity_floor(raw);
                if parsed.is_none() {
                    warn!(
                        value = raw,
                        "ignoring unknown [notifier].panic_floor; \
                             use one of informational|low|medium|high|critical|fatal; \
                             no panic floor will apply",
                    );
                }
                parsed
            });
            let mut dispatcher_builder = PayloadDispatcher::new(engine, channels)
                .with_mode(mode)
                .with_profile(profile.clone())
                .with_subscriptions(channel_subscriptions);
            if let Some(floor) = panic_floor {
                dispatcher_builder = dispatcher_builder.with_panic_floor(floor);
            }
            let dispatcher = Arc::new(dispatcher_builder);
            info!(
                path = %escalations_path.display(),
                channels = dispatcher.channel_count(),
                mode = mode.name(),
                profile = profile.name,
                max_rung = profile.max_rung(),
                panic_floor = ?panic_floor,
                "escalation engine enabled (SDD-008 D-5d + D-6b + D-7)",
            );
            let wake_handle = tokio::spawn({
                let d = Arc::clone(&dispatcher);
                let sd = shutdown.clone();
                async move { wake_task::run(d, sd).await }
            });
            let adapter: Arc<dyn selfdef_notifier::Notifier> = Arc::new(
                dispatcher_adapter::DispatcherAdapter::new(dispatcher)
                    .with_ack_link_base(cfg.notifier.ack_link_base.clone()),
            );
            (adapter, Some(wake_handle), Some(engine_for_api))
        }
        Err(e) => {
            error!(
                error = %e,
                path = %escalations_path.display(),
                "failed to open escalation engine; falling back to M4 fire-and-forget",
            );
            let chain = build_notifier_chain(cfg);
            if chain.is_empty() {
                warn!("no notification channels configured");
            }
            (Arc::new(chain), None, None)
        }
    }
}

/// SDD-008 D-5d: build the `Vec<Arc<dyn Channel>>` consumed by the
/// `PayloadDispatcher`. Parallels `build_notifier_chain` but
/// constructs the orchestrator-shaped trait objects instead of the
/// legacy chain.
///
/// Per-channel subscription filtering (D-3) is **applied** as of
/// D-5e: [`build_channel_subscriptions`] converts
/// `[notifier.subscriptions.<channel>]` config entries into the
/// `HashMap<String, Subscription>` that the dispatcher consults
/// before each `channel.send`.
fn build_channel_set(cfg: &Config) -> Vec<Arc<dyn Channel>> {
    let mut channels: Vec<Arc<dyn Channel>> = Vec::new();
    for channel in &cfg.notifier.channels {
        match channel.as_str() {
            "ntfy" if !cfg.notifier.ntfy.url.is_empty() && !cfg.notifier.ntfy.topic.is_empty() => {
                channels.push(Arc::new(NtfyNotifier::from_config(
                    &cfg.notifier.ntfy.url,
                    &cfg.notifier.ntfy.topic,
                    cfg.notifier.ntfy.token_file.as_ref(),
                )));
                info!(channel, "engine-channel enabled");
            }
            "signal"
                if !cfg.notifier.signal.account.is_empty()
                    && !cfg.notifier.signal.recipient.is_empty() =>
            {
                channels.push(Arc::new(SignalCliNotifier::new(
                    cfg.notifier.signal.binary.clone(),
                    cfg.notifier.signal.account.clone(),
                    cfg.notifier.signal.recipient.clone(),
                )));
                info!(channel, "engine-channel enabled");
            }
            "smtp"
                if !cfg.notifier.smtp.relay_host.is_empty() && !cfg.notifier.smtp.to.is_empty() =>
            {
                let tls = match cfg.notifier.smtp.tls.as_str() {
                    "implicit_tls" => selfdef_integration_smtp::TlsProfile::ImplicitTls,
                    "plain" => selfdef_integration_smtp::TlsProfile::Plain,
                    _ => selfdef_integration_smtp::TlsProfile::StartTls,
                };
                match selfdef_integration_smtp::SmtpNotifier::from_config(
                    &cfg.notifier.smtp.relay_host,
                    cfg.notifier.smtp.relay_port,
                    tls,
                    cfg.notifier.smtp.username.as_deref(),
                    cfg.notifier.smtp.password_file.as_ref(),
                    &cfg.notifier.smtp.from,
                    &cfg.notifier.smtp.to,
                    std::time::Duration::from_secs(cfg.notifier.smtp.timeout_secs),
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "smtp engine-channel skipped");
                    }
                }
            }
            "discord" if cfg.notifier.discord.webhook_url_file.is_some() => {
                let Some(url_path) = cfg.notifier.discord.webhook_url_file.as_ref() else {
                    continue;
                };
                match selfdef_integration_discord::DiscordNotifier::from_config(
                    url_path,
                    &cfg.notifier.discord.username,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "discord engine-channel skipped");
                    }
                }
            }
            "pagerduty" if cfg.notifier.pagerduty.routing_key_file.is_some() => {
                let Some(key_path) = cfg.notifier.pagerduty.routing_key_file.as_ref() else {
                    continue;
                };
                match selfdef_integration_pagerduty::PagerDutyNotifier::from_config(
                    key_path,
                    &cfg.notifier.pagerduty.endpoint,
                    &cfg.notifier.pagerduty.source,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "pagerduty engine-channel skipped");
                    }
                }
            }
            "loki" if !cfg.notifier.loki.endpoint.is_empty() => {
                match selfdef_integration_loki::LokiNotifier::from_config(
                    &cfg.notifier.loki.endpoint,
                    &cfg.notifier.loki.tenant_id,
                    cfg.notifier.loki.auth_token_file.as_ref(),
                    &cfg.notifier.loki.source,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "loki engine-channel skipped");
                    }
                }
            }
            "opensearch" if !cfg.notifier.opensearch.endpoint.is_empty() => {
                match selfdef_integration_opensearch::OpenSearchNotifier::from_config(
                    &cfg.notifier.opensearch.endpoint,
                    &cfg.notifier.opensearch.index,
                    &cfg.notifier.opensearch.auth_kind,
                    &cfg.notifier.opensearch.username,
                    cfg.notifier.opensearch.auth_token_file.as_ref(),
                    &cfg.notifier.opensearch.source,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "opensearch engine-channel skipped");
                    }
                }
            }
            "thehive"
                if !cfg.notifier.thehive.endpoint.is_empty()
                    && cfg.notifier.thehive.api_key_file.is_some() =>
            {
                let Some(key_path) = cfg.notifier.thehive.api_key_file.as_ref() else {
                    continue;
                };
                match selfdef_integration_thehive::TheHiveNotifier::from_config(
                    &cfg.notifier.thehive.endpoint,
                    key_path,
                    &cfg.notifier.thehive.source,
                    &cfg.notifier.thehive.alert_type,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "thehive engine-channel skipped");
                    }
                }
            }
            "slack" if cfg.notifier.slack.webhook_url_file.is_some() => {
                let Some(url_path) = cfg.notifier.slack.webhook_url_file.as_ref() else {
                    continue;
                };
                match selfdef_integration_slack::SlackNotifier::from_config(
                    url_path,
                    &cfg.notifier.slack.username,
                    &cfg.notifier.slack.icon_emoji,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "slack engine-channel skipped");
                    }
                }
            }
            "twilio"
                if !cfg.notifier.twilio.account_sid.is_empty()
                    && !cfg.notifier.twilio.to.is_empty() =>
            {
                let Some(token_path) = cfg.notifier.twilio.auth_token_file.as_ref() else {
                    warn!(
                        channel,
                        "twilio engine-channel skipped (auth_token_file not set)"
                    );
                    continue;
                };
                match selfdef_integration_twilio::TwilioNotifier::from_config(
                    &cfg.notifier.twilio.account_sid,
                    token_path,
                    &cfg.notifier.twilio.from,
                    &cfg.notifier.twilio.to,
                    std::time::Duration::from_secs(cfg.notifier.twilio.timeout_secs),
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "twilio engine-channel skipped");
                    }
                }
            }
            "wall" if !cfg.notifier.wall.binary.as_os_str().is_empty() => {
                let floor = if cfg.notifier.wall.severity_floor.is_empty() {
                    None
                } else {
                    Some(cfg.notifier.wall.severity_floor.as_str())
                };
                match selfdef_integration_wall::WallChannel::from_config(
                    &cfg.notifier.wall.binary,
                    floor,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "wall engine-channel skipped");
                    }
                }
            }
            "write"
                if !cfg.notifier.write.binary.as_os_str().is_empty()
                    && !cfg.notifier.write.users.is_empty() =>
            {
                let floor = if cfg.notifier.write.severity_floor.is_empty() {
                    None
                } else {
                    Some(cfg.notifier.write.severity_floor.as_str())
                };
                match selfdef_integration_write::WriteChannel::from_config(
                    &cfg.notifier.write.binary,
                    floor,
                    &cfg.notifier.write.users,
                ) {
                    Ok(n) => {
                        channels.push(Arc::new(n));
                        info!(channel, "engine-channel enabled");
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "write engine-channel skipped");
                    }
                }
            }
            "shared-audit-summary" if selfdef_config::resolve_shared_audit_summary_enabled(cfg) => {
                let Some(path) = selfdef_config::resolve_shared_audit_summary_path(cfg) else {
                    warn!(
                        channel,
                        "shared-audit-summary enabled but no path resolvable (generic target without override?)"
                    );
                    continue;
                };
                let pointer = selfdef_config::resolve_shared_audit_summary_pointer(cfg);
                let jsonl_twin = selfdef_config::resolve_shared_audit_summary_jsonl_twin(cfg);
                let ch =
                    selfdef_integration_shared_audit_summary::SharedAuditSummaryChannel::with_paths_and_jsonl_twin(
                        path.clone(),
                        pointer.clone(),
                        jsonl_twin,
                    );
                channels.push(Arc::new(ch));
                info!(
                    channel,
                    path = %path.display(),
                    pointer = %pointer.display(),
                    "engine-channel enabled (SDD-014)"
                );
            }
            "oracle-triage" if cfg.notifier.oracle_triage.enabled => {
                match build_oracle_triage_channel(cfg) {
                    Ok(ch) => {
                        channels.push(Arc::new(ch));
                        info!(
                            channel,
                            endpoint = %cfg.notifier.oracle_triage.endpoint,
                            "engine-channel enabled (SDD-016)"
                        );
                    }
                    Err(e) => {
                        warn!(channel, error = %e, "oracle-triage engine-channel skipped");
                    }
                }
            }
            other => warn!(channel = other, "engine-channel skipped (missing config)"),
        }
    }
    channels
}

/// SDD-008 D-5e: collect every `[notifier.subscriptions.<channel>]`
/// entry from the config into the dispatcher's `HashMap<String,
/// Subscription>` keyed by channel name. Channels without an entry
/// are absent from the map, which the dispatcher treats as
/// "no filter → fire on every event" (legacy behaviour).
///
/// Unknown `severity_floor` strings log a warn and parse as `None`,
/// matching `build_subscription`'s posture on the legacy chain path.
fn build_channel_subscriptions(
    cfg: &Config,
) -> std::collections::HashMap<String, OrchestratorSubscription> {
    let mut map = std::collections::HashMap::new();
    for (channel, sc) in &cfg.notifier.subscriptions {
        let severity_floor = sc.severity_floor.as_deref().and_then(|raw| {
            let parsed = parse_severity_floor(raw);
            if parsed.is_none() {
                warn!(
                    channel,
                    value = raw,
                    "ignoring unknown severity_floor in [notifier.subscriptions] (engine path); \
                     use one of informational|low|medium|high|critical|fatal",
                );
            }
            parsed
        });
        map.insert(
            channel.clone(),
            OrchestratorSubscription {
                severity_floor,
                event_kinds: sc.event_kinds.clone(),
            },
        );
    }
    map
}

fn build_subscription(channel: &str, cfg: &Config) -> Subscription {
    let Some(sc) = cfg.notifier.subscriptions.get(channel) else {
        return Subscription::default();
    };
    let severity_floor = sc.severity_floor.as_deref().and_then(|raw| {
        let parsed = parse_severity_floor(raw);
        if parsed.is_none() {
            warn!(
                channel,
                value = raw,
                "ignoring unknown severity_floor in [notifier.subscriptions]; \
                 use one of informational|low|medium|high|critical|fatal",
            );
        }
        parsed
    });
    Subscription {
        severity_floor,
        event_kinds: sc.event_kinds.clone(),
    }
}

/// SDD-008 D-6a: parse the `[notifier].mode` string into a typed
/// [`Mode`]. Unknown strings log a warn and fall back to the
/// default (`Enforce`) — never fail daemon startup on a typo.
fn parse_dispatcher_mode(raw: &str) -> Mode {
    match Mode::from_str_ci(raw) {
        Some(m) => m,
        None => {
            warn!(
                value = raw,
                "ignoring unknown [notifier].mode; use one of enforce|audit; falling back to enforce",
            );
            Mode::default()
        }
    }
}

/// SDD-008 D-6b / D-6c: resolve `[notifier].profile` against a
/// custom-profile table first, then fall back to the three built-
/// ins. Unknown name + missing table entry logs a warn and falls
/// back to the default (`auto`).
///
/// Lookup order:
/// 1. Operator-defined `[notifier.profiles.<raw>]` (D-6c) — if the
///    name matches a custom-profile key, build via
///    [`Profile::custom`]. Empty rung list rejects the profile and
///    falls through to step 2.
/// 2. Built-in name parse (D-6b) — `auto` / `aggressive` /
///    `patient`.
/// 3. Default (`auto`) — logged warn.
fn parse_dispatcher_profile(raw: &str, cfg: &Config) -> Profile {
    // Step 1: operator-defined custom profile.
    if let Some(custom_cfg) = cfg.notifier.profiles.get(raw) {
        let rungs: Vec<selfdef_notifier_engine::Rung> = custom_cfg
            .rungs
            .iter()
            .enumerate()
            .map(|(idx, r)| {
                let window = if r.ack_window_secs > 0 {
                    r.ack_window_secs
                } else {
                    // SDD-008 D-6c: an invalid ack_window_secs (zero
                    // or negative — a typo / operator misconfig) used
                    // to silently become 300. Now warns first so the
                    // operator notices the bad config instead of
                    // wondering why their "aggressive" profile
                    // ack-waits 5 minutes on this rung.
                    warn!(
                        profile = raw,
                        rung = idx,
                        configured = r.ack_window_secs,
                        fallback_secs = 300,
                        "invalid ack_window_secs (must be > 0) in [[notifier.profiles.<name>.rungs]]; falling back to 300s",
                    );
                    300
                };
                if r.channels.is_empty() {
                    selfdef_notifier_engine::Rung::new(window)
                } else {
                    selfdef_notifier_engine::Rung::with_channels(window, r.channels.clone())
                }
            })
            .collect();
        match Profile::custom(raw, rungs) {
            Ok(p) => {
                info!(profile = raw, "loaded custom escalation profile");
                return p;
            }
            Err(e) => {
                warn!(
                    profile = raw,
                    error = %e,
                    "custom [notifier.profiles.<name>] rejected; falling back to named built-in",
                );
            }
        }
    }
    // Step 2: built-in name.
    match Profile::from_name(raw) {
        Some(p) => p,
        None => {
            warn!(
                value = raw,
                "ignoring unknown [notifier].profile; use one of auto|aggressive|patient or define one under [notifier.profiles.<name>]; falling back to auto",
            );
            Profile::default()
        }
    }
}

/// Parse the string shape used in `[notifier.subscriptions.<ch>].severity_floor`
/// into a [`selfdef_core::severity::SeverityId`]. Unknown strings return
/// `None`; the caller logs a warn and treats it as no floor.
fn parse_severity_floor(s: &str) -> Option<selfdef_core::severity::SeverityId> {
    use selfdef_core::severity::SeverityId;
    match s.to_ascii_lowercase().as_str() {
        "info" | "informational" => Some(SeverityId::Informational),
        "low" => Some(SeverityId::Low),
        "medium" | "med" => Some(SeverityId::Medium),
        "high" => Some(SeverityId::High),
        "critical" | "crit" => Some(SeverityId::Critical),
        "fatal" => Some(SeverityId::Fatal),
        _ => None,
    }
}

fn init_tracing(level_override: Option<&str>, log_format: &str) -> Result<()> {
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

    let filter = level_override.map_or_else(EnvFilter::from_default_env, |lvl| {
        EnvFilter::try_new(lvl).unwrap_or_else(|_| EnvFilter::new("info"))
    });

    if let Ok(journald) = tracing_journald::layer() {
        // journald carries structured fields natively; [daemon].log_format
        // applies to the stderr fallback below (no journald socket).
        tracing_subscriber::registry()
            .with(filter)
            .with(journald)
            .try_init()
            .context("initialize journald tracing")?;
    } else if log_format == "json" {
        // [daemon].log_format = "json": structured stderr for log ingest.
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_target(true).json())
            .try_init()
            .context("initialize stderr JSON tracing")?;
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .try_init()
            .context("initialize stderr tracing")?;
    }
    Ok(())
}

async fn wait_for_shutdown_or_reload(
    correlator: Option<&Arc<Correlator>>,
    api_token_reloader: Option<&selfdef_api::TokenReloader>,
) {
    use selfdef_correlator::ReloadVerifierError;
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
    // SDD-004 F-2026-023 follow-up: SIGUSR2 triggers an api-token
    // reload. Pairs with `selfdefctl api rotate-token`, which
    // writes a new token to `api.token_file` then signals the
    // daemon to pick it up.
    let mut usr2 = signal(SignalKind::user_defined2()).ok();

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
            _ = async {
                if let Some(u) = usr2.as_mut() {
                    u.recv().await;
                } else {
                    std::future::pending::<Option<()>>().await;
                }
            } => {
                info!("SIGUSR2 received");
                // SIGUSR2 fans out to every hot-reloadable thing
                // the daemon owns. Each branch logs at info/warn
                // independently; one failure does not block the
                // others.
                //
                // F-2027-032: track per-branch outcome so we can
                // emit a single summary line at the end. Without
                // it, operators reading journalctl after a
                // SIGUSR2 have to mentally correlate two or three
                // separate log lines to know "did the reload
                // overall succeed?". The summary line answers
                // that in one glance.
                let mut did_anything = false;
                let mut token_outcome: &'static str = "skipped";
                let mut verifier_outcome: &'static str = "skipped";
                let mut rules_outcome: &'static str = "skipped";

                if let Some(rel) = api_token_reloader {
                    did_anything = true;
                    match rel.reload() {
                        Ok(()) => {
                            info!("api tokens reloaded from disk");
                            token_outcome = "ok";
                        }
                        Err(e) => {
                            warn!(error = %e, "api token reload failed; keeping previous tokens");
                            token_outcome = "failed";
                        }
                    }
                }
                // F-2027-005: rotate the rule-signing public key
                // without a restart. After re-loading, also
                // re-run `load_rules` so any rules signed by a
                // key version the previous Verifier didn't trust
                // get picked up.
                if let Some(corr) = correlator
                    && corr.has_verifier()
                {
                    did_anything = true;
                    match corr.reload_verifier() {
                        Ok(path) => {
                            info!(key = %path.display(), "rule-signing verifier reloaded from disk");
                            verifier_outcome = "ok";
                            match corr.load_rules() {
                                Ok(n) => {
                                    info!(rules = n, "rules re-verified after verifier reload");
                                    rules_outcome = "ok";
                                }
                                Err(e) => {
                                    warn!(error = %e, "rule re-verify after verifier reload failed; keeping previous ruleset");
                                    rules_outcome = "failed";
                                }
                            }
                        }
                        Err(ReloadVerifierError::NoVerifierConfigured) => {
                            // Should be unreachable given the
                            // has_verifier guard above, but
                            // handle defensively.
                            debug!("verifier reload skipped — none attached");
                        }
                        Err(e @ ReloadVerifierError::Load(..)) => {
                            warn!(error = %e, "verifier reload failed; keeping previous verifier");
                            verifier_outcome = "failed";
                            // Rules outcome stays "skipped" — we
                            // don't run load_rules when the
                            // verifier reload failed, by design.
                        }
                    }
                }
                if !did_anything {
                    debug!("SIGUSR2 received but no hot-reloadable surface is enabled; ignoring");
                } else {
                    // F-2027-032: single-glance summary. Logged at
                    // info regardless of mix; operators correlate
                    // the three outcomes in one line.
                    info!(
                        tokens = token_outcome,
                        verifier = verifier_outcome,
                        rules = rules_outcome,
                        "SIGUSR2 reload summary",
                    );
                }
                // continue the loop — don't exit on SIGUSR2
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
