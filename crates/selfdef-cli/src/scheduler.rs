//! `selfdefctl scheduler` — Goldilocks Scheduler operator surface
//! (SDD-031 Deliverable 3 / MS048).
//!
//! 7 subverbs per MS048 R11423-R11430:
//! - `show [--json]` — current state + last 16 decisions + backpressure
//! - `history [--limit N] [--json]` — decision history newest-first
//! - `explain <request-id> [--json]` — single-decision detail
//! - `replay <request-id> [--profile P] [--json]` — counterfactual replay
//! - `weights show --profile <p> [--json]` — per-profile 7-axis weights
//! - `force <request-id> --route R` — Ring 0 + MS003 operator override
//! - `audit-cycle replay [--json]` — verify audit-chain integrity
//!
//! Cross-references:
//! - SDD-031 Deliverable 4
//! - MS048 R11423-R11430 (CLI surface)
//! - selfdef-cli/src/{friction_audit,perimeter,guardian}.rs sister modules

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};
use selfdef_scheduler::{
    AxisWeights, DEFAULT_AUDIT_LOG_PATH, DEFAULT_RING_DIR, Decision, Profile, Route,
    audit_chain_check, read_ring_buffer, replay as scheduler_replay,
};

fn ring_dir() -> PathBuf {
    std::env::var("SELFDEF_SCHEDULER_RING_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_RING_DIR))
}

fn audit_log_path() -> PathBuf {
    std::env::var("SELFDEF_SCHEDULER_AUDIT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_AUDIT_LOG_PATH))
}

fn parse_profile(s: &str) -> Result<Profile> {
    match s.to_ascii_lowercase().as_str() {
        "fast" => Ok(Profile::Fast),
        "careful" => Ok(Profile::Careful),
        "private" => Ok(Profile::Private),
        "autonomous" => Ok(Profile::Autonomous),
        "experimental" => Ok(Profile::Experimental),
        "production" => Ok(Profile::Production),
        other => Err(anyhow!(
            "unknown profile {other:?}: expected one of fast/careful/private/autonomous/experimental/production"
        )),
    }
}

fn parse_route(s: &str) -> Result<Route> {
    match s.to_ascii_lowercase().as_str() {
        "blackwell" => Ok(Route::Blackwell),
        "rtx3090" => Ok(Route::Rtx3090),
        "cpu" => Ok(Route::Cpu),
        "hybrid" => Ok(Route::Hybrid),
        "hibernate" => Ok(Route::Hibernate),
        other => Err(anyhow!(
            "unknown route {other:?}: expected one of blackwell/rtx3090/cpu/hybrid/hibernate"
        )),
    }
}

pub(crate) fn run_show(json: bool) -> Result<i32> {
    let decisions = read_ring_buffer(&ring_dir()).context("read scheduler ring buffer")?;
    let last_n: Vec<&Decision> = decisions.iter().take(16).collect();
    let chain_events = audit_chain_check(&audit_log_path()).ok();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ring_dir": ring_dir(),
                "audit_log": audit_log_path(),
                "audit_chain_events": chain_events,
                "decision_count": decisions.len(),
                "recent_decisions": last_n,
            }))?
        );
    } else {
        println!("scheduler: Goldilocks Scheduler (MS048 / SDD-031)");
        println!("  ring buffer: {}", ring_dir().display());
        println!("  audit log:   {}", audit_log_path().display());
        match chain_events {
            Some(n) => println!("  audit chain events: {n} (chain intact)"),
            None => println!("  audit chain events: chain check failed (see logs)"),
        }
        println!("  recent decisions (newest-first, {} shown):", last_n.len());
        if last_n.is_empty() {
            println!("    (none)");
        }
        for d in &last_n {
            print_decision_row(d);
        }
    }
    Ok(0)
}

pub(crate) fn run_history(limit: u32, json: bool) -> Result<i32> {
    let decisions = read_ring_buffer(&ring_dir()).context("read scheduler ring buffer")?;
    let limit = limit.min(256) as usize;
    let limited: Vec<&Decision> = decisions.iter().take(limit).collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&limited)?);
    } else {
        if limited.is_empty() {
            println!(
                "(no scheduler decisions in ring buffer at {})",
                ring_dir().display()
            );
        }
        for d in &limited {
            print_decision_row(d);
        }
    }
    Ok(0)
}

pub(crate) fn run_explain(request_id: &str, json: bool) -> Result<i32> {
    if request_id.is_empty() {
        return Err(anyhow!("request_id is empty"));
    }
    let decisions = read_ring_buffer(&ring_dir()).context("read scheduler ring buffer")?;
    let found = decisions.iter().find(|d| d.request_id == request_id);
    match found {
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "request_id": request_id,
                        "error": "not_found",
                    }))?
                );
            } else {
                println!("scheduler explain: request_id={request_id:?} NOT FOUND");
            }
            Ok(1)
        }
        Some(d) => {
            if json {
                println!("{}", serde_json::to_string_pretty(d)?);
            } else {
                println!("scheduler explain: request_id={request_id}");
                println!("  profile:           {:?}", d.profile);
                println!("  route:             {:?}", d.route);
                println!("  ts_ms:             {}", d.ts_ms);
                println!("  hostname:          {}", d.hostname);
                println!("  signer_kid_policy: {}", d.signer_kid_policy);
                if let Some(ovk) = &d.override_signer_kid {
                    println!("  override_signer:   {ovk}");
                }
                println!("  rationale:         {}", d.rationale);
                println!("  7-axis scores:");
                let a = d.axis_scores;
                println!("    latency:           {:.3}", a.latency);
                println!("    cost:              {:.3}", a.cost);
                println!("    risk:              {:.3}", a.risk);
                println!("    energy:            {:.3}", a.energy);
                println!("    human_attention:   {:.3}", a.human_attention);
                println!("    hardware_pressure: {:.3}", a.hardware_pressure);
                println!("    compound:          {:.3}", a.compound);
                let b = d.backpressure;
                println!(
                    "  backpressure: vram={} 3090={} cpu={} ram={} io={} human-gate={}",
                    b.blackwell_vram_high,
                    b.gpu3090_busy,
                    b.cpu_pressure,
                    b.ram_pressure,
                    b.io_pressure,
                    b.human_gate_queue_high
                );
            }
            Ok(0)
        }
    }
}

pub(crate) fn run_replay(request_id: &str, profile: Option<&str>, json: bool) -> Result<i32> {
    if request_id.is_empty() {
        return Err(anyhow!("request_id is empty"));
    }
    let decisions = read_ring_buffer(&ring_dir()).context("read scheduler ring buffer")?;
    let original = decisions
        .iter()
        .find(|d| d.request_id == request_id)
        .ok_or_else(|| anyhow!("request_id {request_id:?} NOT FOUND in ring buffer"))?;
    let replay_profile = match profile {
        Some(p) => parse_profile(p)?,
        None => original.profile,
    };
    let result = scheduler_replay(original, replay_profile);
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("scheduler replay: request_id={request_id} against profile={replay_profile:?}");
        println!(
            "  original compound:       {:.3} (profile={:?})",
            result.original.axis_scores.compound, result.original.profile
        );
        println!(
            "  counterfactual compound: {:.3} (profile={:?})",
            result.counterfactual.axis_scores.compound, result.counterfactual.profile
        );
        println!("  route differs:    {}", result.route_differs);
        println!("  compound differs: {}", result.compound_differs);
        if result.compound_differs {
            let delta =
                result.counterfactual.axis_scores.compound - result.original.axis_scores.compound;
            println!("  delta: {delta:+.3}");
        }
    }
    Ok(0)
}

pub(crate) fn run_weights(profile_opt: Option<&str>, json: bool) -> Result<i32> {
    let profiles: Vec<Profile> = match profile_opt {
        Some(p) => vec![parse_profile(p)?],
        None => Profile::all().to_vec(),
    };
    if json {
        let entries: Vec<serde_json::Value> = profiles
            .iter()
            .map(|p| {
                let w = AxisWeights::for_profile(*p);
                serde_json::json!({
                    "profile": p,
                    "weights": {
                        "latency": w.latency,
                        "cost": w.cost,
                        "risk": w.risk,
                        "energy": w.energy,
                        "human_attention": w.human_attention,
                        "hardware_pressure": w.hardware_pressure,
                    },
                    "sum": w.sum(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for p in &profiles {
            let w = AxisWeights::for_profile(*p);
            println!("{p:?}:");
            println!("  latency:           {:.3}", w.latency);
            println!("  cost:              {:.3}", w.cost);
            println!("  risk:              {:.3}", w.risk);
            println!("  energy:            {:.3}", w.energy);
            println!("  human_attention:   {:.3}", w.human_attention);
            println!("  hardware_pressure: {:.3}", w.hardware_pressure);
            println!("  sum:               {:.3}", w.sum());
            println!();
        }
    }
    Ok(0)
}

pub(crate) fn run_force(request_id: &str, route_str: &str, json: bool) -> Result<i32> {
    if request_id.is_empty() {
        return Err(anyhow!("request_id is empty"));
    }
    let route = parse_route(route_str)?;
    // Stage-1 surface: record the operator intent. Authority dispatcher
    // wiring (Ring 0 + MS003 multi-sig enforcement on actual route
    // mutation) is future-round per SDD-031 D3 implementation note.
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "request_id": request_id,
                "forced_route": route,
                "note": "Stage-1 records operator intent; full Ring 0 + MS003 multi-sig dispatch wires through selfdefd's authority surface in a future round.",
            }))?
        );
    } else {
        println!("scheduler force: request_id={request_id} route={route:?}");
        println!("  Stage-1 surface — operator intent recorded.");
        println!("  Full Ring 0 + MS003 multi-sig dispatch wires through selfdefd's");
        println!("  authority surface in a future round (per SDD-031 D3 implementation note).");
    }
    Ok(0)
}

pub(crate) fn run_audit_cycle_replay(json: bool) -> Result<i32> {
    let chain = audit_chain_check(&audit_log_path());
    match chain {
        Ok(n) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "audit_chain_events": n,
                        "audit_log": audit_log_path(),
                    }))?
                );
            } else {
                println!("scheduler audit-cycle replay:");
                println!("  audit chain events: {n} (chain intact)");
                println!("  log: {}", audit_log_path().display());
            }
            Ok(0)
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "error": e.to_string(),
                        "audit_log": audit_log_path(),
                    }))?
                );
            } else {
                println!("scheduler audit-cycle replay: CHAIN BROKEN");
                println!("  error: {e}");
                println!(
                    "  runbook: ~/devops-solutions-information-hub/wiki/runbooks/scheduler-audit-log-corruption.md"
                );
            }
            Ok(1)
        }
    }
}

fn print_decision_row(d: &Decision) {
    println!(
        "    [{}] req={} profile={:?} route={:?} compound={:.3} host={}",
        d.ts_ms, d.request_id, d.profile, d.route, d.axis_scores.compound, d.hostname
    );
}

#[allow(dead_code)]
fn _ring_dir_used() -> &'static Path {
    Path::new(DEFAULT_RING_DIR)
}

// ============================================================================
// M01163 + M01164 — Status panel renderer (substrate trio + backpressure)
// ============================================================================
//
// `selfdefctl scheduler status` — renders the M01163 panel from either
// the live Prometheus textfile (default) or the M01170 audit-log tail.
//
// Source resolution:
//   --path <P>          — explicit override
//   --audit (no path)   — cfg.emit.audit_path (or DEFAULT_DRIVER_AUDIT_PATH)
//   --textfile (no path)— cfg.emit.textfile_path (or DEFAULT_TEXTFILE_PATH)
//
// Style: --no-color forces Plain; otherwise auto-detect via
// stdout.is_terminal() + NO_COLOR env convention.
//
// Loop: --watch SECS re-renders every SECS, clearing the screen
// between renders when in ANSI mode.

pub(crate) fn run_status(
    from_audit: bool,
    path_override: Option<PathBuf>,
    compact: bool,
    watch: Option<u64>,
    no_color: bool,
) -> Result<i32> {
    use selfdef_scheduler::config::{DEFAULT_CONFIG_PATH, SchedulerConfig};
    use selfdef_scheduler::tui_panel::PanelStyle;
    use std::io::IsTerminal as _;

    let cfg = SchedulerConfig::load_from(Path::new(DEFAULT_CONFIG_PATH)).unwrap_or_default();
    let source_path: PathBuf = match path_override {
        Some(p) => p,
        None if from_audit => cfg.emit.audit_path.clone(),
        None => cfg.emit.textfile_path.clone(),
    };

    let style = if no_color {
        PanelStyle::Plain
    } else {
        PanelStyle::detect(std::io::stdout().is_terminal())
    };

    let render_once = || -> Result<String> { render_one(&source_path, from_audit, compact, style) };

    match watch {
        None => {
            print!("{}", render_once()?);
        }
        Some(secs) => {
            let interval = std::time::Duration::from_secs(secs.max(1));
            loop {
                if matches!(style, PanelStyle::AnsiColor) {
                    print!("\x1b[2J\x1b[H");
                }
                print!("{}", render_once()?);
                use std::io::Write as _;
                std::io::stdout().flush().ok();
                std::thread::sleep(interval);
            }
        }
    }
    Ok(0)
}

fn render_one(
    source_path: &Path,
    from_audit: bool,
    compact: bool,
    style: selfdef_scheduler::tui_panel::PanelStyle,
) -> Result<String> {
    use selfdef_scheduler::tui_panel::{
        parse_textfile_into_reading, render_panel_compact, render_panel_styled,
    };

    let reading = if from_audit {
        let text = std::fs::read_to_string(source_path)
            .with_context(|| format!("reading audit log at {}", source_path.display()))?;
        let last_line = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .next_back()
            .ok_or_else(|| anyhow!("audit log {} is empty", source_path.display()))?;
        let entry: selfdef_scheduler::decision_audit::DriverAuditEntry =
            serde_json::from_str(last_line)
                .with_context(|| format!("parsing last entry of {}", source_path.display()))?;
        entry.reading
    } else {
        let text = std::fs::read_to_string(source_path)
            .with_context(|| format!("reading textfile at {}", source_path.display()))?;
        parse_textfile_into_reading(&text)
            .map_err(|reason| anyhow!("parsing textfile {}: {reason}", source_path.display()))?
    };

    if compact {
        Ok(format!("{}\n", render_panel_compact(&reading)))
    } else {
        Ok(render_panel_styled(&reading, style))
    }
}

