//! `selfdef-scheduler-decide` — one-shot request-ingress tool (MS048).
//!
//! The request-ingress entry point of the Goldilocks scheduler: reads a TASK
//! descriptor (the scheduling "request" — a profile + the four model-estimated
//! axes), polls the live substrate, runs the full
//! [`selfdef_scheduler::decide::decide_persist_and_emit`] pipeline (score →
//! route under the Key Scheduling Law → Decision → audit chain + ring + OCSF),
//! and prints the resulting [`selfdef_scheduler::Decision`] as JSON.
//!
//! This is the dump's request lifecycle step 1 ("User request arrives") made
//! concrete (dump 846). It is a one-shot binary — like
//! `selfdef-scheduler-textfile` — NOT a new HTTP route or `selfdefctl`
//! subverb, so the 5-route / 7-subverb operator contracts are untouched. A
//! daemon loop or the sovereign-os gateway can invoke it per request, or CI
//! can submit a canned task and assert the routing.
//!
//! Task descriptor (JSON, from `--task-file PATH` or stdin):
//!
//! ```json
//! {
//!   "request_id": "req-...",          // optional; generated if absent
//!   "profile": "careful",             // fast|careful|private|autonomous|experimental|production
//!   "latency": 0.7, "cost": 0.7, "risk": 0.2, "energy": 0.7
//! }
//! ```
//!
//! Substrate axes (hardware_pressure, human_attention) are measured from the
//! live poll, never taken from the task.
//!
//! Standing rule: We do not minimize anything.

use std::env;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use selfdef_scheduler::backpressure_driver::BackpressureDriver;
use selfdef_scheduler::config::{DEFAULT_CONFIG_PATH, SchedulerConfig};
use selfdef_scheduler::dcgm::NvidiaSmiDcgmSource;
use selfdef_scheduler::decide::{RequestContext, decide_persist_and_emit};
use selfdef_scheduler::human_gate::IpsPendingRestoresHumanGateSource;
use selfdef_scheduler::objective_signals::DEFAULT_HUMAN_ATTENTION_QUEUE_CAP;
use selfdef_scheduler::psi::ProcfsPsiSource;
use selfdef_scheduler::{AxisSignals, DEFAULT_RING_MAX_ENTRIES, Profile, now_ms};

use serde::Deserialize;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The task descriptor read from `--task-file` / stdin.
#[derive(Debug, Deserialize)]
struct TaskInput {
    #[serde(default)]
    request_id: Option<String>,
    profile: String,
    #[serde(default = "half")]
    latency: f32,
    #[serde(default = "half")]
    cost: f32,
    #[serde(default = "half")]
    risk: f32,
    #[serde(default = "half")]
    energy: f32,
}

fn half() -> f32 {
    0.5
}

fn parse_profile(s: &str) -> Option<Profile> {
    match s.to_ascii_lowercase().as_str() {
        "fast" => Some(Profile::Fast),
        "careful" => Some(Profile::Careful),
        "private" => Some(Profile::Private),
        "autonomous" => Some(Profile::Autonomous),
        "experimental" => Some(Profile::Experimental),
        "production" => Some(Profile::Production),
        _ => None,
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    env::var(name).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(default))
}

fn env_path_with_default(name: &str, default: &Path) -> PathBuf {
    env::var(name).map(PathBuf::from).unwrap_or_else(|_| default.to_path_buf())
}

fn read_task_input() -> Result<String, String> {
    // --task-file PATH, else stdin.
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--task-file" {
            let p = args.next().ok_or("--task-file needs a PATH")?;
            return std::fs::read_to_string(&p).map_err(|e| format!("read {p}: {e}"));
        }
    }
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("read stdin: {e}"))?;
    Ok(buf)
}

fn main() -> ExitCode {
    let raw = match read_task_input() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[selfdef-scheduler-decide {VERSION}] FAIL reading task: {e}");
            return ExitCode::from(2);
        }
    };
    let task: TaskInput = match serde_json::from_str(&raw) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[selfdef-scheduler-decide {VERSION}] FAIL parsing task JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let Some(profile) = parse_profile(&task.profile) else {
        eprintln!(
            "[selfdef-scheduler-decide {VERSION}] FAIL unknown profile {:?} (expected fast|careful|private|autonomous|experimental|production)",
            task.profile
        );
        return ExitCode::from(2);
    };

    // Config + substrate/emit paths (env overrides, same knobs as the textfile binary).
    let config_path = env_path("SELFDEF_SCHEDULER_CONFIG", DEFAULT_CONFIG_PATH);
    let cfg = SchedulerConfig::load_from(&config_path).unwrap_or_default();
    let psi_dir = env_path_with_default("SELFDEF_SCHEDULER_PSI_DIR", &cfg.substrate.psi_dir);
    let nvidia_smi =
        env_path_with_default("SELFDEF_SCHEDULER_NVIDIA_SMI_BIN", &cfg.substrate.nvidia_smi_bin);
    let state_root =
        env_path_with_default("SELFDEF_SCHEDULER_STATE_ROOT", &cfg.substrate.state_root);
    let audit_path = env_path_with_default("SELFDEF_SCHEDULER_AUDIT_PATH", &cfg.emit.audit_path);
    let ring_dir = env_path_with_default("SELFDEF_SCHEDULER_RING_DIR", &cfg.emit.ring_dir);
    let ocsf_path = env_path_with_default("SELFDEF_SCHEDULER_OCSF_PATH", &cfg.emit.ocsf_path);

    // Poll the live substrate (honest-offline when sources are absent).
    let mut driver = BackpressureDriver::new(
        Box::new(ProcfsPsiSource::with_dir(&psi_dir)),
        Box::new(NvidiaSmiDcgmSource::new().with_command_path(&nvidia_smi)),
        Box::new(IpsPendingRestoresHumanGateSource::with_state_root(&state_root)),
    );
    let reading = driver.poll();

    let request_id = task
        .request_id
        .unwrap_or_else(|| format!("req-{}-{}", now_ms(), std::process::id()));
    let ctx = RequestContext {
        request_id,
        profile,
        model_signals: AxisSignals {
            latency: task.latency,
            cost: task.cost,
            risk: task.risk,
            energy: task.energy,
            human_attention: 0.0,   // overwritten from substrate
            hardware_pressure: 0.0, // overwritten from substrate
        },
        max_queue: DEFAULT_HUMAN_ATTENTION_QUEUE_CAP,
        ts_ms: now_ms(),
        hostname: hostname(),
        signer_kid_policy: cfg.signer.kid.clone().unwrap_or_else(|| "unsigned".to_string()),
    };

    match decide_persist_and_emit(
        &reading,
        &ctx,
        &audit_path,
        &ring_dir,
        DEFAULT_RING_MAX_ENTRIES,
        &ocsf_path,
    ) {
        Ok(decision) => {
            // The decision JSON to stdout (the operator/caller's result).
            match serde_json::to_string_pretty(&decision) {
                Ok(j) => {
                    println!("{j}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("[selfdef-scheduler-decide {VERSION}] FAIL serializing decision: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("[selfdef-scheduler-decide {VERSION}] FAIL deciding: {e}");
            ExitCode::from(1)
        }
    }
}

fn hostname() -> String {
    env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}
