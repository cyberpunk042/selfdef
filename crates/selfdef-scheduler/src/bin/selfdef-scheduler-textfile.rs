//! `selfdef-scheduler-textfile` — M01174: one-shot poll-and-emit binary.
//!
//! Pattern: parallel to the 14 IPS observer shell scripts
//! (`packaging/scripts/selfdef-*-textfile.sh`). Runs ONE
//! `BackpressureDriver::poll()`, writes the Prometheus textfile +
//! appends one OCSF event, exits. Driven by a systemd timer
//! (`selfdef-scheduler-textfile.timer`) at the same 60s cadence as
//! the IPS observers.
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18197):
//! > *"Linux PSI + DCGM + trace metrics feed the scheduler"*
//!
//! Catalog grounding: MS048 module M01174 (selfdef-scheduler-systemd-unit)
//! per `~/selfdef/backlog/milestones/MS048-goldilocks-scheduler-hardware-
//! aware-resource-routing.md`.
//!
//! Configuration precedence (highest → lowest):
//!
//! 1. Env vars (`SELFDEF_SCHEDULER_*`)
//! 2. TOML config at `SELFDEF_SCHEDULER_CONFIG` (or
//!    `/etc/selfdef/scheduler.toml` by default)
//! 3. Compiled-in defaults
//!
//! M01171 operator-facing customization layer.
//!
//! Honored env vars (operator-tunable, override TOML):
//!
//! - `SELFDEF_SCHEDULER_CONFIG` — TOML config path
//!   (default: `/etc/selfdef/scheduler.toml`; missing file is OK)
//! - `SELFDEF_SCHEDULER_TEXTFILE_PATH` — Prometheus textfile target
//!   (default: `/var/lib/node_exporter/textfile_collector/selfdef-scheduler.prom`)
//! - `SELFDEF_SCHEDULER_OCSF_PATH` — OCSF JSONL append target
//!   (default: `/var/log/selfdef/scheduler.ocsf.jsonl`)
//! - `SELFDEF_SCHEDULER_PSI_DIR` — PSI substrate dir
//!   (default: `/proc/pressure`)
//! - `SELFDEF_SCHEDULER_NVIDIA_SMI_BIN` — nvidia-smi binary path
//!   (default: PATH lookup `nvidia-smi`)
//! - `SELFDEF_SCHEDULER_STATE_ROOT` — human-gate state root
//!   (default: `/var/lib/selfdef`)
//! - `SELFDEF_SCHEDULER_OCSF_ENABLE` — set to `0` to disable OCSF
//!   append (default: `1` = enabled)
//! - `SELFDEF_SCHEDULER_AUDIT_PATH` — M01170 SHA-256-chained driver
//!   audit log path (default:
//!   `/var/log/selfdef/scheduler.driver.audit.jsonl`)
//! - `SELFDEF_SCHEDULER_AUDIT_ENABLE` — set to `0` to disable driver
//!   audit append (default: `1` = enabled)
//! - `SELFDEF_SCHEDULER_AUDIT_ROTATE_BYTES` — rotation threshold
//!   (default: 67108864 = 64 MiB)
//! - `SELFDEF_SCHEDULER_AUDIT_MAX_GENERATIONS` — rotation generation cap
//!   (default: 10)
//! - `SELFDEF_SCHEDULER_SIGNER_KID` — MS003-multisig signer kid embedded
//!   in audit entries (default: none / unsigned)
//!
//! Honest-offline (substrate absent) is non-fatal: Prometheus textfile
//! is still written with substrate_health flags showing which substrate
//! is unavailable. OCSF event still emitted with severity scaled to
//! degraded-substrate count. The textfile-emit-failed sentinel only
//! fires if the WRITE itself fails (disk full, permission denied,
//! etc.) — substrate absence is not failure.
//!
//! Standing rule: We do not minimize anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use selfdef_scheduler::backpressure_driver::BackpressureDriver;
use selfdef_scheduler::config::{DEFAULT_CONFIG_PATH, SchedulerConfig};
use selfdef_scheduler::dcgm::NvidiaSmiDcgmSource;
use selfdef_scheduler::decision_audit::{emit_driver_reading, rotate_audit_log};
use selfdef_scheduler::human_gate::IpsPendingRestoresHumanGateSource;
use selfdef_scheduler::ocsf_emitter::{append_ocsf_jsonl, render_ocsf_event};
use selfdef_scheduler::prometheus_exporter::{
    render_decision_metrics, render_failure_sentinel, render_prometheus, write_textfile_atomic,
};
use selfdef_scheduler::psi::ProcfsPsiSource;
use selfdef_scheduler::read_ring_buffer;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    // 1. Load TOML config from SELFDEF_SCHEDULER_CONFIG (env) or
    //    /etc/selfdef/scheduler.toml (default). Missing file is fine
    //    (returns the default config).
    let config_path = env_path("SELFDEF_SCHEDULER_CONFIG", DEFAULT_CONFIG_PATH);
    let cfg = match SchedulerConfig::load_from(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  FAIL loading config from {}: {e}", config_path.display());
            // Fall back to compiled-in defaults so the timer doesn't flap.
            // Operator sees the error in journald.
            SchedulerConfig::default()
        }
    };

    // 2. Layer env-var overrides on top of the TOML config.
    let textfile_path =
        env_path_with_default("SELFDEF_SCHEDULER_TEXTFILE_PATH", &cfg.emit.textfile_path);
    let ocsf_path = env_path_with_default("SELFDEF_SCHEDULER_OCSF_PATH", &cfg.emit.ocsf_path);
    let ring_dir = env_path_with_default("SELFDEF_SCHEDULER_RING_DIR", &cfg.emit.ring_dir);
    let psi_dir = env_path_with_default("SELFDEF_SCHEDULER_PSI_DIR", &cfg.substrate.psi_dir);
    let nvidia_smi = env_path_with_default(
        "SELFDEF_SCHEDULER_NVIDIA_SMI_BIN",
        &cfg.substrate.nvidia_smi_bin,
    );
    let state_root =
        env_path_with_default("SELFDEF_SCHEDULER_STATE_ROOT", &cfg.substrate.state_root);
    let ocsf_enabled = env::var("SELFDEF_SCHEDULER_OCSF_ENABLE")
        .map(|v| v != "0")
        .unwrap_or(cfg.emit.ocsf_enabled);

    let audit_path = env_path_with_default("SELFDEF_SCHEDULER_AUDIT_PATH", &cfg.emit.audit_path);
    let audit_enabled = env::var("SELFDEF_SCHEDULER_AUDIT_ENABLE")
        .map(|v| v != "0")
        .unwrap_or(cfg.emit.audit_enabled);
    let audit_rotate_bytes = env::var("SELFDEF_SCHEDULER_AUDIT_ROTATE_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(cfg.emit.audit_rotate_bytes);
    let audit_max_generations = env::var("SELFDEF_SCHEDULER_AUDIT_MAX_GENERATIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(cfg.emit.audit_max_generations);
    let signer_kid = env::var("SELFDEF_SCHEDULER_SIGNER_KID")
        .ok()
        .or_else(|| cfg.signer.kid.clone());

    eprintln!("[selfdef-scheduler-textfile {VERSION}] starting one-shot poll");
    eprintln!("  config:   {}", config_path.display());
    eprintln!("  textfile: {}", textfile_path.display());
    eprintln!("  ocsf:     {}", ocsf_path.display());
    eprintln!("  audit:    {}", audit_path.display());
    eprintln!("  psi:      {}", psi_dir.display());
    eprintln!("  dcgm:     {}", nvidia_smi.display());
    eprintln!("  state:    {}", state_root.display());

    // Compose the substrate trio + driver.
    let mut driver = BackpressureDriver::new(
        Box::new(ProcfsPsiSource::with_dir(&psi_dir)),
        Box::new(NvidiaSmiDcgmSource::new().with_command_path(&nvidia_smi)),
        Box::new(IpsPendingRestoresHumanGateSource::with_state_root(
            &state_root,
        )),
    );

    // One poll.
    let reading = driver.poll();
    eprintln!(
        "  poll:     degraded_count={} cpu_psi={:.3} blackwell_vram={:.3} queue={}",
        reading.substrate_health.degraded_count(),
        reading.measurements.cpu_psi,
        reading.measurements.blackwell_vram_util,
        reading.measurements.human_gate_queue_depth,
    );

    // Emit Prometheus textfile. Substrate gauges are authoritative; the
    // decision metrics (route/profile/hibernate from the ring window) are
    // appended supplementary. A ring-read failure must NOT block the
    // substrate textfile, so it is best-effort + logged.
    let mut prom = render_prometheus(&reading);
    match read_ring_buffer(&ring_dir) {
        Ok(decisions) => prom.push_str(&render_decision_metrics(&decisions)),
        Err(e) => eprintln!("  WARN ring read for decision metrics failed (non-fatal): {e}"),
    }
    if let Err(e) = write_textfile_atomic(&textfile_path, &prom) {
        eprintln!("  FAIL writing textfile: {e}");
        // Best-effort failure sentinel: try to write the sentinel
        // textfile so node_exporter sees the wedged state. If that
        // also fails, return non-zero exit.
        let sentinel = render_failure_sentinel();
        if let Err(e2) = write_textfile_atomic(&textfile_path, &sentinel) {
            eprintln!("  FAIL writing failure sentinel: {e2}");
        }
        return ExitCode::from(1);
    }

    // Emit OCSF event (if enabled).
    if ocsf_enabled {
        let event = render_ocsf_event(&reading);
        if let Err(e) = append_ocsf_jsonl(&ocsf_path, &event) {
            // OCSF append failure is non-fatal — Prometheus textfile
            // already landed, so the metric pipeline still works.
            // Log the failure to stderr (journald captures it) but
            // exit 0 so the systemd timer doesn't flap.
            eprintln!("  WARN OCSF append failed (non-fatal): {e}");
        }
    } else {
        eprintln!("  ocsf:     disabled (config or SELFDEF_SCHEDULER_OCSF_ENABLE=0)");
    }

    // Emit M01170 SHA-256-chained driver audit entry (if enabled), then
    // rotate if the log exceeds the configured threshold. Both
    // operations are non-fatal — chain integrity is preserved across
    // even partial failures because rotation only happens on success.
    if audit_enabled {
        match emit_driver_reading(&audit_path, &reading, signer_kid.as_deref()) {
            Ok(_) => {
                // Rotate if needed. Failure here is logged but
                // non-fatal — the entry already landed.
                if let Err(e) =
                    rotate_audit_log(&audit_path, audit_rotate_bytes, audit_max_generations)
                {
                    eprintln!("  WARN audit rotation failed (non-fatal): {e}");
                }
            }
            Err(e) => {
                eprintln!("  WARN driver audit append failed (non-fatal): {e}");
            }
        }
    } else {
        eprintln!("  audit:    disabled (config or SELFDEF_SCHEDULER_AUDIT_ENABLE=0)");
    }

    eprintln!("[selfdef-scheduler-textfile {VERSION}] poll complete");
    ExitCode::SUCCESS
}

fn env_path(key: &str, default: &str) -> PathBuf {
    env::var(key)
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(default).to_path_buf())
}

/// Variant that takes a `&Path` as the default, so the env-var
/// override layer can fall back to a TOML-loaded path rather than
/// a compile-time constant.
fn env_path_with_default(key: &str, default: &Path) -> PathBuf {
    env::var(key)
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| default.to_path_buf())
}
