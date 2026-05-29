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
//! Honored env vars (operator-tunable):
//!
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
use selfdef_scheduler::dcgm::NvidiaSmiDcgmSource;
use selfdef_scheduler::human_gate::IpsPendingRestoresHumanGateSource;
use selfdef_scheduler::ocsf_emitter::{append_ocsf_jsonl, render_ocsf_event};
use selfdef_scheduler::prometheus_exporter::{
    render_failure_sentinel, render_prometheus, write_textfile_atomic, DEFAULT_TEXTFILE_PATH,
};
use selfdef_scheduler::psi::ProcfsPsiSource;
use selfdef_scheduler::DEFAULT_OCSF_PATH;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let textfile_path = env_path("SELFDEF_SCHEDULER_TEXTFILE_PATH", DEFAULT_TEXTFILE_PATH);
    let ocsf_path = env_path("SELFDEF_SCHEDULER_OCSF_PATH", DEFAULT_OCSF_PATH);
    let psi_dir = env_path("SELFDEF_SCHEDULER_PSI_DIR", "/proc/pressure");
    let nvidia_smi = env_path("SELFDEF_SCHEDULER_NVIDIA_SMI_BIN", "nvidia-smi");
    let state_root = env_path("SELFDEF_SCHEDULER_STATE_ROOT", "/var/lib/selfdef");
    let ocsf_enabled = env::var("SELFDEF_SCHEDULER_OCSF_ENABLE")
        .map(|v| v != "0")
        .unwrap_or(true);

    eprintln!("[selfdef-scheduler-textfile {VERSION}] starting one-shot poll");
    eprintln!("  textfile: {}", textfile_path.display());
    eprintln!("  ocsf:     {}", ocsf_path.display());
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

    // Emit Prometheus textfile.
    let prom = render_prometheus(&reading);
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
        eprintln!("  ocsf:     disabled via SELFDEF_SCHEDULER_OCSF_ENABLE=0");
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
