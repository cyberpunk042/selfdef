//! `selfdef-scheduler::backpressure_driver` — M01155: BackpressureDriver
//! composes the three substrate-bridges (PSI / DCGM / human-gate) into
//! a single poll-and-update loop for the Goldilocks Scheduler.
//!
//! Dump grounding (avx-plus-plus 2026-05-18 line 18197):
//! > *"Linux PSI + DCGM + trace metrics feed the scheduler"*
//!
//! Catalog grounding: MS048 module `M01155 selfdef-scheduler-backpressure`
//! per `~/selfdef/backlog/milestones/MS048-goldilocks-scheduler-hardware-
//! aware-resource-routing.md`.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — Core Law clause
//! "Runtime routes" (MS048's owned clause) + peace-machine clause
//! "disciplined enough to explain itself" (every poll surfaces per-
//! source SubstrateHealth so the operator sees which substrate is
//! wedged).
//!
//! ## What this module provides
//!
//! 1. `BackpressureDriver` — owns three boxed `Box<dyn PsiSource>` +
//!    `Box<dyn DcgmSource>` + `Box<dyn HumanGateSource>` and a
//!    `BackpressureMonitor`. Single `poll()` method takes one reading
//!    from each source, composes them into `ResourceMeasurements`,
//!    and runs the monitor's hysteresis-honoring `update()`.
//! 2. `SourceStatus` enum — per-source three-state health:
//!    `Healthy` / `Unavailable(String)` (honest-offline) /
//!    `Errored(String)` (substrate-broken). Honest-offline is
//!    distinct from broken — the operator's cockpit needs to show
//!    a fresh-host vs a malfunctioning-substrate vs a healthy
//!    substrate as three different states.
//! 3. `SubstrateHealth` — triple of `SourceStatus` for the three
//!    sources. Carries `degraded_count()` so the IPS-host-overview
//!    can surface "X of 3 substrate sources degraded".
//! 4. `DriverReading` — what `poll()` returns: composed
//!    `ResourceMeasurements`, resulting `BackpressureState`, and
//!    `SubstrateHealth`. Audit-emittable.
//!
//! ## Honest-offline policy
//!
//! When a source is Unavailable OR Errored, the driver uses **0.0**
//! (PSI / DCGM fractions) or **0** (human-gate count) for that
//! source's contribution to `ResourceMeasurements`. This matches the
//! 14 IPS observers' honest-offline pattern: report substrate
//! absence as a discrete signal rather than fabricate pressure or
//! halt the whole driver. The cockpit sees:
//!
//! - `substrate_health.psi_status == Healthy` AND `measurements.cpu_psi=0.2`
//!   ⇒ real 20% cpu pressure
//! - `substrate_health.psi_status == Unavailable(...)` AND `measurements.cpu_psi=0.0`
//!   ⇒ unknown cpu pressure; do NOT route as if 0
//!
//! ## Why the safe-default is 0
//!
//! A wedged substrate should NOT cause the scheduler to fall into
//! emergency-backpressure on a stale `last_state`. Surfacing 0 plus
//! a degraded-source flag lets the operator decide: route as if
//! healthy, hold all routing, or fall back to a manual profile —
//! per the eight-axis choice surface (peace-machine doctrine).
//!
//! ## Non-goals
//!
//! - Not the polling-cadence driver. `poll()` is one-shot; the
//!   caller decides interval (Scheduler::observe loop, future
//!   M01155 expansion to systemd-timer-driven service).
//! - Not a metric emitter. Per-poll metrics export lives in M01168
//!   (Prometheus exporter) and M01169 (OCSF emitter).
//!
//! Standing rule: We do not minimize anything.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::dcgm::{DcgmError, DcgmSource};
use crate::human_gate::{HumanGateError, HumanGateSource};
use crate::psi::{PsiError, PsiSource};
use crate::{BackpressureMonitor, BackpressureState, ResourceMeasurements};

// ============================================================================
// SourceStatus + SubstrateHealth
// ============================================================================

/// Per-source three-state health.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SourceStatus {
    /// Last `poll()` succeeded.
    Healthy,
    /// Last `poll()` returned `*Error::Unavailable(reason)` — substrate
    /// absent (kernel / driver / state-dir not present). Honest-offline.
    Unavailable(String),
    /// Last `poll()` returned a real error (IO / Parse / GpuMissing /
    /// CommandExit). Substrate present but malfunctioning.
    Errored(String),
}

impl SourceStatus {
    /// `true` for [`Self::Healthy`].
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// `true` for [`Self::Unavailable`] or [`Self::Errored`].
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        !self.is_healthy()
    }
}

/// Triple of per-source statuses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubstrateHealth {
    /// PSI substrate status.
    pub psi_status: SourceStatus,
    /// DCGM substrate status.
    pub dcgm_status: SourceStatus,
    /// Human-gate substrate status.
    pub human_gate_status: SourceStatus,
}

impl SubstrateHealth {
    /// All three substrates healthy.
    #[must_use]
    pub const fn all_healthy() -> Self {
        Self {
            psi_status: SourceStatus::Healthy,
            dcgm_status: SourceStatus::Healthy,
            human_gate_status: SourceStatus::Healthy,
        }
    }

    /// Count of degraded sources (0..=3). The IPS-host-overview
    /// cockpit panel consumes this as "X of 3 substrate sources
    /// degraded".
    #[must_use]
    pub fn degraded_count(&self) -> u32 {
        (self.psi_status.is_degraded() as u32)
            + (self.dcgm_status.is_degraded() as u32)
            + (self.human_gate_status.is_degraded() as u32)
    }

    /// `true` iff all three substrates healthy.
    #[must_use]
    pub fn all_healthy_now(&self) -> bool {
        self.psi_status.is_healthy()
            && self.dcgm_status.is_healthy()
            && self.human_gate_status.is_healthy()
    }
}

// ============================================================================
// DriverReading
// ============================================================================

/// What `BackpressureDriver::poll()` returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriverReading {
    /// Wall-clock unix microseconds when the poll completed.
    pub captured_at_unix_micros: u128,
    /// Composed `ResourceMeasurements` (with 0 for unavailable
    /// sources per the honest-offline policy).
    pub measurements: ResourceMeasurements,
    /// Resulting `BackpressureState` from running the measurement
    /// through the hysteresis-honoring `BackpressureMonitor::update()`.
    pub state: BackpressureState,
    /// Per-source health triple.
    pub substrate_health: SubstrateHealth,
}

// ============================================================================
// BackpressureDriver
// ============================================================================

/// Composes the three substrate-bridges into a single
/// poll-and-update loop. Production hosts wire this with
/// `ProcfsPsiSource + NvidiaSmiDcgmSource +
/// IpsPendingRestoresHumanGateSource`; tests use the Mock trio.
pub struct BackpressureDriver {
    psi: Box<dyn PsiSource>,
    dcgm: Box<dyn DcgmSource>,
    human_gate: Box<dyn HumanGateSource>,
    monitor: BackpressureMonitor,
}

impl BackpressureDriver {
    /// Construct a driver with the three boxed sources + a default
    /// `BackpressureMonitor` (sain-01 thresholds).
    pub fn new(
        psi: Box<dyn PsiSource>,
        dcgm: Box<dyn DcgmSource>,
        human_gate: Box<dyn HumanGateSource>,
    ) -> Self {
        Self {
            psi,
            dcgm,
            human_gate,
            monitor: BackpressureMonitor::new(),
        }
    }

    /// Construct with a custom `BackpressureMonitor` (e.g. operator-
    /// tuned thresholds).
    pub fn with_monitor(
        psi: Box<dyn PsiSource>,
        dcgm: Box<dyn DcgmSource>,
        human_gate: Box<dyn HumanGateSource>,
        monitor: BackpressureMonitor,
    ) -> Self {
        Self {
            psi,
            dcgm,
            human_gate,
            monitor,
        }
    }

    /// Borrow the monitor (read-only inspection).
    #[must_use]
    pub const fn monitor(&self) -> &BackpressureMonitor {
        &self.monitor
    }

    /// Take one reading from each source, compose into a
    /// `ResourceMeasurements`, run the monitor, return everything.
    /// Never errors — substrate failures are reported in
    /// `SubstrateHealth`, not as a return-type error.
    pub fn poll(&mut self) -> DriverReading {
        let (cpu_psi, mem_psi, io_psi, psi_status) = match self.psi.read() {
            Ok(r) => (
                r.cpu_some_avg10(),
                r.mem_some_avg10(),
                r.io_some_avg10(),
                SourceStatus::Healthy,
            ),
            Err(PsiError::Unavailable(msg)) => (0.0, 0.0, 0.0, SourceStatus::Unavailable(msg)),
            Err(e) => (0.0, 0.0, 0.0, SourceStatus::Errored(e.to_string())),
        };
        let (blackwell_vram_util, gpu3090_util, dcgm_status) = match self.dcgm.read() {
            Ok(r) => (
                r.blackwell_vram_util(),
                r.gpu3090_util(),
                SourceStatus::Healthy,
            ),
            Err(DcgmError::Unavailable(msg)) => (0.0, 0.0, SourceStatus::Unavailable(msg)),
            Err(e) => (0.0, 0.0, SourceStatus::Errored(e.to_string())),
        };
        let (human_gate_queue_depth, human_gate_status) = match self.human_gate.read() {
            Ok(r) => (r.total_pending, SourceStatus::Healthy),
            Err(HumanGateError::Unavailable(msg)) => (0, SourceStatus::Unavailable(msg)),
            Err(e) => (0, SourceStatus::Errored(e.to_string())),
        };

        let measurements = ResourceMeasurements {
            blackwell_vram_util,
            gpu3090_util,
            cpu_psi,
            mem_psi,
            io_psi,
            human_gate_queue_depth,
        };
        let state = self.monitor.update(measurements);
        let captured_at_unix_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros())
            .unwrap_or(0);
        DriverReading {
            captured_at_unix_micros,
            measurements,
            state,
            substrate_health: SubstrateHealth {
                psi_status,
                dcgm_status,
                human_gate_status,
            },
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcgm::MockDcgmSource;
    use crate::human_gate::MockHumanGateSource;
    use crate::psi::MockPsiSource;

    fn driver(
        psi: MockPsiSource,
        dcgm: MockDcgmSource,
        hg: MockHumanGateSource,
    ) -> BackpressureDriver {
        BackpressureDriver::new(Box::new(psi), Box::new(dcgm), Box::new(hg))
    }

    // ---------------- SourceStatus + SubstrateHealth ----------------------

    #[test]
    fn source_status_health_predicates() {
        assert!(SourceStatus::Healthy.is_healthy());
        assert!(!SourceStatus::Healthy.is_degraded());
        let u = SourceStatus::Unavailable("x".into());
        assert!(!u.is_healthy());
        assert!(u.is_degraded());
        let e = SourceStatus::Errored("y".into());
        assert!(!e.is_healthy());
        assert!(e.is_degraded());
    }

    #[test]
    fn substrate_health_all_healthy_count() {
        let h = SubstrateHealth::all_healthy();
        assert_eq!(h.degraded_count(), 0);
        assert!(h.all_healthy_now());
    }

    #[test]
    fn substrate_health_one_degraded() {
        let h = SubstrateHealth {
            psi_status: SourceStatus::Healthy,
            dcgm_status: SourceStatus::Unavailable("no driver".into()),
            human_gate_status: SourceStatus::Healthy,
        };
        assert_eq!(h.degraded_count(), 1);
        assert!(!h.all_healthy_now());
    }

    #[test]
    fn substrate_health_all_degraded() {
        let h = SubstrateHealth {
            psi_status: SourceStatus::Unavailable("a".into()),
            dcgm_status: SourceStatus::Errored("b".into()),
            human_gate_status: SourceStatus::Unavailable("c".into()),
        };
        assert_eq!(h.degraded_count(), 3);
    }

    // ---------------- Driver poll() — all healthy path --------------------

    #[test]
    fn poll_all_healthy_composes_measurements() {
        let mut d = driver(
            MockPsiSource::clean()
                .with_cpu(0.2)
                .with_mem(0.1)
                .with_io(0.05),
            MockDcgmSource::clean()
                .with_blackwell_vram(12288, 24576)
                .with_gpu3090_util(0.4),
            MockHumanGateSource::clean().with_total(3),
        );
        let r = d.poll();
        assert!((r.measurements.cpu_psi - 0.2).abs() < 1e-5);
        assert!((r.measurements.mem_psi - 0.1).abs() < 1e-5);
        assert!((r.measurements.io_psi - 0.05).abs() < 1e-5);
        assert!((r.measurements.blackwell_vram_util - 0.5).abs() < 1e-4);
        assert!((r.measurements.gpu3090_util - 0.4).abs() < 1e-5);
        assert_eq!(r.measurements.human_gate_queue_depth, 3);
        assert!(r.substrate_health.all_healthy_now());
    }

    // ---------------- Driver poll() — honest-offline ----------------------

    #[test]
    fn poll_psi_unavailable_zeros_psi_only() {
        let mut d = driver(
            MockPsiSource::unavailable(),
            MockDcgmSource::clean()
                .with_blackwell_vram(12288, 24576)
                .with_gpu3090_util(0.4),
            MockHumanGateSource::clean().with_total(3),
        );
        let r = d.poll();
        assert_eq!(r.measurements.cpu_psi, 0.0);
        assert_eq!(r.measurements.mem_psi, 0.0);
        assert_eq!(r.measurements.io_psi, 0.0);
        assert!((r.measurements.blackwell_vram_util - 0.5).abs() < 1e-4);
        assert_eq!(r.measurements.human_gate_queue_depth, 3);
        assert!(matches!(
            r.substrate_health.psi_status,
            SourceStatus::Unavailable(_)
        ));
        assert!(r.substrate_health.dcgm_status.is_healthy());
        assert!(r.substrate_health.human_gate_status.is_healthy());
        assert_eq!(r.substrate_health.degraded_count(), 1);
    }

    #[test]
    fn poll_dcgm_unavailable_zeros_gpu_only() {
        let mut d = driver(
            MockPsiSource::clean().with_cpu(0.3),
            MockDcgmSource::unavailable(),
            MockHumanGateSource::clean(),
        );
        let r = d.poll();
        assert!((r.measurements.cpu_psi - 0.3).abs() < 1e-5);
        assert_eq!(r.measurements.blackwell_vram_util, 0.0);
        assert_eq!(r.measurements.gpu3090_util, 0.0);
        assert!(matches!(
            r.substrate_health.dcgm_status,
            SourceStatus::Unavailable(_)
        ));
    }

    #[test]
    fn poll_human_gate_unavailable_zeros_count_only() {
        let mut d = driver(
            MockPsiSource::clean().with_cpu(0.3),
            // Set VRAM (which IS a backpressure axis) so we can verify
            // DCGM stays healthy while only human-gate degrades.
            MockDcgmSource::clean().with_blackwell_vram(12288, 24576),
            MockHumanGateSource::unavailable(),
        );
        let r = d.poll();
        assert!((r.measurements.cpu_psi - 0.3).abs() < 1e-5);
        assert!((r.measurements.blackwell_vram_util - 0.5).abs() < 1e-4);
        assert_eq!(r.measurements.human_gate_queue_depth, 0);
        assert!(r.substrate_health.psi_status.is_healthy());
        assert!(r.substrate_health.dcgm_status.is_healthy());
        assert!(matches!(
            r.substrate_health.human_gate_status,
            SourceStatus::Unavailable(_)
        ));
    }

    #[test]
    fn poll_all_three_unavailable_yields_clean_state() {
        let mut d = driver(
            MockPsiSource::unavailable(),
            MockDcgmSource::unavailable(),
            MockHumanGateSource::unavailable(),
        );
        let r = d.poll();
        assert_eq!(r.measurements.cpu_psi, 0.0);
        assert_eq!(r.measurements.blackwell_vram_util, 0.0);
        assert_eq!(r.measurements.human_gate_queue_depth, 0);
        // No backpressure surface fires when measurements are all 0.
        assert!(!r.state.cpu_pressure);
        assert!(!r.state.blackwell_vram_high);
        assert!(!r.state.human_gate_queue_high);
        assert_eq!(r.substrate_health.degraded_count(), 3);
    }

    // ---------------- Errored vs Unavailable distinction ------------------

    #[test]
    fn poll_dcgm_errored_distinguishable_from_unavailable() {
        let mut d = driver(
            MockPsiSource::clean(),
            MockDcgmSource::gpu_missing(0),
            MockHumanGateSource::clean(),
        );
        let r = d.poll();
        assert!(
            matches!(r.substrate_health.dcgm_status, SourceStatus::Errored(_)),
            "expected Errored, got {:?}",
            r.substrate_health.dcgm_status
        );
        assert_eq!(r.substrate_health.degraded_count(), 1);
    }

    // ---------------- Hysteresis still honored ----------------------------

    #[test]
    fn poll_threads_state_through_monitor_hysteresis() {
        // First poll: high cpu pressure → enters cpu_pressure=true.
        // Second poll: cpu drops into hysteresis band → stays true.
        // Third poll: cpu drops below band → exits cpu_pressure=false.
        let mut d = BackpressureDriver::new(
            Box::new(MockPsiSource::clean().with_cpu(0.7)),
            Box::new(MockDcgmSource::clean()),
            Box::new(MockHumanGateSource::clean()),
        );
        let r1 = d.poll();
        assert!(r1.state.cpu_pressure, "first high cpu poll enters pressure");

        // Swap in a 0.45 cpu source — in hysteresis band (threshold
        // 0.50 - margin 0.10 = 0.40, so 0.45 stays under pressure).
        d = BackpressureDriver::with_monitor(
            Box::new(MockPsiSource::clean().with_cpu(0.45)),
            Box::new(MockDcgmSource::clean()),
            Box::new(MockHumanGateSource::clean()),
            BackpressureMonitor::new(),
        );
        // Re-prime last_state on the new monitor to simulate continuity.
        let _ = d.poll(); // baseline clean state on a fresh monitor.

        // Independent test: with a fresh monitor + 0.7 cpu, then 0.45,
        // hysteresis keeps pressure on for 0.45 because previous was 0.7.
        let mut d2 = BackpressureDriver::new(
            Box::new(MockPsiSource::clean().with_cpu(0.7)),
            Box::new(MockDcgmSource::clean()),
            Box::new(MockHumanGateSource::clean()),
        );
        let _ = d2.poll();
        // Mutate the boxed source — but Box<dyn PsiSource> is opaque,
        // so we construct a fresh driver instead, preserving the
        // monitor across the boundary.
        let monitor_after = d2.monitor().clone();
        let mut d3 = BackpressureDriver::with_monitor(
            Box::new(MockPsiSource::clean().with_cpu(0.45)),
            Box::new(MockDcgmSource::clean()),
            Box::new(MockHumanGateSource::clean()),
            monitor_after,
        );
        let r3 = d3.poll();
        assert!(
            r3.state.cpu_pressure,
            "in-band 0.45 stays under pressure due to hysteresis"
        );
    }

    // ---------------- captured_at advances --------------------------------

    #[test]
    fn poll_captured_at_monotonic_across_polls() {
        let mut d = driver(
            MockPsiSource::clean(),
            MockDcgmSource::clean(),
            MockHumanGateSource::clean(),
        );
        let r1 = d.poll();
        let r2 = d.poll();
        assert!(r2.captured_at_unix_micros >= r1.captured_at_unix_micros);
    }

    // ---------------- Boxed-source heterogeneity --------------------------

    #[test]
    fn driver_accepts_heterogeneous_box_sources() {
        // Confirms that the trait bounds permit composing different
        // concrete types via the trait objects.
        let psi: Box<dyn PsiSource> = Box::new(MockPsiSource::clean().with_cpu(0.1));
        let dcgm: Box<dyn DcgmSource> = Box::new(MockDcgmSource::unavailable());
        let hg: Box<dyn HumanGateSource> = Box::new(MockHumanGateSource::clean().with_total(2));
        let mut d = BackpressureDriver::new(psi, dcgm, hg);
        let r = d.poll();
        assert!((r.measurements.cpu_psi - 0.1).abs() < 1e-5);
        assert_eq!(r.measurements.blackwell_vram_util, 0.0);
        assert_eq!(r.measurements.human_gate_queue_depth, 2);
    }
}
