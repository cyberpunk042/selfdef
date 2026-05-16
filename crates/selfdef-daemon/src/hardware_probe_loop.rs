//! SD-R22: daemon-side periodic hardware probe + thermal-event emission.
//!
//! When `[hardware_probe].enabled = true` in `/etc/selfdef/selfdef.toml`,
//! the daemon spawns a tokio task that re-probes every
//! `interval_seconds` and:
//!
//! 1. Updates the Layer B textfile-collector .prom file (if
//!    `[deployment].hardware_metrics_path` is set), so the thermal
//!    timeseries stays fresh while the daemon runs.
//!
//! 2. When `emit_thermal_events = true`, classifies each thermal
//!    reading against the configured thresholds and publishes an
//!    OCSF Detection Finding (class_uid=2004, severity=Critical)
//!    to the bus for every sensor crossing the critical threshold.
//!
//! The pure event-builder is in [`build_thermal_critical_event`] and
//! is unit-tested in isolation. The loop function does I/O + tokio
//! ticks and is tested at the daemon-integration level.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use selfdef_bus::Publisher;
use selfdef_config::HardwareProbeConfig;
use selfdef_core::category::ClassUid;
use selfdef_core::envelope::Event;
use selfdef_core::prelude::SeverityId;
use selfdef_hardware::ThermalReading;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// SD-R22: build a single OCSF Detection Finding event for a
/// thermal-critical breach. Pure function — no I/O. Used by the
/// loop's emit path + tested in isolation.
///
/// Returned event carries:
/// - `class_uid = DETECTION_FINDING` (2004)
/// - `activity_id = 1` ("create" — the finding was just observed)
/// - `severity_id = SeverityId::Critical` (5)
/// - `source = "selfdef.hardware_probe.thermal"` so operators can
///   filter on it from a single label
/// - `message` includes the sensor name + reading + critical
///   threshold
/// - `raw` (preserves the structured shape for forensic replay):
///   `{"sensor": "...", "celsius": <N>, "critical_threshold": <N>}`
#[must_use]
pub(crate) fn build_thermal_critical_event(
    reading: &ThermalReading,
    critical_threshold: i32,
    host_tag: &str,
    sequence: u64,
) -> Event {
    let mut e = Event::new(
        ClassUid::DETECTION_FINDING,
        /*activity_id*/ 1,
        SeverityId::Critical,
        host_tag.to_string(),
        "selfdef.hardware_probe.thermal".to_string(),
        sequence,
    );
    e.message = Some(format!(
        "thermal critical: {} at {}°C (threshold {}°C)",
        reading.source, reading.celsius, critical_threshold,
    ));
    e.raw = Some(serde_json::json!({
        "sensor": reading.source,
        "celsius": reading.celsius,
        "critical_threshold": critical_threshold,
        "source_round": "SD-R22",
    }));
    e
}

/// SD-R22: daemon's periodic hardware probe loop. Cooperates with
/// the daemon's shutdown signal (clean exit on cancel).
///
/// Cadence: `cfg.hardware_probe.interval_seconds`, with a fast-skip
/// MissedTickBehavior so a slow probe doesn't pile up ticks.
pub(crate) async fn run_hardware_probe_loop(
    cfg: HardwareProbeConfig,
    metrics_path: Option<PathBuf>,
    publisher: Publisher,
    host_tag: String,
    shutdown: CancellationToken,
) {
    if !cfg.enabled {
        return;
    }
    let interval = Duration::from_secs(cfg.interval_seconds.max(30));
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick — startup already did one probe.
    tick.tick().await;
    info!(
        interval_secs = cfg.interval_seconds,
        emit_thermal_events = cfg.emit_thermal_events,
        thermal_warn_celsius = cfg.thermal_warn_celsius,
        thermal_critical_celsius = cfg.thermal_critical_celsius,
        gpu_critical_celsius = cfg.gpu_critical_celsius,
        "SD-R22: hardware-probe loop running"
    );
    let sequence = Arc::new(AtomicU64::new(0));
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                info!("SD-R22: shutdown signalled; exiting hardware-probe loop");
                return;
            }
            _ = tick.tick() => {
                let snap = match selfdef_hardware::probe() {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "SD-R22: probe failed; will retry next tick");
                        continue;
                    }
                };
                let m = selfdef_hardware::matches_sain01(&snap);
                if let Some(ref p) = metrics_path {
                    if let Err(e) = selfdef_hardware::write_layer_b_metrics(p, &snap, &m) {
                        warn!(path = %p.display(), error = %e, "SD-R22: Layer B refresh failed");
                    } else {
                        debug!(path = %p.display(), "SD-R22: Layer B refreshed");
                    }
                }
                if cfg.emit_thermal_events {
                    emit_thermal_events_for_snap(&cfg, &snap.thermals, &publisher, &host_tag, &sequence);
                }
            }
        }
    }
}

/// SD-R22: pure-of-I/O classification + emission helper. Walks the
/// thermals + publishes one event per sensor crossing CRITICAL.
fn emit_thermal_events_for_snap(
    cfg: &HardwareProbeConfig,
    thermals: &[ThermalReading],
    publisher: &Publisher,
    host_tag: &str,
    sequence: &Arc<AtomicU64>,
) {
    for reading in thermals {
        let label = selfdef_config::classify_thermal_reading(cfg, &reading.source, reading.celsius);
        if label != "critical" {
            continue;
        }
        let critical = if reading.source.starts_with("nvidia-gpu-") && cfg.gpu_critical_celsius > 0
        {
            cfg.gpu_critical_celsius
        } else {
            cfg.thermal_critical_celsius
        };
        let seq = sequence.fetch_add(1, Ordering::Relaxed);
        let event = build_thermal_critical_event(reading, critical, host_tag, seq);
        publisher.publish_lossy(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(source: &str, celsius: i32) -> ThermalReading {
        ThermalReading {
            source: source.into(),
            celsius,
        }
    }

    #[test]
    fn sdr22_build_event_class_and_severity() {
        let r = reading("k10temp/Tctl", 97);
        let e = build_thermal_critical_event(&r, 95, "test-host", 0);
        assert_eq!(e.class_uid, ClassUid::DETECTION_FINDING);
        assert_eq!(e.severity_id, SeverityId::Critical);
        assert_eq!(e.activity_id, 1);
        assert_eq!(e.source, "selfdef.hardware_probe.thermal");
        assert_eq!(e.host_tag, "test-host");
    }

    #[test]
    fn sdr22_build_event_message_includes_sensor_and_celsius() {
        let r = reading("nvidia-gpu-0", 102);
        let e = build_thermal_critical_event(&r, 95, "h", 1);
        let msg = e.message.expect("must have message");
        assert!(msg.contains("nvidia-gpu-0"), "got: {msg}");
        assert!(msg.contains("102"), "got: {msg}");
        assert!(msg.contains("95"), "got: {msg}");
    }

    #[test]
    fn sdr22_build_event_raw_carries_structured_payload() {
        let r = reading("k10temp/Tctl", 97);
        let e = build_thermal_critical_event(&r, 95, "h", 0);
        let raw = e.raw.expect("must have raw payload");
        assert_eq!(raw["sensor"], "k10temp/Tctl");
        assert_eq!(raw["celsius"], 97);
        assert_eq!(raw["critical_threshold"], 95);
        assert_eq!(raw["source_round"], "SD-R22");
    }

    #[test]
    fn sdr22_emit_publishes_one_event_per_critical_sensor() {
        let bus = selfdef_bus::Bus::new(64);
        let _sub = bus.subscribe();
        let publisher = bus.publisher();
        let cfg = HardwareProbeConfig {
            enabled: true,
            emit_thermal_events: true,
            thermal_warn_celsius: 85,
            thermal_critical_celsius: 95,
            gpu_critical_celsius: 0,
            ..Default::default()
        };
        let thermals = vec![
            reading("k10temp/Tctl", 60),   // ok → no event
            reading("k10temp/temp2", 92),  // warn → no event
            reading("nvme/Composite", 96), // critical → event #1
            reading("nvidia-gpu-0", 110),  // critical → event #2
        ];
        let seq = Arc::new(AtomicU64::new(0));
        emit_thermal_events_for_snap(&cfg, &thermals, &publisher, "h", &seq);
        assert_eq!(seq.load(Ordering::Relaxed), 2, "expected 2 events emitted");
    }

    #[test]
    fn sdr22_emit_uses_gpu_threshold_when_set() {
        let bus = selfdef_bus::Bus::new(64);
        let _sub = bus.subscribe();
        let publisher = bus.publisher();
        let cfg = HardwareProbeConfig {
            enabled: true,
            emit_thermal_events: true,
            thermal_warn_celsius: 85,
            thermal_critical_celsius: 95,
            gpu_critical_celsius: 85,
            ..Default::default()
        };
        let thermals = vec![
            reading("k10temp/Tctl", 90), // CPU sensor at 90 → warn (not critical)
            reading("nvidia-gpu-0", 90), // GPU sensor at 90 → critical (gpu thr = 85)
        ];
        let seq = Arc::new(AtomicU64::new(0));
        emit_thermal_events_for_snap(&cfg, &thermals, &publisher, "h", &seq);
        assert_eq!(
            seq.load(Ordering::Relaxed),
            1,
            "only the GPU event should fire"
        );
    }

    #[test]
    fn sdr22_emit_skips_when_disabled() {
        // The caller (run_hardware_probe_loop) gates the call by
        // cfg.emit_thermal_events; we just verify that the
        // CLASSIFICATION still maps non-critical correctly.
        let bus = selfdef_bus::Bus::new(64);
        let _sub = bus.subscribe();
        let publisher = bus.publisher();
        let cfg = HardwareProbeConfig::default();
        let thermals = vec![reading("k10temp/Tctl", 60)];
        let seq = Arc::new(AtomicU64::new(0));
        emit_thermal_events_for_snap(&cfg, &thermals, &publisher, "h", &seq);
        assert_eq!(seq.load(Ordering::Relaxed), 0);
    }
}
