//! `selfdef-scheduler::config` — M01171: TOML config loader.
//!
//! Catalog grounding: MS048 module `M01171 selfdef-scheduler-config
//! (selfdef.toml)` per `~/selfdef/backlog/milestones/MS048-goldilocks-
//! scheduler-hardware-aware-resource-routing.md`. Implements the
//! operator-facing customization layer the operator's *"endless
//! configurations and options and personalization's"* requirement
//! maps to.
//!
//! Doctrinal anchor: [Peace Machine + Core Law](https://github.com/
//! cyberpunk042/devops-solutions-information-hub/blob/main/wiki/spine/
//! doctrine/peace-machine-and-core-law.md) — peace-machine clause
//! "flexible enough to evolve" (every threshold, every path, every
//! cadence is operator-tunable without recompilation) + the
//! eight-axis choice surface (operator-supervised toggle set).
//!
//! ## Layered loading
//!
//! Per the operator's directive that defaults exist + every layer
//! is overridable:
//!
//! 1. **Crate defaults** — `SchedulerConfig::default()`. Match the
//!    `crate::DEFAULT_*` constants. Compiled-in safe baseline.
//! 2. **`/etc/selfdef/scheduler.toml`** — operator-host-level
//!    customization. Optional. Missing file is NOT an error
//!    (default config still loads).
//! 3. **Environment variables** — `SELFDEF_SCHEDULER_*` per-process
//!    overrides. Take precedence over the TOML.
//! 4. **CLI flags** (binary-specific) — not handled here; the
//!    `selfdef-scheduler-textfile` binary reads env vars after the
//!    loader returns and overlays them. Future work: a
//!    `selfdefctl scheduler config` CLI for atomic edits.
//!
//! Validation runs after merge: bad combinations
//! (e.g. `rotate_bytes < 1024`) error at load time so the operator
//! sees the problem before the timer fires.
//!
//! ## File format
//!
//! ```toml
//! [substrate]
//! psi_dir = "/proc/pressure"
//! nvidia_smi_bin = "nvidia-smi"
//! state_root = "/var/lib/selfdef"
//!
//! [substrate.dcgm_indices]
//! blackwell = 0
//! gpu3090 = 1
//!
//! [emit]
//! textfile_path = "/var/lib/node_exporter/textfile_collector/selfdef-scheduler.prom"
//! ocsf_path = "/var/log/selfdef/scheduler.ocsf.jsonl"
//! ring_dir = "/var/cache/selfdef/scheduler/ring"
//! ocsf_enabled = true
//! audit_path = "/var/log/selfdef/scheduler.driver.audit.jsonl"
//! audit_enabled = true
//! audit_rotate_bytes = 67108864
//! audit_max_generations = 10
//!
//! [thresholds]
//! blackwell_vram_high = 0.90
//! gpu3090_busy = 0.80
//! cpu_pressure = 0.50
//! ram_pressure = 0.30
//! io_pressure = 0.40
//! human_gate_queue_high = 5
//!
//! [signer]
//! kid = "kid-2026-q2"
//! ```
//!
//! All sections + all keys are OPTIONAL — missing keys fall back to
//! defaults. This lets operators ship minimal overrides without
//! restating the full schema.
//!
//! ## Non-goals
//!
//! - Not a hot-reload mechanism. Re-running the binary picks up
//!   config changes; a long-running daemon reload is M01155-future-
//!   expansion.
//! - Not a config-distribution layer. Sovereign-os ansible /
//!   provisioning ships the TOML file; this module reads it.
//!
//! Standing rule: We do not minimize anything.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::BackpressureThresholds;
use crate::dcgm::DcgmGpuIndices;
use crate::decision_audit::{
    DEFAULT_DRIVER_AUDIT_PATH, DEFAULT_MAX_GENERATIONS, DEFAULT_ROTATE_BYTES,
};
use crate::prometheus_exporter::DEFAULT_TEXTFILE_PATH;
use crate::{DEFAULT_OCSF_PATH, DEFAULT_RING_DIR};

/// Default TOML config path.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/selfdef/scheduler.toml";

// ============================================================================
// SchedulerConfig — the top-level loaded shape
// ============================================================================

/// Top-level operator-tunable configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SchedulerConfig {
    /// Substrate-source paths + GPU index mapping.
    pub substrate: SubstrateConfig,
    /// Emission targets + enable flags + rotation policy.
    pub emit: EmitConfig,
    /// Backpressure thresholds (overrides sain-01 baseline).
    pub thresholds: ThresholdsConfig,
    /// MS003-multisig signer kid (None = unsigned).
    pub signer: SignerConfig,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            substrate: SubstrateConfig::default(),
            emit: EmitConfig::default(),
            thresholds: ThresholdsConfig::default(),
            signer: SignerConfig::default(),
        }
    }
}

/// Substrate-source configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SubstrateConfig {
    /// `/proc/pressure/` directory for the PSI source.
    pub psi_dir: PathBuf,
    /// `nvidia-smi` binary path for the DCGM source.
    pub nvidia_smi_bin: PathBuf,
    /// `/var/lib/selfdef/` state root for the human-gate source.
    pub state_root: PathBuf,
    /// Per-host DCGM GPU index mapping.
    pub dcgm_indices: DcgmGpuIndices,
}

impl Default for SubstrateConfig {
    fn default() -> Self {
        Self {
            psi_dir: PathBuf::from("/proc/pressure"),
            nvidia_smi_bin: PathBuf::from("nvidia-smi"),
            state_root: PathBuf::from("/var/lib/selfdef"),
            dcgm_indices: DcgmGpuIndices::sain01_baseline(),
        }
    }
}

/// Emission-target configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EmitConfig {
    /// Prometheus textfile target.
    pub textfile_path: PathBuf,
    /// OCSF JSONL append target.
    pub ocsf_path: PathBuf,
    /// Decision ring-buffer directory (read for the decision metrics the
    /// textfile binary appends; written by the orchestrator's
    /// `decide_and_persist`).
    pub ring_dir: PathBuf,
    /// `true` to emit OCSF events on every poll.
    pub ocsf_enabled: bool,
    /// M01170 driver-audit JSONL target.
    pub audit_path: PathBuf,
    /// `true` to emit M01170 audit entries on every poll.
    pub audit_enabled: bool,
    /// Audit rotation threshold (bytes).
    pub audit_rotate_bytes: u64,
    /// Audit rotation generation cap.
    pub audit_max_generations: u32,
}

impl Default for EmitConfig {
    fn default() -> Self {
        Self {
            textfile_path: PathBuf::from(DEFAULT_TEXTFILE_PATH),
            ocsf_path: PathBuf::from(DEFAULT_OCSF_PATH),
            ring_dir: PathBuf::from(DEFAULT_RING_DIR),
            ocsf_enabled: true,
            audit_path: PathBuf::from(DEFAULT_DRIVER_AUDIT_PATH),
            audit_enabled: true,
            audit_rotate_bytes: DEFAULT_ROTATE_BYTES,
            audit_max_generations: DEFAULT_MAX_GENERATIONS,
        }
    }
}

/// Backpressure threshold overrides.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdsConfig {
    /// Blackwell VRAM threshold fraction (0.0–1.0).
    pub blackwell_vram_high: f32,
    /// 3090 busy threshold fraction.
    pub gpu3090_busy: f32,
    /// CPU PSI threshold fraction.
    pub cpu_pressure: f32,
    /// RAM PSI threshold fraction.
    pub ram_pressure: f32,
    /// IO PSI threshold fraction.
    pub io_pressure: f32,
    /// Human-gate count threshold.
    pub human_gate_queue_high: u32,
}

impl Default for ThresholdsConfig {
    fn default() -> Self {
        let t = BackpressureThresholds::default_for_sain01();
        Self {
            blackwell_vram_high: t.blackwell_vram_high,
            gpu3090_busy: t.gpu3090_busy,
            cpu_pressure: t.cpu_pressure,
            ram_pressure: t.ram_pressure,
            io_pressure: t.io_pressure,
            human_gate_queue_high: t.human_gate_queue_high,
        }
    }
}

impl ThresholdsConfig {
    /// Convert to the `BackpressureThresholds` shape the
    /// `BackpressureMonitor` consumes.
    #[must_use]
    pub const fn to_backpressure_thresholds(&self) -> BackpressureThresholds {
        BackpressureThresholds {
            blackwell_vram_high: self.blackwell_vram_high,
            gpu3090_busy: self.gpu3090_busy,
            cpu_pressure: self.cpu_pressure,
            ram_pressure: self.ram_pressure,
            io_pressure: self.io_pressure,
            human_gate_queue_high: self.human_gate_queue_high,
        }
    }
}

/// MS003-multisig signer config.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SignerConfig {
    /// Signer kid (None = unsigned mode).
    pub kid: Option<String>,
}

// ============================================================================
// Errors
// ============================================================================

/// Errors raised by config loading + validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// IO error reading the config file.
    #[error("config io ({path}): {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// TOML parse error.
    #[error("config parse ({path}): {source}")]
    Parse {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: toml::de::Error,
    },
    /// Post-load validation failure.
    #[error("config validation: {0}")]
    Validation(String),
}

// ============================================================================
// Loading + validation
// ============================================================================

impl SchedulerConfig {
    /// Load from `path`. If the file does not exist, returns
    /// `Ok(SchedulerConfig::default())` — missing config is fine
    /// (operator hasn't customized anything yet).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] on IO failure (other than NotFound),
    /// [`ConfigError::Parse`] on malformed TOML,
    /// [`ConfigError::Validation`] on post-load validation failure.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(ConfigError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            ConfigError::Validation(format!("{} contains non-UTF-8 bytes", path.display()))
        })?;
        let cfg: SchedulerConfig = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Convenience: load from [`DEFAULT_CONFIG_PATH`].
    ///
    /// # Errors
    ///
    /// Same as `load_from`.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(Path::new(DEFAULT_CONFIG_PATH))
    }

    /// Parse a TOML string directly (test convenience).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] on malformed TOML,
    /// [`ConfigError::Validation`] on validation failure.
    pub fn parse_str(toml_text: &str) -> Result<Self, ConfigError> {
        let cfg: SchedulerConfig =
            toml::from_str(toml_text).map_err(|source| ConfigError::Parse {
                path: PathBuf::from("<string>"),
                source,
            })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate config. Called automatically from `load_from` +
    /// `parse_str`. Operator can call it after manual mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] with a human reason.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Threshold fractions must be in [0.0, 1.0].
        for (name, v) in [
            ("blackwell_vram_high", self.thresholds.blackwell_vram_high),
            ("gpu3090_busy", self.thresholds.gpu3090_busy),
            ("cpu_pressure", self.thresholds.cpu_pressure),
            ("ram_pressure", self.thresholds.ram_pressure),
            ("io_pressure", self.thresholds.io_pressure),
        ] {
            if !(0.0..=1.0).contains(&v) {
                return Err(ConfigError::Validation(format!(
                    "thresholds.{name} = {v} outside [0.0, 1.0]"
                )));
            }
        }
        // Rotation threshold sanity: too-small values would rotate
        // every poll, defeating the chain. Cap at 1 KiB minimum.
        if self.emit.audit_rotate_bytes < 1024 {
            return Err(ConfigError::Validation(format!(
                "emit.audit_rotate_bytes = {} < 1024 (would rotate every poll)",
                self.emit.audit_rotate_bytes
            )));
        }
        // Generation cap sanity: 0 disables rotation entirely; >100 wastes disk.
        if self.emit.audit_max_generations == 0 {
            return Err(ConfigError::Validation(
                "emit.audit_max_generations = 0 (rotation disabled — set ≥1)".to_string(),
            ));
        }
        if self.emit.audit_max_generations > 100 {
            return Err(ConfigError::Validation(format!(
                "emit.audit_max_generations = {} > 100 (excessive)",
                self.emit.audit_max_generations
            )));
        }
        // Empty paths are invalid (would write to "").
        for (name, p) in [
            ("substrate.psi_dir", &self.substrate.psi_dir),
            ("substrate.nvidia_smi_bin", &self.substrate.nvidia_smi_bin),
            ("substrate.state_root", &self.substrate.state_root),
            ("emit.textfile_path", &self.emit.textfile_path),
            ("emit.ocsf_path", &self.emit.ocsf_path),
            ("emit.ring_dir", &self.emit.ring_dir),
            ("emit.audit_path", &self.emit.audit_path),
        ] {
            if p.as_os_str().is_empty() {
                return Err(ConfigError::Validation(format!("{name} is empty path")));
            }
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ---------------- Defaults ------------------------------------------

    #[test]
    fn defaults_match_documented_baseline() {
        let c = SchedulerConfig::default();
        assert_eq!(c.substrate.psi_dir, PathBuf::from("/proc/pressure"));
        assert_eq!(c.substrate.nvidia_smi_bin, PathBuf::from("nvidia-smi"));
        assert_eq!(c.substrate.state_root, PathBuf::from("/var/lib/selfdef"));
        assert_eq!(c.substrate.dcgm_indices, DcgmGpuIndices::sain01_baseline());
        assert_eq!(c.emit.textfile_path, PathBuf::from(DEFAULT_TEXTFILE_PATH));
        assert_eq!(c.emit.ocsf_path, PathBuf::from(DEFAULT_OCSF_PATH));
        assert_eq!(c.emit.ring_dir, PathBuf::from(DEFAULT_RING_DIR));
        assert!(c.emit.ocsf_enabled);
        assert!(c.emit.audit_enabled);
        assert_eq!(c.emit.audit_rotate_bytes, DEFAULT_ROTATE_BYTES);
        assert_eq!(c.emit.audit_max_generations, DEFAULT_MAX_GENERATIONS);
        // Thresholds default to sain-01.
        let t = BackpressureThresholds::default_for_sain01();
        assert_eq!(c.thresholds.to_backpressure_thresholds(), t);
        assert_eq!(c.signer.kid, None);
    }

    // ---------------- Loading -------------------------------------------

    #[test]
    fn load_from_missing_file_returns_default() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("does-not-exist.toml");
        let c = SchedulerConfig::load_from(&path).unwrap();
        assert_eq!(c, SchedulerConfig::default());
    }

    #[test]
    fn load_full_config_from_disk() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("scheduler.toml");
        fs::write(
            &path,
            r#"
[substrate]
psi_dir = "/host/proc/pressure"
nvidia_smi_bin = "/opt/nvidia/bin/nvidia-smi"
state_root = "/srv/selfdef"

[substrate.dcgm_indices]
blackwell = 2
gpu3090 = 5

[emit]
textfile_path = "/srv/metrics/selfdef-scheduler.prom"
ocsf_path = "/srv/audit/scheduler.ocsf.jsonl"
ocsf_enabled = false
audit_path = "/srv/audit/scheduler.driver.audit.jsonl"
audit_enabled = true
audit_rotate_bytes = 33554432
audit_max_generations = 5

[thresholds]
blackwell_vram_high = 0.85
gpu3090_busy = 0.75
cpu_pressure = 0.40
ram_pressure = 0.25
io_pressure = 0.30
human_gate_queue_high = 10

[signer]
kid = "kid-prod-2026"
"#,
        )
        .unwrap();
        let c = SchedulerConfig::load_from(&path).unwrap();
        assert_eq!(c.substrate.psi_dir, PathBuf::from("/host/proc/pressure"));
        assert_eq!(c.substrate.dcgm_indices, DcgmGpuIndices::custom(2, 5));
        assert!(!c.emit.ocsf_enabled);
        assert!(c.emit.audit_enabled);
        assert_eq!(c.emit.audit_rotate_bytes, 33_554_432);
        assert_eq!(c.emit.audit_max_generations, 5);
        assert!((c.thresholds.blackwell_vram_high - 0.85).abs() < 1e-5);
        assert_eq!(c.thresholds.human_gate_queue_high, 10);
        assert_eq!(c.signer.kid.as_deref(), Some("kid-prod-2026"));
    }

    #[test]
    fn partial_config_fills_in_defaults() {
        // Operator only overrides one section; the rest defaults.
        let c = SchedulerConfig::parse_str(
            r#"
[thresholds]
blackwell_vram_high = 0.95
"#,
        )
        .unwrap();
        assert!((c.thresholds.blackwell_vram_high - 0.95).abs() < 1e-5);
        // The rest defaults.
        assert_eq!(c.substrate.psi_dir, PathBuf::from("/proc/pressure"));
        assert!(c.emit.ocsf_enabled);
        let t = BackpressureThresholds::default_for_sain01();
        // Other thresholds still default.
        assert!((c.thresholds.cpu_pressure - t.cpu_pressure).abs() < 1e-5);
    }

    #[test]
    fn empty_toml_yields_default() {
        let c = SchedulerConfig::parse_str("").unwrap();
        assert_eq!(c, SchedulerConfig::default());
    }

    // ---------------- Validation ----------------------------------------

    #[test]
    fn validation_rejects_threshold_out_of_range() {
        let err = SchedulerConfig::parse_str(
            r#"
[thresholds]
blackwell_vram_high = 1.5
"#,
        )
        .unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected Validation")
        };
        assert!(msg.contains("blackwell_vram_high"));
    }

    #[test]
    fn validation_rejects_negative_threshold() {
        let err = SchedulerConfig::parse_str(
            r#"
[thresholds]
cpu_pressure = -0.1
"#,
        )
        .unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected Validation")
        };
        assert!(msg.contains("cpu_pressure"));
    }

    #[test]
    fn validation_rejects_tiny_rotate_bytes() {
        let err = SchedulerConfig::parse_str(
            r#"
[emit]
audit_rotate_bytes = 16
"#,
        )
        .unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected Validation")
        };
        assert!(msg.contains("audit_rotate_bytes"));
    }

    #[test]
    fn validation_rejects_zero_generations() {
        let err = SchedulerConfig::parse_str(
            r#"
[emit]
audit_max_generations = 0
"#,
        )
        .unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected Validation")
        };
        assert!(msg.contains("audit_max_generations"));
    }

    #[test]
    fn validation_rejects_excessive_generations() {
        let err = SchedulerConfig::parse_str(
            r#"
[emit]
audit_max_generations = 1000
"#,
        )
        .unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected Validation")
        };
        assert!(msg.contains("audit_max_generations"));
    }

    #[test]
    fn validation_rejects_empty_path() {
        let err = SchedulerConfig::parse_str(
            r#"
[substrate]
psi_dir = ""
"#,
        )
        .unwrap_err();
        let ConfigError::Validation(msg) = err else {
            panic!("expected Validation")
        };
        assert!(msg.contains("psi_dir"));
    }

    // ---------------- Parse errors --------------------------------------

    #[test]
    fn malformed_toml_returns_parse_error() {
        let err = SchedulerConfig::parse_str("not = valid = toml = at = all").unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn unknown_field_tolerated_for_forward_compat() {
        // serde(default) + no deny-unknown means future fields don't
        // break old binaries. (Standard forward-compat pattern.)
        let c = SchedulerConfig::parse_str(
            r#"
[emit]
future_field_we_dont_know_about = 42
"#,
        )
        .unwrap();
        assert_eq!(c, SchedulerConfig::default());
    }

    // ---------------- Threshold → BackpressureThresholds round-trip ----

    #[test]
    fn thresholds_round_trip_to_backpressure_shape() {
        let cfg = ThresholdsConfig {
            blackwell_vram_high: 0.93,
            gpu3090_busy: 0.77,
            cpu_pressure: 0.42,
            ram_pressure: 0.28,
            io_pressure: 0.35,
            human_gate_queue_high: 7,
        };
        let bp = cfg.to_backpressure_thresholds();
        assert!((bp.blackwell_vram_high - 0.93).abs() < 1e-5);
        assert!((bp.gpu3090_busy - 0.77).abs() < 1e-5);
        assert_eq!(bp.human_gate_queue_high, 7);
    }

    // ---------------- DEFAULT_CONFIG_PATH ------------------------------

    #[test]
    fn default_path_matches_etc_convention() {
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/selfdef/scheduler.toml");
    }
}
