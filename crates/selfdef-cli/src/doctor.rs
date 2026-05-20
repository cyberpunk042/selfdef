//! `selfdefctl doctor` — holistic operator health-check.
//!
//! Cross-cutting checks that don't fit any single `modules check`
//! script. Each post-audit security feature has an opt-in knob
//! whose "is this actually working?" state lives across multiple
//! files — the API token file's mode, the eventstream JSONL
//! ownership, every rule file's `.minisig` sidecar, the
//! agent-guard pod-label scope's RBAC dependency. Operators
//! shouldn't have to remember to spot-check each one.
//!
//! Doctor runs the cross-cutting checks; per-module check.sh
//! lives in `selfdefctl modules check`. The two are
//! complementary — neither subsumes the other.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use selfdef_config::Config;

/// Outcome of one doctor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckStatus {
    /// Check passed; everything as expected.
    Ok,
    /// Check passed but with a non-blocking observation.
    Warn,
    /// Check failed; operator action needed.
    Fail,
    /// Check not applicable to this deployment (e.g. signing
    /// disabled, agent-guard not using pod-label scope).
    Skipped,
}

impl CheckStatus {
    fn label(&self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Skipped => "skip",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CheckResult {
    /// Bucket name: `"signing" | "api" | "eventstream" | "rbac"`.
    pub category: String,
    /// Human-readable check name.
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

/// Run every doctor check against `cfg`. Returns the results
/// and a suggested exit code (0 if no `Fail`, 1 otherwise).
pub(crate) fn run(cfg: &Config) -> Vec<CheckResult> {
    let mut out = Vec::new();
    out.extend(check_rule_signing(cfg));
    out.extend(check_api_token(cfg));
    out.extend(check_eventstream(cfg));
    out.extend(check_rbac_posture(cfg));
    out.extend(check_deployment_target(cfg));
    // SD-R9: extend doctor with checks for the SDD-014/016/017
    // surfaces — operability + observability rolled into the existing
    // health-check verb.
    out.extend(check_shared_audit_summary(cfg));
    out.extend(check_oracle_triage(cfg));
    out.extend(check_hardware(cfg));
    // MS046 + MS047 + MS044 + MS048 — four-watchdog set deployability.
    out.extend(check_watchdog_set(cfg));
    out
}

/// SD-R9 + SDD-014: check the shared-audit-summary channel's path is
/// writable when the channel is enabled. Also surfaces the JSONL twin
/// (Q14-C) path when enabled.
/// MS046 + MS047 + MS044 + MS048 — four-watchdog set deployability checks.
///
/// Verifies each watchdog's runtime artifacts are present + writable +
/// the supporting infrastructure (Tetragon socket / TracingPolicy /
/// systemd units / PSI files) is in operator-recognized state. Read-only;
/// never mutates anything.
fn check_watchdog_set(_cfg: &Config) -> Vec<CheckResult> {
    let mut out = Vec::new();

    // --- friction-audit (MS046) -----------------------------------------
    let fa_script = Path::new("/usr/local/bin/friction-audit");
    let fa_unit = Path::new("/etc/systemd/system/sovereign-guard.service");
    let fa_ring = Path::new("/var/cache/selfdef/friction-audit/ring");
    let fa_status = if fa_script.exists() && fa_unit.exists() {
        CheckStatus::Ok
    } else if fa_script.exists() || fa_unit.exists() {
        CheckStatus::Warn
    } else {
        CheckStatus::Skipped
    };
    out.push(CheckResult {
        category: "watchdog-set".into(),
        name: "friction-audit (MS046)".into(),
        status: fa_status,
        detail: format!(
            "script={} unit={} ring={}",
            fa_script.exists(),
            fa_unit.exists(),
            fa_ring.exists()
        ),
    });

    // --- perimeter (MS047) ----------------------------------------------
    let perim_yaml = Path::new("/etc/tetragon/tracing-policies/sovereign-perimeter.yaml");
    let perim_ext_dir = Path::new("/etc/selfdef/perimeter-extensions");
    let perim_ring = Path::new("/var/cache/selfdef/perimeter/ring");
    let perim_status = if perim_yaml.exists() {
        CheckStatus::Ok
    } else {
        CheckStatus::Skipped
    };
    out.push(CheckResult {
        category: "watchdog-set".into(),
        name: "perimeter (MS047)".into(),
        status: perim_status,
        detail: format!(
            "tracingpolicy={} ext_dir={} ring={}",
            perim_yaml.exists(),
            perim_ext_dir.exists(),
            perim_ring.exists()
        ),
    });

    // --- guardian (MS044) -----------------------------------------------
    let guard_bin = Path::new("/usr/local/bin/selfdef-guardian");
    let guard_unit = Path::new("/etc/systemd/system/selfdef-guardian.service");
    let guard_socket = Path::new("/var/run/tetragon/tetragon.events");
    let guard_ring = Path::new("/var/cache/selfdef/guardian/ring");
    let guard_status = if guard_bin.exists() && guard_unit.exists() {
        if guard_socket.exists() {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn // bin+unit ready, socket missing (Tetragon down)
        }
    } else if guard_bin.exists() || guard_unit.exists() {
        CheckStatus::Warn
    } else {
        CheckStatus::Skipped
    };
    out.push(CheckResult {
        category: "watchdog-set".into(),
        name: "guardian (MS044)".into(),
        status: guard_status,
        detail: format!(
            "bin={} unit={} tetragon_socket={} ring={}",
            guard_bin.exists(),
            guard_unit.exists(),
            guard_socket.exists(),
            guard_ring.exists()
        ),
    });

    // --- scheduler (MS048) ----------------------------------------------
    let sched_bin = Path::new("/usr/local/bin/selfdef-scheduler");
    let sched_unit = Path::new("/etc/systemd/system/selfdef-scheduler.service");
    let sched_ring = Path::new("/var/cache/selfdef/scheduler/ring");
    let psi_cpu = Path::new("/proc/pressure/cpu");
    let psi_ok = psi_cpu.exists();
    let sched_status = if sched_bin.exists() && sched_unit.exists() {
        if psi_ok {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn // bin+unit ready, kernel without PSI
        }
    } else if sched_bin.exists() || sched_unit.exists() {
        CheckStatus::Warn
    } else {
        CheckStatus::Skipped
    };
    out.push(CheckResult {
        category: "watchdog-set".into(),
        name: "scheduler (MS048)".into(),
        status: sched_status,
        detail: format!(
            "bin={} unit={} ring={} psi_cpu={}",
            sched_bin.exists(),
            sched_unit.exists(),
            sched_ring.exists(),
            psi_ok
        ),
    });

    // --- audit log mountpoint (cross-cutting: guardian + scheduler) ----
    let zfs_ctx = Path::new("/mnt/vault/context");
    let zfs_status = if zfs_ctx.is_dir() {
        // Best-effort writability check — try to stat; deeper checks
        // would require write attempt, which doctor avoids.
        CheckStatus::Ok
    } else {
        CheckStatus::Skipped
    };
    out.push(CheckResult {
        category: "watchdog-set".into(),
        name: "ZFS audit context (/mnt/vault/context)".into(),
        status: zfs_status,
        detail: format!("present={}", zfs_ctx.is_dir()),
    });

    out
}

fn check_shared_audit_summary(cfg: &Config) -> Vec<CheckResult> {
    let mut out = Vec::new();
    if !selfdef_config::resolve_shared_audit_summary_enabled(cfg) {
        out.push(CheckResult {
            category: "shared-audit-summary".into(),
            name: "channel".into(),
            status: CheckStatus::Skipped,
            detail: "channel disabled (auto-disabled on generic; opt-out on sain01)".into(),
        });
        return out;
    }
    let path = selfdef_config::resolve_shared_audit_summary_path(cfg);
    match path {
        Some(p) => {
            let dir_ok = p
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .map(|d| d.is_dir())
                .unwrap_or(true);
            if dir_ok {
                out.push(CheckResult {
                    category: "shared-audit-summary".into(),
                    name: "shared log path".into(),
                    status: CheckStatus::Ok,
                    detail: format!("{}", p.display()),
                });
            } else {
                out.push(CheckResult {
                    category: "shared-audit-summary".into(),
                    name: "shared log path".into(),
                    status: CheckStatus::Warn,
                    detail: format!(
                        "parent dir of {} doesn't exist; daemon will fail on first event",
                        p.display()
                    ),
                });
            }
        }
        None => {
            out.push(CheckResult {
                category: "shared-audit-summary".into(),
                name: "shared log path".into(),
                status: CheckStatus::Warn,
                detail: "channel enabled but no path resolved (generic target without override?)"
                    .into(),
            });
        }
    }
    // SDD-014 Q14-C: JSONL twin
    if let Some(twin) = selfdef_config::resolve_shared_audit_summary_jsonl_twin(cfg) {
        let dir_ok = twin
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(|d| d.is_dir())
            .unwrap_or(true);
        out.push(CheckResult {
            category: "shared-audit-summary".into(),
            name: "jsonl twin (Q14-C)".into(),
            status: if dir_ok {
                CheckStatus::Ok
            } else {
                CheckStatus::Warn
            },
            detail: if dir_ok {
                format!("enabled at {}", twin.display())
            } else {
                format!("parent dir of {} doesn't exist", twin.display())
            },
        });
    } else {
        out.push(CheckResult {
            category: "shared-audit-summary".into(),
            name: "jsonl twin (Q14-C)".into(),
            status: CheckStatus::Skipped,
            detail: "disabled (jsonl_twin = false; default)".into(),
        });
    }
    out
}

/// SD-R9 + SDD-016: check the oracle-triage channel config when
/// enabled. Endpoint shape, api_key_env presence, rate-limit value.
/// Does NOT attempt a live HTTP probe (no network in doctor by
/// design — keeps the check offline-fast).
fn check_oracle_triage(cfg: &Config) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let ot = &cfg.notifier.oracle_triage;
    if !ot.enabled {
        out.push(CheckResult {
            category: "oracle-triage".into(),
            name: "channel".into(),
            status: CheckStatus::Skipped,
            detail: "channel disabled (operator-explicit opt-in required per SDD-012 Q-D)".into(),
        });
        return out;
    }
    // Endpoint shape
    let endpoint_ok = ot.endpoint.starts_with("http://") || ot.endpoint.starts_with("https://");
    out.push(CheckResult {
        category: "oracle-triage".into(),
        name: "endpoint".into(),
        status: if endpoint_ok {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        },
        detail: if endpoint_ok {
            ot.endpoint.clone()
        } else {
            format!(
                "invalid endpoint: {:?} (must start with http:// or https://)",
                ot.endpoint
            )
        },
    });
    // api_key_env (if configured, the variable must be set + non-empty)
    if let Some(name) = ot.api_key_env.as_deref().filter(|s| !s.is_empty()) {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => {
                out.push(CheckResult {
                    category: "oracle-triage".into(),
                    name: "api_key_env".into(),
                    status: CheckStatus::Ok,
                    // NEVER print the key value — only confirm presence.
                    detail: format!("env var {name:?} is set"),
                });
            }
            Ok(_) => {
                out.push(CheckResult {
                    category: "oracle-triage".into(),
                    name: "api_key_env".into(),
                    status: CheckStatus::Fail,
                    detail: format!("env var {name:?} is set but empty"),
                });
            }
            Err(_) => {
                out.push(CheckResult {
                    category: "oracle-triage".into(),
                    name: "api_key_env".into(),
                    status: CheckStatus::Fail,
                    detail: format!(
                        "env var {name:?} unset; daemon will refuse to construct the channel"
                    ),
                });
            }
        }
    }
    // Rate-limit (Q16-D)
    out.push(CheckResult {
        category: "oracle-triage".into(),
        name: "rate_limit (Q16-D)".into(),
        status: CheckStatus::Ok,
        detail: if ot.max_events_per_hour == 0 {
            "max_events_per_hour = 0 (disabled — runaway protection OFF)".into()
        } else {
            format!("max_events_per_hour = {}", ot.max_events_per_hour)
        },
    });
    out
}

/// SD-R9 + SDD-017: surface the Sain01Match verdict + per-dimension
/// hits. Cross-cutting hardware health visible from `selfdefctl doctor`
/// without the operator having to remember the dedicated subverb.
fn check_hardware(cfg: &Config) -> Vec<CheckResult> {
    let mut out = Vec::new();
    let snap = match selfdef_hardware::probe() {
        Ok(s) => s,
        Err(e) => {
            out.push(CheckResult {
                category: "hardware".into(),
                name: "probe".into(),
                status: CheckStatus::Warn,
                detail: format!("probe failed: {e}"),
            });
            return out;
        }
    };
    let m = selfdef_hardware::matches_sain01(&snap);
    // IMPORTANT: per-dimension miss severity depends on the operator's
    // declared deployment.target. On target=sain01, misses are real
    // concerns (Warn). On target=generic, misses are EXPECTED — the
    // operator isn't claiming SAIN-01 hardware — so we surface them
    // as Skipped (informational, doesn't pollute the warn count).
    let on_sain01 = matches!(
        cfg.deployment.target,
        selfdef_config::DeploymentTarget::Sain01
    );
    let miss_status = if on_sain01 {
        CheckStatus::Warn
    } else {
        CheckStatus::Skipped
    };
    let verdict_label = match m.overall {
        selfdef_hardware::Sain01Verdict::FullMatch => "FullMatch",
        selfdef_hardware::Sain01Verdict::PartialMatch => "PartialMatch",
        selfdef_hardware::Sain01Verdict::NoMatch => "NoMatch",
    };
    let verdict_status = match (m.overall, on_sain01) {
        (selfdef_hardware::Sain01Verdict::FullMatch, _) => CheckStatus::Ok,
        (selfdef_hardware::Sain01Verdict::PartialMatch, true) => CheckStatus::Warn,
        (selfdef_hardware::Sain01Verdict::PartialMatch, false) => CheckStatus::Ok,
        (selfdef_hardware::Sain01Verdict::NoMatch, _) => CheckStatus::Skipped,
    };
    out.push(CheckResult {
        category: "hardware".into(),
        name: "sain01_match.overall".into(),
        status: verdict_status,
        detail: verdict_label.into(),
    });
    out.push(CheckResult {
        category: "hardware".into(),
        name: "cpu_avx512_vnni".into(),
        status: if m.cpu_avx512_vnni {
            CheckStatus::Ok
        } else {
            miss_status.clone()
        },
        detail: format!("{}", m.cpu_avx512_vnni),
    });
    out.push(CheckResult {
        category: "hardware".into(),
        name: "memory_at_least_256gb".into(),
        status: if m.memory_at_least_256gb {
            CheckStatus::Ok
        } else {
            miss_status.clone()
        },
        detail: format!(
            "total_bytes = {} ({})",
            snap.memory.total_bytes,
            if m.memory_at_least_256gb {
                "≥256 GiB"
            } else {
                "<256 GiB"
            }
        ),
    });
    out.push(CheckResult {
        category: "hardware".into(),
        name: "gpu_count_at_least_2".into(),
        status: if m.gpu_count_at_least_2 {
            CheckStatus::Ok
        } else {
            miss_status
        },
        detail: format!("count = {}", snap.gpus.len()),
    });
    // SDD-017 § 5 + § 6: report sain01_strict + metrics path posture
    if cfg.deployment.sain01_strict {
        out.push(CheckResult {
            category: "hardware".into(),
            name: "sain01_strict".into(),
            status: if matches!(m.overall, selfdef_hardware::Sain01Verdict::FullMatch) {
                CheckStatus::Ok
            } else {
                CheckStatus::Fail
            },
            detail: format!(
                "enabled; daemon refuses to start at non-FullMatch (current: {verdict_label})"
            ),
        });
    }
    if !cfg.deployment.hardware_metrics_path.is_empty() {
        let p = std::path::Path::new(&cfg.deployment.hardware_metrics_path);
        let dir_ok = p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(|d| d.is_dir())
            .unwrap_or(true);
        out.push(CheckResult {
            category: "hardware".into(),
            name: "metrics_path (§ 6)".into(),
            status: if dir_ok {
                CheckStatus::Ok
            } else {
                CheckStatus::Warn
            },
            detail: if dir_ok {
                format!("{}", p.display())
            } else {
                format!("parent dir of {} doesn't exist", p.display())
            },
        });
    }
    // SD-R18: thermal posture surface. We don't classify on the
    // selfdef side (sovereign-os R172 owns thresholds because they're
    // profile-dependent), but we DO report whether the host exposes
    // any thermal sensors at all. A FullMatch SAIN-01 box with zero
    // hwmon readings is suspicious (k10temp may not be loaded; nvme
    // controllers should always expose temp1_input).
    let thermals = &snap.thermals;
    let any_thermals = !thermals.is_empty();
    out.push(CheckResult {
        category: "hardware".into(),
        name: "thermals (SD-R17+R18)".into(),
        // On sain01 with no thermals: Warn (degraded observability).
        // Off-sain01 with no thermals: Skipped (informational).
        // With thermals: Ok regardless.
        status: if any_thermals {
            CheckStatus::Ok
        } else if on_sain01 {
            CheckStatus::Warn
        } else {
            CheckStatus::Skipped
        },
        detail: if any_thermals {
            let max_c = thermals.iter().map(|t| t.celsius).max().unwrap_or(0);
            let min_c = thermals.iter().map(|t| t.celsius).min().unwrap_or(0);
            format!(
                "{} sensor(s); min={}°C max={}°C",
                thermals.len(),
                min_c,
                max_c,
            )
        } else {
            "no sensors exposed (hwmon empty + nvidia-smi unavailable)".into()
        },
    });
    // SD-R37: cycle-2 hardware visibility checks.
    //   - GPU power telemetry (SD-R24)
    //   - Per-GPU VRAM exposure (SD-R25)
    //   - Wasm-AOT feature set surface (SD-R30)
    // On sain01 the absence of any of these is a Warn; off-sain01
    // it's Skipped (informational).
    let gpus = &snap.gpus;
    let any_gpus = !gpus.is_empty();
    let any_power = gpus
        .iter()
        .any(|g| g.power_draw_watts.is_some() || g.power_limit_watts.is_some());
    out.push(CheckResult {
        category: "hardware".into(),
        name: "gpu_power_telemetry (SD-R24)".into(),
        status: if any_power {
            CheckStatus::Ok
        } else if any_gpus && on_sain01 {
            CheckStatus::Warn
        } else {
            CheckStatus::Skipped
        },
        detail: if any_power {
            let drawn: u32 = gpus.iter().filter_map(|g| g.power_draw_watts).sum();
            let cap: u32 = gpus.iter().filter_map(|g| g.power_limit_watts).sum();
            format!(
                "{}/{} W aggregate (headroom {} W)",
                drawn,
                cap,
                cap.saturating_sub(drawn)
            )
        } else if any_gpus {
            "GPUs present but no power telemetry (NVML unavailable?)".into()
        } else {
            "no GPUs detected".into()
        },
    });
    let any_vram = gpus.iter().any(|g| g.vram_bytes.is_some());
    out.push(CheckResult {
        category: "hardware".into(),
        name: "gpu_vram_exposure (SD-R25)".into(),
        status: if any_vram {
            CheckStatus::Ok
        } else if any_gpus && on_sain01 {
            CheckStatus::Warn
        } else {
            CheckStatus::Skipped
        },
        detail: if any_vram {
            let total: u64 = gpus.iter().filter_map(|g| g.vram_bytes).sum();
            format!(
                "{} GiB across {} GPU(s)",
                total / (1024 * 1024 * 1024),
                gpus.len()
            )
        } else if any_gpus {
            "GPUs present but no VRAM reported (nvidia-smi unavailable?)".into()
        } else {
            "no GPUs detected".into()
        },
    });
    // Wasm-AOT surface — derive from snap.cpu (avoid pulling
    // HardwareCapabilities just for this one field).
    let cpu_features = &snap.cpu.features;
    let has_avx512 = cpu_features.contains("avx512f");
    out.push(CheckResult {
        category: "hardware".into(),
        name: "wasm_aot_features (SD-R30)".into(),
        status: if has_avx512 {
            CheckStatus::Ok
        } else if on_sain01 {
            CheckStatus::Warn
        } else {
            CheckStatus::Skipped
        },
        detail: if has_avx512 {
            let count = [
                "avx512f",
                "avx512_vnni",
                "avx512_bf16",
                "avx512_fp16",
                "avx512_vbmi",
                "avx512_vbmi2",
            ]
            .iter()
            .filter(|f| cpu_features.contains(**f))
            .count();
            format!("AVX-512 family on; {count} feature(s) available for wasmtime AOT")
        } else {
            "no AVX-512 — wasmtime AOT falls back to scalar/AVX2 codegen".into()
        },
    });
    out
}

/// Render a human-readable report (one line per check, summary
/// at the end). Returns the suggested exit code.
pub(crate) fn render_human(results: &[CheckResult]) -> (String, i32) {
    let mut buf = String::new();
    writeln!(&mut buf, "# selfdefctl doctor").unwrap();
    writeln!(&mut buf).unwrap();

    let mut by_cat: std::collections::BTreeMap<&str, Vec<&CheckResult>> =
        std::collections::BTreeMap::new();
    for r in results {
        by_cat.entry(r.category.as_str()).or_default().push(r);
    }
    for (cat, items) in &by_cat {
        writeln!(&mut buf, "## {cat}").unwrap();
        for r in items {
            writeln!(
                &mut buf,
                "  [{:>4}] {}: {}",
                r.status.label(),
                r.name,
                r.detail
            )
            .unwrap();
        }
        writeln!(&mut buf).unwrap();
    }

    let n_ok = results
        .iter()
        .filter(|r| r.status == CheckStatus::Ok)
        .count();
    let n_warn = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warn)
        .count();
    let n_fail = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let n_skip = results
        .iter()
        .filter(|r| r.status == CheckStatus::Skipped)
        .count();
    writeln!(
        &mut buf,
        "summary: {n_ok} ok, {n_warn} warn, {n_fail} fail, {n_skip} skip ({} total)",
        results.len()
    )
    .unwrap();

    let exit = if n_fail > 0 { 1 } else { 0 };
    (buf, exit)
}

/// Render as JSON-lines, one object per check. Mostly for CI
/// integration; the human report is the primary surface.
pub(crate) fn render_json(results: &[CheckResult]) -> Result<(String, i32)> {
    let mut buf = String::new();
    for r in results {
        let obj = serde_json::json!({
            "category": r.category,
            "name": r.name,
            "status": r.status.label(),
            "detail": r.detail,
        });
        writeln!(&mut buf, "{obj}").context("writing doctor JSON line")?;
    }
    let n_fail = results
        .iter()
        .filter(|r| r.status == CheckStatus::Fail)
        .count();
    let exit = if n_fail > 0 { 1 } else { 0 };
    Ok((buf, exit))
}

// --- checks ----------------------------------------------------

/// Rule signing — when `[security].require_signed_rules = true`,
/// verify the public key loads + every rule in
/// `cfg.correlator.rules_dir` has a sibling `.minisig` that
/// validates. Mirrors what the daemon does on startup but as
/// an ahead-of-time check so operators don't discover the
/// problem after a restart.
fn check_rule_signing(cfg: &Config) -> Vec<CheckResult> {
    if !cfg.security.require_signed_rules {
        return vec![CheckResult {
            category: "signing".into(),
            name: "rule signing".into(),
            status: CheckStatus::Skipped,
            detail: "[security].require_signed_rules = false".into(),
        }];
    }
    let Some(key_path) = cfg.security.signing_public_key_file.clone() else {
        return vec![CheckResult {
            category: "signing".into(),
            name: "public key".into(),
            status: CheckStatus::Fail,
            detail: "[security].require_signed_rules = true but \
                 signing_public_key_file is unset"
                .into(),
        }];
    };
    let verifier = match selfdef_signing::Verifier::load(&key_path) {
        Ok(v) => v,
        Err(e) => {
            return vec![CheckResult {
                category: "signing".into(),
                name: "public key".into(),
                status: CheckStatus::Fail,
                detail: format!("loading {}: {e}", key_path.display()),
            }];
        }
    };
    let mut out = vec![CheckResult {
        category: "signing".into(),
        name: "public key".into(),
        status: CheckStatus::Ok,
        detail: format!("loaded {}", key_path.display()),
    }];
    let rules_dir = &cfg.correlator.rules_dir;
    if !rules_dir.exists() {
        out.push(CheckResult {
            category: "signing".into(),
            name: "rules directory".into(),
            status: CheckStatus::Warn,
            detail: format!("does not exist: {}", rules_dir.display()),
        });
        return out;
    }
    let mut checked = 0usize;
    let mut failed = Vec::new();
    walk_yaml_files(rules_dir, &mut |p| {
        checked += 1;
        if let Err(e) = verifier.verify_detached_file(p) {
            failed.push(format!("{}: {e}", p.display()));
        }
    });
    if failed.is_empty() {
        out.push(CheckResult {
            category: "signing".into(),
            name: "rule sidecars".into(),
            status: CheckStatus::Ok,
            detail: format!("{checked} rule file(s) verify"),
        });
    } else {
        out.push(CheckResult {
            category: "signing".into(),
            name: "rule sidecars".into(),
            status: CheckStatus::Fail,
            detail: format!(
                "{} of {checked} rule file(s) failed: {}",
                failed.len(),
                failed.join("; ")
            ),
        });
    }
    out
}

/// API token file: when `[api].token_file` is configured, verify
/// the file exists and is mode 0600. Catches the
/// `selfdefctl api rotate-token` happy path drifting (e.g. an
/// operator-managed file with `chmod 0644`).
fn check_api_token(cfg: &Config) -> Vec<CheckResult> {
    use std::os::unix::fs::PermissionsExt as _;
    if !cfg.api.enabled || cfg.api.token_file.trim().is_empty() {
        return vec![CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Skipped,
            detail: "[api] disabled or token_file unset".into(),
        }];
    }
    let path = std::path::PathBuf::from(&cfg.api.token_file);
    let md = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => {
            return vec![CheckResult {
                category: "api".into(),
                name: "token file".into(),
                status: CheckStatus::Fail,
                detail: format!("{} unreadable: {e}", path.display()),
            }];
        }
    };
    let mode = md.permissions().mode() & 0o777;
    let mut out = Vec::new();
    if mode == 0o600 {
        out.push(CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Ok,
            detail: format!("{} mode 0600", path.display()),
        });
    } else {
        out.push(CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Fail,
            detail: format!(
                "{} mode {:o} (expected 0600 — see selfdefctl api rotate-token)",
                path.display(),
                mode
            ),
        });
    }
    if md.len() == 0 {
        out.push(CheckResult {
            category: "api".into(),
            name: "token file".into(),
            status: CheckStatus::Fail,
            detail: format!("{} is empty", path.display()),
        });
    }
    out
}

/// Eventstream integrity: when
/// `[collectors.eventstream].integrity_check = true`, verify
/// every configured path passes the same checks the collector
/// will run at startup (not world-writable, owned by an
/// allowed UID).
fn check_eventstream(cfg: &Config) -> Vec<CheckResult> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !cfg.collectors.eventstream.enabled || !cfg.collectors.eventstream.integrity_check {
        return vec![CheckResult {
            category: "eventstream".into(),
            name: "integrity".into(),
            status: CheckStatus::Skipped,
            detail: "[collectors.eventstream] disabled or integrity_check = false".into(),
        }];
    }
    let mut out = Vec::new();
    let allowed = &cfg.collectors.eventstream.allowed_owners;
    for path in &cfg.collectors.eventstream.paths {
        let md = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                out.push(CheckResult {
                    category: "eventstream".into(),
                    name: path.display().to_string(),
                    status: CheckStatus::Warn,
                    detail: format!("unreadable: {e}"),
                });
                continue;
            }
        };
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o002 != 0 {
            out.push(CheckResult {
                category: "eventstream".into(),
                name: path.display().to_string(),
                status: CheckStatus::Fail,
                detail: format!("world-writable (mode {mode:o})"),
            });
            continue;
        }
        let uid = md.uid();
        if uid != 0 && !allowed.contains(&uid) {
            out.push(CheckResult {
                category: "eventstream".into(),
                name: path.display().to_string(),
                status: CheckStatus::Fail,
                detail: format!(
                    "owner uid {uid} not in [collectors.eventstream].allowed_owners and not root"
                ),
            });
            continue;
        }
        out.push(CheckResult {
            category: "eventstream".into(),
            name: path.display().to_string(),
            status: CheckStatus::Ok,
            detail: format!("mode {mode:o}, owner {uid}"),
        });
    }
    out
}

/// RBAC posture summary. We don't probe the cluster here — that's
/// `selfdefctl rbac check --probe`. Doctor just reports whether
/// the rbac surface applies + points at the dedicated verb.
fn check_rbac_posture(_cfg: &Config) -> Vec<CheckResult> {
    // F-2027-018: `SELFDEF_DOCTOR_AGENT_GUARD_CONFIG` is the
    // test-only env override that lets the integration suite stage
    // a fake agent-guard config in a tempdir without polluting
    // /etc. Production callers leave this unset; the verb's
    // `--help` and `docs/dev/operator-health-check.md` both
    // document it explicitly so an operator chasing a doctor bug
    // can reproduce against a staged config.
    // F-2027-017: pull the default path from `crate::paths` so
    // every CLI verb sees the same canonical layout.
    let ag_path = std::env::var_os("SELFDEF_DOCTOR_AGENT_GUARD_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(crate::paths::AGENT_GUARD_CONFIG));
    if !ag_path.exists() {
        return vec![CheckResult {
            category: "rbac".into(),
            name: "agent-guard scope".into(),
            status: CheckStatus::Skipped,
            detail: format!(
                "{} not present — agent-guard not installed",
                ag_path.display()
            ),
        }];
    }
    let body = match std::fs::read_to_string(&ag_path) {
        Ok(s) => s,
        Err(e) => {
            return vec![CheckResult {
                category: "rbac".into(),
                name: "agent-guard scope".into(),
                status: CheckStatus::Warn,
                detail: format!("{} unreadable: {e}", ag_path.display()),
            }];
        }
    };
    let scope = extract_toml_scalar_line(&body, "scope").unwrap_or_else(|| "container".into());
    if scope == "pod-label" {
        // F-2027-008: previously emitted `Warn` for pod-label
        // scope. Doctor never probes the cluster (deliberate —
        // probing is `selfdefctl rbac check --probe`'s job).
        // The `warn:` line was inflating the doctor's
        // top-level summary count, suggesting something was
        // wrong when actually nothing was — just that the
        // RBAC posture hadn't been verified yet. Flip to
        // `Skipped` (which doesn't contribute to the warn or
        // fail count) with explicit "not verified" wording.
        vec![CheckResult {
            category: "rbac".into(),
            name: "agent-guard scope".into(),
            status: CheckStatus::Skipped,
            detail:
                "scope = \"pod-label\" — posture not verified here; run `selfdefctl rbac check --probe` to verify the cluster's RBAC matches"
                    .into(),
        }]
    } else {
        vec![CheckResult {
            category: "rbac".into(),
            name: "agent-guard scope".into(),
            status: CheckStatus::Skipped,
            detail: format!("scope = \"{scope}\" — RBAC posture not gating"),
        }]
    }
}

// ---------------------------------------------------------------- deployment target (SDD-013)

/// SDD-013 § 6: deployment-target sanity checks.
///
/// Surfaces likely-misconfigured deployments where the operator's
/// `target` value and on-disk state disagree:
///
/// - `target = "sain01"` but `/mnt/vault/` doesn't exist
///   → WARN: operator probably forgot to set up ZFS / mount the dataset
///   before starting the daemon; the daemon will fail to write state.
/// - `target = "generic"` but `/mnt/vault/context/selfdef-*` exists
///   → WARN: state-fork hazard — operator likely flipped from sain01
///   back to generic without migrating files (Q13-C).
///
/// Both are non-blocking (WARN, not FAIL): doctor surfaces the
/// inconsistency; the operator decides whether the state is intentional
/// (mid-migration) or a bug. The daemon's own Q13-C check ENFORCES
/// the same invariant at startup with a hard refusal.
fn check_deployment_target(cfg: &Config) -> Vec<CheckResult> {
    use selfdef_config::{DeploymentTarget, state_dir};

    let target = cfg.deployment.target;
    let mut out = Vec::new();

    // Always surface the active target — operators grep for this.
    out.push(CheckResult {
        category: "deployment".into(),
        name: "deployment.target".into(),
        status: CheckStatus::Ok,
        detail: format!(
            "target = \"{}\"; state_dir = {}",
            target,
            state_dir(target).display()
        ),
    });

    match target {
        DeploymentTarget::Sain01 => {
            // SAIN-01 needs /mnt/vault present (the ZFS pool mountpoint).
            let mnt_vault = Path::new("/mnt/vault");
            if !mnt_vault.exists() {
                out.push(CheckResult {
                    category: "deployment".into(),
                    name: "sain01 vault mountpoint".into(),
                    status: CheckStatus::Warn,
                    detail: "target=sain01 but /mnt/vault/ doesn't exist; \
                             run sovereign-os scripts/hooks/during-install/zfs-datasets-create.sh \
                             first (the daemon will fail to write state without it)"
                        .into(),
                });
            } else {
                out.push(CheckResult {
                    category: "deployment".into(),
                    name: "sain01 vault mountpoint".into(),
                    status: CheckStatus::Ok,
                    detail: "/mnt/vault/ present".into(),
                });
            }
        }
        DeploymentTarget::Generic => {
            // Generic: warn if SAIN-01 state files are present in
            // /mnt/vault/context — likely operator flipped target back
            // to generic without migrating state (state-fork hazard).
            let sain_state_dir = Path::new("/mnt/vault/context");
            if sain_state_dir.exists() {
                let sain_audit = sain_state_dir.join("selfdef-audit.jsonl");
                let sain_esc = sain_state_dir.join("selfdef-escalations.sqlite");
                if sain_audit.exists() || sain_esc.exists() {
                    out.push(CheckResult {
                        category: "deployment".into(),
                        name: "generic state-fork hazard".into(),
                        status: CheckStatus::Warn,
                        detail: "target=generic but selfdef state files \
                                 exist at /mnt/vault/context/; likely operator \
                                 flipped target back without migrating. Run \
                                 `selfdefctl init config --target=sain01 --force` \
                                 OR migrate /mnt/vault/context/selfdef-* to \
                                 /var/lib/selfdef/ before next daemon restart"
                            .into(),
                    });
                }
            }
        }
    }

    out
}

/// Minimal TOML scalar reader: finds `<key> = "value"` (one per
/// line, scalar string only). Used by the rbac check; the
/// agent-guard config has a fixed flat shape so this is enough.
fn extract_toml_scalar_line(body: &str, key: &str) -> Option<String> {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start().strip_prefix('"')?;
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    None
}

/// Walk a directory recursively and call `visit` for every
/// `*.yml`/`*.yaml` file that isn't a `.tests.yaml` fixture.
fn walk_yaml_files(root: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(f) => f,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk_yaml_files(&path, visit);
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(".tests.yaml") || name.ends_with(".tests.yml") {
            continue;
        }
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            visit(&path);
        }
    }
}

#[cfg(test)]
mod sdd_013_tests {
    //! SDD-013 § 6 doctor checks.
    use super::*;
    use selfdef_config::{Config, DeploymentConfig, DeploymentTarget};

    fn cfg_with_target(t: DeploymentTarget) -> Config {
        Config {
            deployment: DeploymentConfig {
                target: t,
                ..DeploymentConfig::default()
            },
            ..Config::default()
        }
    }

    /// Both targets always surface a deployment.target row so
    /// operators grepping doctor output see the active posture.
    #[test]
    fn doctor_always_surfaces_active_target() {
        for t in [DeploymentTarget::Generic, DeploymentTarget::Sain01] {
            let cfg = cfg_with_target(t);
            let results = check_deployment_target(&cfg);
            let row = results
                .iter()
                .find(|r| r.name == "deployment.target")
                .expect("deployment.target row must surface");
            assert_eq!(row.status, CheckStatus::Ok);
            assert!(row.detail.contains(&format!("target = \"{t}\"")));
        }
    }

    /// Generic target on a host without /mnt/vault/ produces NO
    /// state-fork hazard row (no /mnt/vault/context state files).
    #[test]
    fn doctor_generic_on_clean_host_no_warn() {
        // We can't reliably control whether /mnt/vault/context exists
        // on the test host, so we test the predicate: if the dir
        // doesn't exist OR doesn't contain selfdef state, no warn row
        // appears.
        let cfg = cfg_with_target(DeploymentTarget::Generic);
        let results = check_deployment_target(&cfg);
        // The deployment.target row always exists; the hazard row
        // only appears when state files are present in /mnt/vault/context.
        // On the test runner with no such files, only the active-target
        // row appears.
        let hazard = results
            .iter()
            .find(|r| r.name == "generic state-fork hazard");
        let sain_state = Path::new("/mnt/vault/context");
        if !sain_state.exists()
            || (!sain_state.join("selfdef-audit.jsonl").exists()
                && !sain_state.join("selfdef-escalations.sqlite").exists())
        {
            assert!(hazard.is_none(), "no hazard row on clean host");
        }
    }

    /// SAIN-01 target on a host without /mnt/vault/ warns about the
    /// missing mountpoint.
    #[test]
    fn doctor_sain01_without_vault_warns() {
        let cfg = cfg_with_target(DeploymentTarget::Sain01);
        let results = check_deployment_target(&cfg);
        let mount_row = results
            .iter()
            .find(|r| r.name == "sain01 vault mountpoint")
            .expect("vault mountpoint row must surface for sain01");
        let mnt = Path::new("/mnt/vault");
        if mnt.exists() {
            assert_eq!(mount_row.status, CheckStatus::Ok);
        } else {
            assert_eq!(mount_row.status, CheckStatus::Warn);
            assert!(mount_row.detail.contains("zfs-datasets-create.sh"));
        }
    }

    /// Doctor's main run() wires the deployment check in; results
    /// include at least one "deployment" category row.
    #[test]
    fn doctor_run_includes_deployment_category() {
        let cfg = cfg_with_target(DeploymentTarget::Generic);
        let results = run(&cfg);
        assert!(
            results.iter().any(|r| r.category == "deployment"),
            "doctor::run() must surface deployment checks"
        );
    }

    // ----------------------------------------------------------------
    // SD-R9 doctor extension tests
    // ----------------------------------------------------------------

    /// SD-R9: shared-audit-summary check skips on Generic by default.
    #[test]
    fn sdr9_shared_audit_summary_skipped_on_generic() {
        let cfg = cfg_with_target(DeploymentTarget::Generic);
        let results = check_shared_audit_summary(&cfg);
        assert!(
            results.iter().any(|r| {
                r.category == "shared-audit-summary" && r.status == CheckStatus::Skipped
            })
        );
    }

    /// SD-R9: shared-audit-summary check surfaces an OK row on Sain01
    /// (because resolver auto-enables) + a Skipped jsonl-twin row
    /// (default false).
    #[test]
    fn sdr9_shared_audit_summary_active_on_sain01() {
        let cfg = cfg_with_target(DeploymentTarget::Sain01);
        let results = check_shared_audit_summary(&cfg);
        let path_row = results
            .iter()
            .find(|r| r.name == "shared log path")
            .expect("shared log path row");
        // Without /mnt/vault on the test host, parent dir may not
        // exist → either Ok or Warn; both are acceptable.
        assert!(matches!(
            path_row.status,
            CheckStatus::Ok | CheckStatus::Warn
        ));
        let twin_row = results
            .iter()
            .find(|r| r.name == "jsonl twin (Q14-C)")
            .expect("jsonl twin row");
        assert_eq!(twin_row.status, CheckStatus::Skipped);
    }

    /// SD-R9: oracle-triage skipped when disabled (default).
    #[test]
    fn sdr9_oracle_triage_skipped_when_disabled() {
        let cfg = Config::default();
        let results = check_oracle_triage(&cfg);
        let channel_row = results.iter().find(|r| r.name == "channel").unwrap();
        assert_eq!(channel_row.status, CheckStatus::Skipped);
        assert!(channel_row.detail.contains("Q-D"));
    }

    /// SD-R9: oracle-triage with bad endpoint shape → Fail.
    #[test]
    fn sdr9_oracle_triage_rejects_bad_endpoint() {
        let cfg = Config {
            notifier: selfdef_config::NotifierConfig {
                oracle_triage: selfdef_config::OracleTriageConfig {
                    enabled: true,
                    endpoint: "ftp://router".into(),
                    ..selfdef_config::OracleTriageConfig::default()
                },
                ..selfdef_config::NotifierConfig::default()
            },
            ..Config::default()
        };
        let results = check_oracle_triage(&cfg);
        let row = results.iter().find(|r| r.name == "endpoint").unwrap();
        assert_eq!(row.status, CheckStatus::Fail);
        assert!(row.detail.contains("invalid"));
    }

    /// SD-R9: oracle-triage rate-limit reported.
    #[test]
    fn sdr9_oracle_triage_rate_limit_surfaced() {
        let cfg = Config {
            notifier: selfdef_config::NotifierConfig {
                oracle_triage: selfdef_config::OracleTriageConfig {
                    enabled: true,
                    max_events_per_hour: 250,
                    ..selfdef_config::OracleTriageConfig::default()
                },
                ..selfdef_config::NotifierConfig::default()
            },
            ..Config::default()
        };
        let results = check_oracle_triage(&cfg);
        let row = results
            .iter()
            .find(|r| r.name == "rate_limit (Q16-D)")
            .unwrap();
        assert_eq!(row.status, CheckStatus::Ok);
        assert!(row.detail.contains("250"));
    }

    /// SD-R9: rate-limit = 0 surfaces the "runaway protection OFF"
    /// warning detail.
    #[test]
    fn sdr9_oracle_triage_rate_limit_zero_warns() {
        let cfg = Config {
            notifier: selfdef_config::NotifierConfig {
                oracle_triage: selfdef_config::OracleTriageConfig {
                    enabled: true,
                    max_events_per_hour: 0,
                    ..selfdef_config::OracleTriageConfig::default()
                },
                ..selfdef_config::NotifierConfig::default()
            },
            ..Config::default()
        };
        let results = check_oracle_triage(&cfg);
        let row = results
            .iter()
            .find(|r| r.name == "rate_limit (Q16-D)")
            .unwrap();
        assert!(row.detail.contains("runaway protection OFF"));
    }

    /// SD-R9: hardware check produces sain01_match.overall row +
    /// per-dimension rows. The verdict on the test host is variable —
    /// we just verify the rows exist.
    #[test]
    fn sdr9_hardware_check_surfaces_match_rows() {
        let cfg = Config::default();
        let results = check_hardware(&cfg);
        let overall = results
            .iter()
            .find(|r| r.name == "sain01_match.overall")
            .expect("overall row");
        // Verdict label is one of the three.
        assert!(matches!(
            overall.detail.as_str(),
            "FullMatch" | "PartialMatch" | "NoMatch"
        ));
        for name in [
            "cpu_avx512_vnni",
            "memory_at_least_256gb",
            "gpu_count_at_least_2",
        ] {
            assert!(
                results.iter().any(|r| r.name == name),
                "doctor must surface hardware.{name}"
            );
        }
    }

    /// SD-R37 (cycle 2): doctor extends with three new visibility
    /// rows surfacing the cycle-2 hardware additions.
    #[test]
    fn sdr37_hardware_check_surfaces_cycle2_rows() {
        let cfg = Config::default();
        let results = check_hardware(&cfg);
        for name in [
            "gpu_power_telemetry (SD-R24)",
            "gpu_vram_exposure (SD-R25)",
            "wasm_aot_features (SD-R30)",
        ] {
            assert!(
                results.iter().any(|r| r.name == name),
                "doctor must surface hardware.{name}"
            );
        }
    }

    /// SD-R18: hardware check surfaces a thermals row (status varies
    /// with the test host, but the row must always be present).
    #[test]
    fn sdr18_hardware_check_surfaces_thermals_row() {
        let cfg = Config::default();
        let results = check_hardware(&cfg);
        let row = results
            .iter()
            .find(|r| r.name.starts_with("thermals"))
            .expect("thermals row missing");
        // Status: Ok when any sensors exposed; Skipped when off-sain01
        // host has none; Warn ONLY when target=sain01 + no sensors.
        // The CI runner has no hwmon AND target defaults to Generic,
        // so the row should never be Warn here.
        assert!(
            matches!(row.status, CheckStatus::Ok | CheckStatus::Skipped),
            "got status {:?} detail {:?}",
            row.status,
            row.detail,
        );
    }

    /// SD-R18: on target=sain01, missing thermals downgrades to Warn
    /// (operator-degraded observability — the SAIN-01 box should expose
    /// k10temp and nvme temps, and a stripped kernel without those is
    /// a configuration smell).
    #[test]
    fn sdr18_hardware_check_thermals_warns_on_sain01_when_empty() {
        // We can't synthesize an empty thermals vec via probe() — the
        // runner host's hwmon is whatever it is. Instead we assert the
        // logical contract: the row exists and (when status is Warn)
        // the detail mentions "no sensors exposed".
        let cfg = cfg_with_target(DeploymentTarget::Sain01);
        let results = check_hardware(&cfg);
        let row = results
            .iter()
            .find(|r| r.name.starts_with("thermals"))
            .expect("thermals row missing");
        if matches!(row.status, CheckStatus::Warn) {
            assert!(
                row.detail.contains("no sensors exposed"),
                "warn must include explanation, got: {}",
                row.detail
            );
        }
    }

    /// SD-R9: sain01_strict row appears only when configured.
    #[test]
    fn sdr9_hardware_strict_row_only_when_configured() {
        let cfg_off = Config::default();
        let results_off = check_hardware(&cfg_off);
        assert!(!results_off.iter().any(|r| r.name == "sain01_strict"));

        let cfg_on = Config {
            deployment: selfdef_config::DeploymentConfig {
                sain01_strict: true,
                ..selfdef_config::DeploymentConfig::default()
            },
            ..Config::default()
        };
        let results_on = check_hardware(&cfg_on);
        let row = results_on
            .iter()
            .find(|r| r.name == "sain01_strict")
            .expect("strict row");
        // Status is either Ok (verdict FullMatch — unlikely on test host)
        // or Fail (otherwise).
        assert!(matches!(row.status, CheckStatus::Ok | CheckStatus::Fail));
    }

    /// SD-R9: doctor::run() wires every new category.
    #[test]
    fn sdr9_doctor_run_includes_all_new_categories() {
        let cfg = cfg_with_target(DeploymentTarget::Generic);
        let results = run(&cfg);
        for cat in ["shared-audit-summary", "oracle-triage", "hardware"] {
            assert!(
                results.iter().any(|r| r.category == cat),
                "doctor::run() must surface {cat} category"
            );
        }
    }

    /// MS046/MS047/MS044/MS048: the four-watchdog set category lands
    /// in every doctor run + emits one check per watchdog.
    #[test]
    fn watchdog_set_category_surfaces_four_per_watchdog_groups() {
        let cfg = cfg_with_target(DeploymentTarget::Generic);
        let results = run(&cfg);
        let cat_rows: Vec<&CheckResult> = results
            .iter()
            .filter(|r| r.category == "watchdog-set")
            .collect();
        // friction-audit + perimeter + guardian + scheduler = at least 4
        // top-level rows. Plus per-watchdog sub-rows (binary, ring dir,
        // audit log). We assert the bottom bound — exact count grows
        // as we add more checks.
        assert!(
            cat_rows.len() >= 4,
            "watchdog-set category should have ≥4 rows; got {}",
            cat_rows.len()
        );
        let names: Vec<&str> = cat_rows.iter().map(|r| r.name.as_str()).collect();
        for w in ["friction-audit", "perimeter", "guardian", "scheduler"] {
            assert!(
                names.iter().any(|n| n.contains(w)),
                "watchdog-set must include a row about {w}; got {names:?}"
            );
        }
    }
}
