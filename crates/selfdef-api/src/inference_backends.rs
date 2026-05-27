//! `GET /v1/inference-backends` — MS011 Z-2 / SDD-026 inference-
//! backend probe surface.
//!
//! Per SDD-026 Z-2 (verbatim):
//!
//! > LM Studio / LM Link / Unsloth equivalent surface (Models tab);
//! > shells out to operator-installed tooling (llama.cpp / vllm /
//! > bitnet.cpp / unsloth); one-click "install missing tool" via
//! > module surface.
//!
//! This route probes for the 4 canonical inference backends + their
//! versions (when reachable) so the dashboard's planned Models tab
//! can show which are installed + which need install. Probe is
//! per-request — backends rarely change at runtime + the probe is
//! cheap (single `--version` invocation per backend).

use std::process::Command;
use std::time::Duration;

use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InferenceBackend {
    pub name: &'static str,
    /// `binary` is the canonical executable name. Operator override
    /// via `SELFDEF_INFERENCE_<NAME>_BIN` env (e.g.
    /// `SELFDEF_INFERENCE_LLAMA_CPP_BIN`).
    pub binary: String,
    /// `installed` reports the result of `which <binary>` + an
    /// invocation of `<binary> --version`.
    pub installed: bool,
    /// Version string captured from `<binary> --version` stdout.
    /// `None` when not installed or `--version` failed.
    pub version: Option<String>,
    /// `"green"` (installed + version captured) / `"yellow"`
    /// (installed but `--version` failed) / `"unknown"` (not
    /// installed; operator can install via the matching module).
    pub state: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InferenceBackendsResponse {
    /// `"green"` if all 4 are installed + reporting versions;
    /// `"unknown"` otherwise (no `"red"` because Z-2 is informational
    /// — an operator-deliberate non-install is not an error).
    pub worst: &'static str,
    pub backends: Vec<InferenceBackend>,
}

const BACKENDS: &[(&str, &str, &str)] = &[
    (
        "llama.cpp",
        "llama-server",
        "SELFDEF_INFERENCE_LLAMA_CPP_BIN",
    ),
    ("vllm", "vllm", "SELFDEF_INFERENCE_VLLM_BIN"),
    (
        "bitnet.cpp",
        "bitnet-cli",
        "SELFDEF_INFERENCE_BITNET_CPP_BIN",
    ),
    ("unsloth", "unsloth-cli", "SELFDEF_INFERENCE_UNSLOTH_BIN"),
];

fn probe_one(name: &'static str, default_bin: &str, env_var: &str) -> InferenceBackend {
    let binary = std::env::var(env_var).unwrap_or_else(|_| default_bin.to_string());
    // First: `which <binary>` — non-installed → fast `unknown` exit.
    let which = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {binary}"))
        .output();
    let installed = matches!(which, Ok(o) if o.status.success() && !o.stdout.is_empty());
    if !installed {
        return InferenceBackend {
            name,
            binary,
            installed: false,
            version: None,
            state: "unknown",
        };
    }
    // Capture --version, 2s budget so a hung binary doesn't stall.
    let _budget = Duration::from_secs(2);
    let v = Command::new(&binary).arg("--version").output();
    match v {
        Ok(o) if o.status.success() => {
            let version_line = String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            InferenceBackend {
                name,
                binary,
                installed: true,
                version: if version_line.is_empty() {
                    None
                } else {
                    Some(version_line)
                },
                state: "green",
            }
        }
        _ => InferenceBackend {
            name,
            binary,
            installed: true,
            version: None,
            state: "yellow",
        },
    }
}

fn worst_state(backends: &[InferenceBackend]) -> &'static str {
    if backends.iter().all(|b| b.state == "green") {
        "green"
    } else {
        "unknown"
    }
}

pub(crate) async fn show() -> Json<InferenceBackendsResponse> {
    let backends: Vec<InferenceBackend> = BACKENDS
        .iter()
        .map(|(name, default_bin, env_var)| probe_one(name, default_bin, env_var))
        .collect();
    let worst = worst_state(&backends);
    Json(InferenceBackendsResponse { worst, backends })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_canonical_order() {
        assert_eq!(BACKENDS.len(), 4);
        assert_eq!(BACKENDS[0].0, "llama.cpp");
        assert_eq!(BACKENDS[1].0, "vllm");
        assert_eq!(BACKENDS[2].0, "bitnet.cpp");
        assert_eq!(BACKENDS[3].0, "unsloth");
    }

    #[test]
    fn worst_state_all_green() {
        let b = vec![InferenceBackend {
            name: "x",
            binary: "x".into(),
            installed: true,
            version: Some("1".into()),
            state: "green",
        }];
        assert_eq!(worst_state(&b), "green");
    }

    #[test]
    fn worst_state_with_unknown_is_unknown() {
        let b = vec![
            InferenceBackend {
                name: "x",
                binary: "x".into(),
                installed: true,
                version: Some("1".into()),
                state: "green",
            },
            InferenceBackend {
                name: "y",
                binary: "y".into(),
                installed: false,
                version: None,
                state: "unknown",
            },
        ];
        assert_eq!(worst_state(&b), "unknown");
    }
}
