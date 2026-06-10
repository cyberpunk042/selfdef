//! `GET /v1/network` — MS011 Z-7 network state surface.
//!
//! Per-component green/yellow/red status for the 5 operator-relevant
//! network components called out in SDD-026 Z-7:
//!
//! - **internet** — reachability of a configurable external host (defaults
//!   to `1.1.1.1` so the probe doesn't depend on DNS being up; operator
//!   overrides via `SELFDEF_NETWORK_INTERNET_HOST` env).
//! - **dns** — `getent hosts <name>` against a configurable name (defaults
//!   to `cloudflare.com`; operator override via
//!   `SELFDEF_NETWORK_DNS_NAME`).
//! - **cloudflared** — `systemctl is-active cloudflared` (the canonical
//!   Cloudflare Tunnel service unit name).
//! - **tailscale** — `systemctl is-active tailscaled`.
//! - **traefik** — `systemctl is-active traefik`.
//!
//! Each component is probed best-effort. Missing systemd / missing
//! probe tool degrades a component to `unknown`, not `red` — the panel
//! must not lie about a component the operator hasn't installed.
//!
//! Probe runs synchronously per request (no caching) — the underlying
//! commands return in milliseconds and operator dashboards refresh on a
//! 15-30s cadence, so a fresh probe per request is fine.
//!
//! Source: MS011 catalog row M00276 + SDD-026 Z-7.

use std::process::Command;
use std::time::Duration;

use axum::Json;
use serde::Serialize;

/// One network component's probe result.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkComponent {
    /// `"internet" | "dns" | "cloudflared" | "tailscale" | "traefik"`.
    pub name: &'static str,
    /// One-line operator-readable summary (e.g. `"systemd unit
    /// inactive"`, `"ping reachable 12.3 ms"`, `"resolved 4 records"`).
    pub detail: String,
    /// `"green" | "yellow" | "red" | "unknown"`.
    pub state: &'static str,
}

/// Aggregate response.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct NetworkResponse {
    /// Worst-state across all components (`red > yellow > unknown > green`).
    pub worst: &'static str,
    pub components: Vec<NetworkComponent>,
}

fn worst_state(components: &[NetworkComponent]) -> &'static str {
    let mut worst = "green";
    for c in components {
        match (worst, c.state) {
            (_, "red") => return "red",
            ("green", "yellow") => worst = "yellow",
            ("green", "unknown") => worst = "unknown",
            ("unknown", "yellow") => worst = "yellow",
            _ => {}
        }
    }
    worst
}

fn probe_internet() -> NetworkComponent {
    let host =
        std::env::var("SELFDEF_NETWORK_INTERNET_HOST").unwrap_or_else(|_| "1.1.1.1".to_string());
    let out = Command::new("ping")
        .args(["-c", "1", "-W", "2", &host])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            // Extract the rtt from the stdout — best-effort, harmless
            // if the format changes (we just show "reachable").
            let rtt = text
                .lines()
                .find(|l| l.contains("time="))
                .and_then(|l| l.split("time=").nth(1))
                .map(|s| s.split_whitespace().next().unwrap_or("?"))
                .unwrap_or("?");
            NetworkComponent {
                name: "internet",
                detail: format!("ping {host} reachable, time={rtt}ms"),
                state: "green",
            }
        }
        Ok(_) => NetworkComponent {
            name: "internet",
            detail: format!("ping {host} no response within 2s"),
            state: "red",
        },
        Err(e) => NetworkComponent {
            name: "internet",
            detail: format!("ping tool unavailable: {e}"),
            state: "unknown",
        },
    }
}

fn probe_dns() -> NetworkComponent {
    let name =
        std::env::var("SELFDEF_NETWORK_DNS_NAME").unwrap_or_else(|_| "cloudflare.com".to_string());
    let out = Command::new("getent").args(["hosts", &name]).output();
    match out {
        Ok(o) if o.status.success() && !o.stdout.is_empty() => {
            let count = String::from_utf8_lossy(&o.stdout).lines().count();
            NetworkComponent {
                name: "dns",
                detail: format!("resolved {name} to {count} record(s)"),
                state: "green",
            }
        }
        Ok(_) => NetworkComponent {
            name: "dns",
            detail: format!("no record for {name}"),
            state: "red",
        },
        Err(e) => NetworkComponent {
            name: "dns",
            detail: format!("getent unavailable: {e}"),
            state: "unknown",
        },
    }
}

fn probe_systemd_unit(unit: &'static str, component_name: &'static str) -> NetworkComponent {
    let out = Command::new("systemctl").args(["is-active", unit]).output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let text = stdout.trim();
            match text {
                "active" => NetworkComponent {
                    name: component_name,
                    detail: format!("systemd unit {unit} active"),
                    state: "green",
                },
                "activating" | "reloading" => NetworkComponent {
                    name: component_name,
                    detail: format!("systemd unit {unit} {text}"),
                    state: "yellow",
                },
                "inactive" | "failed" | "deactivating" => NetworkComponent {
                    name: component_name,
                    detail: format!("systemd unit {unit} {text}"),
                    state: "red",
                },
                _ => NetworkComponent {
                    name: component_name,
                    detail: format!(
                        "systemd unit {unit} not installed (is-active returned {text:?})"
                    ),
                    state: "unknown",
                },
            }
        }
        Err(e) => NetworkComponent {
            name: component_name,
            detail: format!("systemctl unavailable: {e}"),
            state: "unknown",
        },
    }
}

/// Build the full network response. Sequential SYNC probes — run this on
/// the blocking pool, never directly on an async worker. `ping` is
/// self-bounding (`-W 2`) but `getent` can block long on a broken NSS/DNS
/// stack and `systemctl is-active` can hang on a wedged D-Bus; the caller
/// (`show`) bounds what the REQUEST waits via [`PROBE_DEADLINE`].
pub(crate) fn probe() -> NetworkResponse {
    let components = vec![
        probe_internet(),
        probe_dns(),
        probe_systemd_unit("cloudflared", "cloudflared"),
        probe_systemd_unit("tailscaled", "tailscale"),
        probe_systemd_unit("traefik", "traefik"),
    ];
    let worst = worst_state(&components);
    NetworkResponse { worst, components }
}

/// Hard ceiling on what one `/v1/network` request waits for the probe.
/// The predecessor of this constant was a declared-but-unused `_budget`
/// local — a defense that existed only in a comment (P4). It is now
/// enforced at the request boundary: on expiry the request gets an
/// honest `unknown` instead of hanging, and the probe itself runs on
/// the blocking pool so a wedged subprocess can't starve the executor.
const PROBE_DEADLINE: Duration = Duration::from_secs(10);

async fn show_bounded(
    deadline: Duration,
    probe_fn: fn() -> NetworkResponse,
) -> Json<NetworkResponse> {
    let degraded = |detail: String| NetworkResponse {
        worst: "unknown",
        components: vec![NetworkComponent {
            name: "probe",
            detail,
            state: "unknown",
        }],
    };
    match tokio::time::timeout(deadline, tokio::task::spawn_blocking(probe_fn)).await {
        Ok(Ok(resp)) => Json(resp),
        Ok(Err(join_err)) => Json(degraded(format!("probe task failed: {join_err}"))),
        Err(_) => Json(degraded(format!(
            "probe timed out after {}s (hung subprocess?)",
            deadline.as_secs()
        ))),
    }
}

/// `GET /v1/network` handler.
pub(crate) async fn show() -> Json<NetworkResponse> {
    show_bounded(PROBE_DEADLINE, probe).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_state_red_dominates() {
        let comps = vec![
            NetworkComponent {
                name: "internet",
                detail: "ok".into(),
                state: "green",
            },
            NetworkComponent {
                name: "dns",
                detail: "down".into(),
                state: "red",
            },
            NetworkComponent {
                name: "tailscale",
                detail: "ok".into(),
                state: "green",
            },
        ];
        assert_eq!(worst_state(&comps), "red");
    }

    #[test]
    fn worst_state_yellow_above_unknown_and_green() {
        let comps = vec![
            NetworkComponent {
                name: "a",
                detail: "x".into(),
                state: "green",
            },
            NetworkComponent {
                name: "b",
                detail: "x".into(),
                state: "unknown",
            },
            NetworkComponent {
                name: "c",
                detail: "x".into(),
                state: "yellow",
            },
        ];
        assert_eq!(worst_state(&comps), "yellow");
    }

    #[test]
    fn worst_state_unknown_above_green() {
        let comps = vec![
            NetworkComponent {
                name: "a",
                detail: "x".into(),
                state: "green",
            },
            NetworkComponent {
                name: "b",
                detail: "x".into(),
                state: "unknown",
            },
        ];
        assert_eq!(worst_state(&comps), "unknown");
    }

    #[test]
    fn probe_returns_five_components_in_canonical_order() {
        let r = probe();
        assert_eq!(r.components.len(), 5);
        let names: Vec<&str> = r.components.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            vec!["internet", "dns", "cloudflared", "tailscale", "traefik"]
        );
    }

    /// The request deadline is REAL (its predecessor was a declared-but-
    /// unused `_budget` local): a zero deadline must deterministically take
    /// the timeout branch and return an honest degraded `unknown` instead of
    /// waiting on the probe.
    #[tokio::test]
    async fn show_bounded_returns_degraded_unknown_on_deadline() {
        // Injected probe that wedges far past the deadline — deterministic.
        fn stalled() -> NetworkResponse {
            std::thread::sleep(Duration::from_secs(5));
            probe()
        }
        let start = std::time::Instant::now();
        let Json(resp) = show_bounded(Duration::from_millis(50), stalled).await;
        assert!(
            start.elapsed() < Duration::from_secs(4),
            "must not wait the probe out"
        );
        assert_eq!(resp.worst, "unknown");
        assert_eq!(resp.components.len(), 1);
        assert_eq!(resp.components[0].name, "probe");
        assert!(resp.components[0].detail.contains("timed out"));
    }
}
