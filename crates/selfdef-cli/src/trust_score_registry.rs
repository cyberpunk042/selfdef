//! `selfdefctl trust-scores` — operator surface for the M060 D-18
//! trust-score *live registry*. Daemon-populated by scoring events;
//! operator verbs are `show` + `admit` + `operator-delta` (signed
//! manual delta override of the engine's canonical magnitude).

use std::process::Command as Proc;

use anyhow::{Context, Result, anyhow};

/// 9 MS035 DeltaReason snake_case tokens.
const REASONS: [&str; 9] = [
    "baseline",
    "successful_execution",
    "mismatch_minor",
    "mismatch_major",
    "mismatch_critical",
    "operator_adjustment",
    "decay",
    "quarantine_release",
    "forfeiture",
];

fn socket_path() -> String {
    std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string())
}

fn http_get(path: &str) -> Result<String> {
    let socket = socket_path();
    if std::path::Path::new(&socket).exists() {
        let out = Proc::new("curl")
            .args([
                "-s",
                "--fail",
                "--unix-socket",
                &socket,
                &format!("http://localhost{path}"),
            ])
            .output()
            .with_context(|| format!("curl GET via UNIX socket for {path}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    if let (Ok(url), Ok(token)) = (
        std::env::var("SELFDEF_API_URL"),
        std::env::var("SELFDEF_API_TOKEN"),
    ) {
        let out = Proc::new("curl")
            .args([
                "-s",
                "--fail",
                "-H",
                &format!("Authorization: Bearer {token}"),
                &format!("{url}{path}"),
            ])
            .output()
            .with_context(|| format!("curl GET via TCP for {path}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not reach {path} — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

fn http_post(path: &str, body: &str) -> Result<String> {
    let socket = socket_path();
    if std::path::Path::new(&socket).exists() {
        let out = Proc::new("curl")
            .args([
                "-s",
                "--fail",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "--data",
                body,
                "--unix-socket",
                &socket,
                &format!("http://localhost{path}"),
            ])
            .output()
            .with_context(|| format!("curl POST via UNIX socket for {path}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    if let (Ok(url), Ok(token)) = (
        std::env::var("SELFDEF_API_URL"),
        std::env::var("SELFDEF_API_TOKEN"),
    ) {
        let out = Proc::new("curl")
            .args([
                "-s",
                "--fail",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-H",
                &format!("Authorization: Bearer {token}"),
                "--data",
                body,
                &format!("{url}{path}"),
            ])
            .output()
            .with_context(|| format!("curl POST via TCP for {path}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not POST {path} — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

/// `selfdefctl trust-scores show`.
pub(crate) fn run_show(json: bool) -> Result<i32> {
    let body = http_get("/v1/trust-scores/snapshot")?;
    if json {
        println!("{body}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&body)
        .ok()
        .ok_or_else(|| anyhow!("daemon returned non-JSON body for /v1/trust-scores/snapshot"))?;
    let tools = v
        .get("tools")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();
    println!("trust-scores registry");
    println!("  tool count: {}", tools.len());
    for t in &tools {
        let tool = t.get("tool").and_then(|x| x.as_str()).unwrap_or("?");
        let score = t.get("current_score").and_then(|x| x.as_u64()).unwrap_or(0);
        let band = t.get("band").and_then(|x| x.as_str()).unwrap_or("?");
        let execs = t
            .get("executions_total")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let mm = t
            .get("mismatches_total")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        println!("  - {tool}  score={score} ({band})  execs={execs} mismatches={mm}");
    }
    Ok(0)
}

/// `selfdefctl trust-scores admit`.
pub(crate) fn run_admit(
    tool: &str,
    declarer: &str,
    initial_score: u16,
    signature: &str,
) -> Result<i32> {
    if initial_score > 1000 {
        return Err(anyhow!(
            "initial-score {initial_score} out of range (0..=1000)"
        ));
    }
    let body = serde_json::json!({
        "tool": tool,
        "declarer": declarer,
        "initial_score": initial_score,
        "signature": signature,
    })
    .to_string();
    http_post("/v1/trust-scores/admit", &body)?;
    println!("admitted trust-score {tool} (initial {initial_score})");
    Ok(0)
}

/// `selfdefctl trust-scores operator-delta`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_operator_delta(
    tool: &str,
    actor: &str,
    reason: &str,
    delta: i32,
    trace_id: &str,
    signature: &str,
) -> Result<i32> {
    if !REASONS.contains(&reason) {
        return Err(anyhow!(
            "invalid --reason {reason:?}; expected one of {}",
            REASONS.join(", ")
        ));
    }
    let body = serde_json::json!({
        "tool": tool,
        "actor": actor,
        "reason": reason,
        "delta": delta,
        "trace_id": trace_id,
        "signature": signature,
    })
    .to_string();
    http_post("/v1/trust-scores/operator-delta", &body)?;
    println!("applied operator delta {delta:+} to {tool} (reason {reason})");
    Ok(0)
}
