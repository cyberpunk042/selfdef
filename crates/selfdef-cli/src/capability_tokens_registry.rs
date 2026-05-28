//! `selfdefctl capability-tokens` — operator surface for the M060 D-14
//! capability-token *live registry* (the IPS-side write path the daemon
//! mirror-export republishes READ-ONLY for sovereign-os).
//!
//! Distinct from `selfdefctl capability-tokens schema` (the offline
//! doctrine print). 3 subverbs via the daemon API (UNIX socket
//! `/run/selfdef.sock`, else `SELFDEF_API_URL` + `SELFDEF_API_TOKEN`):
//!   - `show`   — GET  /v1/capability-tokens/snapshot
//!   - `issue`  — POST /v1/capability-tokens/issue
//!   - `revoke` — POST /v1/capability-tokens/revoke
//!
//! Mutations require the operator's MS003 `--signature` (signed
//! externally with the `minisign` CLI per the selfdef signing doctrine).

use std::process::Command as Proc;

use anyhow::{Context, Result, anyhow};

/// 8 MS035 ToolClass kebab-case tokens, used for client-side validation.
const TOOLS: [&str; 8] = [
    "read-only-host",
    "write-host",
    "tests",
    "builds",
    "network-egress",
    "gpu-compute",
    "vm-spawn",
    "browser",
];

/// 5 MS039 trust ring snake_case tokens.
const RINGS: [&str; 5] = ["ring0", "ring1", "ring2", "ring3", "ring4"];

/// 7 MS039 authority-level snake_case tokens.
const AUTHORITY_LEVELS: [&str; 7] = [
    "l0_observe",
    "l1_suggest",
    "l2_simulate",
    "l3_prepare",
    "l4_execute",
    "l5_commit",
    "l6_persist",
];

/// 4 MS036 sandbox-tier letters.
const SANDBOX_TIERS: [&str; 4] = ["A", "B", "C", "D"];

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

/// `selfdefctl capability-tokens show` — GET /v1/capability-tokens/snapshot.
pub(crate) fn run_show(json: bool) -> Result<i32> {
    let body = http_get("/v1/capability-tokens/snapshot")?;
    if json {
        println!("{body}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&body).ok().ok_or_else(|| {
        anyhow!("daemon returned non-JSON body for /v1/capability-tokens/snapshot")
    })?;
    let tokens = v
        .get("tokens")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();
    let status = if v
        .get("captured_at")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .is_empty()
    {
        "empty"
    } else {
        "online"
    };
    println!("capability-tokens registry ({status})");
    println!(
        "  schema_version: {}",
        v.get("schema_version")
            .and_then(|s| s.as_str())
            .unwrap_or("?")
    );
    println!("  token count:    {}", tokens.len());
    for t in &tokens {
        let id = t.get("token_id").and_then(|x| x.as_str()).unwrap_or("?");
        let ring = t.get("trust_ring").and_then(|x| x.as_str()).unwrap_or("?");
        let state = t.get("state").and_then(|x| x.as_str()).unwrap_or("?");
        let tier = t
            .get("sandbox_tier")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let tools = t
            .get("allowed_tools")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        println!("  - {id}  [{state}] {ring} tier={tier} tools={tools}");
    }
    Ok(0)
}

/// `selfdefctl capability-tokens issue` — POST /v1/capability-tokens/issue.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_issue(
    actor: &str,
    profile: &str,
    tools: &[String],
    trust_ring: &str,
    authority_level: &str,
    sandbox_tier: &str,
    parent_token_id: &str,
    ttl_seconds: u32,
    signature: &str,
    json: bool,
) -> Result<i32> {
    // Client-side validation for clean errors.
    for t in tools {
        if !TOOLS.contains(&t.as_str()) {
            return Err(anyhow!(
                "invalid tool {t:?}; expected one of {}",
                TOOLS.join(", ")
            ));
        }
    }
    if !RINGS.contains(&trust_ring) {
        return Err(anyhow!(
            "invalid --trust-ring {trust_ring:?}; expected one of {}",
            RINGS.join(", ")
        ));
    }
    if !AUTHORITY_LEVELS.contains(&authority_level) {
        return Err(anyhow!(
            "invalid --authority-level {authority_level:?}; expected one of {}",
            AUTHORITY_LEVELS.join(", ")
        ));
    }
    if !SANDBOX_TIERS.contains(&sandbox_tier) {
        return Err(anyhow!(
            "invalid --sandbox-tier {sandbox_tier:?}; expected one of {}",
            SANDBOX_TIERS.join(", ")
        ));
    }
    let body = serde_json::json!({
        "actor": actor,
        "profile": profile,
        "allowed_tools": tools,
        "trust_ring": trust_ring,
        "authority_level": authority_level,
        "sandbox_tier": sandbox_tier,
        "parent_token_id": parent_token_id,
        "ttl_seconds": ttl_seconds,
        "signature": signature,
    })
    .to_string();
    let resp = http_post("/v1/capability-tokens/issue", &body)?;
    if json {
        println!("{resp}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap_or_default();
    let id = v.get("token_id").and_then(|x| x.as_str()).unwrap_or("?");
    let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("?");
    let word = v
        .get("capability_word")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    println!("issued capability-token {id} [{state}] {trust_ring} tier={sandbox_tier}");
    println!("  capability_word: {word}");
    println!("  allowed_tools:   {}", tools.join(", "));
    Ok(0)
}

/// `selfdefctl capability-tokens revoke <token_id>`.
pub(crate) fn run_revoke(token_id: &str) -> Result<i32> {
    let body = serde_json::json!({ "token_id": token_id }).to_string();
    http_post("/v1/capability-tokens/revoke", &body)?;
    println!("revoked capability-token {token_id}");
    Ok(0)
}
