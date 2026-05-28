//! `selfdefctl grants` — operator surface for the M060 D-13 grant
//! registry (the IPS-side write path the daemon mirror-export republishes
//! READ-ONLY for sovereign-os).
//!
//! 3 subverbs, all via the daemon API (UNIX socket `/run/selfdef.sock`,
//! else `SELFDEF_API_URL` + `SELFDEF_API_TOKEN`):
//!   - `show`    — GET  /v1/grants        (current resident snapshot)
//!   - `issue`   — POST /v1/grants/issue  (operator-signed grant request)
//!   - `revoke`  — POST /v1/grants/revoke (by grant id)
//!
//! Mutations require the operator's MS003 `--signature` over the request
//! (the daemon refuses unsigned per selfdef-grant-issuer); operators sign
//! with the standalone `minisign` CLI per the selfdef signing doctrine.

use std::process::Command as Proc;

use anyhow::{Context, Result, anyhow};

/// The 5 MS037/MS038/MS035/MS034/MS036 grant kinds (snake_case wire form).
const KINDS: [&str; 5] = [
    "filesystem",
    "network",
    "capability",
    "communication",
    "sandbox",
];

fn socket_path() -> String {
    std::env::var("SELFDEF_SOCKET").unwrap_or_else(|_| "/run/selfdef.sock".to_string())
}

/// GET `path` from the daemon (UNIX socket first, then TCP+token).
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
            .with_context(|| format!("invoking curl against the UNIX socket for {path}"))?;
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
            .with_context(|| format!("invoking curl against the TCP API URL for {path}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not reach {path} — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

/// POST a JSON `body` to `path`.
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
            .with_context(|| format!("invoking curl POST against the UNIX socket for {path}"))?;
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
            .with_context(|| format!("invoking curl POST against the TCP API URL for {path}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
    }
    Err(anyhow!(
        "could not POST {path} — neither {socket} nor SELFDEF_API_URL+SELFDEF_API_TOKEN reachable"
    ))
}

/// `selfdefctl grants show` — GET /v1/grants.
pub(crate) fn run_show(json: bool) -> Result<i32> {
    let body = http_get("/v1/grants")?;
    if json {
        println!("{body}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&body)
        .ok()
        .ok_or_else(|| anyhow!("daemon returned non-JSON body for /v1/grants"))?;
    let grants = v
        .get("grants")
        .and_then(|g| g.as_array())
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
    println!("grants registry ({status})");
    println!(
        "  schema_version: {}",
        v.get("schema_version")
            .and_then(|s| s.as_str())
            .unwrap_or("?")
    );
    println!("  grant count:    {}", grants.len());
    for g in &grants {
        let id = g.get("grant_id").and_then(|x| x.as_str()).unwrap_or("?");
        let kind = g.get("kind").and_then(|x| x.as_str()).unwrap_or("?");
        let state = g.get("state").and_then(|x| x.as_str()).unwrap_or("?");
        let scope = g.get("scope").and_then(|x| x.as_str()).unwrap_or("?");
        println!("  - {id}  [{state}] {kind}: {scope}");
    }
    Ok(0)
}

/// `selfdefctl grants issue` — POST /v1/grants/issue.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_issue(
    kind: &str,
    scope: &str,
    reason: &str,
    profile: &str,
    actor: &str,
    ttl_seconds: u32,
    signature: &str,
    json: bool,
) -> Result<i32> {
    if !KINDS.contains(&kind) {
        return Err(anyhow!(
            "invalid --kind {kind:?}; expected one of {}",
            KINDS.join(", ")
        ));
    }
    let body = serde_json::json!({
        "kind": kind,
        "scope": scope,
        "reason": reason,
        "profile": profile,
        "actor": actor,
        "ttl_seconds": ttl_seconds,
        "signature": signature,
    })
    .to_string();
    let resp = http_post("/v1/grants/issue", &body)?;
    if json {
        println!("{resp}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap_or_default();
    let id = v.get("grant_id").and_then(|x| x.as_str()).unwrap_or("?");
    let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("?");
    println!("issued grant {id} [{state}] {kind}: {scope}");
    Ok(0)
}

/// `selfdefctl grants revoke <grant_id>` — POST /v1/grants/revoke.
pub(crate) fn run_revoke(grant_id: &str) -> Result<i32> {
    let body = serde_json::json!({ "grant_id": grant_id }).to_string();
    http_post("/v1/grants/revoke", &body)?;
    println!("revoked grant {grant_id}");
    Ok(0)
}
