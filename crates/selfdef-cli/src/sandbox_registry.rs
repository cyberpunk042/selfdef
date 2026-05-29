//! `selfdefctl sandboxes` — operator surface for the M060 D-15
//! sandbox-allocation *live registry* (the IPS-side write path the
//! daemon mirror-export republishes READ-ONLY for sovereign-os).
//!
//! Distinct from `selfdefctl sandbox-tiers` (the offline tier doctrine).
//! 3 subverbs via the daemon API (UNIX socket `/run/selfdef.sock`,
//! else `SELFDEF_API_URL` + `SELFDEF_API_TOKEN`):
//!   - `show`     — GET  /v1/sandboxes/snapshot
//!   - `allocate` — POST /v1/sandboxes/allocate
//!   - `release`  — POST /v1/sandboxes/release

use std::process::Command as Proc;

use anyhow::{Context, Result, anyhow};

/// 4 MS036 sandbox-tier letters.
const TIERS: [&str; 4] = ["tier-a", "tier-b", "tier-c", "tier-d"];

/// 8 MS032 isolation primitives (snake_case wire form).
const ISOLATIONS: [&str; 8] = [
    "host_seccomp",
    "user_namespace",
    "networked_namespace",
    "kvm_vfio",
    "kvm_headless",
    "criu_checkpoint",
    "zfs_clone",
    "firecracker_microvm",
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

/// `selfdefctl sandboxes show` — GET /v1/sandboxes/snapshot.
pub(crate) fn run_show(json: bool) -> Result<i32> {
    let body = http_get("/v1/sandboxes/snapshot")?;
    if json {
        println!("{body}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&body)
        .ok()
        .ok_or_else(|| anyhow!("daemon returned non-JSON body for /v1/sandboxes/snapshot"))?;
    let allocs = v
        .get("allocations")
        .and_then(|a| a.as_array())
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
    println!("sandboxes registry ({status})");
    println!("  allocation count: {}", allocs.len());
    for a in &allocs {
        let id = a
            .get("allocation_id")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let tier = a.get("tier").and_then(|x| x.as_str()).unwrap_or("?");
        let state = a.get("state").and_then(|x| x.as_str()).unwrap_or("?");
        let tool = a.get("tool").and_then(|x| x.as_str()).unwrap_or("?");
        let iso = a.get("isolation").and_then(|x| x.as_str()).unwrap_or("?");
        println!("  - {id}  [{state}] {tier}/{iso} tool={tool}");
    }
    Ok(0)
}

/// `selfdefctl sandboxes allocate` — POST /v1/sandboxes/allocate.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_allocate(
    actor: &str,
    profile: &str,
    tier: &str,
    ms032_tier: u8,
    isolation: &str,
    tool: &str,
    capability_token_id: &str,
    ttl_seconds: u32,
    signature: &str,
    json: bool,
) -> Result<i32> {
    if !TIERS.contains(&tier) {
        return Err(anyhow!(
            "invalid --tier {tier:?}; expected one of {}",
            TIERS.join(", ")
        ));
    }
    if !ISOLATIONS.contains(&isolation) {
        return Err(anyhow!(
            "invalid --isolation {isolation:?}; expected one of {}",
            ISOLATIONS.join(", ")
        ));
    }
    let body = serde_json::json!({
        "actor": actor,
        "profile": profile,
        "tier": tier,
        "ms032_tier": ms032_tier,
        "isolation": isolation,
        "tool": tool,
        "capability_token_id": capability_token_id,
        "ttl_seconds": ttl_seconds,
        "signature": signature,
    })
    .to_string();
    let resp = http_post("/v1/sandboxes/allocate", &body)?;
    if json {
        println!("{resp}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap_or_default();
    let id = v
        .get("allocation_id")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    let state = v.get("state").and_then(|x| x.as_str()).unwrap_or("?");
    println!("allocated sandbox {id} [{state}] {tier}/{isolation} tool={tool}");
    Ok(0)
}

/// `selfdefctl sandboxes release <allocation_id>`.
pub(crate) fn run_release(allocation_id: &str) -> Result<i32> {
    let body = serde_json::json!({ "allocation_id": allocation_id }).to_string();
    http_post("/v1/sandboxes/release", &body)?;
    println!("released sandbox {allocation_id}");
    Ok(0)
}
