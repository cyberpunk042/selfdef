//! `selfdefctl quarantine` — operator surface for the M060 D-17
//! quarantine *live registry*. Daemon-populated by MS042 detection;
//! operator verbs are `show` + the post-block `release` / `forfeit`
//! overrides (MS003-signed).

use std::process::Command as Proc;

use anyhow::{Context, Result, anyhow};

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

/// `selfdefctl quarantine show`.
pub(crate) fn run_show(json: bool) -> Result<i32> {
    let body = http_get("/v1/quarantine/snapshot")?;
    if json {
        println!("{body}");
        return Ok(0);
    }
    let v: serde_json::Value = serde_json::from_str(&body)
        .ok()
        .ok_or_else(|| anyhow!("daemon returned non-JSON body for /v1/quarantine/snapshot"))?;
    let entries = v
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    println!("quarantine registry");
    println!("  entry count: {}", entries.len());
    for e in &entries {
        let id = e
            .get("quarantine_id")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        let tool = e.get("tool").and_then(|x| x.as_str()).unwrap_or("?");
        let state = e.get("state").and_then(|x| x.as_str()).unwrap_or("?");
        let sev = e
            .get("max_severity")
            .and_then(|x| x.as_str())
            .unwrap_or("?");
        println!("  - {id}  [{state}] tool={tool} max_severity={sev}");
    }
    Ok(0)
}

/// `selfdefctl quarantine release <quarantine_id> --actor X --signature S`.
pub(crate) fn run_release(quarantine_id: &str, actor: &str, signature: &str) -> Result<i32> {
    let body = serde_json::json!({
        "quarantine_id": quarantine_id,
        "actor": actor,
        "signature": signature,
    })
    .to_string();
    http_post("/v1/quarantine/release", &body)?;
    println!("released quarantine {quarantine_id}");
    Ok(0)
}

/// `selfdefctl quarantine forfeit <quarantine_id> --actor X --signature S`.
pub(crate) fn run_forfeit(quarantine_id: &str, actor: &str, signature: &str) -> Result<i32> {
    let body = serde_json::json!({
        "quarantine_id": quarantine_id,
        "actor": actor,
        "signature": signature,
    })
    .to_string();
    http_post("/v1/quarantine/forfeit", &body)?;
    println!("forfeited quarantine {quarantine_id}");
    Ok(0)
}
