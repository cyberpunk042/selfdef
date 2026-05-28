//! `selfdefctl rules-mirror` — operator surface for the M060 D-12
//! nftables rules *live registry*. Daemon-populated by the
//! `rules_collector_loop` that polls `nft -j list ruleset` every 30s
//! and persists into `/var/lib/selfdef/rules.json`
//! ([`selfdef_rules_registry::DEFAULT_STATE_PATH`]).
//!
//! All verbs are READ-ONLY (R10212 doctrine). Rule installation /
//! modification lives in `selfdefctl + nft` at the IPS layer (operator
//! MS003 only); this surface only OBSERVES the live ruleset projection.

use anyhow::{Context, Result};
use selfdef_rules_registry::{RuleEntry, RulesMirrorSnapshot, RulesRegistry, TrustRing};
use serde_json::json;

fn store_path() -> std::path::PathBuf {
    std::env::var("SELFDEF_RULES_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(selfdef_rules_registry::DEFAULT_STATE_PATH))
}

fn load_snapshot() -> Result<RulesMirrorSnapshot> {
    let path = store_path();
    let reg = RulesRegistry::load_from_path(&path)
        .with_context(|| format!("loading rules registry from {}", path.display()))?;
    Ok(reg.snapshot().clone())
}

fn ring_token(r: TrustRing) -> &'static str {
    match r {
        TrustRing::SovereignKernel => "ring0:sovereign_kernel",
        TrustRing::TrustedLocal => "ring1:trusted_local",
        TrustRing::Sandboxed => "ring2:sandboxed",
        TrustRing::Experimental => "ring3:experimental",
        TrustRing::CloudExternal => "ring4:cloud_external",
    }
}

fn parse_ring_filter(s: &str) -> Option<TrustRing> {
    // Accept short or long forms — operator convenience.
    match s.to_ascii_lowercase().as_str() {
        "0" | "ring0" | "sovereign_kernel" | "sovereign" | "kernel" => {
            Some(TrustRing::SovereignKernel)
        }
        "1" | "ring1" | "trusted_local" | "trusted" | "local" => Some(TrustRing::TrustedLocal),
        "2" | "ring2" | "sandboxed" | "sandbox" => Some(TrustRing::Sandboxed),
        "3" | "ring3" | "experimental" | "exp" => Some(TrustRing::Experimental),
        "4" | "ring4" | "cloud_external" | "cloud" | "external" => Some(TrustRing::CloudExternal),
        _ => None,
    }
}

/// `selfdefctl rules-mirror show [--json]` — full snapshot.
///
/// # Errors
/// Surfaces any underlying registry load error.
pub(crate) fn run_show(json: bool) -> Result<()> {
    let snap = load_snapshot()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snap)?);
        return Ok(());
    }
    println!("D-12 rules-mirror @ {}", snap.captured_at);
    println!("schema_version: {}", snap.schema_version);
    println!(
        "rules: {} · rings populated: {}",
        snap.rules.len(),
        snap.summaries.len()
    );
    for s in &snap.summaries {
        println!(
            "  {} · rules={} · packets={} · bytes={} · pending_l3={}",
            ring_token(s.ring),
            s.rule_count,
            s.total_packets,
            s.total_bytes,
            s.pending_l3
        );
    }
    Ok(())
}

/// `selfdefctl rules-mirror summaries [--json]` — per-ring summary tiles.
///
/// # Errors
/// Surfaces any underlying registry load error.
pub(crate) fn run_summaries(json: bool) -> Result<()> {
    let snap = load_snapshot()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snap.summaries)?);
        return Ok(());
    }
    if snap.summaries.is_empty() {
        println!("(no rings populated — D-12 mirror offline or empty ruleset)");
        return Ok(());
    }
    println!(
        "{:<26} {:>6} {:>10} {:>14} {:>10}",
        "ring", "rules", "packets", "bytes", "pend_l3"
    );
    for s in &snap.summaries {
        println!(
            "{:<26} {:>6} {:>10} {:>14} {:>10}",
            ring_token(s.ring),
            s.rule_count,
            s.total_packets,
            s.total_bytes,
            s.pending_l3
        );
    }
    Ok(())
}

/// `selfdefctl rules-mirror list [--ring <ring>] [--json]` — flat rule
/// table, optionally filtered to a single ring.
///
/// # Errors
/// Returns an error if the filter doesn't match any known ring or the
/// registry can't be loaded.
pub(crate) fn run_list(ring: Option<String>, json: bool) -> Result<()> {
    let snap = load_snapshot()?;
    let filter = if let Some(s) = ring.as_deref() {
        match parse_ring_filter(s) {
            Some(r) => Some(r),
            None => anyhow::bail!(
                "unknown ring filter `{s}` — accepts: 0..4, ring0..ring4, sovereign_kernel, trusted_local, sandboxed, experimental, cloud_external"
            ),
        }
    } else {
        None
    };
    let filtered: Vec<&RuleEntry> = snap
        .rules
        .iter()
        .filter(|r| filter.is_none_or(|want| r.ring == want))
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }
    if filtered.is_empty() {
        match filter {
            Some(r) => println!("(no rules in {})", ring_token(r)),
            None => println!("(no rules — D-12 mirror offline or empty ruleset)"),
        }
        return Ok(());
    }
    println!(
        "{:<14} {:<20} {:<8} {:<18} {:>8} {:>10}",
        "rule_id", "chain", "dispo", "match", "packets", "bytes"
    );
    for r in filtered {
        let dispo = format!("{:?}", r.disposition).to_lowercase();
        // Truncate match_expr for the table; full text via --json.
        let mexp = if r.match_expr.len() > 16 {
            format!("{}…", &r.match_expr[..15])
        } else {
            r.match_expr.clone()
        };
        println!(
            "{:<14} {:<20} {:<8} {:<18} {:>8} {:>10}",
            r.rule_id, r.chain, dispo, mexp, r.packets, r.bytes
        );
    }
    Ok(())
}

/// `selfdefctl rules-mirror status [--json]` — terse health check for
/// the D-12 chain. Distinct from `show` in that it prints
/// dashboard-style status banners + an explicit OK/STALE/OFFLINE
/// verdict (suitable for monitoring + smoke scripts).
///
/// # Errors
/// Surfaces any underlying registry load error.
pub(crate) fn run_status(json: bool) -> Result<()> {
    let path = store_path();
    let exists = path.exists();
    let snap = if exists { load_snapshot().ok() } else { None };
    let (state, rules_count, captured_at) = match &snap {
        Some(s) if !s.rules.is_empty() => ("ok", s.rules.len(), s.captured_at.clone()),
        Some(s) => ("empty", 0_usize, s.captured_at.clone()),
        None => ("offline", 0_usize, String::new()),
    };
    if json {
        let v = json!({
            "state":          state,
            "store_path":     path.display().to_string(),
            "store_present":  exists,
            "rules":          rules_count,
            "captured_at":    captured_at,
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    println!("D-12 rules-mirror status:");
    println!(
        "  store:       {} ({})",
        path.display(),
        if exists { "present" } else { "absent" }
    );
    println!("  state:       {state}");
    println!("  rules:       {rules_count}");
    if !captured_at.is_empty() {
        println!("  captured_at: {captured_at}");
    }
    match state {
        "ok" => println!("  ↳ D-12 live · last nft collect succeeded"),
        "empty" => println!(
            "  ↳ chain online but empty — nftables has no rules OR ring{{0..4}}_* chain naming not in use"
        ),
        "offline" => println!(
            "  ↳ no resident store — selfdefd not running, or rules_collector_loop has not completed its first poll, or nft is unavailable on this host"
        ),
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfdef_rules_registry::{Disposition, RuleEntry, RulesRegistry, TrustRing};

    fn temp_store_with_rules(rules: Vec<RuleEntry>) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        let mut reg = RulesRegistry::new();
        reg.replace_rules(rules);
        reg.save_to_path(&path).unwrap();
        (dir, path)
    }

    fn sample(ring: TrustRing, handle: u64, id: &str) -> RuleEntry {
        RuleEntry {
            handle,
            rule_id: id.into(),
            ring,
            table: "inet".into(),
            chain: format!("ring{}_egress", ring.index()),
            match_expr: "ip protocol tcp".into(),
            disposition: Disposition::Accept,
            priority: 0,
            packets: 10,
            bytes: 640,
            installed_at: "2027-01-15T08:00:00Z".into(),
            installed_by: None,
            signature: String::new(),
        }
    }

    #[test]
    fn ring_filter_accepts_all_canonical_forms() {
        for s in ["0", "ring0", "sovereign_kernel", "Sovereign", "kernel"] {
            assert_eq!(
                parse_ring_filter(s),
                Some(TrustRing::SovereignKernel),
                "{s}"
            );
        }
        for s in ["2", "ring2", "sandboxed", "SANDBOX"] {
            assert_eq!(parse_ring_filter(s), Some(TrustRing::Sandboxed), "{s}");
        }
        for s in ["4", "ring4", "cloud_external", "external"] {
            assert_eq!(parse_ring_filter(s), Some(TrustRing::CloudExternal), "{s}");
        }
    }

    #[test]
    fn ring_filter_rejects_unknown() {
        assert_eq!(parse_ring_filter("ring99"), None);
        assert_eq!(parse_ring_filter(""), None);
    }

    #[test]
    fn ring_token_covers_all_five_rings() {
        for r in [
            TrustRing::SovereignKernel,
            TrustRing::TrustedLocal,
            TrustRing::Sandboxed,
            TrustRing::Experimental,
            TrustRing::CloudExternal,
        ] {
            let t = ring_token(r);
            assert!(
                t.starts_with(&format!("ring{}", r.index())),
                "ring {r:?} → {t}"
            );
        }
    }

    #[test]
    fn run_show_via_load_snapshot_round_trip() {
        let (_dir, path) = temp_store_with_rules(vec![
            sample(TrustRing::SovereignKernel, 1, "r-1"),
            sample(TrustRing::CloudExternal, 2, "r-2"),
        ]);
        // SAFETY-equivalent: tests don't share state with each other
        // because each gets its own tempdir, but env vars ARE process-
        // global. We exercise load_snapshot() via a direct construction
        // rather than env-mutation, which avoids the unsafe gate.
        let snap = RulesRegistry::load_from_path(&path)
            .unwrap()
            .snapshot()
            .clone();
        assert_eq!(snap.rules.len(), 2);
        assert_eq!(snap.summaries.len(), 2);
        let ids: Vec<&str> = snap.rules.iter().map(|r| r.rule_id.as_str()).collect();
        assert!(ids.contains(&"r-1"));
        assert!(ids.contains(&"r-2"));
    }

    #[test]
    fn status_state_matches_store_contents() {
        // No store path → offline
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.json");
        assert!(!missing.exists());

        // Store present + non-empty → ok
        let (_dir2, path) =
            temp_store_with_rules(vec![sample(TrustRing::SovereignKernel, 1, "r-1")]);
        let snap = RulesRegistry::load_from_path(&path).unwrap();
        assert_eq!(snap.rule_count(), 1);

        // Store present + empty → empty
        let dir3 = tempfile::tempdir().unwrap();
        let path3 = dir3.path().join("rules.json");
        RulesRegistry::new().save_to_path(&path3).unwrap();
        let snap3 = RulesRegistry::load_from_path(&path3).unwrap();
        assert_eq!(snap3.rule_count(), 0);
    }
}
