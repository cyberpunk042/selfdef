//! `nft -j list ruleset` → `Vec<RuleEntry>` projection.
//!
//! Pure parser: takes the JSON document produced by `nft -j list ruleset`
//! (nftables ≥ 0.9 with libjansson, schema v1) and projects each `rule`
//! object into a [`RuleEntry`] for the [`RulesRegistry`](super::RulesRegistry).
//!
//! # Wire shape (nftables json schema 1)
//!
//! ```json
//! {
//!   "nftables": [
//!     {"metainfo": {"version": "1.0.6", "json_schema_version": 1}},
//!     {"table": {"family": "inet", "name": "selfdef_bridge", "handle": 1}},
//!     {"chain": {
//!         "family": "inet", "table": "selfdef_bridge",
//!         "name": "ring0_egress", "handle": 1, "type": "filter",
//!         "hook": "output", "prio": 0, "policy": "accept"}},
//!     {"rule": {
//!         "family": "inet", "table": "selfdef_bridge",
//!         "chain": "ring0_egress", "handle": 1,
//!         "expr": [ ..., {"counter": {"packets": 5, "bytes": 320}}, {"drop": null}],
//!         "comment": "selfdef:rule-001"}}
//!   ]
//! }
//! ```
//!
//! # Ring inference
//!
//! The trust ring is derived from the chain name prefix:
//!
//! - `ring0_*`  → [`TrustRing::SovereignKernel`]
//! - `ring1_*`  → [`TrustRing::TrustedLocal`]
//! - `ring2_*`  → [`TrustRing::Sandboxed`]
//! - `ring3_*`  → [`TrustRing::Experimental`]
//! - `ring4_*`  → [`TrustRing::CloudExternal`]
//! - other      → [`TrustRing::Experimental`] (fail-safe — unknown chains
//!   are quarantined to the experimental ring per MS039 R10248
//!   "unknown = experimental until classified")
//!
//! # `rule_id` inference
//!
//! If the rule has a `comment` of the form `selfdef:<id>`, the suffix is
//! used as `rule_id`. Otherwise the rule_id falls back to
//! `nft-<table>-<chain>-<handle>` (stable across reloads on the same
//! nftables ruleset object identity).
//!
//! # Disposition inference
//!
//! The disposition is taken from the LAST verb-like expr in the rule's
//! `expr` array. Recognized verbs: `accept`, `drop`, `reject`, `jump`,
//! `continue`, `return`. Default: `continue` (when no verb is present —
//! pure-match rule, e.g., counter-only).
//!
//! # Counter projection
//!
//! Packets + bytes are extracted from the first `counter` expr in the
//! rule's `expr` array. Default: 0 packets / 0 bytes.

use selfdef_rules_mirror::{Disposition, RuleEntry, TrustRing};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// nft parser errors.
#[derive(Debug, Error)]
pub enum NftParseError {
    /// Top-level structure was not the expected `{"nftables": [...]}`.
    #[error("nft json missing top-level 'nftables' array")]
    MissingNftables,
    /// The JSON document itself was malformed.
    #[error("nft json deserialization failed: {0}")]
    Deserialize(#[from] serde_json::Error),
}

/// Parse the output of `nft -j list ruleset` into a list of [`RuleEntry`]
/// objects. Skips non-rule entries (table / chain / set / counter /
/// metainfo).
///
/// # Errors
/// Returns [`NftParseError::Deserialize`] if the input is not valid JSON,
/// or [`NftParseError::MissingNftables`] if the document doesn't carry a
/// top-level `nftables` array (per the json-schema-v1 contract).
pub fn parse_nft_ruleset_json(json: &str) -> Result<Vec<RuleEntry>, NftParseError> {
    let v: serde_json::Value = serde_json::from_str(json)?;
    let arr = v
        .get("nftables")
        .and_then(|x| x.as_array())
        .ok_or(NftParseError::MissingNftables)?;
    let captured_at = now_rfc3339();
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(rule_obj) = item.get("rule").and_then(|x| x.as_object()) else {
            continue;
        };
        if let Some(entry) = project_rule(rule_obj, &captured_at) {
            out.push(entry);
        }
    }
    Ok(out)
}

fn project_rule(
    obj: &serde_json::Map<String, serde_json::Value>,
    captured_at: &str,
) -> Option<RuleEntry> {
    let table = obj.get("table").and_then(|x| x.as_str()).unwrap_or("");
    let chain = obj.get("chain").and_then(|x| x.as_str()).unwrap_or("");
    let handle = obj.get("handle").and_then(|x| x.as_u64()).unwrap_or(0);
    if table.is_empty() || chain.is_empty() {
        // Malformed rule entry — skip rather than crash. nft always
        // populates table+chain on real rules.
        return None;
    }

    let ring = ring_from_chain(chain);
    let comment = obj.get("comment").and_then(|x| x.as_str()).unwrap_or("");
    let rule_id = if let Some(suffix) = comment.strip_prefix("selfdef:") {
        suffix.to_string()
    } else {
        format!("nft-{table}-{chain}-{handle}")
    };

    let (disposition, packets, bytes, match_expr) =
        project_expr(obj.get("expr").and_then(|x| x.as_array()));

    Some(RuleEntry {
        handle,
        rule_id,
        ring,
        table: table.to_string(),
        chain: chain.to_string(),
        match_expr,
        disposition,
        // nft does not expose a per-rule priority — chain priority lives
        // on the chain object. Use 0 as a stable placeholder; a future
        // pass can join chain priorities into the entries.
        priority: 0,
        packets,
        bytes,
        installed_at: captured_at.to_string(),
        // nft does not record the operator fingerprint; that comes from
        // selfdefctl's audit log. Leave None — the dashboard's
        // "installed_by" column will render `unknown` for these.
        installed_by: None,
        // Signature is computed by the daemon-side signer; nft does not
        // sign rules. Leave empty for the registry to fill.
        signature: String::new(),
    })
}

fn ring_from_chain(chain: &str) -> TrustRing {
    // MS039 chain-naming convention: ring{N}_<direction>_<purpose>
    if chain.starts_with("ring0") {
        TrustRing::SovereignKernel
    } else if chain.starts_with("ring1") {
        TrustRing::TrustedLocal
    } else if chain.starts_with("ring2") {
        TrustRing::Sandboxed
    } else if chain.starts_with("ring3") {
        TrustRing::Experimental
    } else if chain.starts_with("ring4") {
        TrustRing::CloudExternal
    } else {
        // Unknown chain — fail-safe to the experimental ring per MS039
        // R10248 ("unknown = experimental until classified"). The
        // dashboard will surface these for operator review.
        TrustRing::Experimental
    }
}

/// Walk the rule's `expr` array and return (disposition, packets, bytes,
/// match_summary). The disposition is the LAST verb-shaped expr;
/// packets+bytes come from the FIRST counter expr; the match_summary is
/// a compact one-liner combining all non-verb, non-counter exprs.
fn project_expr(expr: Option<&Vec<serde_json::Value>>) -> (Disposition, u64, u64, String) {
    let Some(expr) = expr else {
        return (Disposition::Continue, 0, 0, String::new());
    };
    let mut disposition = Disposition::Continue;
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut match_parts: Vec<String> = Vec::new();
    for e in expr {
        let Some(obj) = e.as_object() else {
            continue;
        };
        // Single-key dispatch — nft expr objects are always single-key.
        if let Some((k, v)) = obj.iter().next() {
            match k.as_str() {
                "accept" => disposition = Disposition::Accept,
                "drop" => disposition = Disposition::Drop,
                "reject" => disposition = Disposition::Reject,
                "jump" => disposition = Disposition::Jump,
                "continue" => disposition = Disposition::Continue,
                "return" => disposition = Disposition::Return,
                "counter" => {
                    if let Some(cobj) = v.as_object() {
                        packets = cobj.get("packets").and_then(|x| x.as_u64()).unwrap_or(0);
                        bytes = cobj.get("bytes").and_then(|x| x.as_u64()).unwrap_or(0);
                    }
                }
                // Match-class exprs (match / payload / meta / ct / set
                // lookup / etc.) — collapse into a one-liner. Keep small
                // to fit the dashboard row; full detail lives in
                // `selfdefctl rules show --rule-id <id>`.
                _ => {
                    let summary = summarize_match_expr(k, v);
                    if !summary.is_empty() {
                        match_parts.push(summary);
                    }
                }
            }
        }
    }
    let match_expr = match_parts.join(" ");
    (disposition, packets, bytes, match_expr)
}

fn summarize_match_expr(kind: &str, v: &serde_json::Value) -> String {
    match kind {
        "match" => {
            // {"match": {"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}}
            if let Some(obj) = v.as_object() {
                let op = obj.get("op").and_then(|x| x.as_str()).unwrap_or("==");
                let left = obj.get("left").map(stringify_operand).unwrap_or_default();
                let right = obj.get("right").map(stringify_operand).unwrap_or_default();
                format!("{left} {op} {right}")
            } else {
                kind.to_string()
            }
        }
        "payload" | "meta" | "ct" => stringify_operand(v),
        _ => kind.to_string(),
    }
}

fn stringify_operand(v: &serde_json::Value) -> String {
    if let Some(s) = v.as_str() {
        return s.to_string();
    }
    if let Some(n) = v.as_u64() {
        return n.to_string();
    }
    if let Some(obj) = v.as_object() {
        // Common shape: {"meta":{"key":"l4proto"}} → "meta:l4proto"
        // Or:           {"payload":{"protocol":"tcp","field":"dport"}} → "tcp:dport"
        if let Some((k, inner)) = obj.iter().next() {
            if let Some(iobj) = inner.as_object() {
                if let Some(key) = iobj.get("key").and_then(|x| x.as_str()) {
                    return format!("{k}:{key}");
                }
                if let (Some(proto), Some(field)) = (
                    iobj.get("protocol").and_then(|x| x.as_str()),
                    iobj.get("field").and_then(|x| x.as_str()),
                ) {
                    return format!("{proto}:{field}");
                }
            }
            return k.to_string();
        }
    }
    String::new()
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ruleset_yields_empty_vec() {
        let json = r#"{"nftables": []}"#;
        assert!(parse_nft_ruleset_json(json).unwrap().is_empty());
    }

    #[test]
    fn ruleset_with_only_metainfo_yields_empty_vec() {
        let json = r#"{
            "nftables": [
                {"metainfo": {"version":"1.0.6","json_schema_version":1}},
                {"table": {"family":"inet","name":"selfdef_bridge","handle":1}},
                {"chain": {"family":"inet","table":"selfdef_bridge","name":"ring0_egress","handle":1,"type":"filter","hook":"output","prio":0,"policy":"accept"}}
            ]
        }"#;
        assert!(parse_nft_ruleset_json(json).unwrap().is_empty());
    }

    #[test]
    fn missing_nftables_key_returns_error() {
        let json = r#"{"unrelated": "data"}"#;
        assert!(matches!(
            parse_nft_ruleset_json(json).unwrap_err(),
            NftParseError::MissingNftables
        ));
    }

    #[test]
    fn malformed_json_returns_error() {
        let json = "not json";
        assert!(matches!(
            parse_nft_ruleset_json(json).unwrap_err(),
            NftParseError::Deserialize(_)
        ));
    }

    #[test]
    fn single_rule_with_drop_disposition() {
        let json = r#"{
            "nftables": [
                {"rule": {
                    "family":"inet","table":"selfdef_bridge",
                    "chain":"ring0_egress","handle":5,
                    "expr":[
                        {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},
                        {"counter":{"packets":100,"bytes":6400}},
                        {"drop":null}
                    ],
                    "comment":"selfdef:rule-007"
                }}
            ]
        }"#;
        let out = parse_nft_ruleset_json(json).unwrap();
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(r.handle, 5);
        assert_eq!(r.rule_id, "rule-007");
        assert_eq!(r.ring, TrustRing::SovereignKernel);
        assert_eq!(r.table, "selfdef_bridge");
        assert_eq!(r.chain, "ring0_egress");
        assert_eq!(r.disposition, Disposition::Drop);
        assert_eq!(r.packets, 100);
        assert_eq!(r.bytes, 6400);
        assert!(r.match_expr.contains("tcp"));
    }

    #[test]
    fn rule_id_falls_back_to_nft_handle_when_no_comment() {
        let json = r#"{
            "nftables": [
                {"rule": {
                    "family":"inet","table":"selfdef_bridge",
                    "chain":"ring2_egress","handle":42,
                    "expr":[{"accept":null}]
                }}
            ]
        }"#;
        let r = &parse_nft_ruleset_json(json).unwrap()[0];
        assert_eq!(r.rule_id, "nft-selfdef_bridge-ring2_egress-42");
        assert_eq!(r.ring, TrustRing::Sandboxed);
        assert_eq!(r.disposition, Disposition::Accept);
    }

    #[test]
    fn rule_id_uses_arbitrary_selfdef_comment_suffix() {
        let json = r#"{
            "nftables": [
                {"rule": {
                    "family":"inet","table":"t","chain":"ring4_in","handle":1,
                    "expr":[{"reject":null}],
                    "comment":"selfdef:custom-id-xyz"
                }}
            ]
        }"#;
        let r = &parse_nft_ruleset_json(json).unwrap()[0];
        assert_eq!(r.rule_id, "custom-id-xyz");
        assert_eq!(r.ring, TrustRing::CloudExternal);
        assert_eq!(r.disposition, Disposition::Reject);
    }

    #[test]
    fn unknown_chain_falls_back_to_experimental_ring() {
        let json = r#"{
            "nftables": [
                {"rule": {
                    "family":"inet","table":"t","chain":"unrelated_chain","handle":1,
                    "expr":[{"jump":null}]
                }}
            ]
        }"#;
        let r = &parse_nft_ruleset_json(json).unwrap()[0];
        assert_eq!(r.ring, TrustRing::Experimental);
        assert_eq!(r.disposition, Disposition::Jump);
    }

    #[test]
    fn each_ring_prefix_maps_correctly() {
        for (chain, expected) in [
            ("ring0_egress", TrustRing::SovereignKernel),
            ("ring1_in", TrustRing::TrustedLocal),
            ("ring2_egress", TrustRing::Sandboxed),
            ("ring3_in", TrustRing::Experimental),
            ("ring4_in", TrustRing::CloudExternal),
        ] {
            let json = format!(
                r#"{{"nftables":[{{"rule":{{"family":"inet","table":"t","chain":"{chain}","handle":1,"expr":[{{"continue":null}}]}}}}]}}"#
            );
            let r = &parse_nft_ruleset_json(&json).unwrap()[0];
            assert_eq!(r.ring, expected, "chain {chain}");
        }
    }

    #[test]
    fn rule_with_no_disposition_verb_defaults_to_continue() {
        let json = r#"{
            "nftables": [
                {"rule": {
                    "family":"inet","table":"t","chain":"ring1_egress","handle":1,
                    "expr":[{"counter":{"packets":1,"bytes":64}}]
                }}
            ]
        }"#;
        let r = &parse_nft_ruleset_json(json).unwrap()[0];
        assert_eq!(r.disposition, Disposition::Continue);
        assert_eq!(r.packets, 1);
        assert_eq!(r.bytes, 64);
    }

    #[test]
    fn rule_without_table_or_chain_is_skipped() {
        let json = r#"{
            "nftables": [
                {"rule": {"family":"inet","handle":1,"expr":[{"accept":null}]}},
                {"rule": {"family":"inet","table":"t","chain":"ring0_egress","handle":2,"expr":[{"accept":null}]}}
            ]
        }"#;
        let out = parse_nft_ruleset_json(json).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].handle, 2);
    }

    #[test]
    fn multiple_rules_yield_multiple_entries_in_input_order() {
        let json = r#"{
            "nftables": [
                {"rule": {"family":"inet","table":"t","chain":"ring0_egress","handle":1,"expr":[{"accept":null}]}},
                {"rule": {"family":"inet","table":"t","chain":"ring4_in","handle":2,"expr":[{"drop":null}]}},
                {"rule": {"family":"inet","table":"t","chain":"ring2_egress","handle":3,"expr":[{"continue":null}]}}
            ]
        }"#;
        let out = parse_nft_ruleset_json(json).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].ring, TrustRing::SovereignKernel);
        assert_eq!(out[1].ring, TrustRing::CloudExternal);
        assert_eq!(out[2].ring, TrustRing::Sandboxed);
    }

    #[test]
    fn match_expr_summary_includes_protocol_and_field() {
        let json = r#"{
            "nftables": [
                {"rule": {
                    "family":"inet","table":"t","chain":"ring2_egress","handle":1,
                    "expr":[
                        {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
                        {"accept":null}
                    ]
                }}
            ]
        }"#;
        let r = &parse_nft_ruleset_json(json).unwrap()[0];
        assert!(r.match_expr.contains("tcp:dport"), "got {}", r.match_expr);
        assert_eq!(r.disposition, Disposition::Accept);
    }

    #[test]
    fn captured_at_is_rfc3339() {
        let json = r#"{"nftables":[{"rule":{"family":"inet","table":"t","chain":"ring0_egress","handle":1,"expr":[{"accept":null}]}}]}"#;
        let r = &parse_nft_ruleset_json(json).unwrap()[0];
        // Sanity: RFC-3339 has 'T' separator and 'Z' suffix for UTC.
        assert!(r.installed_at.contains('T'));
        assert!(r.installed_at.ends_with('Z'));
    }
}
