//! MS022 — SSE subscriber quota Prometheus exposition.
//!
//! Surfaces the per-token + global SSE subscriber counters carried in
//! [`ApiState::sse_subscribers`] + [`ApiState::sse_subscribers_per_token`]
//! so operators can monitor + alert on SSE quota saturation. Without
//! this surface, the only signal an operator gets when a token
//! saturates its `[api].max_sse_subscribers_per_token` cap is a
//! per-request HTTP 429 — invisible to the broader alerting pipeline.
//!
//! Series emitted (all gauges):
//!
//!   selfdef_sse_subscribers_global_active        Current live SSE
//!     subscribers across all tokens (`ApiState::sse_subscribers`
//!     atomic). Operators alert on this approaching
//!     `_global_cap`.
//!   selfdef_sse_subscribers_global_cap           Effective global
//!     cap (operator-overridden `[api].max_sse_subscribers` or
//!     the compiled default 64).
//!   selfdef_sse_subscribers_global_saturation    Ratio
//!     `_active / _cap` in [0.0, 1.0]. The single
//!     gauge an alert rule typically watches (e.g.
//!     `> 0.85 for 5m`).
//!   selfdef_sse_subscribers_per_token_cap        Effective
//!     per-token cap (operator override or compiled default 8).
//!   selfdef_sse_subscribers_per_token            Live count per
//!     token fingerprint. Cardinality bounded by the active
//!     token set (small in practice — operator + 0..N admin tools).
//!   selfdef_sse_subscribers_per_token_saturated  Count of tokens
//!     currently at-or-above the per-token cap. The fast
//!     alert-trigger signal: > 0 means at least one operator
//!     is being throttled right now.
//!
//! Project boundary: pure observability — no mutation surface.
//! Operator-controlled caps live in `[api].max_sse_subscribers{,
//! _per_token}` (config) + `crate::handlers` (enforcement). This
//! module only READS them.

use std::sync::atomic::Ordering;

use crate::ApiState;
use crate::TokenFingerprint;
use crate::handlers::{MAX_SSE_SUBSCRIBERS, MAX_SSE_SUBSCRIBERS_PER_TOKEN};

/// Privacy-preserving 8-hex-char prefix for the per-token label.
/// Matches the `Debug` impl on TokenFingerprint — operators see a
/// stable identifier across scrapes without the metric leaking the
/// full SHA-256 of the bearer token.
fn fingerprint_label(fp: &TokenFingerprint) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        fp.0[0], fp.0[1], fp.0[2], fp.0[3],
    )
}

/// Escape a Prometheus label value per the exposition format:
/// backslash + double-quote + newline must be backslash-escaped.
fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            ch => out.push(ch),
        }
    }
    out
}

/// Compute the effective global cap honoring the operator override.
/// Mirrors the SubscriberGuard::try_acquire logic in handlers.rs so
/// the metric always reflects the value the enforcement path uses.
fn effective_global_cap(state: &ApiState) -> usize {
    match state.sse_caps.global {
        Some(n) if n > 0 => n,
        _ => MAX_SSE_SUBSCRIBERS,
    }
}

/// Same for the per-token cap.
fn effective_per_token_cap(state: &ApiState) -> usize {
    match state.sse_caps.per_token {
        Some(n) if n > 0 => n,
        _ => MAX_SSE_SUBSCRIBERS_PER_TOKEN,
    }
}

/// Sample the per-token counter HashMap under the lock + drop the
/// lock before formatting. Returns `(fp_hex, count)` rows sorted by
/// fp_hex so the exposition is deterministic — the operator can
/// diff scrapes for stable comparison.
fn sample_per_token(state: &ApiState) -> Vec<(String, usize)> {
    let map = state
        .sse_subscribers_per_token
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut rows: Vec<(String, usize)> = map
        .iter()
        .map(|(fp, counter)| (fingerprint_label(fp), counter.load(Ordering::Acquire)))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

/// Render the SSE-quota metrics block as a Prometheus exposition-format
/// string. Concatenated by `crate::handlers::metrics` into the larger
/// `/metrics` response — same pattern as `watchdog_metrics::render`.
#[must_use]
pub(crate) fn render(state: &ApiState) -> String {
    let mut out = String::new();

    let active = state.sse_subscribers.load(Ordering::Acquire);
    let global_cap = effective_global_cap(state);
    let per_token_cap = effective_per_token_cap(state);

    // selfdef_sse_subscribers_global_active
    out.push_str(
        "# HELP selfdef_sse_subscribers_global_active Current live SSE \
         subscribers across all tokens (MS022 quota live count).\n",
    );
    out.push_str("# TYPE selfdef_sse_subscribers_global_active gauge\n");
    out.push_str(&format!("selfdef_sse_subscribers_global_active {active}\n"));

    // selfdef_sse_subscribers_global_cap
    out.push_str(
        "# HELP selfdef_sse_subscribers_global_cap Effective global SSE \
         subscriber cap (operator override [api].max_sse_subscribers or \
         compiled default).\n",
    );
    out.push_str("# TYPE selfdef_sse_subscribers_global_cap gauge\n");
    out.push_str(&format!(
        "selfdef_sse_subscribers_global_cap {global_cap}\n"
    ));

    // selfdef_sse_subscribers_global_saturation
    //
    // Safe-divide: when the operator misconfigures cap=0 we still
    // return 0.0 (would otherwise be NaN). The enforcement path
    // treats 0 as "fall back to compiled default" so this case is
    // unreachable in practice, but the safety guard means a future
    // refactor doesn't silently regress.
    let saturation = if global_cap > 0 {
        // Use f64 division so partial saturation is visible (e.g.
        // 12/64 = 0.1875). Alert rules typically threshold around 0.85.
        active as f64 / global_cap as f64
    } else {
        0.0
    };
    out.push_str(
        "# HELP selfdef_sse_subscribers_global_saturation Ratio of active \
         to cap (0.0..1.0). Alert rules typically watch this approaching 1.\n",
    );
    out.push_str("# TYPE selfdef_sse_subscribers_global_saturation gauge\n");
    out.push_str(&format!(
        "selfdef_sse_subscribers_global_saturation {saturation:.6}\n"
    ));

    // selfdef_sse_subscribers_per_token_cap
    out.push_str(
        "# HELP selfdef_sse_subscribers_per_token_cap Effective per-token \
         SSE subscriber cap (operator override [api].max_sse_subscribers_\
         per_token or compiled default).\n",
    );
    out.push_str("# TYPE selfdef_sse_subscribers_per_token_cap gauge\n");
    out.push_str(&format!(
        "selfdef_sse_subscribers_per_token_cap {per_token_cap}\n"
    ));

    // Per-token live count + saturated-count rollup.
    let per_token = sample_per_token(state);
    out.push_str(
        "# HELP selfdef_sse_subscribers_per_token Live SSE subscriber count \
         per token fingerprint. Cardinality bounded by active tokens.\n",
    );
    out.push_str("# TYPE selfdef_sse_subscribers_per_token gauge\n");
    let mut saturated = 0usize;
    for (fp, count) in &per_token {
        out.push_str(&format!(
            "selfdef_sse_subscribers_per_token{{token_fp=\"{}\"}} {count}\n",
            escape_label(fp),
        ));
        if *count >= per_token_cap {
            saturated += 1;
        }
    }

    out.push_str(
        "# HELP selfdef_sse_subscribers_per_token_saturated Count of tokens \
         currently at or above the per-token cap (operator is being \
         throttled right now).\n",
    );
    out.push_str("# TYPE selfdef_sse_subscribers_per_token_saturated gauge\n");
    out.push_str(&format!(
        "selfdef_sse_subscribers_per_token_saturated {saturated}\n"
    ));

    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use selfdef_bus::Bus;
    use selfdef_store::SqliteStore;

    use super::*;
    use crate::state::SseCaps;

    fn _state_with_caps(caps: SseCaps) -> ApiState {
        // Tempfile path — SqliteStore::open creates the schema if absent.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(dir.path().join("state.sqlite")).unwrap());
        // Hold the tempdir alive for the duration of the test by leaking
        // it — these tests are small and the dir is cleaned up by the
        // OS on process exit. Using leak avoids a 'static-lifetime
        // refactor on _state_with_caps signatures.
        Box::leak(Box::new(dir));
        let bus = Arc::new(Bus::new(1024));
        ApiState::new(store, bus, "test-host".to_string()).with_sse_caps(caps)
    }

    #[test]
    fn escape_label_handles_quote_backslash_newline() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("with \"quote\""), "with \\\"quote\\\"");
        assert_eq!(escape_label("with\\bs"), "with\\\\bs");
        assert_eq!(escape_label("with\nnl"), "with\\nnl");
    }

    #[test]
    fn render_emits_all_required_metrics_and_help_lines() {
        let state = _state_with_caps(SseCaps::default());
        let body = render(&state);
        for metric in [
            "selfdef_sse_subscribers_global_active",
            "selfdef_sse_subscribers_global_cap",
            "selfdef_sse_subscribers_global_saturation",
            "selfdef_sse_subscribers_per_token_cap",
            "selfdef_sse_subscribers_per_token",
            "selfdef_sse_subscribers_per_token_saturated",
        ] {
            assert!(
                body.contains(&format!("# HELP {metric}")),
                "missing HELP for {metric}; body:\n{body}"
            );
            assert!(
                body.contains(&format!("# TYPE {metric} gauge")),
                "missing TYPE for {metric}; body:\n{body}"
            );
        }
    }

    #[test]
    fn render_global_cap_falls_back_to_compiled_default() {
        let state = _state_with_caps(SseCaps {
            global: None,
            per_token: None,
        });
        let body = render(&state);
        assert!(body.contains(&format!(
            "selfdef_sse_subscribers_global_cap {MAX_SSE_SUBSCRIBERS}"
        )));
        assert!(body.contains(&format!(
            "selfdef_sse_subscribers_per_token_cap {MAX_SSE_SUBSCRIBERS_PER_TOKEN}"
        )));
    }

    #[test]
    fn render_global_cap_honors_operator_override() {
        let state = _state_with_caps(SseCaps {
            global: Some(128),
            per_token: Some(16),
        });
        let body = render(&state);
        assert!(body.contains("selfdef_sse_subscribers_global_cap 128"));
        assert!(body.contains("selfdef_sse_subscribers_per_token_cap 16"));
    }

    #[test]
    fn render_cap_zero_falls_back_to_compiled_default() {
        // Operator left the knob commented (`Some(0)`) → compiled default.
        let state = _state_with_caps(SseCaps {
            global: Some(0),
            per_token: Some(0),
        });
        let body = render(&state);
        assert!(body.contains(&format!(
            "selfdef_sse_subscribers_global_cap {MAX_SSE_SUBSCRIBERS}"
        )));
    }

    #[test]
    fn render_saturation_zero_when_no_subscribers() {
        let state = _state_with_caps(SseCaps::default());
        let body = render(&state);
        assert!(
            body.contains("selfdef_sse_subscribers_global_saturation 0.000000"),
            "no subscribers should be 0.0 saturation; body:\n{body}"
        );
        assert!(body.contains("selfdef_sse_subscribers_global_active 0"));
    }

    #[test]
    fn render_saturation_reflects_active_over_cap() {
        let state = _state_with_caps(SseCaps {
            global: Some(100),
            per_token: None,
        });
        // Manually pump the atomic to simulate active subscribers.
        state.sse_subscribers.store(25, Ordering::Release);
        let body = render(&state);
        // 25/100 = 0.25
        assert!(
            body.contains("selfdef_sse_subscribers_global_saturation 0.250000"),
            "25/100 should be 0.25; body:\n{body}"
        );
        assert!(body.contains("selfdef_sse_subscribers_global_active 25"));
    }

    #[test]
    fn render_per_token_saturated_counts_tokens_at_or_above_cap() {
        let state = _state_with_caps(SseCaps {
            global: None,
            per_token: Some(4),
        });
        // Pump the per-token map with 3 tokens: one at-cap, one over, one below.
        {
            let mut map = state.sse_subscribers_per_token.lock().unwrap();
            // We can't construct a TokenFingerprint without the upstream
            // helper, so use the public TokenFingerprint::from_str fake
            // path via the crate's testing surface. Test the rollup
            // arithmetic by inserting via the same crate-internal API
            // the production path uses.
            use crate::TokenFingerprint;
            let fps = [
                TokenFingerprint::of("alpha"),
                TokenFingerprint::of("beta"),
                TokenFingerprint::of("gamma"),
            ];
            map.insert(fps[0], AtomicUsize::new(4)); // at cap
            map.insert(fps[1], AtomicUsize::new(7)); // over cap
            map.insert(fps[2], AtomicUsize::new(1)); // under cap
        }
        let body = render(&state);
        // Three per-token series + saturated=2 (two at-or-above cap=4).
        assert!(
            body.contains("selfdef_sse_subscribers_per_token_saturated 2"),
            "expected saturated=2 (cap=4, counts [4,7,1]); body:\n{body}"
        );
    }

    #[test]
    fn render_per_token_rows_are_sorted_for_deterministic_output() {
        let state = _state_with_caps(SseCaps::default());
        {
            let mut map = state.sse_subscribers_per_token.lock().unwrap();
            use crate::TokenFingerprint;
            map.insert(TokenFingerprint::of("zzz"), AtomicUsize::new(1));
            map.insert(TokenFingerprint::of("aaa"), AtomicUsize::new(2));
            map.insert(TokenFingerprint::of("mmm"), AtomicUsize::new(3));
        }
        let body = render(&state);
        // Find the three per-token lines + confirm they appear in sorted
        // fingerprint-hex order. Since fingerprints are hashes, sort
        // ordering is on the hex strings.
        let lines: Vec<&str> = body
            .lines()
            .filter(|l| l.starts_with("selfdef_sse_subscribers_per_token{"))
            .collect();
        assert_eq!(lines.len(), 3, "expected 3 per-token rows; body:\n{body}");
        let mut sorted = lines.clone();
        sorted.sort();
        assert_eq!(
            lines, sorted,
            "per-token rows must be emitted in sorted fingerprint order \
             so operators can diff successive scrapes; body:\n{body}"
        );
    }
}
