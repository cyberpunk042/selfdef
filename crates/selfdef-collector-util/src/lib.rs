//! Shared helpers for the file-tailing collectors.
//!
//! The collectors tail append-only JSONL files (`eve.json`, the eventstream,
//! Tetragon's export, journald exports). A naive `read_line`-then-parse loop
//! loses an event whenever a read races a concurrent write: `read_line` returns
//! the half-written line (no trailing newline), the parse fails, and the bytes
//! are consumed — so the completing bytes are read separately and also fail.
//! [`drain_complete_lines`] is the partial-line-safe accumulation that every
//! collector shares.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Drain the COMPLETE (`'\n'`-terminated) lines from `pending`, returning each
/// trimmed non-empty line and leaving any trailing partial line buffered in
/// `pending` for the next read.
///
/// Usage in a tail loop: `pending.push_str(&just_read); for line in
/// drain_complete_lines(&mut pending) { parse(line) }`. A chunk that doesn't
/// reach a newline contributes nothing yet (the event isn't split and dropped);
/// it completes on a later read.
#[must_use]
pub fn drain_complete_lines(pending: &mut String) -> Vec<String> {
    let Some(last_nl) = pending.rfind('\n') else {
        return Vec::new(); // no complete line yet — keep buffering
    };
    let out: Vec<String> = pending[..=last_nl]
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    // Keep whatever follows the last newline (a partial line, or empty).
    *pending = pending[last_nl + 1..].to_string();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_line_yields_nothing_and_stays_buffered() {
        let mut p = String::from("{\"partial\":");
        assert!(drain_complete_lines(&mut p).is_empty());
        assert_eq!(p, "{\"partial\":");
    }

    #[test]
    fn partial_then_completion_yields_one_whole_line_no_loss() {
        let mut p = String::new();
        p.push_str("{\"a\":1"); // first read: partial
        assert!(drain_complete_lines(&mut p).is_empty());
        p.push_str("}\n"); // second read: the completion
        assert_eq!(drain_complete_lines(&mut p), vec!["{\"a\":1}".to_string()]);
        assert!(p.is_empty());
    }

    #[test]
    fn multiple_complete_lines_drain_leaving_trailing_partial() {
        let mut p = String::from("one\ntwo\nthree-part");
        assert_eq!(
            drain_complete_lines(&mut p),
            vec!["one".to_string(), "two".to_string()]
        );
        assert_eq!(p, "three-part");
    }

    #[test]
    fn blank_lines_are_skipped() {
        let mut p = String::from("a\n\n  \nb\n");
        assert_eq!(
            drain_complete_lines(&mut p),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(p.is_empty());
    }
}
