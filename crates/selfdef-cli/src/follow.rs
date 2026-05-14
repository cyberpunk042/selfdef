//! `selfdefctl events follow` — live tail of the daemon's
//! `/events/stream` SSE endpoint.
//!
//! Two transports:
//!
//! - **UNIX socket** (`events_follow_unix`): default path that
//!   matches the daemon's `[api].unix_socket`. Talks raw
//!   HTTP/1.1 directly over `tokio::net::UnixStream` so the
//!   CLI doesn't have to pull a full HTTP client just to read
//!   one long-lived chunked response.
//! - **TCP / HTTP(S)** (`events_follow_tcp`, F-2027-010): opt-in
//!   path for operators whose daemons are reachable only via the
//!   TCP transport. Pulls `reqwest::Response::bytes_stream()`
//!   (reqwest already lives in the workspace via
//!   `selfdef-notifier`) and feeds each chunk into the same
//!   SSE-frame parser the UNIX path uses, so behaviour parity
//!   is automatic.
//!
//! Frame parsing lives in [`SseParser`] so both transports
//! share the same logic: blank-line frame termination, `event:`
//! / `data:` / `:comment` dispatch, and the `event: shutdown`
//! and `event: lagged` handling F-2027-029 + -028 introduced.
//!
//! F-2028-019: both transports hand the parser **raw bytes**
//! via [`SseParser::feed_bytes`]; chunk boundaries are invisible
//! to the parser by construction. Any future third transport
//! must do the same — never call `String::from_utf8_lossy`
//! per-chunk before feeding, because a multi-byte UTF-8 sequence
//! that straddles a chunk boundary would be destroyed (F-2028-018).
//!
//! Module-level entry points:
//!
//! - [`events_follow_unix`] — UNIX-socket transport.
//! - [`events_follow_tcp`] — TCP/HTTP(S) transport (F-2027-010).
//! - [`read_token_file`] — F-2028-007: helper used by the
//!   `Follow` clap dispatch site (`main.rs`) to load a bearer
//!   token from disk. Mirrors the daemon-side `read_token` in
//!   `selfdef-api/src/transport.rs` byte-for-byte (mode check
//!   `mode & 0o077 == 0` + Unicode-aware `trim()`).

use std::path::Path;

use anyhow::{Context, Result};
use futures::StreamExt as _;
use selfdef_core::Event;
use selfdef_core::category::CategoryUid;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// One decoded SSE frame, in the form the printer needs.
#[derive(Debug, PartialEq, Eq)]
enum SseFrame {
    /// Default-type event frame — payload is the JSON `data:` body.
    Data(String),
    /// `event: shutdown` — the daemon's writer task is exiting cleanly.
    Shutdown(String),
    /// `event: lagged` — the subscriber missed events; payload is the
    /// human-readable reason ("missed N events").
    Lagged(String),
    /// Unknown `event: <other>` — surface to the operator without
    /// trying to JSON-decode the payload.
    UnknownEventType { kind: String, payload: String },
    /// Operator-surfaced SSE comment (anything that isn't `:ping`,
    /// which is the keep-alive the daemon emits every 15s).
    Comment(String),
}

/// Stateful line-oriented SSE parser. Owns the partial-line buffer
/// plus the in-progress `event:` accumulator (which is per-frame
/// and resets on each blank-line terminator).
///
/// F-2028-018: the buffer holds **raw bytes** rather than UTF-8.
/// Each transport hands the parser `&[u8]` directly; the parser
/// only converts a slice to UTF-8 once a complete line is in the
/// buffer (newline-bounded). This keeps chunk boundaries invisible
/// — a multi-byte UTF-8 sequence split across two `feed_bytes`
/// calls round-trips cleanly instead of being mangled into two
/// `U+FFFD` replacements as it would under per-chunk
/// `String::from_utf8_lossy`.
#[derive(Default)]
struct SseParser {
    buf: Vec<u8>,
    current_event_type: String,
}

impl SseParser {
    fn new() -> Self {
        Self::default()
    }

    /// Feed raw bytes from the wire. Returns every frame the added
    /// bytes complete; partial trailing data stays in the buffer
    /// until the next call. UTF-8 conversion happens line-at-a-time
    /// after a `\n` terminator is found — so a multi-byte codepoint
    /// split across `feed_bytes` calls is reassembled before
    /// decoding.
    fn feed_bytes(&mut self, chunk: &[u8]) -> Vec<SseFrame> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            let Some(idx) = self.buf.iter().position(|b| *b == b'\n') else {
                break;
            };
            // Take the bytes up to (not including) the newline; strip
            // a trailing `\r` if present (HTTP-style CRLF). Decode the
            // resulting slice as UTF-8; replacement happens at the
            // line level rather than the chunk level, so a malformed
            // codepoint only corrupts the line that contains it.
            let mut line_bytes = &self.buf[..idx];
            if line_bytes.last() == Some(&b'\r') {
                line_bytes = &line_bytes[..line_bytes.len() - 1];
            }
            let line = String::from_utf8_lossy(line_bytes).into_owned();
            self.buf.drain(..=idx);

            // Blank line → frame terminator. The current-event-type
            // accumulator resets so a fresh `data:` without a paired
            // `event:` is treated as the default event.
            if line.is_empty() {
                self.current_event_type.clear();
                continue;
            }

            // F-2027-029: track `event: <type>` for the next `data:`
            // in this frame.
            if let Some(payload) = line.strip_prefix("event:") {
                self.current_event_type = payload.trim().to_string();
                continue;
            }

            // F-2027-028: `:ping` is the daemon's keep-alive — drop
            // silently. Anything else is operator-surfaced.
            if let Some(comment) = line.strip_prefix(':') {
                let trimmed = comment.trim();
                if !trimmed.is_empty() && trimmed != "ping" {
                    out.push(SseFrame::Comment(trimmed.to_string()));
                }
                continue;
            }

            let Some(payload) = line.strip_prefix("data:") else {
                // Unknown SSE field (`id:`, `retry:`, etc.) — per spec, ignore.
                continue;
            };
            let payload = payload.trim_start();
            if payload.is_empty() {
                continue;
            }

            match self.current_event_type.as_str() {
                "" => out.push(SseFrame::Data(payload.to_string())),
                "shutdown" => out.push(SseFrame::Shutdown(payload.to_string())),
                "lagged" => out.push(SseFrame::Lagged(payload.to_string())),
                other => out.push(SseFrame::UnknownEventType {
                    kind: other.to_string(),
                    payload: payload.to_string(),
                }),
            }
        }
        out
    }
}

/// Disposition the print loop returns to the caller.
enum PrintOutcome {
    /// Frame consumed; keep going.
    Continue,
    /// Stream is finished cleanly (`event: shutdown` from the daemon
    /// OR limit reached).
    Done,
}

/// Apply the user-facing `alerts_only` + `limit` filters to one frame,
/// printing it as appropriate. Mutates `printed_so_far`.
fn handle_frame(
    frame: SseFrame,
    alerts_only: bool,
    limit: Option<usize>,
    printed_so_far: &mut usize,
) -> PrintOutcome {
    match frame {
        SseFrame::Data(payload) => {
            match serde_json::from_str::<Event>(&payload) {
                Ok(event) => {
                    if alerts_only && event.category_uid != CategoryUid::Findings {
                        return PrintOutcome::Continue;
                    }
                    println!("{payload}");
                }
                Err(e) => {
                    eprintln!("# malformed event frame: {e}");
                    return PrintOutcome::Continue;
                }
            }
            *printed_so_far += 1;
            if let Some(target) = limit {
                if *printed_so_far >= target {
                    return PrintOutcome::Done;
                }
            }
            PrintOutcome::Continue
        }
        SseFrame::Shutdown(reason) => {
            eprintln!("# daemon stream shutdown: {reason}");
            PrintOutcome::Done
        }
        SseFrame::Lagged(reason) => {
            eprintln!("# lagged: {reason}");
            PrintOutcome::Continue
        }
        SseFrame::Comment(c) => {
            eprintln!("# sse-comment: {c}");
            PrintOutcome::Continue
        }
        SseFrame::UnknownEventType { kind, payload } => {
            eprintln!("# unknown event-type {kind:?}: {payload}");
            PrintOutcome::Continue
        }
    }
}

/// Live-tail events from the daemon's `/events/stream` endpoint
/// over a UNIX socket. Prints each Event as a JSON line on stdout.
/// Stops after `limit` events when set, otherwise streams forever.
pub(crate) async fn events_follow_unix(
    socket_path: &Path,
    alerts_only: bool,
    limit: Option<usize>,
) -> Result<()> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting to {}", socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();

    let req = b"GET /events/stream HTTP/1.1\r\n\
                Host: selfdef\r\n\
                Accept: text/event-stream\r\n\
                Connection: keep-alive\r\n\
                \r\n";
    write_half
        .write_all(req)
        .await
        .context("writing HTTP request to daemon")?;
    write_half.flush().await.context("flushing HTTP request")?;

    let mut reader = BufReader::new(read_half);

    let mut status = String::new();
    reader
        .read_line(&mut status)
        .await
        .context("reading status line")?;
    if !status.contains(" 200 ") {
        anyhow::bail!("daemon refused /events/stream: {}", status.trim_end());
    }
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    // Body is `Transfer-Encoding: chunked`. Each chunk: a hex-length
    // line, then the body, then `\r\n`. We hand each chunk's body
    // to the shared SSE parser.
    let mut parser = SseParser::new();
    let mut printed = 0usize;
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line).await? == 0 {
            return Ok(());
        }
        let size_hex = size_line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .split(';')
            .next()
            .unwrap_or("0");
        let size = usize::from_str_radix(size_hex.trim(), 16)
            .with_context(|| format!("parsing chunk size: {size_hex:?}"))?;
        if size == 0 {
            let mut _trailer = String::new();
            let _ = reader.read_line(&mut _trailer).await;
            return Ok(());
        }
        let mut body = vec![0u8; size];
        use tokio::io::AsyncReadExt as _;
        reader
            .read_exact(&mut body)
            .await
            .context("reading chunk body")?;
        let mut _trailer = [0u8; 2];
        let _ = reader.read_exact(&mut _trailer).await;

        // F-2028-018: feed raw bytes, not lossy-decoded text. A
        // multi-byte UTF-8 sequence at the very end of `body` whose
        // bytes complete only after the next chunk arrives is now
        // reassembled inside the parser before decoding.
        let frames = parser.feed_bytes(&body);
        for frame in frames {
            match handle_frame(frame, alerts_only, limit, &mut printed) {
                PrintOutcome::Continue => {}
                PrintOutcome::Done => return Ok(()),
            }
        }
    }
}

/// F-2027-010: TCP / HTTP(S) live-tail. `base_url` is the daemon's
/// base URL (e.g. `https://selfdef.example.com:7443`); the path
/// `/events/stream` is appended. `bearer_token` is the token the
/// daemon's TCP transport's bearer-auth middleware will accept;
/// pass `None` to skip the header (e.g. for a reverse-proxy-gated
/// deployment).
///
/// F-2028-006: when `bearer_token` is `Some(t)`, the request sets
/// `Authorization: Bearer <t>` (space-separated, no quoting). This
/// matches the wire format `selfdef-api`'s bearer-auth middleware
/// expects.
pub(crate) async fn events_follow_tcp(
    base_url: &str,
    bearer_token: Option<&str>,
    alerts_only: bool,
    limit: Option<usize>,
) -> Result<()> {
    let url = format!("{}/events/stream", base_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        // No request timeout: the body is a long-lived stream by
        // design. Connect timeout is short so a wrong URL fails
        // fast instead of hanging.
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .context("building reqwest client")?;
    let mut req = client.get(&url).header("Accept", "text/event-stream");
    if let Some(t) = bearer_token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let resp = req.send().await.with_context(|| format!("GET {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        // F-2028-016: when the daemon returns an `ApiError`-shaped
        // JSON body (`{"error": "..."}`), surface the typed reason
        // directly so an operator hitting a 503 sees "sse subscriber
        // cap reached" instead of having to manually parse the
        // wire body. Falls back to the raw text for non-JSON
        // bodies (e.g. an upstream proxy's HTML 5xx page).
        let detail = serde_json::from_str::<serde_json::Value>(body.trim())
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
            .unwrap_or_else(|| body.trim().to_owned());
        anyhow::bail!(
            "daemon refused /events/stream: HTTP {} {}",
            status.as_u16(),
            detail,
        );
    }

    let mut parser = SseParser::new();
    let mut printed = 0usize;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.context("reading sse chunk")?;
        // F-2028-018: feed raw bytes. `reqwest::bytes_stream` doesn't
        // promise that each `Bytes` ends on a UTF-8 boundary —
        // upstream re-chunking under HTTP/2 or any intermediate proxy
        // can split a multi-byte codepoint across two `Bytes`. The
        // parser's internal byte buffer reassembles them.
        for frame in parser.feed_bytes(&bytes) {
            match handle_frame(frame, alerts_only, limit, &mut printed) {
                PrintOutcome::Continue => {}
                PrintOutcome::Done => return Ok(()),
            }
        }
    }
    Ok(())
}

/// Read a bearer token from `path`. Mirrors the daemon-side
/// `read_token` in `selfdef-api/src/transport.rs` so a file the
/// daemon accepts/refuses is treated the same way by the CLI:
///
/// - **F-2028-004**: refuses files whose mode has any `group` or
///   `other` bits set (`mode & 0o077 != 0`). An operator who
///   `chmod 0644 /etc/selfdef/api.token` after rotation would
///   otherwise see the daemon refuse to load the file
///   (F-2027-031) but the CLI silently consume it. Symmetric
///   strictness lets operators discover the loose-mode footgun
///   the same way regardless of which side they hit first.
/// - **F-2028-005**: uses `str::trim()` (Unicode-whitespace aware)
///   to match the daemon's trimming. A token file with stray
///   non-ASCII whitespace (NBSP, BOM, ZWSP) would otherwise
///   round-trip through the CLI verbatim but be stripped by the
///   daemon — auth mismatch.
pub(crate) fn read_token_file(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt as _;
    let md = std::fs::metadata(path)
        .with_context(|| format!("stat-ing token file {}", path.display()))?;
    let mode = md.mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "refusing to read token from {}: mode {:o} is too permissive \
             (any group/other bit set); chmod 0600 to fix",
            path.display(),
            mode,
        );
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading token from {}", path.display()))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("token file is empty: {}", path.display());
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl SseParser {
        /// Test-only ergonomic wrapper. The production path always
        /// feeds raw bytes via `feed_bytes`; the unit tests use this
        /// shim so their string literals stay readable.
        fn feed(&mut self, chunk: &str) -> Vec<SseFrame> {
            self.feed_bytes(chunk.as_bytes())
        }
    }

    #[test]
    fn parser_handles_a_single_data_frame() {
        let mut p = SseParser::new();
        let frames = p.feed("data: {\"k\":1}\n\n");
        assert_eq!(frames, vec![SseFrame::Data("{\"k\":1}".to_string())]);
    }

    #[test]
    fn parser_strips_optional_space_after_data_colon() {
        let mut p = SseParser::new();
        let frames = p.feed("data:{\"k\":1}\n\n");
        assert_eq!(frames, vec![SseFrame::Data("{\"k\":1}".to_string())]);
    }

    #[test]
    fn parser_pairs_event_type_with_following_data() {
        let mut p = SseParser::new();
        let frames = p.feed("event: lagged\ndata: missed 4 events\n\n");
        assert_eq!(
            frames,
            vec![SseFrame::Lagged("missed 4 events".to_string())]
        );
    }

    #[test]
    fn parser_resets_event_type_after_blank_line() {
        let mut p = SseParser::new();
        let frames = p.feed(
            "event: lagged\ndata: missed 1\n\n\
             data: {\"k\":1}\n\n",
        );
        assert_eq!(
            frames,
            vec![
                SseFrame::Lagged("missed 1".to_string()),
                SseFrame::Data("{\"k\":1}".to_string()),
            ],
        );
    }

    #[test]
    fn parser_filters_ping_keepalive_but_surfaces_other_comments() {
        let mut p = SseParser::new();
        let frames = p.feed(":ping\n\n:something else\n\n");
        assert_eq!(
            frames,
            vec![SseFrame::Comment("something else".to_string())]
        );
    }

    #[test]
    fn parser_emits_shutdown_for_event_shutdown() {
        let mut p = SseParser::new();
        let frames = p.feed("event: shutdown\ndata: bus closed\n\n");
        assert_eq!(frames, vec![SseFrame::Shutdown("bus closed".to_string())]);
    }

    #[test]
    fn parser_surfaces_unknown_event_type() {
        let mut p = SseParser::new();
        let frames = p.feed("event: weird\ndata: payload\n\n");
        assert_eq!(
            frames,
            vec![SseFrame::UnknownEventType {
                kind: "weird".into(),
                payload: "payload".into(),
            }],
        );
    }

    #[test]
    fn parser_buffers_partial_lines_across_feeds() {
        let mut p = SseParser::new();
        assert!(p.feed("data: {\"k\"").is_empty());
        assert!(p.feed(":1}").is_empty());
        let frames = p.feed("\n\n");
        assert_eq!(frames, vec![SseFrame::Data("{\"k\":1}".to_string())]);
    }

    #[test]
    fn parser_ignores_unknown_sse_fields() {
        let mut p = SseParser::new();
        let frames = p.feed("id: 42\nretry: 5000\ndata: ok\n\n");
        assert_eq!(frames, vec![SseFrame::Data("ok".to_string())]);
    }

    /// F-2028-018: a multi-byte UTF-8 sequence split across two
    /// `feed_bytes` calls must round-trip cleanly. Pre-fix, each
    /// call's `String::from_utf8_lossy` replaced the partial
    /// bytes with `U+FFFD`, destroying the codepoint.
    #[test]
    fn parser_reassembles_multibyte_utf8_split_across_chunks() {
        // 4-byte UTF-8 sequence for 🦀 (U+1F980, F0 9F A6 80) inside
        // a JSON payload. Split 2/2 across the two feed_bytes calls,
        // immediately before the terminating `\n\n`.
        let prefix = b"data: \"rust ".to_vec();
        let crab = [0xF0, 0x9F, 0xA6, 0x80];
        let suffix = b"\"\n\n".to_vec();
        let mut p = SseParser::new();

        let mut first = prefix;
        first.extend_from_slice(&crab[..2]); // ← cut mid-codepoint
        assert!(p.feed_bytes(&first).is_empty());

        let mut second = crab[2..].to_vec();
        second.extend_from_slice(&suffix);
        let frames = p.feed_bytes(&second);
        assert_eq!(frames, vec![SseFrame::Data("\"rust 🦀\"".to_string())]);
    }

    /// F-2028-018: even when a chunk boundary lands inside a
    /// 3-byte codepoint, the parser reassembles cleanly. Covers
    /// the most-common non-ASCII case (Latin-1 supplement and
    /// most BMP CJK glyphs are 2- or 3-byte).
    #[test]
    fn parser_reassembles_3byte_utf8_split_across_chunks() {
        // 3-byte UTF-8 sequence for 漢 (U+6F22, E6 BC A2).
        let prefix = b"data: ".to_vec();
        let han = [0xE6, 0xBC, 0xA2];
        let suffix = b"\n\n".to_vec();
        let mut p = SseParser::new();

        let mut first = prefix;
        first.push(han[0]); // ← only the first byte of the codepoint
        assert!(p.feed_bytes(&first).is_empty());

        let mut second = han[1..].to_vec();
        second.extend_from_slice(&suffix);
        let frames = p.feed_bytes(&second);
        assert_eq!(frames, vec![SseFrame::Data("漢".to_string())]);
    }
}
