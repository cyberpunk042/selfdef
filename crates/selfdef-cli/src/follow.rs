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
#[derive(Default)]
struct SseParser {
    buf: String,
    current_event_type: String,
}

impl SseParser {
    fn new() -> Self {
        Self::default()
    }

    /// Feed raw UTF-8 bytes from the wire. Returns every frame the
    /// added bytes complete; partial trailing data stays in the
    /// buffer until the next `feed`.
    fn feed(&mut self, chunk: &str) -> Vec<SseFrame> {
        self.buf.push_str(chunk);
        let mut out = Vec::new();
        loop {
            let Some(idx) = self.buf.find('\n') else {
                break;
            };
            let line = self.buf[..idx].trim_end_matches('\r').to_string();
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

        let frames = parser.feed(&String::from_utf8_lossy(&body));
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
        anyhow::bail!(
            "daemon refused /events/stream: HTTP {} {}",
            status.as_u16(),
            body.trim(),
        );
    }

    let mut parser = SseParser::new();
    let mut printed = 0usize;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.context("reading sse chunk")?;
        let text = String::from_utf8_lossy(&bytes);
        for frame in parser.feed(&text) {
            match handle_frame(frame, alerts_only, limit, &mut printed) {
                PrintOutcome::Continue => {}
                PrintOutcome::Done => return Ok(()),
            }
        }
    }
    Ok(())
}

/// Read a bearer token from `path`, trimming trailing whitespace.
/// Used by `events follow --token-file <path>` to mirror the
/// daemon's `[api].token_file` knob without echoing the token onto
/// the operator's process table via `--token`.
pub(crate) fn read_token_file(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading token from {}", path.display()))?;
    let trimmed = raw.trim_end_matches(['\n', '\r', ' ', '\t']).to_string();
    if trimmed.is_empty() {
        anyhow::bail!("token file is empty: {}", path.display());
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
