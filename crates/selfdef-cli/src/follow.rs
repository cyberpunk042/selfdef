//! `selfdefctl events follow` — live tail of the daemon's
//! `/events/stream` SSE endpoint over a UNIX socket.
//!
//! Talks raw HTTP/1.1 directly over `tokio::net::UnixStream`
//! rather than pulling a full HTTP client (hyper) into the CLI:
//! the request is one GET, the response is a long-lived
//! `Transfer-Encoding: chunked` SSE body that we line-tokenise
//! into `data: <json>` records. ~100 LoC end-to-end.
//!
//! TCP transport is not supported here; operators with TCP-only
//! daemons run `curl --no-buffer -H "Authorization: Bearer ..."
//! http://host:port/events/stream` directly.

use std::path::Path;

use anyhow::{Context, Result};
use selfdef_core::Event;
use selfdef_core::category::CategoryUid;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Live-tail events from the daemon's `/events/stream` endpoint.
/// Prints each Event as a JSON line on stdout. Stops after
/// `limit` events when set, otherwise streams forever.
pub(crate) async fn events_follow(
    socket_path: &Path,
    alerts_only: bool,
    limit: Option<usize>,
) -> Result<()> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting to {}", socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();

    // Minimal HTTP/1.1 GET. The daemon ignores Host but axum
    // requires the header so we send `Host: selfdef`.
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

    // Read response headers until the blank-line terminator.
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
        // Discard each header line — we don't care about
        // anything but a 200 OK + the chunked body.
    }

    // Body is `Transfer-Encoding: chunked`. Each chunk: a
    // hex-length line, then the body, then `\r\n`. Within the
    // body, SSE frames are `event: <type>\ndata: <payload>\n\n`.
    // The current_event_type accumulator resets on each blank
    // line (frame terminator) so a `data:` line is paired with
    // the most-recent `event:` line in the same frame.
    let mut sse_buf = String::new();
    let mut printed = 0usize;
    let mut current_event_type = String::new();
    loop {
        // chunk size line
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
            // trailer headers + final CRLF
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
        // trailing CRLF after each chunk
        let mut _trailer = [0u8; 2];
        let _ = reader.read_exact(&mut _trailer).await;

        sse_buf.push_str(&String::from_utf8_lossy(&body));

        // Parse SSE frames line-by-line. Each frame is a
        // run of `field: value` lines terminated by a blank
        // line. The current_event_type accumulator tracks the
        // last-seen `event:` line within the current frame.
        loop {
            let Some(idx) = sse_buf.find('\n') else {
                break;
            };
            let line = sse_buf[..idx].trim_end_matches('\r').to_string();
            sse_buf.drain(..=idx);

            // Blank line → frame terminator. Reset the
            // event-type accumulator for the next frame.
            if line.is_empty() {
                current_event_type.clear();
                continue;
            }

            // F-2027-029: `event: shutdown` from the writer
            // means the daemon's stream task is exiting (bus
            // closed = clean shutdown OR bus error). Exit Ok
            // so the CLI returns 0; a torn TCP connection
            // hits the chunk-size `n == 0` branch above and
            // also returns Ok, but the daemon-driven case is
            // distinguishable in logs by the printed line.
            // Future enhancement: distinguish exit codes once
            // operators ask for it.
            if let Some(payload) = line.strip_prefix("event:") {
                current_event_type = payload.trim().to_string();
                continue;
            }

            // F-2027-028: SSE comments start with `:`. The
            // daemon emits `:ping` keep-alives every 15s; we
            // silently ignore those. Any other comment is
            // unexpected and we surface it to operators on
            // stderr so a future protocol change isn't a
            // silent no-op.
            if let Some(comment) = line.strip_prefix(':') {
                let trimmed = comment.trim();
                if !trimmed.is_empty() && trimmed != "ping" {
                    eprintln!("# sse-comment: {trimmed}");
                }
                continue;
            }

            let Some(payload) = line.strip_prefix("data:") else {
                // Unknown SSE field (`id:`, `retry:`, etc.)
                // — silently ignored per the SSE spec.
                continue;
            };
            let payload = payload.trim_start();
            if payload.is_empty() {
                continue;
            }

            // Dispatch on the current event type.
            match current_event_type.as_str() {
                "shutdown" => {
                    eprintln!("# daemon stream shutdown: {payload}");
                    return Ok(());
                }
                "lagged" => {
                    eprintln!("# lagged: {payload}");
                    continue;
                }
                "" => {
                    // Default event type: JSON-encoded Event.
                    match serde_json::from_str::<Event>(payload) {
                        Ok(event) => {
                            if alerts_only && event.category_uid != CategoryUid::Findings {
                                continue;
                            }
                            println!("{payload}");
                        }
                        Err(e) => {
                            eprintln!("# malformed event frame: {e}");
                            continue;
                        }
                    }
                    printed += 1;
                    if let Some(target) = limit {
                        if printed >= target {
                            return Ok(());
                        }
                    }
                }
                other => {
                    // Unknown event type — surface it but
                    // don't try to decode as Event.
                    eprintln!("# unknown event-type {other:?}: {payload}");
                }
            }
        }
    }
}
