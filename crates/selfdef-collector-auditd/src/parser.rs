//! Auditd record line parser.
//!
//! Handles the most common single-line record types selfdef cares about for
//! M3: `USER_AUTH`, `USER_LOGIN`, `USER_ACCT`. Other types are emitted as
//! generic events with the raw payload preserved, so nothing is silently
//! dropped. Multi-line records (SYSCALL+EXECVE pairs) are a later milestone.
//!
//! A line looks like:
//! ```text
//! type=USER_AUTH msg=audit(1736944496.789:1234567): pid=1234 uid=0 \
//!   msg='op=PAM:authentication acct="alice" addr=192.0.2.5 res=failed'
//! ```

use std::collections::HashMap;

/// Parsed auditd line, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub kind: String,
    /// Audit timestamp (seconds since epoch, fractional part lost — fine for M3).
    pub timestamp_secs: u64,
    /// Audit serial.
    pub serial: u64,
    pub fields: HashMap<String, String>,
}

impl AuditRecord {
    /// Pull a field; case-sensitive.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

/// AVC records have a non-key=value preamble (`avc:  denied  { read } for`)
/// that the generic key=value parser skips silently. This helper scans the
/// preamble + returns the decision verb when present. `None` otherwise.
///
/// Format reference (Linux audit subsystem AVC record):
/// ```text
/// type=AVC msg=audit(<ts>:<serial>): avc:  denied  { read }  for  pid=<n> comm=<...>
/// ```
pub fn parse_avc_decision(line: &str) -> Option<&str> {
    // Walk the line looking for the literal `avc:` token followed by
    // exactly one of `denied` / `granted`. We do NOT require any
    // surrounding whitespace count; auditd has used 1 + 2 spaces
    // across kernels.
    let after_avc = line.find("avc:")?;
    let tail = &line[after_avc + "avc:".len()..];
    let trimmed = tail.trim_start();
    if let Some(rest) = trimmed.strip_prefix("denied") {
        if rest.starts_with(|c: char| c.is_whitespace()) || rest.is_empty() {
            return Some("denied");
        }
    }
    if let Some(rest) = trimmed.strip_prefix("granted") {
        if rest.starts_with(|c: char| c.is_whitespace()) || rest.is_empty() {
            return Some("granted");
        }
    }
    None
}

/// Parse one audit log line. Returns `None` for lines that don't look like
/// audit records (blank, comments, malformed); callers can warn or ignore.
#[allow(clippy::manual_map)] // explicit None branch is clearer here
pub(crate) fn parse_line(line: &str) -> Option<AuditRecord> {
    let line = line.trim();
    if line.is_empty() || !line.starts_with("type=") {
        return None;
    }

    // Split into tokens, but respect single- and double-quoted strings.
    let tokens = tokenize_kv(line);

    // Pull out type and audit(...) ts:serial first.
    let mut kind = None;
    let mut timestamp_secs = None;
    let mut serial = None;
    let mut fields = HashMap::new();

    for (k, v) in &tokens {
        match k.as_str() {
            "type" => kind = Some(v.clone()),
            "msg" if v.starts_with("audit(") => {
                // audit(1736944496.789:1234567)[:] — auditd writes the
                // trailing colon as part of the header on most distros, so
                // we accept both `)` and `):` as the close.
                let inner = v
                    .strip_prefix("audit(")
                    .and_then(|s| s.strip_suffix("):").or_else(|| s.strip_suffix(')')))?;
                let (ts, ser) = inner.split_once(':')?;
                let secs: f64 = ts.parse().ok()?;
                timestamp_secs = Some(secs.trunc() as u64);
                serial = ser.parse().ok();
            }
            "msg" => {
                // Inline nested key=value style: msg='op=... acct="..." ...'
                let stripped = strip_outer_quotes(v);
                for (nk, nv) in tokenize_kv(stripped) {
                    fields.insert(nk, nv);
                }
            }
            _ => {
                fields.insert(k.clone(), v.clone());
            }
        }
    }

    Some(AuditRecord {
        kind: kind?,
        timestamp_secs: timestamp_secs?,
        serial: serial?,
        fields,
    })
}

fn strip_outer_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Split a key=value-ish string into a Vec of (key, value), respecting
/// single- and double-quotes around values. Whitespace separates tokens.
fn tokenize_kv(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Skip whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        // Read key up to '='.
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            // Stray token; skip.
            continue;
        }
        let key = std::str::from_utf8(&bytes[key_start..i])
            .unwrap_or("")
            .to_string();
        i += 1; // past '='

        // Read value: quoted or until whitespace.
        let value = if i < bytes.len() && (bytes[i] == b'\'' || bytes[i] == b'"') {
            let quote = bytes[i];
            let val_start = i; // include opening quote
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // include closing quote
            }
            std::str::from_utf8(&bytes[val_start..i])
                .unwrap_or("")
                .to_string()
        } else {
            let val_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            std::str::from_utf8(&bytes[val_start..i])
                .unwrap_or("")
                .to_string()
        };

        // Strip outer quotes for plain key=value cases; keep them where
        // the next stage will re-parse (msg='...').
        let value = if key == "msg" {
            value
        } else {
            strip_outer_quotes(&value).to_string()
        };

        out.push((key, value));
    }

    out
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_auth_failure() {
        let line = r#"type=USER_AUTH msg=audit(1736944496.789:1234567): pid=1234 uid=0 msg='op=PAM:authentication acct="alice" addr=192.0.2.5 res=failed'"#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.kind, "USER_AUTH");
        assert_eq!(r.timestamp_secs, 1_736_944_496);
        assert_eq!(r.serial, 1_234_567);
        assert_eq!(r.get("acct"), Some("alice"));
        assert_eq!(r.get("addr"), Some("192.0.2.5"));
        assert_eq!(r.get("res"), Some("failed"));
        assert_eq!(r.get("op"), Some("PAM:authentication"));
    }

    #[test]
    fn parses_user_login_success() {
        let line = r#"type=USER_LOGIN msg=audit(1736944500.123:1234568): pid=4567 uid=0 acct="alice" exe="/usr/sbin/sshd" hostname=192.0.2.5 res=success"#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.kind, "USER_LOGIN");
        assert_eq!(r.get("acct"), Some("alice"));
        assert_eq!(r.get("res"), Some("success"));
    }

    #[test]
    fn rejects_non_audit_lines() {
        assert!(parse_line("").is_none());
        assert!(parse_line("# comment").is_none());
        assert!(parse_line("random text").is_none());
    }

    #[test]
    fn unknown_record_type_still_parses() {
        let line = r#"type=ANOM_PROMISCUOUS msg=audit(1736944600.000:1234569): dev=eth0 prom=256 old_prom=0"#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.kind, "ANOM_PROMISCUOUS");
        assert_eq!(r.get("dev"), Some("eth0"));
    }

    #[test]
    fn parses_avc_denied_record_fields() {
        // Real AVC log shape — note the non-key=value `avc:  denied  { read } for`
        // preamble that the generic tokenizer skips, plus the trailing
        // key=value pairs the tokenizer DOES pick up.
        let line = r#"type=AVC msg=audit(1736944700.000:1234580): avc:  denied  { read } for  pid=4242 comm="sshd" name="shadow" dev="sda1" ino=12345 scontext=system_u:system_r:sshd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0"#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.kind, "AVC");
        assert_eq!(r.get("pid"),       Some("4242"));
        assert_eq!(r.get("comm"),      Some("sshd"));
        assert_eq!(r.get("name"),      Some("shadow"));
        assert_eq!(r.get("tclass"),    Some("file"));
        assert_eq!(r.get("permissive"),Some("0"));
        assert_eq!(parse_avc_decision(line), Some("denied"));
    }

    #[test]
    fn parses_avc_granted_record_decision() {
        let line = r#"type=AVC msg=audit(1736944710.000:1234581): avc:  granted  { execute } for  pid=99 comm="bash" tclass=file"#;
        assert_eq!(parse_avc_decision(line), Some("granted"));
    }

    #[test]
    fn avc_decision_missing_returns_none() {
        // No `avc:` preamble — a USER_AUTH line.
        let line = r#"type=USER_AUTH msg=audit(1736944496.789:1234567): pid=1234"#;
        assert_eq!(parse_avc_decision(line), None);
    }

    #[test]
    fn avc_decision_partial_word_does_not_match() {
        // Substring `deniedfoo` must NOT match `denied`.
        let line = r#"type=AVC msg=audit(1.0:1): avc:  deniedfoo  { read }"#;
        assert_eq!(parse_avc_decision(line), None);
    }

    #[test]
    fn parses_seccomp_record_fields() {
        // Real kernel-emitted SECCOMP line shape (x86_64 arch =
        // c000003e, syscall 42 = connect, sig 31 = SIGSYS).
        let line = r#"type=SECCOMP msg=audit(1736944800.000:1234582): auid=1000 uid=1000 gid=1000 ses=1 pid=4242 comm="badapp" exe="/usr/bin/badapp" sig=31 arch=c000003e syscall=42 compat=0 ip=0x7fffffff code=0x0"#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.kind, "SECCOMP");
        assert_eq!(r.get("pid"),     Some("4242"));
        assert_eq!(r.get("comm"),    Some("badapp"));
        assert_eq!(r.get("exe"),     Some("/usr/bin/badapp"));
        assert_eq!(r.get("syscall"), Some("42"));
        assert_eq!(r.get("arch"),    Some("c000003e"));
        assert_eq!(r.get("sig"),     Some("31"));
        assert_eq!(r.get("code"),    Some("0x0"));
    }

    #[test]
    fn parses_anom_abend_record_fields() {
        // ANOM_ABEND emitted by the kernel on abnormal program
        // termination via signal (SIGSEGV here).
        let line = r#"type=ANOM_ABEND msg=audit(1736944900.000:1234583): auid=1000 uid=1000 gid=1000 ses=1 pid=4244 comm="crashy" exe="/usr/bin/crashy" sig=11"#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.kind, "ANOM_ABEND");
        assert_eq!(r.get("pid"),  Some("4244"));
        assert_eq!(r.get("comm"), Some("crashy"));
        assert_eq!(r.get("sig"),  Some("11"));
    }

    #[test]
    fn parses_anom_promiscuous_record_fields() {
        // Interface dropped INTO promiscuous: old_prom=0 prom=256.
        let line = r#"type=ANOM_PROMISCUOUS msg=audit(1736945000.000:1234584): dev=eth0 prom=256 old_prom=0 auid=0 uid=0 gid=0 ses=1"#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.kind, "ANOM_PROMISCUOUS");
        assert_eq!(r.get("dev"),      Some("eth0"));
        assert_eq!(r.get("prom"),     Some("256"));
        assert_eq!(r.get("old_prom"), Some("0"));
    }
}
