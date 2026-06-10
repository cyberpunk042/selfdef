//! ssh argv parsing.
//!
//! We don't reimplement ssh's option grammar — we only need enough to:
//! 1. find the target spec (`user@host`) in argv,
//! 2. classify each token as "flag", "option needing value", or "positional",
//! 3. filter out user-supplied flags that conflict with policy.

/// Single-letter ssh options that consume the next argv element as a value.
/// Taken from ssh(1). Conservative: anything we're not sure about goes here.
const VALUE_OPTIONS: &[char] = &[
    'B', 'b', 'c', 'D', 'E', 'e', 'F', 'I', 'i', 'J', 'L', 'l', 'm', 'O', 'o', 'p', 'Q', 'R', 'S',
    'W', 'w',
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<'a> {
    /// Bare flag like `-A`, `-v`, `-4`. No value follows.
    Flag(char),
    /// Option with separate value: `-o`, `Foo=bar`.
    Option(char, &'a str),
    /// Option with attached value: `-pPORT`.
    AttachedOption(char, &'a str),
    /// Positional (target or remote command).
    Positional(&'a str),
    /// `--` end-of-options marker.
    EndOfOptions,
}

/// Classified view of an argv slice (skipping argv[0]).
pub fn classify(args: &[String]) -> Vec<Token<'_>> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    let mut after_dashdash = false;

    while i < args.len() {
        let arg = &args[i];

        if after_dashdash || !arg.starts_with('-') || arg == "-" {
            out.push(Token::Positional(arg));
            i += 1;
            continue;
        }
        if arg == "--" {
            out.push(Token::EndOfOptions);
            after_dashdash = true;
            i += 1;
            continue;
        }

        // Multi-char form like "-pPORT" or "-oFoo=bar".
        let bytes = arg.as_bytes();
        if bytes.len() >= 2 {
            let c = bytes[1] as char;
            if VALUE_OPTIONS.contains(&c) {
                if bytes.len() == 2 {
                    // "-o" then value in next argv slot
                    if let Some(val) = args.get(i + 1) {
                        out.push(Token::Option(c, val.as_str()));
                        i += 2;
                        continue;
                    }
                    // Trailing -o with no value; treat as flag.
                    out.push(Token::Flag(c));
                    i += 1;
                    continue;
                }
                let val = &arg[2..];
                out.push(Token::AttachedOption(c, val));
                i += 1;
                continue;
            }

            // Combined flags like "-Aq" or "-vvv".
            for ch in arg[1..].chars() {
                out.push(Token::Flag(ch));
            }
            i += 1;
            continue;
        }
        // "-" alone is positional (stdin).
        out.push(Token::Positional(arg));
        i += 1;
    }
    out
}

/// Index in `args` of the target spec — the first non-option word.
///
/// ssh stops option parsing at the target: everything from the target onward
/// (the `[user@]host` spec **and** the remote command) is handed to the server
/// verbatim and MUST NOT be reinterpreted as ssh options. `classify` has no
/// notion of "the target ends the options", so feeding it the whole argv turns
/// a remote command like `mytool --recursive` into ssh-flag tokens
/// (`--recursive` → `-- -r -e -c …`) and, worse, drops a remote flag that
/// happens to collide with a denied ssh flag. We therefore locate the target
/// up front and only ever classify/filter the slice *before* it.
///
/// Walks the same single-letter grammar as `classify`: a bare value-option
/// (`-o`, `-p`, …) consumes the next argv element; `--` ends options so the
/// target is the element after it. Returns `None` when argv is all options
/// (no host) — the caller passes those through to real ssh for its usage error.
pub fn target_index(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            return if i + 1 < args.len() {
                Some(i + 1)
            } else {
                None
            };
        }
        if !arg.starts_with('-') || arg == "-" {
            return Some(i);
        }
        // Option cluster. `-o`/`-p`/… in their bare two-char form swallow the
        // next argv element as their value; everything else (attached value,
        // combined flags) is self-contained.
        let c = arg.as_bytes()[1] as char;
        if arg.len() == 2 && VALUE_OPTIONS.contains(&c) {
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

/// First positional after any options is the target spec.
pub fn extract_target<'a>(tokens: &[Token<'a>]) -> Option<&'a str> {
    let mut seen_marker = false;
    for tok in tokens {
        match tok {
            Token::EndOfOptions => seen_marker = true,
            Token::Positional(p) => return Some(*p),
            _ if seen_marker => {}
            _ => {}
        }
    }
    None
}

/// Filter user-supplied flags. Returns a new argv (excluding argv[0]) with
/// `denied_flags` removed and `-o` overrides matching `denied_o_keys` (case-
/// insensitive on the key) removed.
/// Extract the option KEY from an `-o` value for denylist matching.
///
/// `ssh_config(5)` separates a keyword from its argument with EITHER `=` OR
/// whitespace, so `StrictHostKeyChecking=no` and `StrictHostKeyChecking no`
/// denote the SAME option and `ssh -o` honours both. The pre-fix code split
/// on `=` alone, so the whitespace form (`-o "StrictHostKeyChecking no"`)
/// produced the key `"StrictHostKeyChecking no"`, never matched the denied
/// `"StrictHostKeyChecking"`, and slipped past the policy — a client-side
/// defense bypass (an agent could re-enable a denied option ssh would then
/// apply). Split on the first `=` or whitespace run so both forms collapse to
/// the same key.
pub fn o_option_key(val: &str) -> &str {
    val.trim_start()
        .split(|c: char| c == '=' || c.is_whitespace())
        .next()
        .unwrap_or("")
}

pub fn filter(tokens: &[Token<'_>], denied_flags: &[char], denied_o_keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for tok in tokens {
        match tok {
            Token::Flag(c) => {
                if denied_flags.contains(c) {
                    continue;
                }
                out.push(format!("-{c}"));
            }
            Token::Option('o', val) => {
                let key = o_option_key(val);
                if denied_o_keys.iter().any(|k| key.eq_ignore_ascii_case(k)) {
                    continue;
                }
                out.push("-o".into());
                out.push((*val).to_string());
            }
            Token::Option(c, val) => {
                out.push(format!("-{c}"));
                out.push((*val).to_string());
            }
            Token::AttachedOption('o', val) => {
                let key = o_option_key(val);
                if denied_o_keys.iter().any(|k| key.eq_ignore_ascii_case(k)) {
                    continue;
                }
                out.push(format!("-o{val}"));
            }
            Token::AttachedOption(c, val) => {
                out.push(format!("-{c}{val}"));
            }
            Token::Positional(p) => out.push((*p).to_string()),
            Token::EndOfOptions => out.push("--".into()),
        }
    }
    out
}

/// Split target like `user@host:port` (or just `host`) into parts.
///
/// Follows ssh's hostname convention so the HOST the policy keys on is the
/// real host — including IPv6, where a naive `rsplit_once(':')` would slice an
/// address like `2001:db8::1` into host `2001:db8:` + port `1` and silently
/// resolve the WRONG (or default) policy for that connection:
///   - `[addr]:port` / `[addr]` — bracketed; the port (if any) follows `]`.
///   - a bare literal with more than one `:` is an unbracketed IPv6 address,
///     no port.
///   - otherwise `host[:port]`.
pub fn parse_target(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match spec.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, spec),
    };
    // Bracketed IPv6: `[2001:db8::1]` or `[2001:db8::1]:22`.
    if let Some(after_lb) = rest.strip_prefix('[') {
        if let Some((addr, tail)) = after_lb.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (user, addr.to_string(), port);
        }
        // Unterminated bracket — fall through and treat the whole thing as host.
    }
    // Unbracketed IPv6 literal (>1 colon) carries no port.
    if rest.matches(':').count() > 1 {
        return (user, rest.to_string(), None);
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => {
            (h.to_string(), p.parse::<u16>().ok())
        }
        _ => (rest.to_string(), None),
    };
    (user, host, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn simple_target() {
        let argv = s(&["user@host"]);
        let toks = classify(&argv);
        assert_eq!(extract_target(&toks), Some("user@host"));
    }

    #[test]
    fn target_after_options() {
        let argv = s(&["-A", "-p", "2222", "-i", "/tmp/key", "user@host", "ls"]);
        let toks = classify(&argv);
        assert_eq!(extract_target(&toks), Some("user@host"));
    }

    #[test]
    fn combined_flags() {
        let argv = s(&["-Aq", "user@host"]);
        let toks = classify(&argv);
        // -Aq should split into Flag(A), Flag(q)
        let flags: Vec<_> = toks
            .iter()
            .filter_map(|t| {
                if let Token::Flag(c) = t {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect();
        assert!(flags.contains(&'A'));
        assert!(flags.contains(&'q'));
    }

    #[test]
    fn attached_option_value() {
        let argv = s(&["-p2222", "host"]);
        let toks = classify(&argv);
        assert!(matches!(toks[0], Token::AttachedOption('p', "2222")));
    }

    #[test]
    fn parse_target_pieces() {
        assert_eq!(parse_target("host"), (None, "host".into(), None));
        assert_eq!(
            parse_target("user@host"),
            (Some("user".into()), "host".into(), None)
        );
        assert_eq!(
            parse_target("user@host:2222"),
            (Some("user".into()), "host".into(), Some(2222))
        );
    }

    #[test]
    fn parse_target_ipv6() {
        // Bare IPv6 literal: NOT sliced into host `2001:db8:` + port `1` (the
        // pre-fix bug that mis-scoped the policy for IPv6 connections).
        assert_eq!(
            parse_target("2001:db8::1"),
            (None, "2001:db8::1".into(), None)
        );
        assert_eq!(parse_target("::1"), (None, "::1".into(), None));
        assert_eq!(
            parse_target("user@fe80::1"),
            (Some("user".into()), "fe80::1".into(), None)
        );
        // Bracketed forms carry the port after `]`; host has no brackets.
        assert_eq!(
            parse_target("[2001:db8::1]:22"),
            (None, "2001:db8::1".into(), Some(22))
        );
        assert_eq!(
            parse_target("user@[2001:db8::1]"),
            (Some("user".into()), "2001:db8::1".into(), None)
        );
        // A trailing non-numeric ":x" is not a port (host keeps its value).
        assert_eq!(
            parse_target("host:notaport"),
            (None, "host:notaport".into(), None)
        );
    }

    #[test]
    fn target_index_walks_option_grammar() {
        // Bare value-options consume the next argv slot.
        assert_eq!(target_index(&s(&["-p", "22", "host"])), Some(2));
        assert_eq!(
            target_index(&s(&["-A", "-i", "/k", "host", "cmd"])),
            Some(3)
        );
        // Attached value (`-pq`) and combined flags are self-contained.
        assert_eq!(target_index(&s(&["-pq", "host"])), Some(1));
        assert_eq!(target_index(&s(&["-Aq", "host"])), Some(1));
        // `--` ends options; the target is the next element (even if dashy).
        assert_eq!(target_index(&s(&["--", "-weirdhost"])), Some(1));
        // Bare `-` is stdin, a positional.
        assert_eq!(target_index(&s(&["-"])), Some(0));
        assert_eq!(target_index(&s(&["host"])), Some(0));
        // All options, no host.
        assert_eq!(target_index(&s(&["-A", "-q"])), None);
        // A trailing bare value-option with no value still "consumes" past the
        // end and yields no target (real ssh would error on the missing value).
        assert_eq!(target_index(&s(&["-o"])), None);
    }

    #[test]
    fn remote_command_passes_through_verbatim() {
        // ssh stops option parsing at the target; the remote command must reach
        // the server byte-for-byte. The pre-fix wrapper classified the WHOLE
        // argv and rebuilt it, so `--recursive` decomposed into `-- -r -e -c …`
        // and a remote flag colliding with a denied ssh flag was silently
        // dropped. Reconstruct the way run() now does — filter only the
        // pre-target options, then append `raw_args[target_idx..]` untouched.
        let argv = s(&["-A", "host", "mytool", "--recursive", "-A", "subcmd"]);
        let idx = target_index(&argv).expect("target present");
        assert_eq!(idx, 1, "target `host` is at index 1");

        let opts = classify(&argv[..idx]);
        let mut out = filter(&opts, &['A'], &[]); // -A denied for ssh
        out.extend(argv[idx..].iter().cloned());

        // The pre-target ssh -A is stripped; the remote command — including its
        // OWN -A and its --recursive — is byte-for-byte intact.
        assert_eq!(out, vec!["host", "mytool", "--recursive", "-A", "subcmd"]);
        assert_eq!(
            out.iter().filter(|x| x.as_str() == "-A").count(),
            1,
            "only the remote-command -A survives, got {out:?}"
        );
    }

    #[test]
    fn filter_strips_denied_agent_flag() {
        let argv = s(&["-A", "-v", "user@host"]);
        let toks = classify(&argv);
        let filtered = filter(&toks, &['A'], &[]);
        assert!(!filtered.contains(&"-A".to_string()));
        assert!(filtered.contains(&"-v".to_string()));
        assert!(filtered.contains(&"user@host".to_string()));
    }

    #[test]
    fn filter_strips_denied_o_overrides() {
        let argv = s(&["-o", "ForwardAgent=yes", "-o", "BatchMode=yes", "host"]);
        let toks = classify(&argv);
        let filtered = filter(&toks, &[], &["ForwardAgent"]);
        assert!(!filtered.iter().any(|s| s == "ForwardAgent=yes"));
        assert!(filtered.iter().any(|s| s == "BatchMode=yes"));
    }

    #[test]
    fn o_option_key_handles_both_separators() {
        // ssh_config accepts `Key=Val` AND `Key Val` (whitespace).
        assert_eq!(
            o_option_key("StrictHostKeyChecking=no"),
            "StrictHostKeyChecking"
        );
        assert_eq!(
            o_option_key("StrictHostKeyChecking no"),
            "StrictHostKeyChecking"
        );
        assert_eq!(
            o_option_key("  StrictHostKeyChecking   no"),
            "StrictHostKeyChecking"
        );
        assert_eq!(
            o_option_key("StrictHostKeyChecking\tno"),
            "StrictHostKeyChecking"
        );
    }

    #[test]
    fn filter_strips_denied_o_via_whitespace_form() {
        // BYPASS regression: ssh honours `-o "StrictHostKeyChecking no"` (space,
        // not '='). Splitting the key on '=' alone let it slip the denylist and
        // ssh would then disable host-key checking despite the policy. Both the
        // separate-value and attached forms of the whitespace variant must be
        // stripped, while the `=` form and an unrelated `-o` still behave.
        let denied = ["StrictHostKeyChecking"];

        // Separate-value, whitespace separator.
        let argv = s(&["-o", "StrictHostKeyChecking no", "host"]);
        let f = filter(&classify(&argv), &[], &denied);
        assert!(
            !f.iter().any(|x| x.contains("StrictHostKeyChecking")),
            "whitespace-form -o must be stripped, got {f:?}"
        );

        // Attached, whitespace separator (`-oStrictHostKeyChecking no`).
        let argv = s(&["-oStrictHostKeyChecking no", "host"]);
        let f = filter(&classify(&argv), &[], &denied);
        assert!(
            !f.iter().any(|x| x.contains("StrictHostKeyChecking")),
            "attached whitespace-form -o must be stripped, got {f:?}"
        );

        // Case-insensitive whitespace form.
        let argv = s(&["-o", "stricthostkeychecking no", "host"]);
        let f = filter(&classify(&argv), &[], &denied);
        assert!(
            !f.iter()
                .any(|x| x.to_lowercase().contains("stricthostkeychecking"))
        );

        // The `=` form still strips (regression) ...
        let argv = s(&["-o", "StrictHostKeyChecking=no", "host"]);
        let f = filter(&classify(&argv), &[], &denied);
        assert!(!f.iter().any(|x| x.contains("StrictHostKeyChecking")));
        // ... and an unrelated option is preserved (no over-strip).
        let argv = s(&["-o", "ServerAliveInterval 30", "host"]);
        let f = filter(&classify(&argv), &[], &denied);
        assert!(
            f.iter().any(|x| x.contains("ServerAliveInterval")),
            "got {f:?}"
        );
    }
}
