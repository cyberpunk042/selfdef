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

        // Option cluster like "-pPORT", "-oFoo=bar", "-Aq", or "-qoFoo=bar".
        // ssh uses getopt: walk the cluster left-to-right; leading non-value
        // letters are bare flags, and the FIRST value-option letter consumes
        // the REST of the cluster as its attached value — or, if it is the last
        // letter, the next argv element. Classifying every cluster letter as a
        // bare flag (the pre-fix behavior) let `-qo ProxyCommand=…` smuggle a
        // denied `-o` option past the key-denylist, since the embedded `o` was
        // never seen as Token::Option.
        let cluster = &arg[1..];
        let mut consumed_next = false;
        for (off, ch) in cluster.char_indices() {
            if VALUE_OPTIONS.contains(&ch) {
                let rest = &cluster[off + ch.len_utf8()..];
                if rest.is_empty() {
                    // value is the next argv element (`-o VALUE`)
                    if let Some(val) = args.get(i + 1) {
                        out.push(Token::Option(ch, val.as_str()));
                        consumed_next = true;
                    } else {
                        // trailing value-option with no value; real ssh errors,
                        // we pass it as a bare flag.
                        out.push(Token::Flag(ch));
                    }
                } else {
                    // value attached in the cluster (`-oVALUE`, `-qoVALUE`)
                    out.push(Token::AttachedOption(ch, rest));
                }
                break;
            }
            out.push(Token::Flag(ch));
        }
        i += if consumed_next { 2 } else { 1 };
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
        // Option cluster. Walk it getopt-style (same as `classify`): the first
        // value-option letter consumes the next argv element ONLY when it is the
        // last letter of the cluster (`-o VALUE`, `-qo VALUE`); an attached
        // value (`-pPORT`, `-qoFoo=bar`) or a pure flag cluster is
        // self-contained. The pre-fix check looked only at `bytes[1]` with
        // `len == 2`, so a value-option buried in a cluster (`-qo`) was missed
        // and its value mis-identified as the target host.
        let cluster = &arg[1..];
        let mut consumes_next = false;
        for (off, ch) in cluster.char_indices() {
            if VALUE_OPTIONS.contains(&ch) {
                consumes_next = cluster[off + ch.len_utf8()..].is_empty();
                break;
            }
        }
        i += if consumes_next { 2 } else { 1 };
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
                // A denied *value-option* must be stripped too. denied_flags
                // carries L/R/D/W when port_forwarding=false (and any other
                // value-taking option a policy forbids); these parse as
                // Token::Option, not Token::Flag, so without this check
                // `ssh -L 8080:internal:80 host` would forward through the
                // wrapper despite the policy — a port-forwarding/tunnel bypass.
                // `continue` drops the option AND its value (one token).
                if denied_flags.contains(c) {
                    continue;
                }
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
                // Same as the spaced value-option form: a denied value-option in
                // attached form (`-L8080:internal:80`) must be stripped too.
                if denied_flags.contains(c) {
                    continue;
                }
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
    fn filter_strips_denied_value_option_port_forward() {
        // BYPASS regression: port_forwarding=false makes denied_flags carry
        // L/R/D/W, but those are VALUE-options (parsed as Token::Option /
        // AttachedOption), not flags. Without stripping denied value-options,
        // `ssh -L 8080:internal:80 host` would forward through the wrapper
        // despite the policy — an SSH-tunnel bypass. Both the spaced and the
        // attached forms must be dropped, value included.
        for argv in [
            s(&["-L", "8080:internal-db:5432", "user@host"]),
            s(&["-L8080:internal-db:5432", "user@host"]),
            s(&["-R", "9090:localhost:9090", "user@host"]),
            s(&["-D", "1080", "user@host"]),
            s(&["-W", "internal:22", "user@host"]),
        ] {
            let toks = classify(&argv);
            let filtered = filter(&toks, &['L', 'R', 'D', 'W'], &[]);
            assert!(
                !filtered.iter().any(|a| a.starts_with("-L")
                    || a.starts_with("-R")
                    || a.starts_with("-D")
                    || a.starts_with("-W")),
                "denied value-option survived filter: {filtered:?}"
            );
            // The forward target value must not leak through either.
            assert!(
                !filtered.iter().any(|a| a.contains("internal-db")
                    || a.contains("8080")
                    || a.contains("1080")
                    || a == "internal:22"),
                "forward spec leaked: {filtered:?}"
            );
            // The target host is still forwarded.
            assert!(filtered.iter().any(|a| a == "user@host"));
        }
    }

    #[test]
    fn filter_keeps_allowed_value_option() {
        // A value-option NOT in denied_flags must still pass (e.g. -p port).
        let argv = s(&["-p", "2222", "user@host"]);
        let toks = classify(&argv);
        let filtered = filter(&toks, &['L', 'R', 'D', 'W'], &[]);
        assert!(filtered.contains(&"-p".to_string()));
        assert!(filtered.contains(&"2222".to_string()));
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
    fn filter_strips_denied_o_smuggled_in_combined_flag_cluster() {
        // BYPASS: ssh uses getopt, so `-qo ProxyCommand=…` means `-q -o
        // ProxyCommand=…` — the `o` inside the cluster consumes the next argv
        // element as its value. The pre-fix classifier split `-qo` into bare
        // Flag('q') + Flag('o') and treated "ProxyCommand=…" as the target /
        // positional, so the `-o` KEY denylist (which only fires on
        // Token::Option('o',..)/AttachedOption('o',..)) never saw it; run() then
        // re-emitted `-q -o ProxyCommand=… host`, which real ssh marries back
        // into the denied ProxyCommand — a client-side policy bypass of the
        // entire `-o` denylist. Both target_index and classify must walk the
        // cluster getopt-style so the embedded value-option is recognized.
        let argv = s(&["-qo", "ProxyCommand=/evil/tunnel", "user@host"]);

        // The real host is the target — not the smuggled `-o` value.
        assert_eq!(
            target_index(&argv),
            Some(2),
            "host must be the target; the cluster's `o` consumes the -o value"
        );

        // End-to-end as run() does it: filter the pre-target options, append the
        // target-and-beyond verbatim.
        let idx = target_index(&argv).unwrap();
        let opts = classify(&argv[..idx]);
        let mut out = filter(&opts, &[], &["ProxyCommand"]);
        out.extend(argv[idx..].iter().cloned());

        assert!(
            !out.iter().any(|x| x.contains("ProxyCommand")),
            "denied ProxyCommand smuggled through a combined-flag cluster: {out:?}"
        );
        // The legitimate `-q` flag still survives, and the host is preserved.
        assert!(out.iter().any(|x| x == "-q"), "got {out:?}");
        assert!(out.iter().any(|x| x == "user@host"), "got {out:?}");

        // Attached form too: `-voProxyCommand=…` => `-v -oProxyCommand=…`.
        let argv = s(&["-voProxyCommand=/evil", "user@host"]);
        let idx = target_index(&argv).unwrap();
        let mut out = filter(&classify(&argv[..idx]), &[], &["ProxyCommand"]);
        out.extend(argv[idx..].iter().cloned());
        assert!(
            !out.iter().any(|x| x.contains("ProxyCommand")),
            "denied ProxyCommand smuggled through an attached cluster: {out:?}"
        );
        assert!(out.iter().any(|x| x == "-v"), "got {out:?}");
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
