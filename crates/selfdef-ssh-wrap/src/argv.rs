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
        // denied `-o` option past the key-denylist, because the embedded `o`
        // was never seen as Token::Option. (`-` alone and `--` are handled
        // above, so the cluster here is always at least one char.)
        let cluster = &arg[1..];
        let mut consumed_next = false;
        for (off, ch) in cluster.char_indices() {
            if VALUE_OPTIONS.contains(&ch) {
                let rest = &cluster[off + ch.len_utf8()..];
                if rest.is_empty() {
                    // value is the next argv element (`-o VALUE`, `-qo VALUE`)
                    if let Some(val) = args.get(i + 1) {
                        out.push(Token::Option(ch, val.as_str()));
                        consumed_next = true;
                    } else {
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

/// Extract the option KEY from an `-o` value for denylist matching.
///
/// `ssh_config(5)` separates a keyword from its argument with EITHER `=` OR
/// whitespace, so `StrictHostKeyChecking=no` and `StrictHostKeyChecking no`
/// denote the SAME option and `ssh -o` honours both. Splitting on `=` alone
/// (the pre-fix behaviour) made the whitespace form (`-o "StrictHostKeyChecking
/// no"`) produce the key `"StrictHostKeyChecking no"`, which never matched the
/// denied `"StrictHostKeyChecking"` and slipped past the policy — a client-side
/// defense bypass (an agent could re-enable a denied option ssh would apply).
/// Split on the first `=` or whitespace run so both forms collapse to one key.
pub fn o_option_key(val: &str) -> &str {
    val.trim_start()
        .split(|c: char| c == '=' || c.is_whitespace())
        .next()
        .unwrap_or("")
}

/// Filter user-supplied flags. Returns a new argv (excluding argv[0]) with
/// `denied_flags` removed and `-o` overrides matching `denied_o_keys` (case-
/// insensitive on the key) removed.
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
pub fn parse_target(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match spec.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, spec),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse::<u16>().ok()),
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
    fn filter_strips_denied_o_smuggled_in_combined_flag_cluster() {
        // BYPASS (F-2026-108): ssh uses getopt, so `-qo ProxyCommand=…` means
        // `-q -o ProxyCommand=…` — the `o` inside the cluster consumes the next
        // argv element as its value. The pre-fix classifier split `-qo` into
        // bare Flag('q')+Flag('o'), so the `-o` KEY denylist (which only fires
        // on Token::Option('o',..)/AttachedOption('o',..)) never saw it and
        // run() re-emitted the denied ProxyCommand — a client-side policy bypass
        // of the entire `-o` denylist (ProxyCommand pivot, StrictHostKeyChecking
        // MITM, agent-forward re-enable). classify must treat the embedded `o`
        // as the value-option it is.
        let argv = s(&["-qo", "ProxyCommand=/evil"]);
        let filtered = filter(&classify(&argv), &[], &["ProxyCommand"]);
        assert!(
            !filtered.iter().any(|x| x.contains("ProxyCommand")),
            "denied ProxyCommand smuggled through a combined-flag cluster: {filtered:?}"
        );
        assert!(filtered.iter().any(|x| x == "-q"), "got {filtered:?}");

        // Attached form: `-voProxyCommand=…` => `-v -oProxyCommand=…`.
        let argv = s(&["-voProxyCommand=/evil"]);
        let filtered = filter(&classify(&argv), &[], &["ProxyCommand"]);
        assert!(
            !filtered.iter().any(|x| x.contains("ProxyCommand")),
            "attached cluster smuggled ProxyCommand: {filtered:?}"
        );
        assert!(filtered.iter().any(|x| x == "-v"), "got {filtered:?}");
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
        // BYPASS: port_forwarding=false makes denied_flags carry L/R/D/W, but
        // those are VALUE-options (parsed as Token::Option / AttachedOption),
        // not flags. Without stripping denied value-options, `ssh -L
        // 8080:internal:80 host` would forward through the wrapper despite the
        // policy — an SSH-tunnel bypass. Both spaced and attached forms must be
        // dropped, value included.
        for argv in [
            s(&["-L", "8080:internal-db:5432", "user@host"]),
            s(&["-L8080:internal-db:5432", "user@host"]),
            s(&["-R", "9090:localhost:9090", "user@host"]),
            s(&["-D", "1080", "user@host"]),
        ] {
            let filtered = filter(&classify(&argv), &['L', 'R', 'D', 'W'], &[]);
            assert!(
                !filtered.iter().any(|a| a.starts_with("-L")
                    || a.starts_with("-R")
                    || a.starts_with("-D")
                    || a.starts_with("-W")),
                "denied value-option survived filter: {filtered:?}"
            );
            assert!(
                !filtered.iter().any(|a| a.contains("internal-db")
                    || a.contains("8080")
                    || a.contains("1080")),
                "forward spec leaked: {filtered:?}"
            );
            assert!(filtered.iter().any(|a| a == "user@host"));
        }
        // An allowed value-option (e.g. -p port) still passes.
        let filtered = filter(&classify(&s(&["-p", "2222", "user@host"])), &['L', 'R', 'D', 'W'], &[]);
        assert!(filtered.contains(&"-p".to_string()) && filtered.contains(&"2222".to_string()));
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
        assert_eq!(o_option_key("StrictHostKeyChecking=no"), "StrictHostKeyChecking");
        assert_eq!(o_option_key("StrictHostKeyChecking no"), "StrictHostKeyChecking");
        assert_eq!(o_option_key("  StrictHostKeyChecking   no"), "StrictHostKeyChecking");
        assert_eq!(o_option_key("StrictHostKeyChecking\tno"), "StrictHostKeyChecking");
    }

    #[test]
    fn filter_strips_denied_o_via_whitespace_form() {
        // BYPASS: ssh honours `-o "StrictHostKeyChecking no"` (space, not '=').
        // Splitting the key on '=' alone let it slip the denylist and ssh would
        // then disable host-key checking despite the policy. Both spaced-value
        // and attached forms of the whitespace variant must be stripped.
        let denied = ["StrictHostKeyChecking"];
        let f = filter(&classify(&s(&["-o", "StrictHostKeyChecking no", "host"])), &[], &denied);
        assert!(
            !f.iter().any(|x| x.contains("StrictHostKeyChecking")),
            "whitespace-form -o must be stripped, got {f:?}"
        );
        let f = filter(&classify(&s(&["-oStrictHostKeyChecking no", "host"])), &[], &denied);
        assert!(
            !f.iter().any(|x| x.contains("StrictHostKeyChecking")),
            "attached whitespace-form -o must be stripped, got {f:?}"
        );
        let f = filter(&classify(&s(&["-o", "stricthostkeychecking no", "host"])), &[], &denied);
        assert!(!f.iter().any(|x| x.to_lowercase().contains("stricthostkeychecking")));
        // The `=` form still strips (regression) ...
        let f = filter(&classify(&s(&["-o", "StrictHostKeyChecking=no", "host"])), &[], &denied);
        assert!(!f.iter().any(|x| x.contains("StrictHostKeyChecking")));
        // ... and an unrelated option is preserved (no over-strip).
        let f = filter(&classify(&s(&["-o", "ServerAliveInterval 30", "host"])), &[], &denied);
        assert!(f.iter().any(|x| x.contains("ServerAliveInterval")), "got {f:?}");
    }
}
