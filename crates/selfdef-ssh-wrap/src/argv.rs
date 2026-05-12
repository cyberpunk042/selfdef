//! ssh argv parsing.
//!
//! We don't reimplement ssh's option grammar — we only need enough to:
//! 1. find the target spec (`user@host`) in argv,
//! 2. classify each token as "flag", "option needing value", or "positional",
//! 3. filter out user-supplied flags that conflict with policy.

/// Single-letter ssh options that consume the next argv element as a value.
/// Taken from ssh(1). Conservative: anything we're not sure about goes here.
const VALUE_OPTIONS: &[char] = &[
    'B', 'b', 'c', 'D', 'E', 'e', 'F', 'I', 'i', 'J', 'L', 'l', 'm', 'O', 'o',
    'p', 'Q', 'R', 'S', 'W', 'w',
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
pub fn filter(
    tokens: &[Token<'_>],
    denied_flags: &[char],
    denied_o_keys: &[&str],
) -> Vec<String> {
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
                let key = val.split('=').next().unwrap_or("").trim();
                if denied_o_keys
                    .iter()
                    .any(|k| key.eq_ignore_ascii_case(k))
                {
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
                let key = val.split('=').next().unwrap_or("").trim();
                if denied_o_keys
                    .iter()
                    .any(|k| key.eq_ignore_ascii_case(k))
                {
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
pub fn parse_target(spec: &str) -> (Option<String>, String, Option<u16>) {
    let (user, rest) = match spec.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, spec),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => {
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
        let flags: Vec<_> = toks.iter().filter_map(|t| {
            if let Token::Flag(c) = t { Some(*c) } else { None }
        }).collect();
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
}
