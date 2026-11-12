//! Command-line parsing compatible with the reference `getopt` string
//! `u:U:m:M:t:P:c:a:p:C:f:F:R:vqh`.
//!
//! Differences from the reference (all deliberate):
//! * `-M master-password` is refused: secrets on the command line leak via
//!   `ps` and shell history.
//! * Options may follow the site name (GNU-style permutation); use `--` before
//!   a site name that starts with `-`.
//! * More than one site name is an error instead of being silently ignored.

use crate::log::Fatal;
use crate::EX_USAGE;
use std::ffi::OsString;

/// Raw option values, before validation (mirrors the reference `Arguments`).
#[derive(Debug, Default)]
pub struct Arguments {
    pub full_name: Option<String>,
    /// `-U`: allow updating the master password in the user file.
    pub allow_password_update: bool,
    pub master_password_fd: Option<String>,
    pub site_name: Option<String>,
    pub result_type: Option<String>,
    pub result_param: Option<String>,
    pub site_counter: Option<String>,
    pub algorithm_version: Option<String>,
    pub key_purpose: Option<String>,
    pub key_context: Option<String>,
    pub sites_format: Option<String>,
    /// `-F` (true) vs `-f` (false).
    pub sites_format_fixed: bool,
    pub sites_redacted: Option<String>,
    pub verbosity: i32,
    pub help: bool,
}

/// Parse `argv[1..]`.  Empty option values are treated as absent, like the
/// reference.
pub fn parse(argv: impl IntoIterator<Item = OsString>) -> Result<Arguments, Fatal> {
    let mut args = Arguments::default();
    let mut positional = Vec::new();
    let mut argv = argv.into_iter();

    while let Some(arg) = argv.next() {
        let arg = arg
            .into_string()
            .map_err(|_| Fatal::new(EX_USAGE, "Arguments must be valid UTF-8."))?;
        if arg == "--" {
            for rest in argv.by_ref() {
                positional.push(
                    rest.into_string()
                        .map_err(|_| Fatal::new(EX_USAGE, "Arguments must be valid UTF-8."))?,
                );
            }
            break;
        }
        let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) else {
            positional.push(arg);
            continue;
        };

        for (i, opt) in cluster.char_indices() {
            match opt {
                'v' => args.verbosity += 1,
                'q' => args.verbosity -= 1,
                'h' => args.help = true,
                'u' | 'U' | 'm' | 'M' | 't' | 'P' | 'c' | 'a' | 'p' | 'C' | 'f' | 'F' | 'R' => {
                    // The value is the rest of this argument, or the next one.
                    let rest = &cluster[i + opt.len_utf8()..];
                    let value = if rest.is_empty() {
                        match argv.next() {
                            Some(v) => v.into_string().map_err(|_| {
                                Fatal::new(EX_USAGE, "Arguments must be valid UTF-8.")
                            })?,
                            None => return Err(missing_value(opt)),
                        }
                    } else {
                        rest.to_owned()
                    };
                    let value = Some(value).filter(|v| !v.is_empty());
                    apply(&mut args, opt, value)?;
                    break;
                }
                other => {
                    return Err(Fatal::new(EX_USAGE, format!("Unknown option: -{other}")));
                }
            }
        }
    }

    let mut positional = positional.into_iter();
    args.site_name = positional.next();
    if let Some(extra) = positional.next() {
        return Err(Fatal::new(
            EX_USAGE,
            format!("Unexpected argument: {extra} (only one site name may be given)"),
        ));
    }
    Ok(args)
}

fn apply(args: &mut Arguments, opt: char, value: Option<String>) -> Result<(), Fatal> {
    match opt {
        'u' | 'U' => {
            args.full_name = value;
            args.allow_password_update = opt == 'U';
        }
        'm' => args.master_password_fd = value,
        'M' => {
            // Never accept a secret as an argument: it is visible to every
            // user via `ps` and is kept in shell history.  We cannot scrub it
            // from our own argv either without `unsafe`.
            return Err(Fatal::new(
                EX_USAGE,
                "-M is not supported: a master password on the command line is visible to other \
                 users (ps) and in shell history.\nUse the prompt, pipe it on stdin, or use -m fd.",
            ));
        }
        't' => args.result_type = value,
        'P' => args.result_param = value,
        'c' => args.site_counter = value,
        'a' => args.algorithm_version = value,
        'p' => args.key_purpose = value,
        'C' => args.key_context = value,
        'f' | 'F' => {
            args.sites_format = value;
            args.sites_format_fixed = opt == 'F';
        }
        'R' => args.sites_redacted = value,
        _ => return Err(Fatal::new(EX_USAGE, format!("Unexpected option: {opt}"))),
    }
    Ok(())
}

fn missing_value(opt: char) -> Fatal {
    let what = match opt {
        'u' | 'U' => "full name",
        't' => "type name",
        'c' => "counter value",
        'm' => "file descriptor",
        'a' => "algorithm version",
        'p' => "purpose",
        'C' => "context",
        'P' => "parameter value",
        'f' | 'F' => "format",
        'R' => "redaction flag",
        _ => "value",
    };
    Fatal::new(EX_USAGE, format!("Missing {what} to option: -{opt}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Arguments, Fatal> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn getopt_style() {
        let a = p(&[
            "-u", "Robert", "-tx", "-c3", "-vv", "-q", "site.com", "-a", "1",
        ])
        .unwrap();
        assert_eq!(a.full_name.as_deref(), Some("Robert"));
        assert_eq!(a.result_type.as_deref(), Some("x"));
        assert_eq!(a.site_counter.as_deref(), Some("3"));
        assert_eq!(a.verbosity, 1);
        assert_eq!(a.site_name.as_deref(), Some("site.com"));
        assert_eq!(a.algorithm_version.as_deref(), Some("1"));
        assert!(!a.allow_password_update);
    }

    #[test]
    fn grouped_flags_and_values() {
        let a = p(&["-vqvUJane", "--", "-weird-site"]).unwrap();
        assert_eq!(a.verbosity, 1);
        assert_eq!(a.full_name.as_deref(), Some("Jane"));
        assert!(a.allow_password_update);
        assert_eq!(a.site_name.as_deref(), Some("-weird-site"));
    }

    #[test]
    fn empty_values_are_absent() {
        let a = p(&["-u", "", "-C", ""]).unwrap();
        assert!(a.full_name.is_none());
        assert!(a.key_context.is_none());
    }

    #[test]
    fn errors() {
        assert_eq!(p(&["-u"]).unwrap_err().code, EX_USAGE);
        assert_eq!(p(&["-x"]).unwrap_err().code, EX_USAGE);
        assert_eq!(p(&["-M", "secret"]).unwrap_err().code, EX_USAGE);
        assert_eq!(p(&["a", "b"]).unwrap_err().code, EX_USAGE);
    }
}
