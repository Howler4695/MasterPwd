//! The flat `.mpsites` format (`mpw_marshal_read_flat` / `mpw_marshal_write_flat`).
//!
//! ```text
//! # Master Password site export
//! #     Export of site names and stored passwords (unless device-private) encrypted with the master key.
//! #
//! ##
//! # Format: 1
//! # Date: 2019-05-11T11:14:56Z
//! # User Name: Robert Lee Mitchell
//! # Full Name: Robert Lee Mitchell
//! # Avatar: 0
//! # Identicon: ...
//! # Key ID: 98EEF4D1...
//! # Algorithm: 3
//! # Default Type: 17
//! # Passwords: PROTECTED
//! ##
//! #
//! #               Last     Times  Password                      Login→                     Site→Site
//! #               used      used      type                       name→                     name→password
//! 2019-05-11T11:14:56Z         3    17:3:1                           →    masterpasswordapp.com
//! ```
//! (`→` is a tab.)  Format 0 site lines are `<last used> <uses> <type>:<algorithm> <site name>\t<password>`.

use super::{
    check_len, file_time, parse_algorithm, parse_key_id, parse_time, parse_type, perr, Outputs, Pending, Slot,
    UserSummary,
};
use crate::error::{Error, ParseError, ParseErrorKind, Result};
use crate::limits;
use crate::model::{validate_full_name, validate_site_name, Site, User, UserExtras, UserPreferences};
use crate::time::Timestamp;
use mpw_core::{AlgorithmVersion, Identicon, KeyId, ResultType, COUNTER_DEFAULT};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use zeroize::Zeroizing;

type PResult<T> = std::result::Result<T, ParseError>;

/// Emulates the reference's `mpw_get_token`: skip leading spaces, take up to
/// the first delimiter, step past it.  Delimiters are ASCII, so byte slicing
/// stays on character boundaries.
struct Tokens<'a> {
    rest: &'a str,
}

impl<'a> Tokens<'a> {
    fn next(&mut self, delims: &[u8]) -> &'a str {
        let s = self.rest.trim_start_matches(' ');
        let end = s.bytes().position(|b| delims.contains(&b)).unwrap_or(s.len());
        let (token, rest) = s.split_at(end);
        self.rest = rest.get(1..).unwrap_or("");
        token
    }
}

#[derive(Default)]
struct Header {
    format: u64,
    date: Option<Timestamp>,
    full_name: Option<String>,
    avatar: u32,
    identicon: Option<Identicon>,
    key_id: Option<KeyId>,
    algorithm: AlgorithmVersion,
    default_type: Option<ResultType>,
    redacted: bool,
}

fn header_line(h: &mut Header, line: &str, n: usize) -> PResult<()> {
    let mut t = Tokens { rest: line };
    let name = t.next(b":");
    let value = t.rest.trim_start_matches(' ');
    if !line.contains(':') {
        return Ok(()); // a plain comment inside the header
    }
    let loc = |what: &str| format!("header {what}");
    let invalid = |what: &str| perr(ParseErrorKind::InvalidValue, Some(n), loc(what));
    check_len(value, Some(n), &loc(name.trim()))?;
    match name.trim().to_ascii_lowercase().as_str() {
        "format" => h.format = value.trim().parse().map_err(|_| invalid("Format"))?,
        "date" => h.date = Some(parse_time(value, Some(n), "header Date")?),
        "passwords" => h.redacted = !value.trim().eq_ignore_ascii_case("VISIBLE"),
        "algorithm" => {
            let v = value.trim().parse().map_err(|_| perr(ParseErrorKind::InvalidAlgorithm, Some(n), "header Algorithm"))?;
            h.algorithm = parse_algorithm(v, Some(n), "header Algorithm")?;
        }
        "avatar" => h.avatar = value.trim().parse().map_err(|_| invalid("Avatar"))?,
        "full name" | "user name" => {
            validate_full_name(value).map_err(|_| invalid("Full Name"))?;
            h.full_name = Some(value.to_owned());
        }
        "identicon" => h.identicon = Identicon::decode(value.trim()),
        "key id" => h.key_id = parse_key_id(value, Some(n), "header Key ID")?,
        "default type" => {
            let v = value.trim().parse().map_err(|_| invalid("Default Type"))?;
            h.default_type = Some(parse_type(v, Some(n), "header Default Type")?);
        }
        _ => {}
    }
    Ok(())
}

fn number<T: std::str::FromStr>(s: &str, n: usize, loc: &str) -> PResult<T> {
    s.parse().map_err(|_| perr(ParseErrorKind::InvalidValue, Some(n), loc))
}

pub(super) fn read(text: &str) -> Result<(UserSummary, User, Vec<Pending>)> {
    let mut h = Header { redacted: true, ..Header::default() };
    let (mut started, mut ended) = (false, false);
    let mut user: Option<User> = None;
    let mut pending = Vec::new();

    // Unlike the reference, the last line counts even without a trailing newline.
    for (i, raw) in text.split('\n').enumerate() {
        let n = i + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = line.strip_prefix('#') {
            if !started {
                started = rest.starts_with('#');
            } else if !ended {
                if rest.starts_with('#') {
                    ended = true;
                    user = Some(finish_header(&h, n)?);
                } else {
                    header_line(&mut h, rest, n)?;
                }
            }
            continue;
        }
        let Some(user) = user.as_mut() else { continue };
        if line.trim().is_empty() {
            continue;
        }
        site_line(user, &h, line, n, &mut pending)?;
    }

    let mut user = user.ok_or_else(|| perr(ParseErrorKind::Missing, None, "header"))?;
    if h.date.is_none() {
        // No export date: the user was last used when its latest site was.
        user.last_used = user.sites.values().map(|s| s.last_used).max().unwrap_or(Timestamp::EPOCH);
    }
    let summary = UserSummary {
        format: super::Format::Flat,
        format_version: h.format,
        export_date: h.date,
        redacted: h.redacted,
        full_name: user.full_name.clone(),
        avatar: user.avatar,
        identicon: user.identicon.clone(),
        key_id: user.key_id.clone(),
        algorithm: user.algorithm,
        last_used: user.last_used,
        preferences: UserPreferences::default(),
        site_count: user.sites.len(),
        second_factor: user.second_factor.clone(),
    };
    Ok((summary, user, pending))
}

fn finish_header(h: &Header, n: usize) -> PResult<User> {
    if h.format > 1 {
        return Err(perr(ParseErrorKind::UnsupportedFlatFormat(h.format), Some(n), "header Format"));
    }
    let full_name = h.full_name.clone().ok_or_else(|| perr(ParseErrorKind::Missing, Some(n), "header Full Name"))?;
    Ok(User {
        full_name,
        avatar: h.avatar,
        identicon: h.identicon.clone(),
        key_id: h.key_id.clone(),
        algorithm: h.algorithm,
        default_type: h.default_type.unwrap_or(ResultType::DEFAULT),
        login_type: ResultType::DEFAULT_LOGIN,
        login_state: None,
        last_used: h.date.unwrap_or(Timestamp::EPOCH),
        preferences: UserPreferences::default(),
        sites: BTreeMap::new(),
        extras: UserExtras::default(),
        second_factor: Default::default(),
    })
}

fn site_line(user: &mut User, h: &Header, line: &str, n: usize, pending: &mut Vec<Pending>) -> PResult<()> {
    let mut t = Tokens { rest: line };
    let last_used = t.next(b" \t");
    let uses = t.next(b" \t");
    let spec = t.next(b" \t");
    let (login, name, password) = match h.format {
        0 => ("", t.next(b"\t"), t.rest.trim_start_matches(' ')),
        _ => {
            let login = t.next(b"\t");
            (login, t.next(b"\t"), t.rest.trim_start_matches(' '))
        }
    };
    let last_used = parse_time(last_used, Some(n), "last used")?;
    let uses: u32 = number(uses, n, "uses")?;
    let parts: Vec<&str> = spec.split(':').collect();
    let (result_type, algorithm, counter) = match (h.format, parts.as_slice()) {
        (0, [t, a]) => (*t, *a, None),
        (_, [t, a, c]) => (*t, *a, Some(*c)),
        _ => return Err(perr(ParseErrorKind::InvalidValue, Some(n), "type:algorithm:counter")),
    };
    let result_type = parse_type(number(result_type, n, "type")?, Some(n), "type")?;
    let algorithm = parse_algorithm(number(algorithm, n, "algorithm")?, Some(n), "algorithm")?;
    let counter = match counter {
        Some(c) => number(c, n, "counter")?,
        None => COUNTER_DEFAULT,
    };
    validate_site_name(name).map_err(|_| perr(ParseErrorKind::InvalidValue, Some(n), "site name"))?;
    check_len(login, Some(n), "login name")?;
    check_len(password, Some(n), "password")?;
    if !user.sites.contains_key(name) && user.sites.len() >= limits::MAX_SITES {
        return Err(perr(ParseErrorKind::TooMany { what: "sites", limit: limits::MAX_SITES }, Some(n), ""));
    }

    // A repeated site name replaces the earlier line, like the reference.
    pending.retain(|p| !matches!(&p.slot, Slot::SitePassword(s) | Slot::FlatLogin(s) if s == name));

    let mut site = Site::new(name, algorithm, result_type);
    site.counter = counter;
    site.uses = uses;
    site.last_used = last_used;
    if h.redacted {
        if !password.is_empty() {
            site.result_state = Some(password.to_owned());
        }
        // Only exportable (personal) login names are written to redacted files.
        if !login.is_empty() {
            site.login_type = Some(ResultType::StatefulPersonal);
            site.login_state = Some(login.to_owned());
        }
    } else {
        if !password.is_empty() && result_type.is_stateful() {
            let value = Zeroizing::new(password.to_owned());
            pending.push(Pending { slot: Slot::SitePassword(name.to_owned()), value });
        }
        if !login.is_empty() {
            let value = Zeroizing::new(login.to_owned());
            pending.push(Pending { slot: Slot::FlatLogin(name.to_owned()), value });
        }
    }
    user.sites.insert(name.to_owned(), site);
    Ok(())
}

// ----------------------------------------------------------------------- write

fn check_field(value: &str, what: &'static str) -> Result<()> {
    if value.contains(['\t', '\n', '\r']) {
        return Err(Error::NotRepresentable { what, why: "it contains a tab or line break" });
    }
    if value.starts_with(' ') {
        return Err(Error::NotRepresentable { what, why: "it starts with a space" });
    }
    Ok(())
}

/// Right-align in `width` bytes, like C's `%*s` (which counts bytes, not
/// characters).  Writes straight into the (zeroizing) output buffer.
fn pad(w: &mut String, s: &str, width: usize) {
    for _ in s.len()..width {
        w.push(' ');
    }
    w.push_str(s);
}

pub(super) fn write(user: &User, out: &Outputs, redacted: bool, now: Timestamp) -> Result<Zeroizing<String>> {
    check_field(&user.full_name, "the full name")?;
    // Reserve up front so the buffer holding clear-text values is not
    // reallocated (which would leave unwiped copies behind).
    let mut o = Zeroizing::new(String::with_capacity(super::size_hint(user, out)));
    let w = &mut *o;
    w.push_str("# Master Password site export\n");
    w.push_str(if redacted {
        "#     Export of site names and stored passwords (unless device-private) encrypted with the master key.\n"
    } else {
        "#     Export of site names and passwords in clear-text.\n"
    });
    w.push_str("# \n##\n# Format: 1\n");
    let _ = writeln!(w, "# Date: {}", file_time(now));
    let _ = writeln!(w, "# User Name: {}", user.full_name);
    let _ = writeln!(w, "# Full Name: {}", user.full_name);
    let _ = writeln!(w, "# Avatar: {}", user.avatar);
    let _ = writeln!(w, "# Identicon: {}", user.identicon.as_ref().map(Identicon::encode).unwrap_or_default());
    let _ = writeln!(w, "# Key ID: {}", user.key_id.as_ref().map(KeyId::as_str).unwrap_or_default());
    let _ = writeln!(w, "# Algorithm: {}", user.algorithm.as_u32());
    let _ = writeln!(w, "# Default Type: {}", user.default_type.as_u32());
    let _ = writeln!(w, "# Passwords: {}", if redacted { "PROTECTED" } else { "VISIBLE" });
    w.push_str("##\n#\n");
    w.push_str("#               Last     Times  Password                      Login\t                     Site\tSite\n");
    w.push_str("#               used      used      type                       name\t                     name\tpassword\n");

    for (name, site) in &user.sites {
        check_field(name, "a site name")?;
        let so = out.sites.get(name);
        let login = so.and_then(|s| s.login.as_deref()).map_or("", String::as_str);
        let password = so.and_then(|s| s.password.as_deref()).map_or("", String::as_str);
        check_field(login, "a login name")?;
        check_field(password, "a password")?;
        let spec = format!("{}:{}:{}", site.result_type.as_u32(), site.algorithm.as_u32(), site.counter);
        w.push_str(&file_time(site.last_used));
        w.push_str("  ");
        pad(w, &site.uses.to_string(), 8);
        w.push_str("  ");
        pad(w, &spec, 8);
        w.push_str("  ");
        pad(w, login, 25);
        w.push('\t');
        pad(w, name, 25);
        w.push('\t');
        w.push_str(password);
        w.push('\n');
    }
    Ok(o)
}
