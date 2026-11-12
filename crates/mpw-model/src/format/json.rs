//! The JSON `.mpjson` format (`mpw_marshal_read_json` / `mpw_marshal_write_json`
//! / `mpw_marshal_auth` in the reference).
//!
//! ```text
//! { "export": { "date", "redacted", "format": 1 },
//!   "user":   { "avatar", "full_name", "identicon", "algorithm", "key_id",
//!               "default_type", "last_used", ["login_type", "login_name"], "_ext_mpw": {...} },
//!   "sites":  { "<name>": { "counter", "algorithm", "type", "password", "login_type",
//!                           "login_name", "uses", "last_used",
//!                           "questions": { "<keyword>": { "type", "answer" } },
//!                           "_ext_mpw": { "url" } } } }
//! ```
//! Members we do not interpret are kept and written back after ours.
//!
//! # Generations (verified against `spectre-app/api`, the continuation of the
//! upstream C library)
//!
//! | generation | writes `export.format` | sites key | user login keys | site `login_type` absent/0 | url |
//! |---|---|---|---|---|---|
//! | classic (≤ 2020-09-13, `ac34ba1`) | 1 | `sites` | — | absent: 30; 0: rejected | `_ext_mpw` |
//! | user-login (`f40a38d`, `ebed134`) | 2 | `sites` | `login_type`, `login_name` | "use the user's login" | `_ext_mpw` |
//! | transitional (`71dacb0`…`55a34e6^`, the old macOS app) | 2 | `services` | same | same | `_ext_mpw` |
//! | Spectre (`55a34e6`, `28761d8`…) | 2, later 3 | `sites` | same; v3: `default_type` → `result_type` | same | `_ext_spectre` |
//!
//! Every reader since `ebed134` applies "version 1 fixes" to `format: 1` files:
//! a site `login_type` of 30 is dropped (meaning "use the user's login"), and
//! the transitional readers rename `sites` to `services` — but *only* for
//! format 1.  A format-2 file is therefore readable either by the transitional
//! readers (`services`) or by the others (`sites`), never by both, while a
//! format-1 `sites` file is read correctly by all of them.  So we write format 1
//! with `sites`, the classic layout, and read every generation.

use super::{
    check_len, file_time, parse_algorithm, parse_key_id, parse_time, parse_type, perr, Outputs, Pending, Slot,
    UserSummary,
};
use crate::error::{ParseError, ParseErrorKind, Result};
use crate::limits;
use crate::model::{
    validate_full_name, validate_keyword, validate_site_name, JsonMap, Question, Site, User, UserExtras,
    UserPreferences,
};
use crate::time::Timestamp;
use mpw_core::{Identicon, ResultType, COUNTER_DEFAULT};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

type PResult<T> = std::result::Result<T, ParseError>;

const EXT: &str = "_ext_mpw";
const EXT_SPECTRE: &str = "_ext_spectre";

fn ext_url(ext: Option<&Value>, loc: &str) -> PResult<Option<String>> {
    match ext.and_then(|e| e.get("url")) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(u)) => {
            check_len(u, None, loc)?;
            Ok(Some(u.clone()))
        }
        Some(_) => Err(err(ParseErrorKind::InvalidValue, loc)),
    }
}

fn err(kind: ParseErrorKind, location: impl Into<String>) -> ParseError {
    perr(kind, None, location)
}

/// Remove `key` and require an object (null/missing: `None`).
fn take_object(map: &mut JsonMap, key: &str, loc: &str) -> PResult<Option<JsonMap>> {
    match map.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => Err(err(ParseErrorKind::InvalidValue, loc)),
    }
}

/// Remove `key` as an unsigned integer.  Accepts integral floats (the reference
/// writes numbers with `%g`).
fn take_uint(map: &mut JsonMap, key: &str, max: u64, loc: &str) -> PResult<Option<u64>> {
    let v = match map.remove(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let n = match &v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f <= max as f64).map(|f| f as u64)),
        _ => None,
    };
    n.filter(|n| *n <= max)
        .map(Some)
        .ok_or_else(|| err(ParseErrorKind::InvalidValue, loc))
}

fn take_u32(map: &mut JsonMap, key: &str, loc: &str) -> PResult<Option<u32>> {
    Ok(take_uint(map, key, u64::from(u32::MAX), loc)?.and_then(|n| u32::try_from(n).ok()))
}

/// Remove `key` as a string (null/missing: `None`).  The string is moved out so
/// that clear-text secrets can be wiped later.
fn take_string(map: &mut JsonMap, key: &str, loc: &str) -> PResult<Option<String>> {
    match map.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            check_len(&s, None, loc)?;
            Ok(Some(s))
        }
        Some(mut other) => {
            wipe(&mut other);
            Err(err(ParseErrorKind::InvalidValue, loc))
        }
    }
}

fn take_secret(map: &mut JsonMap, key: &str, loc: &str) -> PResult<Option<Zeroizing<String>>> {
    Ok(take_string(map, key, loc)?.map(Zeroizing::new).filter(|s| !s.is_empty()))
}

/// Wipe every string in a JSON tree (used for clear-text exports).
pub(crate) fn wipe(v: &mut Value) {
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(s) => s.zeroize(),
            Value::Array(a) => stack.extend(a.iter_mut()),
            Value::Object(m) => stack.extend(m.values_mut()),
            _ => {}
        }
    }
}

fn preferences(ext: Option<&Value>) -> UserPreferences {
    let Some(Value::Object(m)) = ext else {
        return UserPreferences::default();
    };
    UserPreferences {
        mask_passwords: m.get("maskPasswords").and_then(Value::as_bool).unwrap_or(false),
        biometric_lock: m.get("biometricLock").and_then(Value::as_bool).unwrap_or(false),
        autofill: m.get("autofill").and_then(Value::as_bool),
        attacker: m.get("attacker").and_then(Value::as_str).map(str::to_owned),
    }
}

pub(super) fn read(text: &str) -> Result<(UserSummary, User, Vec<Pending>)> {
    // serde_json bounds nesting at 128 levels, so hostile input cannot recurse unboundedly.
    let mut root = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(m)) => m,
        Ok(mut other) => {
            wipe(&mut other);
            return Err(err(ParseErrorKind::UnknownFormat, "").into());
        }
        Err(e) => {
            let kind = ParseErrorKind::Json(format!("{:?} error at column {}", e.classify(), e.column()));
            return Err(perr(kind, Some(e.line()), "").into());
        }
    };
    let parsed = read_root(&mut root);
    // Anything left that we did not keep is dropped; wipe it on the way out.
    if parsed.is_err() {
        for v in root.values_mut() {
            wipe(v);
        }
    }
    Ok(parsed?)
}

fn read_root(root: &mut JsonMap) -> PResult<(UserSummary, User, Vec<Pending>)> {
    // ------------------------------------------------------------------ export
    let mut export = take_object(root, "export", "export")?.unwrap_or_default();
    let export_date = take_string(&mut export, "date", "export.date")?
        .map(|s| parse_time(&s, None, "export.date"))
        .transpose()?;
    let redacted = match export.remove("redacted") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => b,
        Some(_) => return Err(err(ParseErrorKind::InvalidValue, "export.redacted")),
    };
    let format_version = take_uint(&mut export, "format", u64::MAX, "export.format")?.unwrap_or(1);
    // Format 1 (and files without a format): a site login type of 30 is the
    // classic writer's default and means "use the user's login" (upstream's
    // "version 1 fixes").
    let v1_login_fix = format_version <= 1;

    // -------------------------------------------------------------------- user
    let mut u = take_object(root, "user", "user")?.ok_or_else(|| err(ParseErrorKind::Missing, "user"))?;
    let full_name = take_string(&mut u, "full_name", "user.full_name")?
        .ok_or_else(|| err(ParseErrorKind::Missing, "user.full_name"))?;
    validate_full_name(&full_name).map_err(|_| err(ParseErrorKind::InvalidValue, "user.full_name"))?;
    let avatar = take_u32(&mut u, "avatar", "user.avatar")?.unwrap_or(0);
    let identicon = take_string(&mut u, "identicon", "user.identicon")?.and_then(|s| Identicon::decode(&s));
    let algorithm = match take_uint(&mut u, "algorithm", u64::MAX, "user.algorithm")? {
        Some(v) => parse_algorithm(v, None, "user.algorithm")?,
        None => Default::default(),
    };
    let key_id = match take_string(&mut u, "key_id", "user.key_id")? {
        Some(s) => parse_key_id(&s, None, "user.key_id")?,
        None => None,
    };
    // Spectre format 3 renamed `default_type` to `result_type` (which wins if both exist).
    let legacy_default = take_uint(&mut u, "default_type", u64::MAX, "user.default_type")?;
    let default_type = match take_uint(&mut u, "result_type", u64::MAX, "user.result_type")?.or(legacy_default) {
        Some(v) => parse_type(v, None, "user.default_type")?,
        None => ResultType::DEFAULT,
    };
    let last_used = match take_string(&mut u, "last_used", "user.last_used")? {
        Some(s) => parse_time(&s, None, "user.last_used")?,
        None => export_date.unwrap_or(Timestamp::EPOCH),
    };
    let login_type = match take_uint(&mut u, "login_type", u64::MAX, "user.login_type")? {
        None | Some(0) => ResultType::DEFAULT_LOGIN,
        Some(v) => parse_type(v, None, "user.login_type")?,
    };
    let login_value = take_secret(&mut u, "login_name", "user.login_name")?;
    let mut user_ext = u.remove(EXT);
    let prefs = preferences(user_ext.as_ref());
    let second_factor = crate::second_factor::read_member(&mut user_ext);

    let mut pending = Vec::new();
    let mut user = User {
        full_name,
        avatar,
        identicon,
        key_id,
        algorithm,
        default_type,
        login_type,
        login_state: None,
        last_used,
        preferences: prefs,
        sites: BTreeMap::new(),
        extras: UserExtras::default(),
        second_factor,
    };
    match login_value {
        Some(v) if !redacted => {
            if login_type.is_stateful() {
                pending.push(Pending { slot: Slot::UserLogin, value: v });
            }
        }
        Some(v) => user.login_state = Some(v.to_string()),
        None => {}
    }

    // ------------------------------------------------------------------- sites
    // The transitional library wrote `services`.  If both exist, merge them like
    // Spectre's "version 2 fixes": a service replaces a site of the same name
    // unless the site is known to be more recently used.
    let mut sites = take_object(root, "sites", "sites")?.unwrap_or_default();
    if let Some(services) = take_object(root, "services", "services")? {
        if services.len() > limits::MAX_SITES {
            return Err(err(ParseErrorKind::TooMany { what: "sites", limit: limits::MAX_SITES }, "services"));
        }
        let used = |v: Option<&Value>| {
            v.and_then(|v| v.get("last_used")).and_then(Value::as_str).and_then(Timestamp::parse_rfc3339)
        };
        for (name, service) in services {
            let keep_site = matches!((used(sites.get(&name)), used(Some(&service))), (Some(a), Some(b)) if a >= b);
            if !keep_site {
                sites.insert(name, service);
            }
        }
    }
    if sites.len() > limits::MAX_SITES {
        return Err(err(ParseErrorKind::TooMany { what: "sites", limit: limits::MAX_SITES }, "sites"));
    }
    for (index, (name, value)) in sites.into_iter().enumerate() {
        let loc = |field: &str| format!("site #{} {field}", index + 1);
        validate_site_name(&name).map_err(|_| err(ParseErrorKind::InvalidValue, loc("name")))?;
        let mut s = match value {
            Value::Object(m) => m,
            _ => return Err(err(ParseErrorKind::InvalidValue, loc(""))),
        };
        let counter = take_u32(&mut s, "counter", &loc("counter"))?.unwrap_or(COUNTER_DEFAULT);
        let algorithm = match take_uint(&mut s, "algorithm", u64::MAX, &loc("algorithm"))? {
            Some(v) => parse_algorithm(v, None, &loc("algorithm"))?,
            None => user.algorithm,
        };
        let result_type = match take_uint(&mut s, "type", u64::MAX, &loc("type"))? {
            Some(v) => parse_type(v, None, &loc("type"))?,
            None => user.default_type,
        };
        let password = take_secret(&mut s, "password", &loc("password"))?;
        // Absent or 0 means "use the user's login" (since `f40a38d`); in format 1
        // so does 30 (see `v1_login_fix`).
        let login_type = match take_uint(&mut s, "login_type", u64::MAX, &loc("login_type"))? {
            None | Some(0) => None,
            Some(v) => Some(parse_type(v, None, &loc("login_type"))?)
                .filter(|t| !(v1_login_fix && *t == ResultType::DEFAULT_LOGIN)),
        };
        let login = take_secret(&mut s, "login_name", &loc("login_name"))?;
        let uses = take_u32(&mut s, "uses", &loc("uses"))?.unwrap_or(0);
        let last_used = match take_string(&mut s, "last_used", &loc("last_used"))? {
            Some(t) => parse_time(&t, None, &loc("last_used"))?,
            None => user.last_used,
        };
        let questions = take_object(&mut s, "questions", &loc("questions"))?.unwrap_or_default();
        if questions.len() > limits::MAX_QUESTIONS {
            return Err(err(
                ParseErrorKind::TooMany { what: "questions", limit: limits::MAX_QUESTIONS },
                loc("questions"),
            ));
        }
        let ext_mpw = s.remove(EXT);
        // Spectre keeps the URL in `_ext_spectre` (left in place as an unknown member).
        let url = match ext_url(ext_mpw.as_ref(), &loc("url"))? {
            Some(u) => Some(u),
            None => ext_url(s.get(EXT_SPECTRE), &loc("url"))?,
        };

        let mut site = Site::new(&name, algorithm, result_type);
        site.counter = counter;
        site.login_type = login_type;
        site.uses = uses;
        site.last_used = last_used;
        site.url = url;
        site.ext_mpw = ext_mpw;

        for (q_index, (keyword, qv)) in questions.into_iter().enumerate() {
            let qloc = |field: &str| format!("site #{} question #{} {field}", index + 1, q_index + 1);
            validate_keyword(&keyword).map_err(|_| err(ParseErrorKind::InvalidValue, qloc("keyword")))?;
            let mut q = match qv {
                Value::Object(m) => m,
                Value::Null => Map::new(),
                _ => return Err(err(ParseErrorKind::InvalidValue, qloc(""))),
            };
            let mut question = Question::new(&keyword);
            if let Some(v) = take_uint(&mut q, "type", u64::MAX, &qloc("type"))? {
                question.result_type = parse_type(v, None, &qloc("type"))?;
            }
            match take_secret(&mut q, "answer", &qloc("answer"))? {
                Some(v) if !redacted => {
                    if question.result_type.is_stateful() {
                        pending.push(Pending { slot: Slot::Answer(name.clone(), keyword.clone()), value: v });
                    }
                }
                Some(v) => question.state = Some(v.to_string()),
                None => {}
            }
            question.extra = q;
            site.questions.insert(keyword, question);
        }

        match password {
            Some(v) if !redacted => {
                if result_type.is_stateful() {
                    pending.push(Pending { slot: Slot::SitePassword(name.clone()), value: v });
                }
            }
            Some(v) => site.result_state = Some(v.to_string()),
            None => {}
        }
        match login {
            Some(v) if !redacted => {
                if login_type.is_some_and(ResultType::is_stateful) {
                    pending.push(Pending { slot: Slot::SiteLogin(name.clone()), value: v });
                }
            }
            Some(v) => site.login_state = Some(v.to_string()),
            None => {}
        }
        site.extra = s;
        user.sites.insert(name, site);
    }

    user.extras = UserExtras { root: std::mem::take(root), export, user: u, user_ext_mpw: user_ext };
    let summary = UserSummary {
        format: super::Format::Json,
        format_version,
        export_date,
        redacted,
        full_name: user.full_name.clone(),
        avatar: user.avatar,
        identicon: user.identicon.clone(),
        key_id: user.key_id.clone(),
        algorithm: user.algorithm,
        last_used: user.last_used,
        preferences: user.preferences.clone(),
        site_count: user.sites.len(),
        second_factor: user.second_factor.clone(),
    };
    Ok((summary, user, pending))
}

// ----------------------------------------------------------------------- write

/// Set a boolean preference: written when true, or when the key already existed.
fn put_flag(m: &mut JsonMap, key: &str, value: bool) {
    if value || m.contains_key(key) {
        m.insert(key.to_owned(), Value::Bool(value));
    }
}

fn user_ext_mpw(user: &User) -> Option<Value> {
    let original = user.extras.user_ext_mpw.as_ref();
    let mut m = match original {
        Some(Value::Object(m)) => m.clone(),
        _ => Map::new(),
    };
    let p = &user.preferences;
    put_flag(&mut m, "maskPasswords", p.mask_passwords);
    put_flag(&mut m, "biometricLock", p.biometric_lock);
    match p.autofill {
        Some(b) => m.insert("autofill".into(), Value::Bool(b)),
        None => m.remove("autofill"),
    };
    match &p.attacker {
        Some(a) => m.insert("attacker".into(), Value::String(a.clone())),
        None => m.remove("attacker"),
    };
    crate::second_factor::write_member(&user.second_factor, &mut m);
    match original {
        Some(v) if !v.is_object() && m.is_empty() => Some(v.clone()),
        _ if m.is_empty() => None,
        _ => Some(Value::Object(m)),
    }
}

fn site_ext_mpw(site: &Site) -> Option<Value> {
    let original = site.ext_mpw.as_ref();
    let mut m = match original {
        Some(Value::Object(m)) => m.clone(),
        _ => Map::new(),
    };
    match &site.url {
        Some(u) => m.insert("url".into(), Value::String(u.clone())),
        None => m.remove("url"),
    };
    match original {
        Some(v) if !v.is_object() && m.is_empty() => Some(v.clone()),
        _ if m.is_empty() => None,
        _ => Some(Value::Object(m)),
    }
}

/// Append `extra` members that do not collide with ours.
fn extend(m: &mut JsonMap, extra: &JsonMap) {
    for (k, v) in extra {
        if !m.contains_key(k) {
            m.insert(k.clone(), v.clone());
        }
    }
}

fn secret(v: &Option<Zeroizing<String>>) -> Option<Value> {
    v.as_ref().map(|s| Value::String(s.to_string()))
}

pub(super) fn write(user: &User, out: &Outputs, redacted: bool, now: Timestamp) -> Result<Zeroizing<String>> {
    let mut root = Map::new();

    let mut export = Map::new();
    export.insert("date".into(), Value::String(file_time(now)));
    export.insert("redacted".into(), Value::Bool(redacted));
    export.insert("format".into(), Value::from(1));
    extend(&mut export, &user.extras.export);
    root.insert("export".into(), Value::Object(export));

    let mut u = Map::new();
    u.insert("avatar".into(), Value::from(user.avatar));
    u.insert("full_name".into(), Value::String(user.full_name.clone()));
    if let Some(i) = &user.identicon {
        u.insert("identicon".into(), Value::String(i.encode()));
    }
    u.insert("algorithm".into(), Value::from(user.algorithm.as_u32()));
    if let Some(id) = &user.key_id {
        u.insert("key_id".into(), Value::String(id.as_str().to_owned()));
    }
    u.insert("default_type".into(), Value::from(user.default_type.as_u32()));
    u.insert("last_used".into(), Value::String(file_time(user.last_used)));
    // Not in the reference C writer; written by the newer library the original
    // app links.  Only written when they carry information.
    if user.login_type != ResultType::DEFAULT_LOGIN || out.user_login.is_some() {
        u.insert("login_type".into(), Value::from(user.login_type.as_u32()));
    }
    if let Some(v) = secret(&out.user_login) {
        u.insert("login_name".into(), v);
    }
    if let Some(ext) = user_ext_mpw(user) {
        u.insert(EXT.into(), ext);
    }
    extend(&mut u, &user.extras.user);
    root.insert("user".into(), Value::Object(u));

    let mut sites = Map::new();
    for (name, site) in &user.sites {
        let so = out.sites.get(name);
        let mut s = Map::new();
        s.insert("counter".into(), Value::from(site.counter));
        s.insert("algorithm".into(), Value::from(site.algorithm.as_u32()));
        s.insert("type".into(), Value::from(site.result_type.as_u32()));
        if let Some(v) = so.and_then(|so| secret(&so.password)) {
            s.insert("password".into(), v);
        }
        // "Use the user's login" is written as 30, exactly like the classic
        // writer: classic readers reject 0 and read 30 as the generated name;
        // every newer reader turns 30 in a format-1 file into "use the user's
        // login".  (So an explicit generated-name login cannot be told apart
        // from "use the user's login" in this format; see `Site::set_generated_login`.)
        let login_type = site.login_type.unwrap_or(ResultType::DEFAULT_LOGIN);
        s.insert("login_type".into(), Value::from(login_type.as_u32()));
        if let Some(v) = so.and_then(|so| secret(&so.login)) {
            s.insert("login_name".into(), v);
        }
        s.insert("uses".into(), Value::from(site.uses));
        s.insert("last_used".into(), Value::String(file_time(site.last_used)));
        if !site.questions.is_empty() {
            let mut qs = Map::new();
            for (kw, q) in &site.questions {
                let mut qm = Map::new();
                qm.insert("type".into(), Value::from(q.result_type.as_u32()));
                if let Some(v) = so.and_then(|so| so.answers.get(kw)).and_then(secret) {
                    qm.insert("answer".into(), v);
                }
                extend(&mut qm, &q.extra);
                qs.insert(kw.clone(), Value::Object(qm));
            }
            s.insert("questions".into(), Value::Object(qs));
        }
        if let Some(ext) = site_ext_mpw(site) {
            s.insert(EXT.into(), ext);
        }
        // Keep a Spectre `_ext_spectre.url` in step with ours.
        if let Some(Value::Object(spectre)) = site.extra.get(EXT_SPECTRE) {
            let mut spectre = spectre.clone();
            match &site.url {
                Some(u) => spectre.insert("url".into(), Value::String(u.clone())),
                None => spectre.remove("url"),
            };
            s.insert(EXT_SPECTRE.into(), Value::Object(spectre));
        }
        extend(&mut s, &site.extra);
        sites.insert(name.clone(), Value::Object(s));
    }
    root.insert("sites".into(), Value::Object(sites));
    extend(&mut root, &user.extras.root);

    let mut value = Value::Object(root);
    // Reserve up front so the buffer holding clear-text values is not
    // reallocated (which would leave unwiped copies behind).
    let mut buf = Zeroizing::new(Vec::with_capacity(super::size_hint(user, out) * 2));
    let written = serde_json::to_writer_pretty(&mut *buf, &value);
    wipe(&mut value);
    written.map_err(|e| std::io::Error::other(e.to_string()))?;
    let text = String::from_utf8(std::mem::take(&mut *buf)).map_err(|e| std::io::Error::other(e.utf8_error()))?;
    Ok(Zeroizing::new(text))
}
