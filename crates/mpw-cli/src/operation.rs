//! The operation on the user: `cli_user`, `cli_site`, `cli_question`,
//! `cli_operation`, the command-line overrides, `cli_mpw` and `cli_save` of
//! the reference, on top of `mpw-model`.

use crate::input;
use crate::log::{dbg_log, inf, wrn, Fatal};
use crate::store::{self, Location};
use crate::{EX_DATAERR, EX_SOFTWARE};
use mpw_core::{AlgorithmVersion, Counter, KeyPurpose, ResultType, COUNTER_INITIAL};
use mpw_model::{Error as ModelError, ExportMode, User, UserFile, UserKeys};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Everything the command line contributes, already validated.
pub struct Request {
    pub full_name: String,
    pub site_name: String,
    pub purpose: KeyPurpose,
    pub key_context: Option<String>,
    pub result_type: Option<ResultType>,
    pub counter: Option<Counter>,
    pub algorithm: Option<AlgorithmVersion>,
    pub result_param: Option<Zeroizing<String>>,
    pub allow_password_update: bool,
    pub files: store::Options,
}

/// What `cli_mpw` prints.
pub struct Outcome {
    pub purpose_result: &'static str,
    pub result: Zeroizing<String>,
}

/// A loaded (or new) user plus where it came from.
struct Session {
    user: User,
    location: Option<Location>,
    loaded_from: Option<PathBuf>,
    /// The loaded file was redacted (new users count as redacted).
    file_redacted: bool,
}

fn data_err(context: &str) -> impl Fn(ModelError) -> Fatal + '_ {
    move |e| Fatal::new(EX_DATAERR, format!("{context}: {e}"))
}

/// Run the operation, then save.  `on_result` is called with the result
/// before the user file is written (the reference prints first, then saves).
pub fn run(
    req: Request,
    keys: &mut UserKeys,
    on_result: impl FnOnce(&Outcome) -> Result<(), Fatal>,
) -> Result<(), Fatal> {
    let mut session = open_user(&req, keys)?;
    let user = &mut session.user;
    let site_name = req.site_name.as_str();

    // cli_site / cli_question: create what the file does not have yet.
    if user.site(site_name).is_none() {
        user.add_site(site_name)
            .map_err(data_err("Couldn't add the site"))?;
    }
    let keyword = req.key_context.clone().unwrap_or_default();
    if req.purpose == KeyPurpose::Recovery {
        let site = user
            .site_mut(site_name)
            .ok_or_else(|| Fatal::new(EX_SOFTWARE, "The site disappeared."))?;
        if site.question(&keyword).is_none() {
            site.add_question(&keyword)
                .map_err(data_err("Couldn't add the question"))?;
        }
    }

    // cli_operation: the stored settings.
    let site = user
        .site(site_name)
        .ok_or_else(|| Fatal::new(EX_SOFTWARE, "The site disappeared."))?;
    let (purpose_result, mut result_type, mut counter) = match req.purpose {
        KeyPurpose::Authentication => ("password", site.result_type, site.counter),
        KeyPurpose::Identification => (
            "login",
            site.login_type().unwrap_or(user.login_type()),
            COUNTER_INITIAL,
        ),
        KeyPurpose::Recovery => (
            "answer",
            site.question(&keyword)
                .map_or(ResultType::DEFAULT_ANSWER, |q| q.result_type),
            COUNTER_INITIAL,
        ),
    };

    // cli_resultType: persisted unless it is an "alternative" type (a derived key).
    if let Some(t) = req.result_type {
        result_type = t;
        if !t.is_alternative() {
            set_type(user, site_name, req.purpose, &keyword, t)?;
        }
    }
    // cli_siteCounter: only the password counter is persisted / used.
    if let Some(c) = req.counter {
        match req.purpose {
            KeyPurpose::Authentication => {
                counter = c;
                if let Some(site) = user.site_mut(site_name) {
                    site.counter = c;
                }
            }
            _ => wrn!(
                "The counter is ignored for {} (like the reference, it is always 1).",
                req.purpose
            ),
        }
    }
    // cli_algorithmVersion: persisted; stored values are re-encrypted.
    if let Some(a) = req.algorithm {
        user.set_site_algorithm(keys, site_name, a)
            .map_err(data_err("Couldn't change the site's algorithm"))?;
    }
    let algorithm = user
        .site(site_name)
        .map_or(AlgorithmVersion::CURRENT, |s| s.algorithm());

    dbg_log!("-----------------");
    dbg_log!("fullName         : {}", req.full_name);
    if let Some(path) = &session.loaded_from {
        dbg_log!("sitesPath        : {}", path.display());
    }
    dbg_log!(
        "sitesFormat      : {:?}{}",
        req.files.format,
        if req.files.format_fixed {
            " (fixed)"
        } else {
            ""
        }
    );
    dbg_log!("siteName         : {site_name}");
    dbg_log!("siteCounter      : {counter}");
    dbg_log!(
        "resultType       : {} ({})",
        result_type.short_name(),
        result_type.as_u32()
    );
    dbg_log!(
        "resultParam      : {}",
        if req.result_param.is_some() {
            "(given)"
        } else {
            "(none)"
        }
    );
    dbg_log!("keyPurpose       : {} ({})", req.purpose, req.purpose as u8);
    dbg_log!(
        "keyContext       : {}",
        req.key_context.as_deref().unwrap_or("(none)")
    );
    dbg_log!("algorithmVersion : {}", algorithm.as_u32());
    dbg_log!("-----------------");

    // A value to store for a stateful type: -P (warned), `-P -` or a prompt.
    let mut result_param = req.result_param;
    if result_type.is_stateful() {
        let value = match result_param.take() {
            Some(p) if p.as_str() == "-" => {
                Some(input::get_secret_value(purpose_noun(req.purpose))?)
            }
            Some(p) => {
                wrn!(
                    "Warning: a {} given with -P is visible to other users (ps) and in shell history; \
                     omit -P (or use -P -) to be prompted instead.",
                    purpose_noun(req.purpose)
                );
                Some(p)
            }
            None if !has_stored_value(user, site_name, req.purpose, &keyword) => {
                Some(input::get_secret_value(purpose_noun(req.purpose))?)
            }
            None => None,
        };
        if let Some(value) = value {
            store_value(
                user,
                keys,
                site_name,
                req.purpose,
                &keyword,
                result_type,
                &value,
            )?;
            // The reference shows the new (encrypted) state.
            let state = keys
                .key(algorithm)
                .map_err(data_err("Couldn't derive master key"))?
                .site_state(
                    site_name,
                    counter,
                    req.purpose,
                    context_for(req.purpose, &keyword, req.key_context.as_deref()),
                    result_type,
                    &value,
                )
                .map_err(|e| {
                    Fatal::new(EX_SOFTWARE, format!("Couldn't encrypt site result: {e}"))
                })?;
            inf!("(state) {state} => ");
            if result_type.is_device_private() && session.location.is_some() {
                wrn!("Note: device-private values are never written to user files; it will not be remembered.");
            }
        }
    }

    // cli_mpw: generate the result.
    let result = result(
        user,
        keys,
        site_name,
        req.purpose,
        &keyword,
        req.key_context.as_deref(),
        result_type,
        counter,
        algorithm,
        result_param.as_ref().map(|p| p.as_str()),
    )?;
    on_result(&Outcome {
        purpose_result,
        result,
    })?;

    // Usage metadata, then cli_save.
    user.use_site(site_name)
        .map_err(data_err("Couldn't record the use of the site"))?;
    save(&mut session, keys, &req.files)
}

fn purpose_noun(purpose: KeyPurpose) -> &'static str {
    match purpose {
        KeyPurpose::Authentication => "personal password",
        KeyPurpose::Identification => "login name",
        KeyPurpose::Recovery => "answer",
    }
}

/// The key context the reference passes to the algorithm.
fn context_for<'a>(
    purpose: KeyPurpose,
    keyword: &'a str,
    context: Option<&'a str>,
) -> Option<&'a str> {
    match purpose {
        KeyPurpose::Recovery => Some(keyword).filter(|k| !k.is_empty()),
        _ => context.filter(|c| !c.is_empty()),
    }
}

// ----------------------------------------------------------------- cli_user

fn open_user(req: &Request, keys: &mut UserKeys) -> Result<Session, Fatal> {
    let location = if req.files.stateless() {
        None
    } else {
        match store::default_dir() {
            Some(dir) => Some(Location::new(dir, &req.full_name)?),
            None => {
                wrn!("HOME is not set; working without a user file.");
                None
            }
        }
    };
    let found = match &location {
        Some(loc) => loc.find(&req.files)?,
        None => None,
    };

    let Some(path) = found else {
        // No user file: a new user (it adopts this master key).
        let mut user = User::new(&req.full_name).map_err(data_err("Invalid full name"))?;
        user.authenticate(keys)
            .map_err(data_err("Couldn't derive master key"))?;
        return Ok(Session {
            user,
            location,
            loaded_from: None,
            file_redacted: true,
        });
    };

    let file = mpw_model::read_user_file(&path).map_err(|e| {
        Fatal::new(
            EX_DATAERR,
            format!(
                "Couldn't parse configuration file:\n  {}: {e}",
                path.display()
            ),
        )
    })?;
    if file.summary().full_name != req.full_name {
        return Err(Fatal::new(
            EX_DATAERR,
            format!(
                "The configuration file {} belongs to a different full name; not using it.",
                path.display()
            ),
        ));
    }
    let file_redacted = file.summary().redacted;
    let user = match file.load(keys) {
        Ok(user) => user,
        Err(ModelError::WrongMasterPassword) if req.allow_password_update => {
            update_master_password(&file, keys, &path)?
        }
        Err(ModelError::WrongMasterPassword) => {
            return Err(incorrect_password(&path));
        }
        Err(e) => {
            return Err(Fatal::new(
                EX_DATAERR,
                format!(
                    "Couldn't load configuration file:\n  {}: {e}",
                    path.display()
                ),
            ))
        }
    };
    Ok(Session {
        user,
        location,
        loaded_from: Some(path),
        file_redacted,
    })
}

fn incorrect_password(path: &Path) -> Fatal {
    Fatal::new(
        EX_DATAERR,
        format!(
            "Incorrect master password according to configuration:\n  {}: incorrect master password",
            path.display()
        ),
    )
}

/// `-U` with a master password that does not match the file: confirm the old
/// master password, then move the user to the new one.
fn update_master_password(
    file: &UserFile,
    new_keys: &mut UserKeys,
    path: &Path,
) -> Result<User, Fatal> {
    inf!("Given master password does not match configuration.");
    inf!("To update the configuration with this new master password, first confirm the old master password.");
    let name = new_keys.full_name().to_owned();
    for _ in 0..3 {
        let Some(old) = input::getpass("Old master password: ")?.filter(|p| !p.is_empty()) else {
            break;
        };
        let mut old_keys = UserKeys::from_password(&name, &old);
        drop(old);
        match file.load(&mut old_keys) {
            Ok(old_user) => return rekey(&old_user, &mut old_keys, new_keys),
            Err(ModelError::WrongMasterPassword) => inf!("Incorrect old master password."),
            Err(e) => return Err(data_err("Couldn't load the configuration")(e)),
        }
    }
    Err(incorrect_password(path))
}

/// Build a copy of `old` keyed to `new_keys`, re-encrypting every stored value.
///
/// mpw-model has no "change master password" operation, so this is assembled
/// from public pieces: a new user adopting the new key, the old user's
/// settings, and `merge` for the sites (which re-encrypts).
fn rekey(old: &User, old_keys: &mut UserKeys, new_keys: &mut UserKeys) -> Result<User, Fatal> {
    let err = data_err("Couldn't move the user to the new master password");
    let mut user = User::new(old.full_name()).map_err(&err)?;
    user.authenticate(new_keys).map_err(&err)?;
    user.set_algorithm(new_keys, old.algorithm())
        .map_err(&err)?;
    user.avatar = old.avatar;
    user.default_type = old.default_type;
    user.preferences = old.preferences.clone();
    let login_type = old.login_type();
    if login_type.is_stateful() {
        if old.has_login_state() {
            let login = old.user_login(old_keys).map_err(&err)?;
            user.set_user_login_name(new_keys, &login).map_err(&err)?;
        }
    } else {
        user.set_generated_login(login_type).map_err(&err)?;
    }
    let summary = mpw_model::merge(&mut user, new_keys, old, old_keys).map_err(&err)?;
    if !summary.skipped.is_empty() {
        return Err(Fatal::new(
            EX_DATAERR,
            format!(
                "Couldn't re-encrypt the stored values of {} site(s); nothing was changed.",
                summary.skipped.len()
            ),
        ));
    }
    user.last_used = old.last_used;
    inf!("The configuration now uses the new master password.");
    Ok(user)
}

// ----------------------------------------------------------- site settings

fn set_type(
    user: &mut User,
    site_name: &str,
    purpose: KeyPurpose,
    keyword: &str,
    t: ResultType,
) -> Result<(), Fatal> {
    let site = user
        .site_mut(site_name)
        .ok_or_else(|| Fatal::new(EX_SOFTWARE, "The site disappeared."))?;
    match purpose {
        KeyPurpose::Authentication => site.result_type = t,
        // Stateful login types are set together with their value (store_value).
        KeyPurpose::Identification if t.is_template() => site
            .set_generated_login(t)
            .map_err(data_err("Couldn't set the login type"))?,
        KeyPurpose::Identification => {}
        KeyPurpose::Recovery => {
            if let Some(q) = site.question_mut(keyword) {
                q.result_type = t;
            }
        }
    }
    Ok(())
}

fn has_stored_value(user: &User, site_name: &str, purpose: KeyPurpose, keyword: &str) -> bool {
    let Some(site) = user.site(site_name) else {
        return false;
    };
    match purpose {
        KeyPurpose::Authentication => site.result_type.is_stateful() && site.has_password_state(),
        KeyPurpose::Identification => match site.login_type() {
            Some(t) => t.is_stateful() && site.has_login_state(),
            None => user.login_type().is_stateful() && user.has_login_state(),
        },
        KeyPurpose::Recovery => site
            .question(keyword)
            .is_some_and(|q| q.result_type.is_stateful() && q.has_answer_state()),
    }
}

fn store_value(
    user: &mut User,
    keys: &mut UserKeys,
    site_name: &str,
    purpose: KeyPurpose,
    keyword: &str,
    result_type: ResultType,
    value: &str,
) -> Result<(), Fatal> {
    let err = data_err("Couldn't store the value");
    match purpose {
        KeyPurpose::Authentication => user
            .set_site_password(keys, site_name, result_type, value)
            .map_err(err),
        _ if result_type != ResultType::StatefulPersonal => Err(Fatal::new(
            EX_DATAERR,
            format!(
                "Only personal ({}) values can be stored for {}.",
                ResultType::StatefulPersonal.abbreviation(),
                purpose_noun(purpose)
            ),
        )),
        KeyPurpose::Identification => user
            .set_site_login_name(keys, site_name, value)
            .map_err(err),
        KeyPurpose::Recovery => user
            .set_answer(keys, site_name, keyword, value)
            .map_err(err),
    }
}

// ------------------------------------------------------------------ cli_mpw

#[allow(clippy::too_many_arguments)]
fn result(
    user: &User,
    keys: &mut UserKeys,
    site_name: &str,
    purpose: KeyPurpose,
    keyword: &str,
    key_context: Option<&str>,
    result_type: ResultType,
    counter: Counter,
    algorithm: AlgorithmVersion,
    result_param: Option<&str>,
) -> Result<Zeroizing<String>, Fatal> {
    let failed = |e: String| Fatal::new(EX_SOFTWARE, format!("Couldn't generate site result: {e}"));

    // Results the model does not model: derived keys (not persisted), and
    // template results with a key context for passwords/logins (the reference
    // passes -C to the algorithm for every purpose; the model only for
    // answers).  Computed with the site's algorithm, counter and the
    // authenticated key.
    let context = context_for(purpose, keyword, key_context);
    let direct = result_type.is_derive()
        || (purpose != KeyPurpose::Recovery && context.is_some() && result_type.is_template());
    if direct {
        return keys
            .key(algorithm)
            .map_err(|e| failed(e.to_string()))?
            .site_result(
                site_name,
                counter,
                purpose,
                context,
                result_type,
                result_param,
            )
            .map_err(|e| failed(e.to_string()));
    }

    match purpose {
        KeyPurpose::Authentication => user.site_password(keys, site_name),
        KeyPurpose::Identification => user.site_login(keys, site_name),
        KeyPurpose::Recovery => user.site_answer(keys, site_name, keyword),
    }
    .map_err(|e| failed(e.to_string()))
}

// ----------------------------------------------------------------- cli_save

fn save(session: &mut Session, keys: &mut UserKeys, files: &store::Options) -> Result<(), Fatal> {
    let Some(location) = &session.location else {
        return Ok(());
    };
    let format = files.save_format();
    if format == store::Format::None {
        return Ok(());
    }
    let revealed = files.redacted == Some(false);
    let path_hint = location.path(format.extensions().first().copied().unwrap_or(""));
    if revealed {
        wrn!(
            "Warning: writing {} with passwords in clear text (-R 0).",
            path_hint.display()
        );
    } else if !session.file_redacted && files.redacted.is_none() {
        wrn!("The configuration file was not redacted; saving it redacted (use -R 0 to keep clear-text passwords).");
    }
    let mode = if revealed {
        ExportMode::Revealed(keys)
    } else {
        ExportMode::Redacted
    };
    location.save(&session.user, format, mode)?;
    Ok(())
}
