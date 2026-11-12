//! The operation on the user: `cli_user`, `cli_site`, `cli_question`,
//! `cli_operation`, the command-line overrides, `cli_mpw` and `cli_save` of
//! the reference, on top of `mpw-model`.

use crate::input;
use crate::log::{dbg_log, inf, wrn, Fatal};
use crate::second_factor;
use crate::store::{self, Location};
use crate::{EX_DATAERR, EX_SOFTWARE, EX_USAGE};
use mpw_core::{AlgorithmVersion, Counter, KeyPurpose, ResultType, COUNTER_INITIAL};
use mpw_model::{Error as ModelError, ExportMode, ResultRequest, User, UserFile, UserKeys};
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
    /// `-k fd`: the recovery code of a second-factor user.
    pub recovery_code_fd: Option<String>,
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
    typed_password: Zeroizing<String>,
    on_result: impl FnOnce(&Outcome) -> Result<(), Fatal>,
) -> Result<(), Fatal> {
    let (mut session, mut keys) = open_user(&req, &typed_password)?;
    drop(typed_password);
    let keys = &mut keys;
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
            Some(p) if p.as_str() == "-" => Some(input::get_secret_value(value_noun(
                req.purpose,
                result_type,
            ))?),
            Some(p) => {
                wrn!(
                    "Warning: a {} given with -P is visible to other users (ps) and in shell history; \
                     omit -P (or use -P -) to be prompted instead.",
                    value_noun(req.purpose, result_type)
                );
                Some(p)
            }
            None if !has_stored_value(user, site_name, req.purpose, &keyword) => Some(
                input::get_secret_value(value_noun(req.purpose, result_type))?,
            ),
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
            if let Some(state) = stored_state(user, site_name, req.purpose, &keyword) {
                inf!("(state) {state} => ");
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

/// What the stored value is called in prompts and messages.
fn value_noun(purpose: KeyPurpose, result_type: ResultType) -> &'static str {
    let device = result_type.is_device_private();
    match purpose {
        KeyPurpose::Authentication if device => "device-private password",
        KeyPurpose::Authentication => "personal password",
        KeyPurpose::Identification if device => "device-private login name",
        KeyPurpose::Identification => "login name",
        KeyPurpose::Recovery if device => "device-private answer",
        KeyPurpose::Recovery => "answer",
    }
}

// ----------------------------------------------------------------- cli_user

fn open_user(req: &Request, typed: &Zeroizing<String>) -> Result<(Session, UserKeys), Fatal> {
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
    // -F flat reads only flat files; do not let it quietly start a separate
    // flat user next to a JSON user that has a second factor.
    if let (Some(loc), store::Format::Flat) = (&location, req.files.save_format()) {
        let json = store::Options {
            format: store::Format::Json,
            format_fixed: true,
            redacted: None,
        };
        if let Some(path) = loc.find(&json)? {
            let blocked = mpw_model::read_user_file(&path).is_ok_and(|f| {
                f.summary().full_name == req.full_name && f.summary().second_factor.is_enabled()
            });
            if blocked {
                return Err(flat_refused());
            }
        }
    }

    let Some(path) = found else {
        // No user file: a new user (it adopts this master key).  A
        // second-factor user without its file can still use the combined
        // `password CODE` form: it is just a master password then.
        let mut keys = UserKeys::from_password(&req.full_name, typed);
        let mut user = User::new(&req.full_name).map_err(data_err("Invalid full name"))?;
        user.authenticate(&mut keys)
            .map_err(data_err("Couldn't derive master key"))?;
        let session = Session {
            user,
            location,
            loaded_from: None,
            file_redacted: true,
        };
        return Ok((session, keys));
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
    let status = &file.summary().second_factor;
    let has_second_factor = status.is_enabled();
    if has_second_factor && req.files.save_format() == store::Format::Flat {
        // Checked before anything is derived or written.
        return Err(flat_refused());
    }

    // The key holder: the typed password, plus the recovery code for a
    // second-factor user (checked before any key derivation).
    let unlock = if has_second_factor {
        Some(second_factor::unlock(
            typed,
            status,
            req.recovery_code_fd.as_deref(),
        )?)
    } else {
        if req.recovery_code_fd.is_some() {
            wrn!("This user has no second factor; -k is ignored.");
        }
        None
    };
    let mut keys = match &unlock {
        Some(u) => UserKeys::from_password_and_secret(&req.full_name, &u.typed, &u.secret),
        None => UserKeys::from_password(&req.full_name, typed),
    };

    let user = match file.load(&mut keys) {
        Ok(user) => user,
        Err(ModelError::WrongMasterPassword) if req.allow_password_update => match &unlock {
            Some(u) => update_second_factor_password(&file, &mut keys, u, &path)?,
            None => update_master_password(&file, &mut keys, &path)?,
        },
        Err(ModelError::WrongMasterPassword) => {
            return Err(incorrect_password(&path, has_second_factor));
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
    let session = Session {
        user,
        location,
        loaded_from: Some(path),
        file_redacted,
    };
    Ok((session, keys))
}

fn flat_refused() -> Fatal {
    Fatal::new(
        EX_USAGE,
        "This user has a second factor, which the flat format cannot store: saving it as flat \
         would lose the smart-card enrolment.  Use -F json (or -f).",
    )
}

fn incorrect_password(path: &Path, second_factor: bool) -> Fatal {
    let mut message = format!(
        "Incorrect master password according to configuration:\n  {}: incorrect master password",
        path.display()
    );
    if second_factor {
        message.push_str(&format!(
            "\nThis user has a second factor and the recovery code was accepted, so the typed \
             master password (without the code) is what is wrong.\nTo supply the code: {}.",
            second_factor::HOW
        ));
    }
    Fatal::new(EX_DATAERR, message)
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
            Ok(old_user) => return rekey(old_user, &mut old_keys, new_keys),
            Err(ModelError::WrongMasterPassword) => inf!("Incorrect old master password."),
            Err(e) => return Err(data_err("Couldn't load the configuration")(e)),
        }
    }
    Err(incorrect_password(path, false))
}

/// Move the user loaded with `old_keys` to `new_keys` (all or nothing).
fn rekey(mut user: User, old_keys: &mut UserKeys, new_keys: &mut UserKeys) -> Result<User, Fatal> {
    user.change_master_password(old_keys, new_keys)
        .map_err(|e| {
            Fatal::new(
                EX_DATAERR,
                format!(
                    "Couldn't move the user to the new master password; nothing was changed: {e}"
                ),
            )
        })?;
    inf!("The configuration now uses the new master password.");
    Ok(user)
}

/// `-U` for a second-factor user: same recovery code, new typed password.
fn update_second_factor_password(
    file: &UserFile,
    keys: &mut UserKeys,
    unlock: &second_factor::Unlock,
    path: &Path,
) -> Result<User, Fatal> {
    inf!("Given master password does not match configuration.");
    inf!("To update the configuration with this new master password, first confirm the old master password (without the recovery code).");
    let name = keys.full_name().to_owned();
    for _ in 0..3 {
        let Some(old) = input::getpass("Old master password: ")?.filter(|p| !p.is_empty()) else {
            break;
        };
        let mut old_keys = UserKeys::from_password_and_secret(&name, &old, &unlock.secret);
        let mut user = match file.load(&mut old_keys) {
            Ok(user) => user,
            Err(ModelError::WrongMasterPassword) => {
                inf!("Incorrect old master password.");
                continue;
            }
            Err(e) => return Err(data_err("Couldn't load the configuration")(e)),
        };
        let new_keys = user
            .change_master_password_with_second_factor(&old, &unlock.typed, &unlock.secret)
            .map_err(|e| {
                Fatal::new(
                    EX_DATAERR,
                    format!("Couldn't move the user to the new master password; nothing was changed: {e}"),
                )
            })?;
        *keys = new_keys;
        inf!(
            "The configuration now uses the new master password (the second factor is unchanged)."
        );
        return Ok(user);
    }
    Err(incorrect_password(path, true))
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
        KeyPurpose::Identification if t.is_template() => site
            .set_generated_login(t)
            .map_err(data_err("Couldn't set the login type"))?,
        // Switch back to a login stored earlier; without one, the value is
        // asked for and stored together with the type (store_value).
        KeyPurpose::Identification => {
            if site.has_login_state() {
                site.use_stored_login(t)
                    .map_err(data_err("Couldn't set the login type"))?;
            }
        }
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
        KeyPurpose::Identification => user
            .store_site_login(keys, site_name, result_type, value)
            .map_err(err),
        KeyPurpose::Recovery => user
            .store_answer(keys, site_name, keyword, result_type, value)
            .map_err(err),
    }
}

/// The stored (encrypted) value for the purpose, as the model holds it.
fn stored_state<'u>(
    user: &'u User,
    site_name: &str,
    purpose: KeyPurpose,
    keyword: &str,
) -> Option<&'u str> {
    let site = user.site(site_name)?;
    match purpose {
        KeyPurpose::Authentication => site.password_state(),
        KeyPurpose::Identification => site.login_state(),
        KeyPurpose::Recovery => site.question(keyword)?.answer_state(),
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
    result_param: Option<&str>,
) -> Result<Zeroizing<String>, Fatal> {
    let failed = |e: String| Fatal::new(EX_SOFTWARE, format!("Couldn't generate site result: {e}"));

    // Every stored setting (type, counter, algorithm) has been applied to the
    // site already; only the per-call parts go into the request.  The
    // reference passes -C to the algorithm for every purpose.
    let mut request = match purpose {
        KeyPurpose::Recovery => ResultRequest::answer(keyword),
        _ => match key_context.filter(|c| !c.is_empty()) {
            Some(context) => ResultRequest::new(purpose).context(context),
            None => ResultRequest::new(purpose),
        },
    };
    if result_type.is_derive() {
        // A derived key is not persisted as the site's type (an "alternative").
        let param = result_param.ok_or_else(|| {
            failed("a key size is required (-P bits, e.g. -P 256; 0 for the default)".into())
        })?;
        let bits = param.trim().parse::<u32>().map_err(|_| {
            Fatal::new(
                EX_USAGE,
                format!("Invalid key size: {param} (expected a number of bits)"),
            )
        })?;
        request = request.derive_key(Some(bits).filter(|b| *b != 0));
    }
    user.site_result(keys, site_name, &request)
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
    if format == store::Format::Flat && session.user.second_factor_status().is_enabled() {
        return Err(flat_refused());
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
    if revealed && has_device_private(&session.user) {
        wrn!("Warning: device-private values are never written in clear text; they are not in this file and will be forgotten.");
    }
    if format == store::Format::Flat && flat_loses_data(&session.user) {
        wrn!("Warning: the flat format cannot store security questions, URLs or site login-name types; they are not saved.  Use -F json to keep them.");
    }
    // This is the device's own store: device-private values are kept (encrypted).
    let mode = if revealed {
        ExportMode::Revealed(keys)
    } else {
        ExportMode::Storage
    };
    location.save(&session.user, format, mode)?;
    Ok(())
}

fn has_device_private(user: &User) -> bool {
    user.login_type().is_device_private()
        || user.sites().any(|s| {
            s.result_type.is_device_private()
                || s.login_type().is_some_and(ResultType::is_device_private)
                || s.questions().any(|q| q.result_type.is_device_private())
        })
}

/// What `.mpsites` (flat format 1) cannot represent.
fn flat_loses_data(user: &User) -> bool {
    user.sites().any(|s| {
        s.questions().next().is_some()
            || s.url.is_some()
            || s.login_type().is_some_and(|t| {
                t != ResultType::DEFAULT_LOGIN && t != ResultType::StatefulPersonal
            })
    })
}
