//! Authentication and site operations (passwords, login names, answers).
//!
//! The defaulting rules follow `MPUser.result`, `MPService.result` and
//! `MPQuestion.result` of the original app (see the crate docs for the
//! deliberate deviations).

use crate::error::{Error, Result};
use crate::keys::UserKeys;
use crate::model::{validate_keyword, Question, Site, User};
use crate::time::Timestamp;
use mpw_core::{AlgorithmVersion, Counter, KeyPurpose, ResultType, COUNTER_INITIAL};
use zeroize::Zeroizing;

/// The outcome of a successful [`User::authenticate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authentication {
    /// The key matched the user's stored key ID.
    Verified,
    /// The user had no key ID (new or reset) and adopted this key's ID.
    Adopted,
}

/// Everything that identifies one stored value to the algorithm.
#[derive(Clone, Copy)]
pub(crate) struct StateCtx<'a> {
    pub name: &'a str,
    pub counter: Counter,
    pub purpose: KeyPurpose,
    pub context: Option<&'a str>,
    pub result_type: ResultType,
    pub algorithm: AlgorithmVersion,
}

impl StateCtx<'_> {
    pub fn generate(&self, keys: &mut UserKeys) -> Result<Zeroizing<String>> {
        let key = keys.key(self.algorithm)?;
        Ok(key.site_result(self.name, self.counter, self.purpose, self.context, self.result_type, None)?)
    }

    pub fn decrypt(&self, keys: &mut UserKeys, state: &str) -> Result<Zeroizing<String>> {
        let key = keys.key(self.algorithm)?;
        Ok(key.site_result(
            self.name,
            self.counter,
            self.purpose,
            self.context,
            self.result_type,
            Some(state),
        )?)
    }

    pub fn encrypt(&self, keys: &mut UserKeys, plaintext: &str) -> Result<String> {
        let key = keys.key(self.algorithm)?;
        Ok(key.site_state(self.name, self.counter, self.purpose, self.context, self.result_type, plaintext)?)
    }

    /// The result: generated for templates, decrypted for stateful types.
    pub fn result(&self, keys: &mut UserKeys, state: Option<&str>, what: &'static str) -> Result<Zeroizing<String>> {
        if self.result_type.is_stateful() {
            match state {
                Some(state) => self.decrypt(keys, state),
                None => Err(Error::NoStoredValue(what)),
            }
        } else {
            self.generate(keys)
        }
    }
}

fn context(keyword: &str) -> Option<&str> {
    // The reference treats an empty context as no context.
    (!keyword.is_empty()).then_some(keyword)
}

impl Site {
    pub(crate) fn password_ctx(&self) -> StateCtx<'_> {
        StateCtx {
            name: &self.name,
            counter: self.counter,
            purpose: KeyPurpose::Authentication,
            context: None,
            result_type: self.result_type,
            algorithm: self.algorithm,
        }
    }

    pub(crate) fn login_ctx(&self, result_type: ResultType) -> StateCtx<'_> {
        StateCtx {
            name: &self.name,
            counter: COUNTER_INITIAL,
            purpose: KeyPurpose::Identification,
            context: None,
            result_type,
            algorithm: self.algorithm,
        }
    }

    pub(crate) fn answer_ctx<'a>(&'a self, keyword: &'a str, result_type: ResultType) -> StateCtx<'a> {
        StateCtx {
            name: &self.name,
            counter: COUNTER_INITIAL,
            purpose: KeyPurpose::Recovery,
            context: context(keyword),
            result_type,
            algorithm: self.algorithm,
        }
    }
}

impl User {
    pub(crate) fn login_ctx(&self) -> StateCtx<'_> {
        StateCtx {
            name: &self.full_name,
            counter: COUNTER_INITIAL,
            purpose: KeyPurpose::Identification,
            context: None,
            result_type: self.login_type,
            algorithm: self.algorithm,
        }
    }

    // ------------------------------------------------------------ authentication

    /// Check `keys` against the user: derive the key for the user's algorithm
    /// and compare key IDs in constant time.  A user without a key ID (new or
    /// reset) adopts the key's ID.
    ///
    /// On success the key holder is marked as unlocking this user, and the
    /// identicon is refreshed if the holder knows the master password.  On
    /// failure nothing about the user changes.
    pub fn authenticate(&mut self, keys: &mut UserKeys) -> Result<Authentication> {
        if keys.full_name() != self.full_name {
            return Err(Error::UserMismatch);
        }
        let id = keys.key(self.algorithm)?.key_id();
        let outcome = match &self.key_id {
            Some(stored) if *stored == id => Authentication::Verified,
            Some(_) => return Err(Error::WrongMasterPassword),
            None => Authentication::Adopted,
        };
        if let Some(identicon) = keys.identicon() {
            self.identicon = Some(identicon);
        }
        self.key_id = Some(id.clone());
        keys.mark_authenticated(id);
        Ok(outcome)
    }

    /// Whether `keys` has been authenticated against this user (cheap; no scrypt).
    pub fn is_unlocked_by(&self, keys: &UserKeys) -> bool {
        keys.full_name() == self.full_name
            && matches!((keys.authenticated_id(), &self.key_id), (Some(a), Some(b)) if a == b)
    }

    pub(crate) fn check_unlocked(&self, keys: &UserKeys) -> Result<()> {
        if keys.full_name() != self.full_name {
            return Err(Error::UserMismatch);
        }
        if !self.is_unlocked_by(keys) {
            return Err(Error::NotAuthenticated);
        }
        Ok(())
    }

    /// Move the user's master key to another algorithm version.  The key ID is
    /// recomputed and a stored user login name re-encrypted.  Sites keep their
    /// own versions.
    pub fn set_algorithm(&mut self, keys: &mut UserKeys, algorithm: AlgorithmVersion) -> Result<()> {
        self.check_unlocked(keys)?;
        if algorithm == self.algorithm {
            return Ok(());
        }
        let dst = StateCtx { algorithm, ..self.login_ctx() };
        let new_state = reencrypt_state(self.login_ctx(), dst, self.login_state.as_deref(), keys, None)?;
        let id = keys.key(algorithm)?.key_id();
        self.algorithm = algorithm;
        self.login_state = new_state;
        self.key_id = Some(id.clone());
        keys.mark_authenticated(id);
        Ok(())
    }

    /// Move a site to another algorithm version.  Generated passwords change;
    /// stored values are re-encrypted.  Nothing changes if any stored value
    /// cannot be decrypted.
    pub fn set_site_algorithm(&mut self, keys: &mut UserKeys, site: &str, algorithm: AlgorithmVersion) -> Result<()> {
        self.check_unlocked(keys)?;
        let current = self.sites.get(site).ok_or(Error::NoSuchSite)?;
        if current.algorithm == algorithm {
            return Ok(());
        }
        let mut updated = current.clone();
        updated.algorithm = algorithm;
        reencrypt_site(current, keys, &mut updated, None)?;
        self.sites.insert(site.to_owned(), updated);
        Ok(())
    }

    // ------------------------------------------------------------------- results

    fn site_ref(&self, site: &str) -> Result<&Site> {
        self.sites.get(site).ok_or(Error::NoSuchSite)
    }

    /// The site's password: generated from its template, or its stored
    /// personal/device password decrypted.  Uses the site's counter, type and
    /// algorithm.
    pub fn site_password(&self, keys: &mut UserKeys, site: &str) -> Result<Zeroizing<String>> {
        self.check_unlocked(keys)?;
        let site = self.site_ref(site)?;
        site.password_ctx().result(keys, site.result_state.as_deref(), "site password")
    }

    /// The user-level login name (sites without their own login type use it).
    pub fn user_login(&self, keys: &mut UserKeys) -> Result<Zeroizing<String>> {
        self.check_unlocked(keys)?;
        self.login_ctx().result(keys, self.login_state.as_deref(), "login name")
    }

    /// The site's login name.  Counter 1 and the site's algorithm are used.
    ///
    /// * Site without a login type: the user's login — the user's stored login
    ///   name, or the user's login template applied to this site.
    /// * Stateful site login type: the stored value, falling back to the user's
    ///   stored login name if the site has none.
    /// * Template site login type: generated for this site.
    pub fn site_login(&self, keys: &mut UserKeys, site: &str) -> Result<Zeroizing<String>> {
        self.check_unlocked(keys)?;
        let site = self.site_ref(site)?;
        match site.login_type {
            Some(t) if t.is_stateful() => match &site.login_state {
                Some(state) => site.login_ctx(t).decrypt(keys, state),
                None => self.inherited_login(keys, site),
            },
            Some(t) => site.login_ctx(t).generate(keys),
            None => self.inherited_login(keys, site),
        }
    }

    fn inherited_login(&self, keys: &mut UserKeys, site: &Site) -> Result<Zeroizing<String>> {
        if self.login_type.is_stateful() {
            // Stored once for the user, encrypted with the user's key.
            self.login_ctx().result(keys, self.login_state.as_deref(), "login name")
        } else {
            site.login_ctx(self.login_type).generate(keys)
        }
    }

    /// The answer to a site's security question (`""`: the site-wide answer).
    /// Counter 1, the question's own type (a phrase unless set otherwise) and
    /// the site's algorithm are used.  A keyword without a stored question is
    /// answered with the default phrase type, like the reference CLI.
    pub fn site_answer(&self, keys: &mut UserKeys, site: &str, keyword: &str) -> Result<Zeroizing<String>> {
        self.check_unlocked(keys)?;
        let site = self.site_ref(site)?;
        let (result_type, state) = match site.questions.get(keyword) {
            Some(q) => (q.result_type, q.state.as_deref()),
            None => (ResultType::DEFAULT_ANSWER, None),
        };
        site.answer_ctx(keyword, result_type).result(keys, state, "answer")
    }

    // ------------------------------------------------------------ stored values

    /// Store a user-chosen password for the site, encrypted with the master key,
    /// and switch the site to `stateful_type` ([`ResultType::StatefulPersonal`],
    /// exported encrypted; or [`ResultType::StatefulDevice`], never exported).
    pub fn set_site_password(
        &mut self,
        keys: &mut UserKeys,
        site: &str,
        stateful_type: ResultType,
        password: &str,
    ) -> Result<()> {
        self.check_unlocked(keys)?;
        require_stateful(stateful_type)?;
        let s = self.site_ref(site)?;
        let ctx = StateCtx { result_type: stateful_type, ..s.password_ctx() };
        let state = ctx.encrypt(keys, password)?;
        if let Some(s) = self.sites.get_mut(site) {
            s.result_type = stateful_type;
            s.result_state = Some(state);
        }
        Ok(())
    }

    /// Store a personal login name for the site.
    pub fn set_site_login_name(&mut self, keys: &mut UserKeys, site: &str, login: &str) -> Result<()> {
        self.store_site_login(keys, site, ResultType::StatefulPersonal, login)
    }

    /// Store a login name for the site as `stateful_type`
    /// ([`ResultType::StatefulPersonal`] or [`ResultType::StatefulDevice`]).
    pub fn store_site_login(
        &mut self,
        keys: &mut UserKeys,
        site: &str,
        stateful_type: ResultType,
        login: &str,
    ) -> Result<()> {
        self.check_unlocked(keys)?;
        require_stateful(stateful_type)?;
        let state = self.site_ref(site)?.login_ctx(stateful_type).encrypt(keys, login)?;
        if let Some(s) = self.sites.get_mut(site) {
            s.login_type = Some(stateful_type);
            s.login_state = Some(state);
        }
        Ok(())
    }

    /// Store a personal login name for the user (used by sites without their own).
    pub fn set_user_login_name(&mut self, keys: &mut UserKeys, login: &str) -> Result<()> {
        self.store_user_login(keys, ResultType::StatefulPersonal, login)
    }

    /// Store the user-level login name as `stateful_type` (personal or device).
    pub fn store_user_login(&mut self, keys: &mut UserKeys, stateful_type: ResultType, login: &str) -> Result<()> {
        self.check_unlocked(keys)?;
        require_stateful(stateful_type)?;
        let ctx = StateCtx { result_type: stateful_type, ..self.login_ctx() };
        let state = ctx.encrypt(keys, login)?;
        self.login_type = stateful_type;
        self.login_state = Some(state);
        Ok(())
    }

    /// Switch the user's login back to a stored value of type `stateful_type`,
    /// reusing the login name stored earlier (see [`User::set_generated_login`]).
    pub fn use_stored_login(&mut self, stateful_type: ResultType) -> Result<()> {
        require_stateful(stateful_type)?;
        self.login_type = stateful_type;
        Ok(())
    }

    /// Generate the user's login name from a template again.  A stored login
    /// name is kept (unused) so that switching back restores it, like the reference.
    pub fn set_generated_login(&mut self, template: ResultType) -> Result<()> {
        if !template.is_template() {
            return Err(Error::NotStateful(template));
        }
        self.login_type = template;
        Ok(())
    }

    /// Store a personal answer for a site's question, creating the question if needed.
    pub fn set_answer(&mut self, keys: &mut UserKeys, site: &str, keyword: &str, answer: &str) -> Result<()> {
        self.store_answer(keys, site, keyword, ResultType::StatefulPersonal, answer)
    }

    /// Store an answer as `stateful_type` (personal or device), creating the
    /// question if needed.
    pub fn store_answer(
        &mut self,
        keys: &mut UserKeys,
        site: &str,
        keyword: &str,
        stateful_type: ResultType,
        answer: &str,
    ) -> Result<()> {
        self.check_unlocked(keys)?;
        validate_keyword(keyword)?;
        require_stateful(stateful_type)?;
        let t = stateful_type;
        let state = self.site_ref(site)?.answer_ctx(keyword, t).encrypt(keys, answer)?;
        let s = self.sites.get_mut(site).ok_or(Error::NoSuchSite)?;
        let q = match s.questions.get_mut(keyword) {
            Some(q) => q,
            None => s.add_question(keyword)?,
        };
        q.result_type = t;
        q.state = Some(state);
        Ok(())
    }

    // ---------------------------------------------------------------------- use

    /// Record a use of the site (after copying its password, login or answer):
    /// bumps its use count and the site's and user's last-used time.
    pub fn use_site(&mut self, site: &str) -> Result<()> {
        let now = Timestamp::now();
        let s = self.sites.get_mut(site).ok_or(Error::NoSuchSite)?;
        s.uses = s.uses.saturating_add(1);
        s.last_used = now;
        self.last_used = now;
        Ok(())
    }
}

fn require_stateful(t: ResultType) -> Result<()> {
    if t.is_stateful() {
        Ok(())
    } else {
        Err(Error::NotStateful(t))
    }
}

fn as_stateful(c: StateCtx<'_>) -> StateCtx<'_> {
    if c.result_type.is_stateful() {
        c
    } else {
        StateCtx { result_type: ResultType::StatefulPersonal, ..c }
    }
}

/// Re-encrypt one stored value from `src` (with `from`) to `dst` (with `to`, or
/// `from` again).  A value kept while a template type is selected ("stale") is
/// converted too, as a personal value; if it cannot be, it is dropped rather
/// than failing the operation.  A live value that cannot be converted is an error.
pub(crate) fn reencrypt_state(
    src: StateCtx<'_>,
    dst: StateCtx<'_>,
    state: Option<&str>,
    from: &mut UserKeys,
    to: Option<&mut UserKeys>,
) -> Result<Option<String>> {
    let Some(state) = state else { return Ok(None) };
    let live = src.result_type.is_stateful();
    let converted = as_stateful(src).decrypt(from, state).and_then(|plain| {
        let dst_keys = match to {
            Some(t) => t,
            None => from,
        };
        as_stateful(dst).encrypt(dst_keys, &plain)
    });
    match converted {
        Ok(s) => Ok(Some(s)),
        Err(e) if live => Err(e),
        Err(_) => Ok(None),
    }
}

/// Re-encrypt every live stored value of `source` into `target` (which has the
/// same name and questions but possibly another algorithm), decrypting with
/// `from` and encrypting with `to` (or `from` again if `to` is `None`).
/// Stale state (state kept for a type that is not stateful) is dropped.
/// On error `target` may be partially updated; callers discard it.
pub(crate) fn reencrypt_site(
    source: &Site,
    from: &mut UserKeys,
    target: &mut Site,
    mut to: Option<&mut UserKeys>,
) -> Result<()> {
    let mut convert = |src_ctx: StateCtx<'_>, dst_ctx: StateCtx<'_>, state: &Option<String>| {
        reencrypt_state(src_ctx, dst_ctx, state.as_deref(), from, to.as_deref_mut())
    };

    target.result_state = convert(source.password_ctx(), target.password_ctx(), &source.result_state)?;
    // A site using the user's login may still hold a stored login of its own.
    let login_t = source.login_type.unwrap_or(ResultType::DEFAULT_LOGIN);
    target.login_state = convert(source.login_ctx(login_t), target.login_ctx(login_t), &source.login_state)?;
    for (keyword, q) in &source.questions {
        let state = convert(
            source.answer_ctx(keyword, q.result_type),
            target.answer_ctx(keyword, q.result_type),
            &q.state,
        )?;
        let t: &mut Question = match target.questions.get_mut(keyword) {
            Some(t) => t,
            None => continue,
        };
        t.state = state;
    }
    Ok(())
}

// ------------------------------------------------------------ general results

/// What [`User::site_result`] should compute.  Start from [`ResultRequest::password`],
/// [`ResultRequest::login`] or [`ResultRequest::answer`] and override only what
/// differs; everything not overridden follows the same defaulting rules as
/// [`User::site_password`], [`User::site_login`] and [`User::site_answer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultRequest<'a> {
    purpose: KeyPurpose,
    context: Option<&'a str>,
    result_type: Option<ResultType>,
    counter: Option<Counter>,
    key_bits: Option<u32>,
}

impl<'a> ResultRequest<'a> {
    /// A request for `purpose` with no overrides.  For
    /// [`KeyPurpose::Recovery`] the context is the question keyword.
    pub fn new(purpose: KeyPurpose) -> Self {
        Self { purpose, context: None, result_type: None, counter: None, key_bits: None }
    }

    /// The site password.
    pub fn password() -> Self {
        Self::new(KeyPurpose::Authentication)
    }

    /// The login name.
    pub fn login() -> Self {
        Self::new(KeyPurpose::Identification)
    }

    /// The answer to the question `keyword` (`""`: the site-wide answer).
    pub fn answer(keyword: &'a str) -> Self {
        Self::new(KeyPurpose::Recovery).context(keyword)
    }

    /// The key context mixed into the derivation (the reference's `-C`).  For
    /// answers it is the question keyword, which also selects the stored
    /// question.  An empty context is no context.
    pub fn context(mut self, context: &'a str) -> Self {
        self.context = Some(context);
        self
    }

    /// Use this result type instead of the stored one.  A stateful type
    /// decrypts the value stored for this purpose.
    pub fn result_type(mut self, result_type: ResultType) -> Self {
        self.result_type = Some(result_type);
        self
    }

    /// Use this counter instead of the default (the site's counter for
    /// passwords, 1 for logins and answers).
    pub fn counter(mut self, counter: Counter) -> Self {
        self.counter = Some(counter);
        self
    }

    /// Derive a binary key ([`ResultType::DeriveKey`]) of `bits` bits
    /// (128–512, a multiple of 8; `None`: the default size), base64-encoded.
    pub fn derive_key(mut self, bits: Option<u32>) -> Self {
        self.result_type = Some(ResultType::DeriveKey);
        self.key_bits = Some(bits.unwrap_or(0));
        self
    }

    pub fn purpose(&self) -> KeyPurpose {
        self.purpose
    }
}

impl User {
    /// The general form of [`User::site_password`], [`User::site_login`] and
    /// [`User::site_answer`]: any purpose, with an optional key context, result
    /// type and counter.  Always computed with the key of the site's algorithm.
    pub fn site_result(&self, keys: &mut UserKeys, site: &str, request: &ResultRequest<'_>) -> Result<Zeroizing<String>> {
        self.check_unlocked(keys)?;
        let s = self.site_ref(site)?;
        let context = request.context.filter(|c| !c.is_empty());
        let (ctx, state, what) = match request.purpose {
            KeyPurpose::Authentication => {
                let t = request.result_type.unwrap_or(s.result_type);
                let ctx = StateCtx {
                    counter: request.counter.unwrap_or(s.counter),
                    context,
                    result_type: t,
                    ..s.password_ctx()
                };
                (ctx, s.result_state.as_deref(), "site password")
            }
            KeyPurpose::Identification => {
                // The same choice as `site_login`: the site's own stored login,
                // else the user's login.
                let (t, state, user_level) = match s.login_type {
                    Some(t) if t.is_stateful() && s.login_state.is_some() => (t, s.login_state.as_deref(), false),
                    Some(t) if !t.is_stateful() => (t, None, false),
                    _ => (self.login_type, self.login_state.as_deref(), true),
                };
                let t = request.result_type.unwrap_or(t);
                if t.is_stateful() && user_level {
                    // Stored once for the user, encrypted with the user's key.
                    let ctx = StateCtx { result_type: t, ..self.login_ctx() };
                    return ctx.result(keys, state, "login name");
                }
                let ctx = StateCtx {
                    counter: request.counter.unwrap_or(COUNTER_INITIAL),
                    context,
                    ..s.login_ctx(t)
                };
                (ctx, state, "login name")
            }
            KeyPurpose::Recovery => {
                let keyword = request.context.unwrap_or("");
                let q = s.questions.get(keyword);
                let t = request
                    .result_type
                    .unwrap_or_else(|| q.map_or(ResultType::DEFAULT_ANSWER, |q| q.result_type));
                let ctx = StateCtx {
                    counter: request.counter.unwrap_or(COUNTER_INITIAL),
                    ..s.answer_ctx(keyword, t)
                };
                (ctx, q.and_then(|q| q.state.as_deref()), "answer")
            }
        };
        if ctx.result_type.is_derive() {
            let bits = request.key_bits.unwrap_or(0).to_string();
            let key = keys.key(ctx.algorithm)?;
            return Ok(key.site_result(ctx.name, ctx.counter, ctx.purpose, ctx.context, ctx.result_type, Some(&bits))?);
        }
        ctx.result(keys, state, what)
    }

    /// Move the user to a new master password: every stored value (site
    /// passwords, site logins, answers and the user's login name) is decrypted
    /// with `old_keys` and re-encrypted with `new_keys`; the key ID and
    /// identicon are updated (the identicon is cleared if `new_keys` holds no
    /// password).  Everything else, including unknown JSON members, is kept.
    ///
    /// `old_keys` must have unlocked the user; `new_keys` must be for the same
    /// full name.  All or nothing: if a value in use cannot be re-encrypted the
    /// user is unchanged and [`Error::ReencryptFailed`] names the site.  (A
    /// value kept only for switching back to a stateful type that cannot be
    /// decrypted is dropped instead.)  On success `new_keys` unlocks the user.
    pub fn change_master_password(&mut self, old_keys: &mut UserKeys, new_keys: &mut UserKeys) -> Result<()> {
        self.check_unlocked(old_keys)?;
        if new_keys.full_name() != self.full_name {
            return Err(Error::UserMismatch);
        }
        let new_id = new_keys.key(self.algorithm)?.key_id();
        let mut updated = self.clone();
        for (name, site) in &self.sites {
            let mut target = site.clone();
            reencrypt_site(site, old_keys, &mut target, Some(&mut *new_keys))
                .map_err(|e| Error::ReencryptFailed { site: Some(name.clone()), source: Box::new(e) })?;
            updated.sites.insert(name.clone(), target);
        }
        updated.login_state = reencrypt_state(
            self.login_ctx(),
            self.login_ctx(),
            self.login_state.as_deref(),
            old_keys,
            Some(&mut *new_keys),
        )
        .map_err(|e| Error::ReencryptFailed { site: None, source: Box::new(e) })?;
        updated.key_id = Some(new_id.clone());
        updated.identicon = new_keys.identicon();
        *self = updated;
        new_keys.mark_authenticated(new_id);
        Ok(())
    }
}
