//! Users, sites and security questions as plain owned data.

use crate::error::{Error, Result};
use crate::limits;
use crate::time::Timestamp;
use mpw_core::{AlgorithmVersion, Counter, Identicon, KeyId, ResultType, COUNTER_DEFAULT};
use serde_json::{Map, Value};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

pub(crate) type JsonMap = Map<String, Value>;

/// JSON members this crate does not interpret, kept verbatim so that a
/// load→save round trip never loses another app's data.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct UserExtras {
    /// Unknown top-level members.
    pub root: JsonMap,
    /// Unknown members of `export` (besides date/redacted/format).
    pub export: JsonMap,
    /// Unknown members of `user`.
    pub user: JsonMap,
    /// The original `user._ext_mpw` (all of it, including the known preference
    /// keys, so that we know which ones were present).  `None` if absent.
    pub user_ext_mpw: Option<Value>,
}

/// Per-user preferences of the original app, stored under `user._ext_mpw`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserPreferences {
    /// Hide passwords in the UI until revealed.
    pub mask_passwords: bool,
    /// Keep the master key in the Keychain behind Touch ID.
    pub biometric_lock: bool,
    /// Offer this user's sites to AutoFill.  `None`: the user has not decided yet.
    pub autofill: Option<bool>,
    /// Name of the attacker profile used for password-strength estimates.
    pub attacker: Option<String>,
}

/// A Master Password user: identity, defaults, preferences and sites.
///
/// Fields that must stay consistent with the master key (full name, key ID,
/// algorithm, stored state) are private and changed only through methods that
/// take the authenticated [`crate::UserKeys`].
///
/// `PartialEq` compares every field.  `User` is intentionally not `Ord`: use
/// [`User::cmp_by_name`] (identity order) or [`sort_most_recent_first`].
#[derive(Clone, PartialEq, Eq)]
pub struct User {
    pub(crate) full_name: String,
    /// Index of the avatar image (0-18 in the original app).
    pub avatar: u32,
    /// The identicon of the full name + master password, shown as a typo hint.
    pub identicon: Option<Identicon>,
    pub(crate) key_id: Option<KeyId>,
    pub(crate) algorithm: AlgorithmVersion,
    /// Result type for new sites.
    pub default_type: ResultType,
    /// How the user's default login name is produced (sites whose
    /// [`Site::login_type`] is `None` use this).
    pub(crate) login_type: ResultType,
    pub(crate) login_state: Option<String>,
    pub last_used: Timestamp,
    pub preferences: UserPreferences,
    pub(crate) sites: BTreeMap<String, Site>,
    pub(crate) extras: UserExtras,
}

/// A site (a "service" in the original app).
#[derive(Clone, PartialEq, Eq)]
pub struct Site {
    pub(crate) name: String,
    pub(crate) algorithm: AlgorithmVersion,
    /// Increment to get a new password for the site.
    pub counter: Counter,
    /// How the site password is produced.  A stateful type needs a stored value
    /// (see [`crate::User::set_site_password`]).
    pub result_type: ResultType,
    pub(crate) result_state: Option<String>,
    /// How the login name is produced; `None` uses the user's login name.
    pub(crate) login_type: Option<ResultType>,
    pub(crate) login_state: Option<String>,
    pub url: Option<String>,
    pub uses: u32,
    pub last_used: Timestamp,
    pub(crate) questions: BTreeMap<String, Question>,
    /// Unknown members of the site object.
    pub(crate) extra: JsonMap,
    /// The original `_ext_mpw` object (holds `url`), if any.
    pub(crate) ext_mpw: Option<Value>,
}

/// A security question of a site, identified by a keyword (`""` is the
/// site-wide default answer).
#[derive(Clone, PartialEq, Eq)]
pub struct Question {
    pub(crate) keyword: String,
    /// How the answer is produced (a phrase by default).
    pub result_type: ResultType,
    pub(crate) state: Option<String>,
    pub(crate) extra: JsonMap,
}

// ------------------------------------------------------------------ validation

pub(crate) fn validate_full_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(Error::InvalidFullName("it is empty"));
    }
    if name.len() > limits::MAX_NAME_LEN {
        return Err(Error::InvalidFullName("it is too long"));
    }
    if name.chars().any(char::is_control) {
        return Err(Error::InvalidFullName("it contains control characters"));
    }
    Ok(())
}

pub(crate) fn validate_site_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidSiteName("it is empty"));
    }
    if name.len() > limits::MAX_NAME_LEN {
        return Err(Error::InvalidSiteName("it is too long"));
    }
    if name.chars().any(char::is_control) {
        return Err(Error::InvalidSiteName("it contains control characters"));
    }
    Ok(())
}

pub(crate) fn validate_keyword(keyword: &str) -> Result<()> {
    if keyword.len() > limits::MAX_NAME_LEN || keyword.chars().any(char::is_control) {
        return Err(Error::InvalidSiteName("invalid question keyword"));
    }
    Ok(())
}

// ------------------------------------------------------------------------ user

impl User {
    /// A new user with the defaults of the original app: current algorithm,
    /// long passwords, generated login names, no key ID yet (the first
    /// [`User::authenticate`] adopts one).
    pub fn new(full_name: &str) -> Result<Self> {
        validate_full_name(full_name)?;
        Ok(Self {
            full_name: full_name.to_owned(),
            avatar: 0,
            identicon: None,
            key_id: None,
            algorithm: AlgorithmVersion::CURRENT,
            default_type: ResultType::DEFAULT,
            login_type: ResultType::DEFAULT_LOGIN,
            login_state: None,
            last_used: Timestamp::now(),
            preferences: UserPreferences::default(),
            sites: BTreeMap::new(),
            extras: UserExtras::default(),
        })
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Fingerprint of the master key; `None` for a new or reset user.
    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// The algorithm of the user's master key (and of new sites).
    pub fn algorithm(&self) -> AlgorithmVersion {
        self.algorithm
    }

    /// How the user-level login name is produced.
    pub fn login_type(&self) -> ResultType {
        self.login_type
    }

    /// Whether a personal login name is stored for the user.
    pub fn has_login_state(&self) -> bool {
        self.login_state.is_some()
    }

    /// Forget the key ID, so that the next [`User::authenticate`] adopts the
    /// key it is given ("I changed my master password").  Every generated
    /// password changes with the master password, and stored personal
    /// passwords can no longer be decrypted.
    pub fn reset_key_id(&mut self) {
        self.key_id = None;
    }

    /// Sites ordered by name.
    pub fn sites(&self) -> impl ExactSizeIterator<Item = &Site> + '_ {
        self.sites.values()
    }

    pub fn site(&self, name: &str) -> Option<&Site> {
        self.sites.get(name)
    }

    pub fn site_mut(&mut self, name: &str) -> Option<&mut Site> {
        self.sites.get_mut(name)
    }

    /// Add a site with the user's defaults (algorithm, default type, counter 1,
    /// last used now).
    pub fn add_site(&mut self, name: &str) -> Result<&mut Site> {
        validate_site_name(name)?;
        if self.sites.contains_key(name) {
            return Err(Error::SiteExists);
        }
        if self.sites.len() >= limits::MAX_SITES {
            return Err(Error::InvalidSiteName("the user has too many sites"));
        }
        let site = Site::new(name, self.algorithm, self.default_type);
        Ok(self.sites.entry(name.to_owned()).or_insert(site))
    }

    pub fn remove_site(&mut self, name: &str) -> Option<Site> {
        self.sites.remove(name)
    }

    /// Rename a site.  The stored state is encrypted with the master key alone,
    /// so it stays valid.
    pub fn rename_site(&mut self, old: &str, new: &str) -> Result<()> {
        validate_site_name(new)?;
        if old == new {
            return self.sites.contains_key(old).then_some(()).ok_or(Error::NoSuchSite);
        }
        if self.sites.contains_key(new) {
            return Err(Error::SiteExists);
        }
        let mut site = self.sites.remove(old).ok_or(Error::NoSuchSite)?;
        site.name = new.to_owned();
        self.sites.insert(new.to_owned(), site);
        Ok(())
    }

    /// Record that the user was used now.
    pub fn touch(&mut self) {
        self.last_used = Timestamp::now();
    }

    /// Total order by full name (byte-wise), the user's identity.  Consistent
    /// with "same user" checks; use it for sorted containers.
    pub fn cmp_by_name(&self, other: &Self) -> Ordering {
        self.full_name.cmp(&other.full_name)
    }
}

/// Sort users most recently used first; ties by full name.  A total order.
pub fn sort_most_recent_first(users: &mut [User]) {
    users.sort_by(|a, b| b.last_used.cmp(&a.last_used).then_with(|| a.cmp_by_name(b)));
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("full_name", &self.full_name)
            .field("avatar", &self.avatar)
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("default_type", &self.default_type)
            .field("login_type", &self.login_type)
            .field("login_state", &self.login_state.as_ref().map(|_| "<encrypted>"))
            .field("last_used", &self.last_used)
            .field("preferences", &self.preferences)
            .field("sites", &self.sites.values().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

// ------------------------------------------------------------------------ site

impl Site {
    pub(crate) fn new(name: &str, algorithm: AlgorithmVersion, result_type: ResultType) -> Self {
        Self {
            name: name.to_owned(),
            algorithm,
            counter: COUNTER_DEFAULT,
            result_type,
            result_state: None,
            login_type: None,
            login_state: None,
            url: None,
            uses: 0,
            last_used: Timestamp::now(),
            questions: BTreeMap::new(),
            extra: JsonMap::new(),
            ext_mpw: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The algorithm this site's results are computed with (may differ from the
    /// user's; change it with [`crate::User::set_site_algorithm`]).
    pub fn algorithm(&self) -> AlgorithmVersion {
        self.algorithm
    }

    /// How the login name is produced; `None` uses the user's login name.
    pub fn login_type(&self) -> Option<ResultType> {
        self.login_type
    }

    /// Use the user's login name for this site again (drops any stored one).
    pub fn use_default_login(&mut self) {
        self.login_type = None;
        self.login_state = None;
    }

    /// Generate the login name from a template (e.g. [`ResultType::TemplateName`])
    /// for this site, instead of inheriting the user's.
    pub fn set_generated_login(&mut self, template: ResultType) -> Result<()> {
        if !template.is_template() {
            return Err(Error::NotStateful(template));
        }
        self.login_type = Some(template);
        self.login_state = None;
        Ok(())
    }

    /// Whether an (encrypted) password is stored for the site.
    pub fn has_password_state(&self) -> bool {
        self.result_state.is_some()
    }

    /// Whether an (encrypted) login name is stored for the site.
    pub fn has_login_state(&self) -> bool {
        self.login_state.is_some()
    }

    /// Questions ordered by keyword.
    pub fn questions(&self) -> impl ExactSizeIterator<Item = &Question> + '_ {
        self.questions.values()
    }

    pub fn question(&self, keyword: &str) -> Option<&Question> {
        self.questions.get(keyword)
    }

    pub fn question_mut(&mut self, keyword: &str) -> Option<&mut Question> {
        self.questions.get_mut(keyword)
    }

    /// Add a question (answer type: phrase).  `""` is the site-wide answer.
    pub fn add_question(&mut self, keyword: &str) -> Result<&mut Question> {
        validate_keyword(keyword)?;
        if self.questions.contains_key(keyword) {
            return Err(Error::QuestionExists);
        }
        if self.questions.len() >= limits::MAX_QUESTIONS {
            return Err(Error::InvalidSiteName("the site has too many questions"));
        }
        let q = Question::new(keyword);
        Ok(self.questions.entry(keyword.to_owned()).or_insert(q))
    }

    pub fn remove_question(&mut self, keyword: &str) -> Option<Question> {
        self.questions.remove(keyword)
    }
}

impl fmt::Debug for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Site")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .field("counter", &self.counter)
            .field("result_type", &self.result_type)
            .field("result_state", &self.result_state.as_ref().map(|_| "<encrypted>"))
            .field("login_type", &self.login_type)
            .field("login_state", &self.login_state.as_ref().map(|_| "<encrypted>"))
            .field("url", &self.url)
            .field("uses", &self.uses)
            .field("last_used", &self.last_used)
            .field("questions", &self.questions.values().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

// -------------------------------------------------------------------- question

impl Question {
    pub(crate) fn new(keyword: &str) -> Self {
        Self {
            keyword: keyword.to_owned(),
            result_type: ResultType::DEFAULT_ANSWER,
            state: None,
            extra: JsonMap::new(),
        }
    }

    pub fn keyword(&self) -> &str {
        &self.keyword
    }

    /// Whether an (encrypted) answer is stored.
    pub fn has_answer_state(&self) -> bool {
        self.state.is_some()
    }
}

impl fmt::Debug for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Question")
            .field("keyword", &self.keyword)
            .field("result_type", &self.result_type)
            .field("state", &self.state.as_ref().map(|_| "<encrypted>"))
            .finish_non_exhaustive()
    }
}
