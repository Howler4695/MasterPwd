//! Merging an imported user into an existing one.

use crate::error::Result;
use crate::keys::UserKeys;
use crate::model::{Site, User};
use crate::ops::reencrypt_site;

/// What [`merge`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeSummary {
    /// Existing sites replaced by a more recently used imported version.
    pub replaced: Vec<String>,
    /// Sites that only existed in the import.
    pub added: Vec<String>,
    /// Sites left alone because a stored value of the import could not be
    /// decrypted with the import's key or re-encrypted with the destination's.
    pub skipped: Vec<String>,
    /// Whether user-level settings were taken from the import.
    pub user_updated: bool,
}

impl MergeSummary {
    /// Nothing changed.
    pub fn is_empty(&self) -> bool {
        self.replaced.is_empty() && self.added.is_empty() && !self.user_updated
    }
}

/// Merge `source` into `dest`.
///
/// * An imported site replaces the existing one only if it was used more
///   recently; sites missing from `dest` are added.
/// * Stored passwords, login names and answers are decrypted with
///   `source_keys` and re-encrypted with `dest_keys` (unless both users have the
///   same master key, in which case they are copied).  A site whose values
///   cannot be converted is skipped and `dest` keeps its version.
/// * `dest`'s key ID is never changed.  If the import is at least as recent,
///   its avatar and last-used time are taken; algorithm, default type,
///   identicon and login settings only when both users share the master key.
///
/// Both key holders must have been authenticated against their user.  On error
/// `dest` is unchanged.
pub fn merge(dest: &mut User, dest_keys: &mut UserKeys, source: &User, source_keys: &mut UserKeys) -> Result<MergeSummary> {
    dest.check_unlocked(dest_keys)?;
    source.check_unlocked(source_keys)?;
    let same_key = dest.full_name == source.full_name && dest.key_id == source.key_id;

    let mut summary = MergeSummary::default();
    let mut merged = dest.clone();
    for (name, imported) in &source.sites {
        let replacing = match dest.sites.get(name) {
            Some(existing) if imported.last_used <= existing.last_used => continue,
            Some(_) => true,
            None => false,
        };
        let site = if same_key {
            imported.clone()
        } else {
            match convert(imported, source_keys, dest_keys) {
                Ok(site) => site,
                Err(_) => {
                    summary.skipped.push(name.clone());
                    continue;
                }
            }
        };
        merged.sites.insert(name.clone(), site);
        if replacing { &mut summary.replaced } else { &mut summary.added }.push(name.clone());
    }

    if source.last_used >= dest.last_used {
        let before = (merged.avatar, merged.last_used, merged.algorithm, merged.default_type);
        merged.avatar = source.avatar;
        merged.last_used = source.last_used;
        if same_key {
            merged.algorithm = source.algorithm;
            merged.default_type = source.default_type;
            merged.login_type = source.login_type;
            merged.login_state.clone_from(&source.login_state);
            if source.identicon.is_some() {
                merged.identicon.clone_from(&source.identicon);
            }
        }
        summary.user_updated = before != (merged.avatar, merged.last_used, merged.algorithm, merged.default_type)
            || merged.login_type != dest.login_type
            || merged.login_state != dest.login_state
            || merged.identicon != dest.identicon;
    }

    *dest = merged;
    Ok(summary)
}

fn convert(imported: &Site, from: &mut UserKeys, to: &mut UserKeys) -> Result<Site> {
    let mut site = imported.clone();
    reencrypt_site(imported, from, &mut site, Some(to))?;
    Ok(site)
}
