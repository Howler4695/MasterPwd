//! The original app's avatar images (`assets/avatars`, copied into the bundle's
//! `Resources/avatars`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;

use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_app_kit::NSImage;
use objc2_foundation::{NSBundle, NSSize};

use super::ns;

thread_local! {
    static CACHE: RefCell<HashMap<String, Option<Retained<NSImage>>>> = RefCell::new(HashMap::new());
}

fn dir() -> PathBuf {
    if super::is_bundled() {
        if let Some(res) = NSBundle::mainBundle().resourcePath() {
            return PathBuf::from(res.to_string()).join("avatars");
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/avatars")
}

fn load(stem: &str) -> Option<Retained<NSImage>> {
    let path = dir().join(format!("{stem}@2x.png"));
    let image = NSImage::initWithContentsOfFile(NSImage::alloc(), &ns(&path.to_string_lossy()))?;
    let size = image.size();
    image.setSize(NSSize::new(size.width / 2.0, size.height / 2.0));
    Some(image)
}

fn cached(stem: String) -> Option<Retained<NSImage>> {
    CACHE.with(|c| c.borrow_mut().entry(stem.clone()).or_insert_with(|| load(&stem)).clone())
}

/// Avatar `i` (0–18).
pub fn avatar(i: u32) -> Option<Retained<NSImage>> {
    cached(format!("avatar-{}", i.min(crate::view_model::AVATAR_COUNT - 1)))
}

/// The "add user" picture.
pub fn add_user() -> Option<Retained<NSImage>> {
    cached("avatar-add".into())
}
