//! Password templates and character classes (`mpw-types.c`).
//!
//! These tables are part of the algorithm; changing them changes every
//! generated password.

use crate::ResultType;

/// The templates for a template result type, or `None` for other types.
pub(crate) fn templates(result_type: ResultType) -> Option<&'static [&'static str]> {
    Some(match result_type {
        ResultType::TemplateMaximum => &["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"],
        ResultType::TemplateLong => &[
            "CvcvnoCvcvCvcv",
            "CvcvCvcvnoCvcv",
            "CvcvCvcvCvcvno",
            "CvccnoCvcvCvcv",
            "CvccCvcvnoCvcv",
            "CvccCvcvCvcvno",
            "CvcvnoCvccCvcv",
            "CvcvCvccnoCvcv",
            "CvcvCvccCvcvno",
            "CvcvnoCvcvCvcc",
            "CvcvCvcvnoCvcc",
            "CvcvCvcvCvccno",
            "CvccnoCvccCvcv",
            "CvccCvccnoCvcv",
            "CvccCvccCvcvno",
            "CvcvnoCvccCvcc",
            "CvcvCvccnoCvcc",
            "CvcvCvccCvccno",
            "CvccnoCvcvCvcc",
            "CvccCvcvnoCvcc",
            "CvccCvcvCvccno",
        ],
        ResultType::TemplateMedium => &["CvcnoCvc", "CvcCvcno"],
        ResultType::TemplateShort => &["Cvcn"],
        ResultType::TemplateBasic => &["aaanaaan", "aannaaan", "aaannaaa"],
        ResultType::TemplatePin => &["nnnn"],
        ResultType::TemplateName => &["cvccvcvcv"],
        ResultType::TemplatePhrase => &[
            "cvcc cvc cvccvcv cvc",
            "cvc cvccvcvcv cvcv",
            "cv cvccv cvc cvcvccv",
        ],
        ResultType::StatefulPersonal | ResultType::StatefulDevice | ResultType::DeriveKey => {
            return None
        }
    })
}

/// The characters of a template character class.
pub(crate) fn class_characters(class: u8) -> Option<&'static str> {
    Some(match class {
        b'V' => "AEIOU",
        b'C' => "BCDFGHJKLMNPQRSTVWXYZ",
        b'v' => "aeiou",
        b'c' => "bcdfghjklmnpqrstvwxyz",
        b'A' => "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
        b'a' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
        b'n' => "0123456789",
        b'o' => "@&%?,=[]_:-+*$#!'^~;()/.",
        b'x' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
        b' ' => " ",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_fits_the_site_key_and_uses_known_classes() {
        for t in ResultType::ALL {
            let Some(list) = templates(t) else {
                assert!(!t.is_template(), "{t:?}");
                continue;
            };
            assert!(t.is_template());
            for template in list {
                // byte 0 picks the template, bytes 1.. the characters.
                assert!(template.len() < 32, "{template}");
                assert!(template.bytes().all(|c| class_characters(c).is_some()));
            }
        }
    }
}
