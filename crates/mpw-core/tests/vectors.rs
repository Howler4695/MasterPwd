//! Runs every case of the reference implementation's `mpw_tests.xml`.
//!
//! Cases inherit missing fields from their `parent` case, exactly like
//! `mpw_xmlTestCaseNode` in the reference `mpw-tests-util.c`; cases with an
//! empty `<result>` are abstract and skipped (only `default`).

use mpw_core::{AlgorithmVersion, KeyId, KeyPurpose, MasterKey, ResultType, MASTER_KEY_SIZE};
use std::collections::HashMap;

const XML: &str = include_str!("mpw_tests.xml");

struct Cases<'a> {
    by_id: HashMap<&'a str, roxmltree::Node<'a, 'a>>,
}

impl<'a> Cases<'a> {
    /// Field lookup with parent inheritance: attribute, then child element,
    /// then the parent case.
    fn get(&self, case: roxmltree::Node<'a, 'a>, field: &str) -> Option<String> {
        if let Some(v) = case.attribute(field) {
            return Some(v.to_owned());
        }
        if let Some(child) = case.children().find(|c| c.has_tag_name(field)) {
            // Concatenate text content (comments such as <!-- abstract --> are ignored).
            return Some(
                child
                    .descendants()
                    .filter(|n| n.is_text())
                    .filter_map(|n| n.text())
                    .collect(),
            );
        }
        if field == "parent" {
            return None;
        }
        let parent_id = self.get(case, "parent")?;
        let parent = *self
            .by_id
            .get(parent_id.as_str())
            .unwrap_or_else(|| panic!("missing parent case {parent_id}"));
        self.get(parent, field)
    }
}

#[test]
fn all_reference_test_vectors_pass() {
    let doc = roxmltree::Document::parse(XML).expect("mpw_tests.xml parses");
    let cases: Vec<_> = doc
        .root_element()
        .children()
        .filter(|n| n.has_tag_name("case"))
        .collect();
    let index = Cases {
        by_id: cases
            .iter()
            .map(|c| (c.attribute("id").expect("case id"), *c))
            .collect(),
    };

    let mut keys: HashMap<(String, String, AlgorithmVersion), [u8; MASTER_KEY_SIZE]> =
        HashMap::new();
    let mut passed = 0;
    let mut abstract_cases = 0;
    let mut per_version = [0usize; 4];
    let mut failures = Vec::new();

    for &case in &cases {
        let field = |name: &str| index.get(case, name);
        let id = field("id").unwrap();
        let expected_result = field("result").unwrap_or_default();
        if expected_result.is_empty() {
            abstract_cases += 1;
            continue;
        }

        let algorithm: u32 = field("algorithm").unwrap().trim().parse().unwrap();
        let algorithm = AlgorithmVersion::from_u32(algorithm).unwrap();
        let full_name = field("fullName").unwrap();
        let master_password = field("masterPassword").unwrap();
        let key_id = KeyId::from_hex(&field("keyID").unwrap()).unwrap();
        let site_name = field("siteName").unwrap();
        let counter: u32 = field("siteCounter").unwrap().trim().parse().unwrap();
        let result_type = ResultType::from_name(&field("resultType").unwrap()).unwrap();
        let purpose = KeyPurpose::from_name(&field("keyPurpose").unwrap()).unwrap();
        let context = field("keyContext");

        let bytes = *keys
            .entry((full_name.clone(), master_password.clone(), algorithm))
            .or_insert_with(|| {
                *MasterKey::derive(&full_name, &master_password, algorithm)
                    .unwrap()
                    .as_bytes()
            });
        let master_key = MasterKey::from_bytes(bytes, algorithm);

        let got_key_id = master_key.key_id();
        if got_key_id != key_id {
            failures.push(format!("{id}: keyID {got_key_id} != {key_id}"));
            continue;
        }
        let result = master_key
            .site_result(
                &site_name,
                counter,
                purpose,
                context.as_deref(),
                result_type,
                None,
            )
            .unwrap();
        if result.as_str() != expected_result {
            failures.push(format!("{id}: result {:?} != {expected_result:?}", *result));
            continue;
        }
        passed += 1;
        per_version[algorithm.as_u32() as usize] += 1;
    }

    eprintln!(
        "mpw_tests.xml: {passed} passed (v0 {}, v1 {}, v2 {}, v3 {}), {} failed, {abstract_cases} abstract, {} total",
        per_version[0],
        per_version[1],
        per_version[2],
        per_version[3],
        failures.len(),
        cases.len()
    );
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
    assert_eq!(passed + abstract_cases, cases.len());
    assert!(
        per_version.iter().all(|&n| n > 0),
        "every version is covered"
    );
}
