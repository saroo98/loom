#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = loom_vault::parse_bounded_request(data) {
        let _ = loom_vault::validate_legacy_learning_import(&value);
    }
});
