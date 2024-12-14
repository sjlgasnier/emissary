#![no_main]

use emissary_core::i2np::database::lookup::DatabaseLookup;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = DatabaseLookup::parse(buffer);
});
