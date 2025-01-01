#![no_main]

use emissary_core::primitives::Date;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = Date::parse(buffer);
});
