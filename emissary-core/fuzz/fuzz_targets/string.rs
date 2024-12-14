#![no_main]

use emissary_core::primitives::Str;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = Str::parse(buffer);
});
