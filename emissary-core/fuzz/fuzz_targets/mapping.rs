#![no_main]

use emissary_core::primitives::Mapping;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = Mapping::parse(buffer);
});
