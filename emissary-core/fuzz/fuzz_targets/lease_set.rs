#![no_main]

use emissary_core::primitives::LeaseSet2;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = LeaseSet2::parse(buffer);
});
