#![no_main]

use emissary_core::primitives::RouterIdentity;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = RouterIdentity::parse(buffer);
});
