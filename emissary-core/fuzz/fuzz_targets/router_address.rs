#![no_main]

use emissary_core::primitives::RouterAddress;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = RouterAddress::parse(buffer);
});
