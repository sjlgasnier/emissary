#![no_main]

use emissary_core::primitives::RouterInfo;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = RouterInfo::parse(buffer);
});
