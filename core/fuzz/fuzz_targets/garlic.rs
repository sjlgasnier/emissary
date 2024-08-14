#![no_main]

use emissary::i2np::garlic::GarlicMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = GarlicMessage::parse(buffer);
});
