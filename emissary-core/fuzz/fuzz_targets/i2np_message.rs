#![no_main]

use emissary_core::i2np::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: Vec<u8>| {
    let _ = Message::parse_standard(&buffer);
    let _ = Message::parse_short(&buffer);
});
