#![no_main]

use emissary::i2np::tunnel::data::{EncryptedTunnelData, TunnelData};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = EncryptedTunnelData::parse(buffer);
    let _ = TunnelData::parse(buffer);
});
