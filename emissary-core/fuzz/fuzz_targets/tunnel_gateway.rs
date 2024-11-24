#![no_main]

use emissary::i2np::tunnel::gateway::TunnelGateway;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = TunnelGateway::parse(buffer);
});
