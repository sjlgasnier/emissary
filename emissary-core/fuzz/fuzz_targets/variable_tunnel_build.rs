#![no_main]

use emissary::i2np::tunnel::build::variable::TunnelBuildRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: Vec<u8>| {
    let _ = TunnelBuildRecord::parse(&buffer);
});
