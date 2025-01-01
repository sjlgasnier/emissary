#![no_main]

use emissary_core::i2np::database::store::DatabaseStore;
use emissary_util::runtime::tokio::Runtime;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = DatabaseStore::<Runtime>::parse(buffer);
});
