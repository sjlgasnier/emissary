#![no_main]

use emissary_core::i2np::database::search_reply::DatabaseSearchReply;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|buffer: &[u8]| {
    let _ = DatabaseSearchReply::parse(buffer);
});
