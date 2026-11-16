#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| browntls_fuzz::tls_ech::run(data));
