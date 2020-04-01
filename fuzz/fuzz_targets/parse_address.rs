#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate multiserver_address_rs;

use std::str::FromStr;
use multiserver_address_rs::MultiserverAddress;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = MultiserverAddress::from_str(s);
    }
});
