//! A request's method and path, classified into the NGSI-LD operation it asks for.
//!
//! The input is a request line without the version: the method, one space, the path.
#![no_main]

use http::Method;
use libfuzzer_sys::fuzz_target;
use libra_ngsi_ld_operation::operation::Operation;

fuzz_target!(|line: &str| {
    let Some((method, path)) = line.split_once(' ') else {
        return;
    };
    let Ok(method) = Method::from_bytes(method.as_bytes()) else {
        return;
    };

    if let Ok(Some(operation)) = Operation::classify(&method, path) {
        let _ = operation.is_read();
    }
});
