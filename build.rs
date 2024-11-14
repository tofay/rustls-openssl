#![allow(clippy::unusual_byte_groupings)]

use std::env;

const OPENSSL_NO_CHACHA: &str = "OPENSSL_NO_CHACHA";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(chacha)");
    // Determine whether to work around https://github.com/openssl/openssl/issues/23448
    // according to the OpenSSL version
    println!("cargo:rustc-check-cfg=cfg(bugged_add_hkdf_info)");
    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();

        if (0x3_00_00_00_0..0x3_04_00_00_0).contains(&version) {
            println!("cargo:rustc-cfg=bugged_add_hkdf_info");
        }
    }

    // Enable the `chacha` cfg if the `OPENSSL_NO_CHACHA` OpenSSL config is not set.
    if std::env::var("DEP_OPENSSL_CONF")
        .map(|conf_string| !conf_string.split(",").any(|conf| conf == OPENSSL_NO_CHACHA))
        .unwrap_or(true)
    {
        println!("cargo:rustc-cfg=chacha");
    }
}
