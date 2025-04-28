// Copyright © 2016–2020 University of Malta

// Copying and distribution of this file, with or without
// modification, are permitted in any medium without royalty provided
// the copyright notice and this notice are preserved. This file is
// offered as-is, without any warranty.

#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]

use std::env;

fn main() {
    if env::var_os("CARGO_FEATURE_GMP_MPFR_SYS").is_some() {
        let bits =
            env::var_os("DEP_GMP_LIMB_BITS").expect("DEP_GMP_LIMB_BITS not set by gmp-mfpr-sys");
        let bits = bits
            .to_str()
            .expect("DEP_GMP_LIMB_BITS contains unexpected characters");
        if bits != "32" && bits != "64" {
            panic!("Limb bits not 32 or 64: \"{}\"", bits);
        }
        println!("cargo:rustc-cfg=gmp_limb_bits_{}", bits);
    }
}
