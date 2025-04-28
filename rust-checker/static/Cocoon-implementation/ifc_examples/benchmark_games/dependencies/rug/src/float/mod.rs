// Copyright © 2016–2020 University of Malta

// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License and a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

/*!
Multi-precision floating-point numbers with correct rounding.

This module provides support for floating-point numbers of type
[`Float`].

[`Float`]: ../struct.Float.html
*/

pub(crate) mod arith;
pub(crate) mod big;
mod casts;
mod cmp;
mod ord;
#[cfg(feature = "serde")]
mod serde;
pub(crate) mod small;
mod traits;

pub use crate::float::{
    big::ParseFloatError,
    ord::OrdFloat,
    small::{SmallFloat, ToSmall},
};
use az::SaturatingCast;
use core::{i32, u32};
use gmp_mpfr_sys::mpfr::{self, prec_t};

/**
Returns the minimum value for the exponent.

# Examples

```rust
use rug::float;
println!("Minimum exponent is {}", float::exp_min());
```
*/
#[inline]
pub fn exp_min() -> i32 {
    unsafe { mpfr::get_emin() }.saturating_cast()
}

/**
Returns the maximum value for the exponent.

# Examples

```rust
use rug::float;
println!("Maximum exponent is {}", float::exp_max());
```
*/
#[inline]
pub fn exp_max() -> i32 {
    unsafe { mpfr::get_emax() }.saturating_cast()
}

/**
Returns the maximum allowed range for the exponent.

# Examples

```rust
use rug::float;
let (min, max) = float::allowed_exp_range();
println!("Minimum and maximum exponents are in [{}, {}]", min, max);
```
*/
#[inline]
pub fn allowed_exp_range() -> (i32, i32) {
    unsafe {
        (
            mpfr::get_emin_min().saturating_cast(),
            mpfr::get_emax_max().saturating_cast(),
        )
    }
}

/**
Returns the minimum value for the precision.

# Examples

```rust
use rug::float;
println!("Minimum precision is {}", float::prec_min());
```
*/
#[inline]
pub const fn prec_min() -> u32 {
    mpfr::PREC_MIN as u32
}

/**
Returns the maximum value for the precision.

# Examples

```rust
use rug::float;
println!("Maximum precision is {}", float::prec_max());
```
*/
#[inline]
pub const fn prec_max() -> u32 {
    const MAX_FITS: bool = mpfr::PREC_MAX < u32::MAX as prec_t;
    const VALUES: [u32; 2] = [u32::MAX, mpfr::PREC_MAX as u32];
    const PREC_MAX: u32 = VALUES[MAX_FITS as usize];
    PREC_MAX
}

/**
The rounding methods for floating-point values.

When rounding to the nearest, if the number to be rounded is exactly
between two representable numbers, it is rounded to the even one, that
is, the one with the least significant bit set to zero.

# Examples

```rust
use rug::{float::Round, ops::AssignRound, Float};
let mut f4 = Float::new(4);
f4.assign_round(10.4, Round::Nearest);
assert_eq!(f4, 10);
f4.assign_round(10.6, Round::Nearest);
assert_eq!(f4, 11);
f4.assign_round(-10.7, Round::Zero);
assert_eq!(f4, -10);
f4.assign_round(10.3, Round::Up);
assert_eq!(f4, 11);
```

Rounding to the nearest will round numbers exactly between two
representable numbers to the even one.

```rust
use rug::{float::Round, ops::AssignRound, Float};
// 24 is 11000 in binary
// 25 is 11001 in binary
// 26 is 11010 in binary
// 27 is 11011 in binary
// 28 is 11100 in binary
let mut f4 = Float::new(4);
f4.assign_round(25, Round::Nearest);
assert_eq!(f4, 24);
f4.assign_round(27, Round::Nearest);
assert_eq!(f4, 28);
```
*/
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
// TODO: replace with exhaustive once rustc dependency >= 1.40
#[allow(clippy::manual_non_exhaustive)]
pub enum Round {
    /// Round towards the nearest.
    Nearest,
    /// Round towards zero.
    Zero,
    /// Round towards plus infinity.
    Up,
    /// Round towards minus infinity.
    Down,
    #[doc(hidden)]
    __Nonexhaustive,
}

impl Default for Round {
    #[inline]
    fn default() -> Round {
        Round::Nearest
    }
}

/**
The available floating-point constants.

# Examples

```rust
use rug::{float::Constant, Float};

let log2 = Float::with_val(53, Constant::Log2);
let pi = Float::with_val(53, Constant::Pi);
let euler = Float::with_val(53, Constant::Euler);
let catalan = Float::with_val(53, Constant::Catalan);

assert_eq!(log2.to_string_radix(10, Some(5)), "6.9315e-1");
assert_eq!(pi.to_string_radix(10, Some(5)), "3.1416");
assert_eq!(euler.to_string_radix(10, Some(5)), "5.7722e-1");
assert_eq!(catalan.to_string_radix(10, Some(5)), "9.1597e-1");
```
*/
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
// TODO: replace with exhaustive once rustc dependency >= 1.40
#[allow(clippy::manual_non_exhaustive)]
pub enum Constant {
    /// The logarithm of two, 0.693...
    Log2,
    /// The value of pi, 3.141...
    Pi,
    /// Euler’s constant, 0.577...
    ///
    /// Note that this is *not* Euler’s number e, which can be
    /// obtained using one of the [`exp`] functions.
    ///
    /// [`exp`]: ../struct.Float.html#method.exp
    Euler,
    /// Catalan’s constant, 0.915...
    Catalan,
    #[doc(hidden)]
    __Nonexhaustive,
}

/**
Special floating-point values.

# Examples

```rust
use rug::{float::Special, Float};

let zero = Float::with_val(53, Special::Zero);
let neg_zero = Float::with_val(53, Special::NegZero);
let infinity = Float::with_val(53, Special::Infinity);
let neg_infinity = Float::with_val(53, Special::NegInfinity);
let nan = Float::with_val(53, Special::Nan);

assert_eq!(zero, 0);
assert!(zero.is_sign_positive());
assert_eq!(neg_zero, 0);
assert!(neg_zero.is_sign_negative());
assert!(infinity.is_infinite());
assert!(infinity.is_sign_positive());
assert!(neg_infinity.is_infinite());
assert!(neg_infinity.is_sign_negative());
assert!(nan.is_nan());
```
*/
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
// TODO: replace with exhaustive once rustc dependency >= 1.40
#[allow(clippy::manual_non_exhaustive)]
pub enum Special {
    /// Positive zero.
    Zero,
    /// Negative zero.
    NegZero,
    /// Positive infinity.
    Infinity,
    /// Negative infinity.
    NegInfinity,
    /// Not a number.
    Nan,
    #[doc(hidden)]
    __Nonexhaustive,
}

/**
Specifies which cache to free.

# Examples

```rust
use rug::float::{self, FreeCache};
use std::thread;

fn main() {
    let child = thread::spawn(move || {
        // some work here that uses Float
        float::free_cache(FreeCache::Local);
    });
    // some work here
    child.join().expect("couldn't join thread");
    float::free_cache(FreeCache::All);
}
```
*/
#[allow(clippy::needless_doctest_main)]
// TODO: replace with exhaustive once rustc dependency >= 1.40
#[allow(clippy::manual_non_exhaustive)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FreeCache {
    /// Free caches local to the current thread.
    Local,
    /// Free caches shared by all threads.
    Global,
    /// Free both local and global caches.
    All,
    #[doc(hidden)]
    __Nonexhaustive,
}

/**
Frees various caches and memory pools that are used internally.

To avoid memory leaks being reported when using tools like [Valgrind],
it is advisable to free thread-local caches before terminating a
thread and all caches before exiting.

# Examples

```rust
use rug::float::{self, FreeCache};
use std::thread;

fn main() {
    let child = thread::spawn(move || {
        // some work here that uses Float
        float::free_cache(FreeCache::Local);
    });
    // some work here
    child.join().expect("couldn't join thread");
    float::free_cache(FreeCache::All);
}
```

[Valgrind]: https://www.valgrind.org/
*/
#[allow(clippy::needless_doctest_main)]
#[inline]
pub fn free_cache(which: FreeCache) {
    let way = match which {
        FreeCache::Local => mpfr::FREE_LOCAL_CACHE,
        FreeCache::Global => mpfr::FREE_GLOBAL_CACHE,
        FreeCache::All => mpfr::FREE_LOCAL_CACHE | mpfr::FREE_GLOBAL_CACHE,
        _ => unreachable!(),
    };
    unsafe {
        mpfr::free_cache2(way);
    }
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity, clippy::float_cmp)]
pub(crate) mod tests {
    #[cfg(feature = "rand")]
    use crate::rand::{RandGen, RandState};
    use crate::{
        float::{self, FreeCache, Round, Special},
        ops::NegAssign,
        Assign, Float,
    };
    use az::Az;
    use core::{
        cmp::Ordering,
        f64,
        fmt::{Debug, Error as FmtError, Formatter},
    };
    use gmp_mpfr_sys::{gmp, mpfr};

    pub fn nanflag() -> bool {
        unsafe { mpfr::nanflag_p() != 0 }
    }

    pub fn clear_nanflag() {
        unsafe {
            mpfr::clear_nanflag();
        }
    }

    #[derive(Clone, Copy)]
    pub enum Cmp {
        F64(f64),
        Nan(bool),
    }

    impl Cmp {
        pub fn inf(neg: bool) -> Cmp {
            Cmp::F64(if neg {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            })
        }
    }

    impl Debug for Cmp {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
            match *self {
                Cmp::F64(ref val) => val.fmt(f),
                Cmp::Nan(negative) => {
                    let s = if negative { "-NaN" } else { "NaN" };
                    s.fmt(f)
                }
            }
        }
    }

    impl PartialEq<Cmp> for Float {
        fn eq(&self, other: &Cmp) -> bool {
            match *other {
                Cmp::F64(ref f) => self.eq(f),
                Cmp::Nan(negative) => self.is_nan() && self.is_sign_negative() == negative,
            }
        }
    }

    #[test]
    fn check_from_str() {
        assert!(Float::with_val(53, Float::parse("-0").unwrap()).is_sign_negative());
        assert!(Float::with_val(53, Float::parse("+0").unwrap()).is_sign_positive());
        assert!(Float::with_val(53, Float::parse("1e1000").unwrap()).is_finite());
        let huge_hex = "1@99999999999999999999999999999999";
        assert!(Float::with_val(53, Float::parse_radix(huge_hex, 16).unwrap()).is_infinite());

        let bad_strings = [
            ("", 10, "string has no digits"),
            ("-", 10, "string has no digits"),
            ("+", 10, "string has no digits"),
            (".", 10, "string has no digits"),
            ("inf", 11, "invalid digit found in string"),
            ("@ nan @", 10, "string has no digits for significand"),
            ("inf", 16, "invalid digit found in string"),
            ("1.1.", 10, "more than one point found in string"),
            ("1e", 10, "string has no digits for exponent"),
            ("e10", 10, "string has no digits for significand"),
            (".e10", 10, "string has no digits for significand"),
            ("1e1.", 10, "string has point in exponent"),
            ("1e1e1", 10, "more than one exponent found in string"),
            ("1e+-1", 10, "invalid digit found in string"),
            ("1e-+1", 10, "invalid digit found in string"),
            ("+-1", 10, "invalid digit found in string"),
            ("-+1", 10, "invalid digit found in string"),
            ("infinit", 10, "invalid digit found in string"),
            ("1@1a", 16, "invalid digit found in string"),
            ("9", 9, "invalid digit found in string"),
            ("nan(20) x", 10, "invalid digit found in string"),
        ];
        for &(s, radix, msg) in bad_strings.iter() {
            match Float::parse_radix(s, radix) {
                Ok(o) => panic!(
                    "\"{}\" (radix {}) parsed correctly as {}, expected: {}",
                    s,
                    radix,
                    Float::with_val(53, o),
                    msg
                ),
                Err(e) => assert_eq!(e.to_string(), msg, "\"{}\" (radix {})", s, radix),
            }
        }
        let good_strings = [
            ("INF", 10, Cmp::inf(false)),
            ("iNfIniTY", 10, Cmp::inf(false)),
            ("- @iNf@", 16, Cmp::inf(true)),
            ("+0e99", 2, Cmp::F64(0.0)),
            ("-9.9e1", 10, Cmp::F64(-99.0)),
            ("-.99e+2", 10, Cmp::F64(-99.0)),
            ("+99.e+0", 10, Cmp::F64(99.0)),
            ("-99@-1", 10, Cmp::F64(-9.9f64)),
            ("-a_b__.C_d_E_@3", 16, Cmp::F64(f64::from(-0xabcde))),
            ("1e1023", 2, Cmp::F64(2.0f64.powi(1023))),
            (" NaN() ", 10, Cmp::Nan(false)),
            (" + NaN (20 Number_Is) ", 10, Cmp::Nan(false)),
            (" - @nan@", 2, Cmp::Nan(true)),
        ];
        for &(s, radix, f) in good_strings.iter() {
            match Float::parse_radix(s, radix) {
                Ok(ok) => assert_eq!(Float::with_val(53, ok), f),
                Err(err) => panic!("could not parse {}: {}", s, err),
            }
        }

        float::free_cache(FreeCache::All);
    }

    #[test]
    fn check_clamping() {
        let mut f = Float::new(4);

        // Both 1.00002 and 1.00001 are rounded to 1.0 with the same
        // rounding direction, so these work even though min > max.

        f.assign(-1);
        let dir = f.clamp_round(&1.00002, &1.00001, Round::Down);
        assert_eq!(f, 1.0);
        assert_eq!(dir, Ordering::Less);

        f.assign(-1);
        let dir = f.clamp_round(&1.00002, &1.00001, Round::Up);
        assert_eq!(f, 1.125);
        assert_eq!(dir, Ordering::Greater);

        f.assign(2);
        let dir = f.clamp_round(&1.00002, &1.00001, Round::Down);
        assert_eq!(f, 1.0);
        assert_eq!(dir, Ordering::Less);

        f.assign(2);
        let dir = f.clamp_round(&1.00002, &1.00001, Round::Up);
        assert_eq!(f, 1.125);
        assert_eq!(dir, Ordering::Greater);

        float::free_cache(FreeCache::All);
    }

    #[test]
    #[should_panic(expected = "minimum larger than maximum")]
    fn check_clamping_panic() {
        let mut f = Float::new(4);
        f.assign(-1);
        // Both 1.00001 and 0.99999 would be rounded to 1.0, but one
        // would be larger and the other would be smaller.
        f.clamp(&1.00001, &0.99999);
    }

    #[test]
    fn check_formatting() {
        let mut f = Float::with_val(53, Special::Zero);
        assert_eq!(format!("{}", f), "0");
        assert_eq!(format!("{:e}", f), "0");
        assert_eq!(format!("{:?}", f), "0");
        assert_eq!(format!("{:+?}", f), "+0");
        assert_eq!(format!("{:<10}", f), "0         ");
        assert_eq!(format!("{:>10}", f), "         0");
        assert_eq!(format!("{:10}", f), "         0");
        assert_eq!(format!("{:^10}", f), "    0     ");
        assert_eq!(format!("{:^11}", f), "     0     ");
        f.assign(Special::NegZero);
        assert_eq!(format!("{}", f), "-0");
        assert_eq!(format!("{:?}", f), "-0");
        assert_eq!(format!("{:+?}", f), "-0");
        f.assign(Special::Infinity);
        assert_eq!(format!("{}", f), "inf");
        assert_eq!(format!("{:+}", f), "+inf");
        assert_eq!(format!("{:x}", f), "@inf@");
        f.assign(Special::NegInfinity);
        assert_eq!(format!("{}", f), "-inf");
        assert_eq!(format!("{:x}", f), "-@inf@");
        f.assign(Special::Nan);
        assert_eq!(format!("{}", f), "NaN");
        assert_eq!(format!("{:+}", f), "+NaN");
        assert_eq!(format!("{:x}", f), "@NaN@");
        f = -f;
        assert_eq!(format!("{}", f), "-NaN");
        assert_eq!(format!("{:x}", f), "-@NaN@");
        f.assign(-2.75);
        assert_eq!(format!("{:.1}", f), "-3");
        assert_eq!(format!("{:.2}", f), "-2.8");
        assert_eq!(format!("{:.4?}", f), "-2.750");
        assert_eq!(format!("{:.1e}", f), "-3e0");
        assert_eq!(format!("{:.2e}", f), "-2.8e0");
        assert_eq!(format!("{:.4e}", f), "-2.750e0");
        assert_eq!(format!("{:.4E}", f), "-2.750E0");
        assert_eq!(format!("{:.8b}", f), "-10.110000");
        assert_eq!(format!("{:.3b}", f), "-11.0");
        assert_eq!(format!("{:#.8b}", f), "-0b10.110000");
        assert_eq!(format!("{:.2o}", f), "-2.6");
        assert_eq!(format!("{:#.2o}", f), "-0o2.6");
        assert_eq!(format!("{:.2x}", f), "-2.c");
        assert_eq!(format!("{:.2X}", f), "-2.C");
        assert_eq!(format!("{:12.1x}", f), "          -3");
        assert_eq!(format!("{:12.2x}", f), "        -2.c");
        assert_eq!(format!("{:012.3X}", f), "-00000002.C0");
        assert_eq!(format!("{:#012.2x}", f), "-0x0000002.c");
        assert_eq!(format!("{:#12.2X}", f), "      -0x2.C");
        f.assign(-27);
        assert_eq!(format!("{:.1}", f), "-3e1");
        assert_eq!(format!("{:.2}", f), "-27");
        assert_eq!(format!("{:.4?}", f), "-27.00");
        assert_eq!(format!("{:.1e}", f), "-3e1");
        assert_eq!(format!("{:.2e}", f), "-2.7e1");
        assert_eq!(format!("{:.4e}", f), "-2.700e1");
        assert_eq!(format!("{:.4E}", f), "-2.700E1");
        assert_eq!(format!("{:.8b}", f), "-11011.000");
        assert_eq!(format!("{:.3b}", f), "-1.11e4");
        assert_eq!(format!("{:#.8b}", f), "-0b11011.000");
        assert_eq!(format!("{:.2o}", f), "-33");
        assert_eq!(format!("{:#.2o}", f), "-0o33");
        assert_eq!(format!("{:.2x}", f), "-1b");
        assert_eq!(format!("{:.2X}", f), "-1B");
        assert_eq!(format!("{:12.1x}", f), "        -2@1");
        assert_eq!(format!("{:12.2x}", f), "         -1b");
        assert_eq!(format!("{:012.3X}", f), "-00000001B.0");
        assert_eq!(format!("{:#012.2x}", f), "-0x00000001b");
        assert_eq!(format!("{:#12.2X}", f), "       -0x1B");
        f <<= 144;
        assert_eq!(format!("{:.8b}", f), "-1.1011000e148");
        assert_eq!(format!("{:.3b}", f), "-1.11e148");
        assert_eq!(format!("{:#.8b}", f), "-0b1.1011000e148");
        assert_eq!(format!("{:.2o}", f), "-3.3e49");
        assert_eq!(format!("{:#.2o}", f), "-0o3.3e49");
        assert_eq!(format!("{:.1x}", f), "-2@37");
        assert_eq!(format!("{:.2x}", f), "-1.b@37");
        assert_eq!(format!("{:.2X}", f), "-1.B@37");
        assert_eq!(format!("{:12.1x}", f), "       -2@37");
        assert_eq!(format!("{:12.2x}", f), "     -1.b@37");
        assert_eq!(format!("{:012.3X}", f), "-00001.B0@37");
        assert_eq!(format!("{:#012.2x}", f), "-0x0001.b@37");
        assert_eq!(format!("{:#12.2X}", f), "   -0x1.B@37");

        float::free_cache(FreeCache::All);
    }

    #[test]
    fn check_assumptions() {
        assert_eq!(unsafe { mpfr::custom_get_size(64) }, 8);
        assert!(unsafe { mpfr::custom_get_size(32) } <= gmp::NUMB_BITS.az::<usize>());

        float::free_cache(FreeCache::All);
    }

    #[test]
    fn check_i_pow_u() {
        for &(i, u) in &[(13, 4), (13, 5), (-13, 4), (-13, 5)] {
            let p = Float::i_pow_u(i, u);
            let f = Float::with_val(53, p);
            assert_eq!(f, i.pow(u));
        }
    }

    #[test]
    fn check_nanflag() {
        clear_nanflag();
        let nan = Float::with_val(53, Special::Nan);
        assert!(!nanflag());

        clear_nanflag();
        let c = nan.clone();
        assert!(c.is_nan());
        assert!(!nanflag());

        clear_nanflag();
        let mut m = Float::new(53);
        assert!(!m.is_nan());
        assert!(!nanflag());
        m.clone_from(&nan);
        assert!(m.is_nan());
        assert!(!nanflag());
        m.assign(&nan);
        assert!(m.is_nan());
        assert!(nanflag());
        clear_nanflag();
        m.assign(nan.clone());
        assert!(m.is_nan());
        assert!(nanflag());

        clear_nanflag();
        let c = Float::with_val(53, -&nan);
        assert!(c.is_nan());
        assert!(nanflag());

        clear_nanflag();
        let mut m = nan.clone();
        m.neg_assign();
        assert!(m.is_nan());
        assert!(nanflag());

        clear_nanflag();
        let c = Float::with_val(53, nan.clamp_ref(&0, &0));
        assert!(c.is_nan());
        assert!(nanflag());

        clear_nanflag();
        let mut m = nan.clone();
        m.clamp_mut(&0, &0);
        assert!(m.is_nan());
        assert!(nanflag());

        clear_nanflag();
        let a = nan.as_neg();
        assert!(a.is_nan());
        assert!(nanflag());

        clear_nanflag();
        let a = nan.as_abs();
        assert!(a.is_nan());
        assert!(nanflag());
    }

    #[cfg(feature = "rand")]
    struct OnesZerosRand {
        one_words: u32,
    }

    #[cfg(feature = "rand")]
    impl RandGen for OnesZerosRand {
        fn gen(&mut self) -> u32 {
            if self.one_words > 0 {
                self.one_words -= 1;
                !0
            } else {
                0
            }
        }
    }

    #[cfg(feature = "rand")]
    #[test]
    fn check_nan_random_bits() {
        // Least significant 64 bits (two 32-bit words) of mantissa
        // will be ones, all others will be zeros. With 256 bits of
        // precision, the "random" number will be 0.0{192}1{64}. This
        // will be normalized to 0.1{64} * 2^-192.
        for i in 0..2 {
            let mut zeros_ones = OnesZerosRand { one_words: 2 };
            let mut rand = RandState::new_custom(&mut zeros_ones);
            let save_emin;
            unsafe {
                save_emin = mpfr::get_emin();
                mpfr::set_emin(-192 + i);
            }
            let f = Float::with_val(256, Float::random_bits(&mut rand));
            if i == 0 {
                assert_eq!(f, Float::with_val(64, !0u64) >> 256);
            } else {
                assert!(f.is_nan());
            }
            unsafe {
                mpfr::set_emin(save_emin);
            }
        }

        float::free_cache(FreeCache::All);
    }
}
