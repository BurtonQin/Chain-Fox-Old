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
Multi-precision complex numbers with correct rounding.

This module provides support for complex numbers of type [`Complex`].

[`Complex`]: ../struct.Complex.html
*/

pub(crate) mod arith;
pub(crate) mod big;
mod cmp;
mod ord;
#[cfg(feature = "serde")]
mod serde;
mod small;
mod traits;

pub use crate::complex::big::ParseComplexError;
pub use crate::complex::ord::OrdComplex;
pub use crate::complex::small::SmallComplex;

/**
The `Prec` trait is used to specify the precision of the real and
imaginary parts of a [`Complex`] number.

This trait is implememented for [`u32`] and for [`(u32, u32)`][tuple].

# Examples

```rust
use rug::Complex;
let c1 = Complex::new(32);
assert_eq!(c1.prec(), (32, 32));
let c2 = Complex::new((32, 64));
assert_eq!(c2.prec(), (32, 64));
```

[`Complex`]: ../struct.Complex.html
[`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
[tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
*/
pub trait Prec {
    /// Returns the precision for the real and imaginary parts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::complex::Prec;
    /// assert_eq!(Prec::prec(24), (24, 24));
    /// assert_eq!(Prec::prec((24, 53)), (24, 53));
    /// ```
    fn prec(self) -> (u32, u32);
}

impl Prec for u32 {
    #[inline]
    fn prec(self) -> (u32, u32) {
        (self, self)
    }
}

impl Prec for (u32, u32) {
    #[inline]
    fn prec(self) -> (u32, u32) {
        self
    }
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod tests {
    use crate::{
        float::{
            self,
            tests::{clear_nanflag, nanflag, Cmp},
            FreeCache, Special,
        },
        ops::NegAssign,
        Assign, Complex,
    };
    use core::f64;

    #[test]
    fn check_from_str() {
        let mut c = Complex::new(53);
        c.assign(Complex::parse("(+0 -0)").unwrap());
        assert_eq!(c, (0, 0));
        assert!(c.real().is_sign_positive());
        assert!(c.imag().is_sign_negative());
        c.assign(Complex::parse("(5 6)").unwrap());
        assert_eq!(c, (5, 6));
        c.assign(Complex::parse_radix("(50 60)", 8).unwrap());
        assert_eq!(c, (0o50, 0o60));
        c.assign(Complex::parse_radix("33", 16).unwrap());
        assert_eq!(c, (0x33, 0));

        let bad_strings = [
            ("", 10, "string has no digits"),
            (
                "(0 0) 0",
                10,
                "string has more characters after closing bracket",
            ),
            (
                "(0 0 0)",
                10,
                "string has more than one separator inside brackets",
            ),
            ("(0) ", 10, "string has no separator inside brackets"),
            ("(, 0)", 10, "string has no real digits"),
            ("(0 )", 10, "string has no separator inside brackets"),
            ("(0, )", 10, "string has no imaginary digits"),
            (
                "(0,,0 )",
                10,
                "string has more than one separator inside brackets",
            ),
            (" ( 2)", 10, "string has no separator inside brackets"),
            (
                "+(1 1)",
                10,
                "string is not a valid float: invalid digit found in string",
            ),
            (
                "-(1. 1.)",
                10,
                "string is not a valid float: invalid digit found in string",
            ),
            (
                "(f 1)",
                10,
                "real part of string is not a valid float: invalid digit found in string",
            ),
            (
                "(1 1@1a)",
                16,
                "imaginary part of string is not a valid float: invalid digit found in string",
            ),
            ("(8 )", 9, "string has no separator inside brackets"),
        ];
        for &(s, radix, msg) in bad_strings.iter() {
            match Complex::parse_radix(s, radix) {
                Ok(o) => panic!(
                    "\"{}\" (radix {}) parsed correctly as {}, expected: {}",
                    s,
                    radix,
                    Complex::with_val(53, o),
                    msg
                ),
                Err(e) => assert_eq!(e.to_string(), msg, "\"{}\" (radix {})", s, radix),
            }
        }
        let good_strings = [
            ("(inf -@inf@)", 10, Cmp::inf(false), Cmp::inf(true)),
            ("(+0e99 1.)", 2, Cmp::F64(0.0), Cmp::F64(1.0)),
            ("(+ 0 e 99, .1)", 2, Cmp::F64(0.0), Cmp::F64(0.5)),
            ("-9.9e1", 10, Cmp::F64(-99.0), Cmp::F64(0.0)),
            (
                " ( -@nan@( _ ) nan( 0 n ) ) ",
                10,
                Cmp::Nan(true),
                Cmp::Nan(false),
            ),
        ];
        for &(s, radix, r, i) in good_strings.iter() {
            match Complex::parse_radix(s, radix) {
                Ok(ok) => {
                    let c = Complex::with_val(53, ok);
                    assert_eq!(*c.real(), r, "real mismatch for {}", s);
                    assert_eq!(*c.imag(), i, "imaginary mismatch for {}", s);
                }
                Err(e) => panic!("could not parse {} because {}", s, e),
            }
        }

        float::free_cache(FreeCache::All);
    }

    #[test]
    fn check_formatting() {
        let mut c = Complex::new((53, 53));
        c.assign((Special::Zero, Special::NegZero));
        assert_eq!(format!("{}", c), "(0 -0)");
        assert_eq!(format!("{:?}", c), "(0 -0)");
        assert_eq!(format!("{:+}", c), "(+0 -0)");
        assert_eq!(format!("{:+}", *c.as_neg()), "(-0 +0)");
        assert_eq!(format!("{:<15}", c), "(0 -0)         ");
        assert_eq!(format!("{:>15}", c), "         (0 -0)");
        assert_eq!(format!("{:15}", c), "         (0 -0)");
        assert_eq!(format!("{:^15}", c), "    (0 -0)     ");
        assert_eq!(format!("{:^16}", c), "     (0 -0)     ");
        c.assign((2.7, f64::NEG_INFINITY));
        assert_eq!(format!("{:.2}", c), "(2.7 -inf)");
        assert_eq!(format!("{:+.8}", c), "(+2.7000000 -inf)");
        assert_eq!(format!("{:.4e}", c), "(2.700e0 -inf)");
        assert_eq!(format!("{:.4E}", c), "(2.700E0 -inf)");
        assert_eq!(format!("{:16.2}", c), "      (2.7 -inf)");
        c.assign((-3.5, 11));
        assert_eq!(format!("{:.4b}", c), "(-11.10 1011)");
        assert_eq!(format!("{:#.4b}", c), "(-0b11.10 0b1011)");
        assert_eq!(format!("{:.4o}", c), "(-3.400 13.00)");
        assert_eq!(format!("{:#.4o}", c), "(-0o3.400 0o13.00)");
        c.assign((3.5, -11));
        assert_eq!(format!("{:.2x}", c), "(3.8 -b.0)");
        assert_eq!(format!("{:#.2x}", c), "(0x3.8 -0xb.0)");
        assert_eq!(format!("{:.2X}", c), "(3.8 -B.0)");
        assert_eq!(format!("{:#.2X}", c), "(0x3.8 -0xB.0)");

        float::free_cache(FreeCache::All);
    }

    #[test]
    fn check_nanflag() {
        clear_nanflag();
        let re_nan = Complex::with_val(53, (Special::Nan, Special::Zero));
        let im_nan = Complex::with_val(53, (Special::Zero, Special::Nan));
        assert!(!nanflag());

        clear_nanflag();
        let c = re_nan.clone();
        assert!(c.real().is_nan() && !c.imag().is_nan());
        assert!(!nanflag());
        clear_nanflag();
        let c = im_nan.clone();
        assert!(!c.real().is_nan() && c.imag().is_nan());
        assert!(!nanflag());

        clear_nanflag();
        let mut m = Complex::new(53);
        assert!(!m.real().is_nan() && !m.imag().is_nan());
        assert!(!nanflag());
        m.clone_from(&re_nan);
        assert!(m.real().is_nan() && !m.imag().is_nan());
        assert!(!nanflag());
        m.assign(&re_nan);
        assert!(m.real().is_nan() && !m.imag().is_nan());
        assert!(nanflag());
        clear_nanflag();
        m.assign(re_nan.clone());
        assert!(m.real().is_nan() && !m.imag().is_nan());
        assert!(nanflag());
        clear_nanflag();
        let mut m = Complex::new(53);
        assert!(!m.real().is_nan() && !m.imag().is_nan());
        assert!(!nanflag());
        m.clone_from(&im_nan);
        assert!(!m.real().is_nan() && m.imag().is_nan());
        assert!(!nanflag());
        m.assign(&im_nan);
        assert!(!m.real().is_nan() && m.imag().is_nan());
        assert!(nanflag());
        clear_nanflag();
        m.assign(im_nan.clone());
        assert!(!m.real().is_nan() && m.imag().is_nan());
        assert!(nanflag());

        clear_nanflag();
        let c = Complex::with_val(53, -&re_nan);
        assert!(c.real().is_nan() && !c.imag().is_nan());
        assert!(nanflag());
        clear_nanflag();
        let c = Complex::with_val(53, -&im_nan);
        assert!(!c.real().is_nan() && c.imag().is_nan());
        assert!(nanflag());

        clear_nanflag();
        let mut m = re_nan.clone();
        m.neg_assign();
        assert!(m.real().is_nan() && !m.imag().is_nan());
        assert!(nanflag());
        clear_nanflag();
        let mut m = im_nan.clone();
        m.neg_assign();
        assert!(!m.real().is_nan() && m.imag().is_nan());
        assert!(nanflag());

        clear_nanflag();
        let a = re_nan.as_neg();
        assert!(a.real().is_nan() && !a.imag().is_nan());
        assert!(nanflag());
        clear_nanflag();
        let a = im_nan.as_neg();
        assert!(!a.real().is_nan() && a.imag().is_nan());
        assert!(nanflag());

        clear_nanflag();
        let a = re_nan.as_conj();
        assert!(a.real().is_nan() && !a.imag().is_nan());
        assert!(!nanflag());
        clear_nanflag();
        let a = im_nan.as_conj();
        assert!(!a.real().is_nan() && a.imag().is_nan());
        assert!(nanflag());

        clear_nanflag();
        let a = re_nan.as_mul_i(false);
        assert!(!a.real().is_nan() && a.imag().is_nan());
        assert!(nanflag());
        clear_nanflag();
        let a = im_nan.as_mul_i(true);
        assert!(a.real().is_nan() && !a.imag().is_nan());
        assert!(nanflag());
    }
}
