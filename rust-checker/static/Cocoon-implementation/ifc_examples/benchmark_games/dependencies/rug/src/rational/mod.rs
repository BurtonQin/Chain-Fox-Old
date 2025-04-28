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
Arbitrary-precision rational numbers.

This module provides support for arbitrary-precision rational numbers
of type [`Rational`].

[`Rational`]: ../struct.Rational.html
*/

mod arith;
pub(crate) mod big;
mod casts;
mod cmp;
#[cfg(feature = "serde")]
mod serde;
mod small;
mod traits;

pub use crate::rational::big::ParseRationalError;
pub use crate::rational::small::SmallRational;

/**
An error which can be returned when a checked conversion from a
floating-point number to a [`Rational`] number fails.

# Examples

```rust
use core::convert::TryFrom;
use rug::{rational::TryFromFloatError, Rational};
// This is not finite and cannot be converted to Rational.
let inf = 1.0f32 / 0.0;
let error: TryFromFloatError = match Rational::try_from(inf) {
    Ok(_) => unreachable!(),
    Err(error) => error,
};
println!("Error: {}", error);
```

[`Rational`]: ../struct.Rational.html
*/
#[derive(Clone, Copy, Debug)]
pub struct TryFromFloatError {
    pub(crate) _unused: (),
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod tests {
    use crate::{rational::SmallRational, Integer, Rational};

    #[test]
    fn check_fract_trunc() {
        let ndwf = [
            (23, 10, 2, 3),
            (-23, 10, -2, -3),
            (20, 10, 2, 0),
            (-20, 10, -2, 0),
            (3, 10, 0, 3),
            (-3, 10, 0, -3),
            (0, 10, 0, 0),
        ];
        for &(n, d, whole, fract_n) in ndwf.iter() {
            let r = Rational::from((n, d));

            let (fract, trunc) = r.clone().fract_trunc(Integer::new());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(trunc, whole);

            let (fract, trunc) = <(Rational, Integer)>::from(r.fract_trunc_ref());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(trunc, whole);

            let sep_fract = Rational::from(r.rem_trunc_ref());
            assert_eq!(sep_fract, (fract_n, d));
            let sep_trunc = Integer::from(r.trunc_ref());
            assert_eq!(sep_trunc, whole);

            let mut r = r;
            let mut trunc = Integer::new();
            r.fract_trunc_mut(&mut trunc);
            assert_eq!(r, (fract_n, d));
            assert_eq!(trunc, whole);
        }
    }

    #[test]
    fn check_fract_ceil() {
        let ndwf = [
            (23, 10, 3, -7),
            (-23, 10, -2, -3),
            (20, 10, 2, 0),
            (-20, 10, -2, 0),
            (3, 10, 1, -7),
            (-3, 10, 0, -3),
            (0, 10, 0, 0),
        ];
        for &(n, d, whole, fract_n) in ndwf.iter() {
            let r = Rational::from((n, d));

            let (fract, ceil) = r.clone().fract_ceil(Integer::new());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(ceil, whole);

            let (fract, ceil) = <(Rational, Integer)>::from(r.fract_ceil_ref());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(ceil, whole);

            let sep_fract = Rational::from(r.rem_ceil_ref());
            assert_eq!(sep_fract, (fract_n, d));
            let sep_ceil = Integer::from(r.ceil_ref());
            assert_eq!(sep_ceil, whole);

            let mut r = r;
            let mut ceil = Integer::new();
            r.fract_ceil_mut(&mut ceil);
            assert_eq!(r, (fract_n, d));
            assert_eq!(ceil, whole);
        }
    }

    #[test]
    fn check_fract_floor() {
        let ndwf = [
            (23, 10, 2, 3),
            (-23, 10, -3, 7),
            (20, 10, 2, 0),
            (-20, 10, -2, 0),
            (3, 10, 0, 3),
            (-3, 10, -1, 7),
            (0, 10, 0, 0),
        ];
        for &(n, d, whole, fract_n) in ndwf.iter() {
            let r = Rational::from((n, d));

            let (fract, floor) = r.clone().fract_floor(Integer::new());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(floor, whole);

            let (fract, floor) = <(Rational, Integer)>::from(r.fract_floor_ref());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(floor, whole);

            let sep_fract = Rational::from(r.rem_floor_ref());
            assert_eq!(sep_fract, (fract_n, d));
            let sep_floor = Integer::from(r.floor_ref());
            assert_eq!(sep_floor, whole);

            let mut r = r;
            let mut floor = Integer::new();
            r.fract_floor_mut(&mut floor);
            assert_eq!(r, (fract_n, d));
            assert_eq!(floor, whole);
        }
    }

    #[test]
    fn check_fract_round() {
        let ndwf = [
            (27, 10, 3, -3),
            (-27, 10, -3, 3),
            (25, 10, 3, -5),
            (-25, 10, -3, 5),
            (23, 10, 2, 3),
            (-23, 10, -2, -3),
            (20, 10, 2, 0),
            (-20, 10, -2, 0),
            (3, 10, 0, 3),
            (-3, 10, 0, -3),
            (0, 10, 0, 0),
        ];
        for &(n, d, whole, fract_n) in ndwf.iter() {
            let r = Rational::from((n, d));

            let (fract, round) = r.clone().fract_round(Integer::new());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(round, whole);

            let (fract, round) = <(Rational, Integer)>::from(r.fract_round_ref());
            assert_eq!(fract, (fract_n, d));
            assert_eq!(round, whole);

            let sep_fract = Rational::from(r.rem_round_ref());
            assert_eq!(sep_fract, (fract_n, d));
            let sep_round = Integer::from(r.round_ref());
            assert_eq!(sep_round, whole);

            let mut r = r;
            let mut round = Integer::new();
            r.fract_round_mut(&mut round);
            assert_eq!(r, (fract_n, d));
            assert_eq!(round, whole);
        }
    }

    #[test]
    fn check_from_str() {
        assert_eq!("-13/7".parse::<Rational>().unwrap(), (-13, 7));

        let bad_strings = [
            ("_1", 10, "invalid digit found in string"),
            ("+_1", 10, "invalid digit found in string"),
            ("-_1", 10, "invalid digit found in string"),
            ("1/_1", 10, "invalid digit found in string"),
            ("+-3", 10, "invalid digit found in string"),
            ("-+3", 10, "invalid digit found in string"),
            ("++3", 10, "invalid digit found in string"),
            ("--3", 10, "invalid digit found in string"),
            ("0+3", 10, "invalid digit found in string"),
            ("", 10, "string has no digits"),
            (" ", 10, "string has no digits"),
            ("1/-1", 10, "invalid digit found in string"),
            ("1/+3", 10, "invalid digit found in string"),
            ("1/0", 10, "string has zero denominator"),
            ("/2", 10, "string has no digits for numerator"),
            ("2/", 10, "string has no digits for denominator"),
            ("2/2/", 10, "more than one / found in string"),
            ("1/80", 8, "invalid digit found in string"),
            ("0xf", 16, "invalid digit found in string"),
            ("9", 9, "invalid digit found in string"),
            (":0", 36, "invalid digit found in string"),
            ("/0", 36, "string has no digits for numerator"),
            (":0", 36, "invalid digit found in string"),
            ("@0", 36, "invalid digit found in string"),
            ("[0", 36, "invalid digit found in string"),
            ("`0", 36, "invalid digit found in string"),
            ("{0", 36, "invalid digit found in string"),
            ("Z0", 35, "invalid digit found in string"),
            ("z0", 35, "invalid digit found in string"),
        ];
        for &(s, radix, msg) in bad_strings.iter() {
            match Rational::parse_radix(s, radix) {
                Ok(o) => panic!(
                    "\"{}\" (radix {}) parsed correctly as {}, expected: {}",
                    s,
                    radix,
                    Rational::from(o),
                    msg
                ),
                Err(e) => assert_eq!(e.to_string(), msg, "\"{}\" (radix {})", s, radix),
            }
        }
        let good_strings = [
            ("0", 10, 0, 1),
            ("+0/fC", 16, 0, 1),
            (" + 1 _ / 2 _ ", 10, 1, 2),
            (" - 1 _ / 2 _ ", 10, -1, 2),
            ("-0/10", 2, 0, 1),
            ("-99/3", 10, -33, 1),
            ("+Ce/fF", 16, 0xce, 0xff),
            ("-77/2", 8, -0o77, 2),
            ("Z/z0", 36, 1, 36),
        ];
        for &(s, radix, n, d) in good_strings.iter() {
            match Rational::parse_radix(s, radix) {
                Ok(ok) => {
                    let r = Rational::from(ok);
                    assert_eq!(*r.numer(), n, "numerator mismatch for {}", s);
                    assert_eq!(*r.denom(), d, "denominator mismatch for {}", s);
                }
                Err(err) => panic!("could not parse {}: {}", s, err),
            }
        }
    }

    #[test]
    fn check_formatting() {
        let r = Rational::from((-11, 15));
        assert_eq!(format!("{}", r), "-11/15");
        assert_eq!(format!("{:?}", r), "-11/15");
        assert_eq!(format!("{:<10}", r), "-11/15    ");
        assert_eq!(format!("{:>10}", r), "    -11/15");
        assert_eq!(format!("{:10}", r), "    -11/15");
        assert_eq!(format!("{:^10}", r), "  -11/15  ");
        assert_eq!(format!("{:^11}", r), "  -11/15   ");
        assert_eq!(format!("{:b}", r), "-1011/1111");
        assert_eq!(format!("{:#b}", r), "-0b1011/1111");
        assert_eq!(format!("{:o}", r), "-13/17");
        assert_eq!(format!("{:#o}", r), "-0o13/17");
        assert_eq!(format!("{:x}", r), "-b/f");
        assert_eq!(format!("{:X}", r), "-B/F");
        assert_eq!(format!("{:8x}", r), "    -b/f");
        assert_eq!(format!("{:08X}", r), "-0000B/F");
        assert_eq!(format!("{:#08x}", r), "-0x00b/f");
        assert_eq!(format!("{:#8X}", r), "  -0xB/F");
        let i = r * &*SmallRational::from(15);
        assert_eq!(format!("{}", i), "-11");
        assert_eq!(format!("{:?}", i), "-11");
        assert_eq!(format!("{:b}", i), "-1011");
        assert_eq!(format!("{:#b}", i), "-0b1011");
        assert_eq!(format!("{:o}", i), "-13");
        assert_eq!(format!("{:#o}", i), "-0o13");
        assert_eq!(format!("{:x}", i), "-b");
        assert_eq!(format!("{:X}", i), "-B");
        assert_eq!(format!("{:8x}", i), "      -b");
        assert_eq!(format!("{:08X}", i), "-000000B");
        assert_eq!(format!("{:#08x}", i), "-0x0000b");
        assert_eq!(format!("{:#8X}", i), "    -0xB");
    }
}
