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
Aribtrary-precision integers.

This module provides support for arbitrary-precision integers of type
[`Integer`]. Instances of [`Integer`] always have a heap allocation
for the bit data; if you want a temporary small integer without heap
allocation, you can use the [`SmallInteger`] type.

# Examples

```rust
use rug::{integer::SmallInteger, Assign, Integer};
let mut int = Integer::from(10);
assert_eq!(int, 10);
let small = SmallInteger::from(-15);
// `small` behaves like an `Integer` in the following line:
int.assign(small.abs_ref());
assert_eq!(int, 15);
```

[`Integer`]: ../struct.Integer.html
[`SmallInteger`]: struct.SmallInteger.html
*/

pub(crate) mod arith;
pub(crate) mod big;
mod casts;
mod cmp;
mod division;
#[cfg(feature = "serde")]
mod serde;
pub(crate) mod small;
mod traits;

pub use crate::integer::{
    big::{IsPrime, ParseIntegerError, UnsignedPrimitive},
    small::{SmallInteger, ToSmall},
};

use libc::c_int;

/**
An error which can be returned when a checked conversion from
[`Integer`] fails.

# Examples

```rust
use core::convert::TryFrom;
use rug::{integer::TryFromIntegerError, Integer};
// This is negative and cannot be converted to u32.
let i = Integer::from(-5);
let error: TryFromIntegerError = match u32::try_from(&i) {
    Ok(_) => unreachable!(),
    Err(error) => error,
};
println!("Error: {}", error);
```

[`Integer`]: ../struct.Integer.html
*/
#[derive(Clone, Copy, Debug)]
pub struct TryFromIntegerError {
    _unused: (),
}

/**
The ordering of digits inside a [slice], and bytes inside a digit.

# Examples

```rust
use rug::{integer::Order, Integer};

let i = Integer::from(0x0102_0304);
let mut buf: [u16; 4] = [0; 4];

// most significant 16-bit digit first, little endian digits
i.write_digits(&mut buf, Order::MsfLe);
assert_eq!(buf, [0, 0, 0x0102u16.to_le(), 0x0304u16.to_le()]);
// least significant 16-bit digit first, big endian digits
i.write_digits(&mut buf, Order::LsfBe);
assert_eq!(buf, [0x0304u16.to_be(), 0x0102u16.to_be(), 0, 0]);
```

[slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
*/
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Order {
    /// Least significant digit first, with each digit in the target’s
    /// endianness.
    Lsf,
    /// Least significant digit first, with little endian digits.
    LsfLe,
    /// Least significant digit first, with big endian digits.
    LsfBe,
    /// Most significant digit first, with each digit in the target’s
    /// endianness.
    Msf,
    /// Most significant digit first, with little endian digits.
    MsfLe,
    /// Most significant digit first, with big endian digits.
    MsfBe,
}

impl Order {
    #[inline]
    fn order(self) -> c_int {
        match self {
            Order::Lsf | Order::LsfLe | Order::LsfBe => -1,
            Order::Msf | Order::MsfLe | Order::MsfBe => 1,
        }
    }
    #[inline]
    fn endian(self) -> c_int {
        match self {
            Order::Lsf | Order::Msf => 0,
            Order::LsfLe | Order::MsfLe => -1,
            Order::LsfBe | Order::MsfBe => 1,
        }
    }
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity, clippy::float_cmp)]
mod tests {
    use crate::{integer::Order, ops::NegAssign, Assign, Integer};
    use az::{Az, WrappingAs};
    use core::{f32, f64, i128, i32, i64, u128, u32, u64};

    #[test]
    fn check_int_conversions() {
        let mut i = Integer::from(-1);
        assert_eq!(i.to_u32_wrapping(), u32::MAX);
        assert_eq!(i.to_i32_wrapping(), -1);
        i.assign(0xff00_0000u32);
        i <<= 4;
        assert_eq!(i.to_u32_wrapping(), 0xf000_0000u32);
        assert_eq!(i.to_i32_wrapping(), 0xf000_0000u32.wrapping_as::<i32>());
        i = i.clone() << 32 | i;
        assert_eq!(i.to_u32_wrapping(), 0xf000_0000u32);
        assert_eq!(i.to_i32_wrapping(), 0xf000_0000u32.wrapping_as::<i32>());
        i.neg_assign();
        assert_eq!(i.to_u32_wrapping(), 0x1000_0000u32);
        assert_eq!(i.to_i32_wrapping(), 0x1000_0000i32);
    }

    #[test]
    fn check_option_conversion() {
        let mut i = Integer::new();
        assert_eq!(i.to_u32(), Some(0));
        assert_eq!(i.to_i32(), Some(0));
        assert_eq!(i.to_u64(), Some(0));
        assert_eq!(i.to_i64(), Some(0));
        i -= 1;
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), Some(-1));
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), Some(-1));

        i.assign(i32::MIN);
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), Some(i32::MIN));
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), Some(i64::from(i32::MIN)));
        i -= 1;
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), Some(i64::from(i32::MIN) - 1));
        i.assign(i32::MAX);
        assert_eq!(i.to_u32(), Some(i32::MAX.wrapping_as::<u32>()));
        assert_eq!(i.to_i32(), Some(i32::MAX));
        assert_eq!(i.to_u64(), Some(i32::MAX.wrapping_as::<u64>()));
        assert_eq!(i.to_i64(), Some(i64::from(i32::MAX)));
        i += 1;
        assert_eq!(i.to_u32(), Some(i32::MAX.wrapping_as::<u32>() + 1));
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), Some(i32::MAX.wrapping_as::<u64>() + 1));
        assert_eq!(i.to_i64(), Some(i64::from(i32::MAX) + 1));
        i.assign(u32::MAX);
        assert_eq!(i.to_u32(), Some(u32::MAX));
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), Some(u64::from(u32::MAX)));
        assert_eq!(i.to_i64(), Some(i64::from(u32::MAX)));
        i += 1;
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), Some(u64::from(u32::MAX) + 1));
        assert_eq!(i.to_i64(), Some(i64::from(u32::MAX) + 1));

        i.assign(i64::MIN);
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), Some(i64::MIN));
        i -= 1;
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);
        i.assign(i64::MAX);
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), Some(i64::MAX.wrapping_as::<u64>()));
        assert_eq!(i.to_i64(), Some(i64::MAX));
        i += 1;
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), Some(i64::MAX.wrapping_as::<u64>() + 1));
        assert_eq!(i.to_i64(), None);
        i.assign(u64::MAX);
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), Some(u64::MAX));
        assert_eq!(i.to_i64(), None);
        i += 1;
        assert_eq!(i.to_u32(), None);
        assert_eq!(i.to_i32(), None);
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);

        i.assign(i128::MIN);
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);
        assert_eq!(i.to_u128(), None);
        assert_eq!(i.to_i128(), Some(i128::MIN));
        i -= 1;
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);
        assert_eq!(i.to_u128(), None);
        assert_eq!(i.to_i128(), None);
        i.assign(i128::MAX);
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);
        assert_eq!(i.to_u128(), Some(i128::MAX.wrapping_as::<u128>()));
        assert_eq!(i.to_i128(), Some(i128::MAX));
        i += 1;
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);
        assert_eq!(i.to_u128(), Some(i128::MAX.wrapping_as::<u128>() + 1));
        assert_eq!(i.to_i128(), None);
        i.assign(u128::MAX);
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);
        assert_eq!(i.to_u128(), Some(u128::MAX));
        assert_eq!(i.to_i128(), None);
        i += 1;
        assert_eq!(i.to_u64(), None);
        assert_eq!(i.to_i64(), None);
        assert_eq!(i.to_u128(), None);
        assert_eq!(i.to_i128(), None);
    }

    #[test]
    fn check_float_conversions() {
        let mut i = Integer::from(0);
        assert_eq!(i.to_f32(), 0.0);
        assert_eq!(i.to_f64(), 0.0);
        i.assign(0xff);
        assert_eq!(i.to_f32(), 255.0);
        assert_eq!(i.to_f64(), 255.0);
        i <<= 80;
        assert_eq!(i.to_f32(), 255.0 * 2f32.powi(80));
        assert_eq!(i.to_f64(), 255.0 * 2f64.powi(80));
        i = i.clone() << 30 | i;
        assert_eq!(i.to_f32(), 255.0 * 2f32.powi(110));
        assert_eq!(i.to_f64(), 255.0 * (2f64.powi(80) + 2f64.powi(110)));
        i <<= 100;
        assert_eq!(i.to_f32(), f32::INFINITY);
        assert_eq!(i.to_f64(), 255.0 * (2f64.powi(180) + 2f64.powi(210)));
        i <<= 1000;
        assert_eq!(i.to_f32(), f32::INFINITY);
        assert_eq!(i.to_f64(), f64::INFINITY);
        i.assign(-0xff_ffff);
        assert_eq!(i.to_f32(), (-0xff_ffff).az::<f32>());
        assert_eq!(i.to_f64(), f64::from(-0xff_ffff));
        i.assign(-0xfff_ffff);
        assert_eq!(i.to_f32(), (-0xfff_fff0).az::<f32>());
        assert_eq!(i.to_f64(), f64::from(-0xfff_ffff));
    }

    #[test]
    fn check_from_str() {
        let mut i: Integer = "+134".parse().unwrap();
        assert_eq!(i, 134);
        i.assign(Integer::parse_radix("-ffFFffffFfFfffffffffffffffffffff", 16).unwrap());
        assert_eq!(i.significant_bits(), 128);
        i -= 1;
        assert_eq!(i.significant_bits(), 129);

        let bad_strings = [
            ("_1", 10, "invalid digit found in string"),
            ("+_1", 10, "invalid digit found in string"),
            ("-_1", 10, "invalid digit found in string"),
            ("+-3", 10, "invalid digit found in string"),
            ("-+3", 10, "invalid digit found in string"),
            ("++3", 10, "invalid digit found in string"),
            ("--3", 10, "invalid digit found in string"),
            ("0+3", 10, "invalid digit found in string"),
            ("", 10, "string has no digits"),
            (" ", 10, "string has no digits"),
            ("9\09", 10, "invalid digit found in string"),
            ("80", 8, "invalid digit found in string"),
            ("0xf", 16, "invalid digit found in string"),
            ("9", 9, "invalid digit found in string"),
            ("/0", 36, "invalid digit found in string"),
            (":0", 36, "invalid digit found in string"),
            ("@0", 36, "invalid digit found in string"),
            ("[0", 36, "invalid digit found in string"),
            ("`0", 36, "invalid digit found in string"),
            ("{0", 36, "invalid digit found in string"),
            ("Z0", 35, "invalid digit found in string"),
            ("z0", 35, "invalid digit found in string"),
        ];
        for &(s, radix, msg) in bad_strings.iter() {
            match Integer::parse_radix(s, radix) {
                Ok(o) => panic!(
                    "\"{}\" (radix {}) parsed correctly as {}, expected: {}",
                    s,
                    radix,
                    Integer::from(o),
                    msg
                ),
                Err(e) => assert_eq!(e.to_string(), msg, "\"{}\" (radix {})", s, radix),
            }
        }
        let good_strings = [
            ("0", 10, 0),
            ("+0", 16, 0),
            ("  + 1_2", 10, 12),
            ("  - 1_2", 10, -12),
            ("-0", 2, 0),
            ("99", 10, 99),
            ("+Cc", 16, 0xcc),
            ("-77", 8, -0o77),
            (" 1 2\n 3 4 ", 10, 1234),
            ("1_2__", 10, 12),
            ("z0", 36, 35 * 36),
            ("Z0", 36, 35 * 36),
        ];
        for &(s, radix, i) in good_strings.iter() {
            match Integer::parse_radix(s, radix) {
                Ok(ok) => assert_eq!(Integer::from(ok), i),
                Err(err) => panic!("could not parse {}: {}", s, err),
            }
        }
    }

    #[test]
    fn check_formatting() {
        let mut i = Integer::from(11);
        assert_eq!(format!("{}", i), "11");
        assert_eq!(format!("{:?}", i), "11");
        assert_eq!(format!("{:<10}", i), "11        ");
        assert_eq!(format!("{:>10}", i), "        11");
        assert_eq!(format!("{:10}", i), "        11");
        assert_eq!(format!("{:^10}", i), "    11    ");
        assert_eq!(format!("{:^11}", i), "    11     ");
        assert_eq!(format!("{:+}", i), "+11");
        assert_eq!(format!("{:b}", i), "1011");
        assert_eq!(format!("{:#b}", i), "0b1011");
        assert_eq!(format!("{:o}", i), "13");
        assert_eq!(format!("{:#o}", i), "0o13");
        assert_eq!(format!("{:x}", i), "b");
        assert_eq!(format!("{:X}", i), "B");
        assert_eq!(format!("{:8x}", i), "       b");
        assert_eq!(format!("{:08X}", i), "0000000B");
        assert_eq!(format!("{:#08x}", i), "0x00000b");
        assert_eq!(format!("{:#8X}", i), "     0xB");
        i.assign(-11);
        assert_eq!(format!("{}", i), "-11");
        assert_eq!(format!("{:?}", i), "-11");
        assert_eq!(format!("{:+}", i), "-11");
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

    #[test]
    fn check_to_digits_bool() {
        const T: bool = true;
        const F: bool = false;

        let i = Integer::from(0b111_0010);
        assert_eq!(i.significant_digits::<bool>(), 7);
        let mut buf: [bool; 10] = [true; 10];

        i.write_digits(&mut buf, Order::Lsf);
        assert_eq!(buf, [F, T, F, F, T, T, T, F, F, F]);
        i.write_digits(&mut buf, Order::LsfLe);
        assert_eq!(buf, [F, T, F, F, T, T, T, F, F, F]);
        i.write_digits(&mut buf, Order::LsfBe);
        assert_eq!(buf, [F, T, F, F, T, T, T, F, F, F]);
        i.write_digits(&mut buf, Order::Msf);
        assert_eq!(buf, [F, F, F, T, T, T, F, F, T, F]);
        i.write_digits(&mut buf, Order::MsfLe);
        assert_eq!(buf, [F, F, F, T, T, T, F, F, T, F]);
        i.write_digits(&mut buf, Order::MsfBe);
        assert_eq!(buf, [F, F, F, T, T, T, F, F, T, F]);

        let vec: Vec<bool> = i.to_digits(Order::MsfBe);
        assert_eq!(vec, [T, T, T, F, F, T, F]);
    }

    #[test]
    fn check_from_digits_bool() {
        const T: bool = true;
        const F: bool = false;

        let mut i = Integer::from_digits(&[T, T, T, F, F, T, F], Order::MsfBe);
        assert_eq!(i, 0b111_0010);

        i.assign_digits(&[T, F, F, F, T, T, T, F, F, F], Order::Lsf);
        assert_eq!(i, 0b111_0001);
        i.assign_digits(&[F, F, F, T, F, F, F, T, T, T], Order::Msf);
        assert_eq!(i, 0b100_0111);
        i.assign_digits(&[T, F, F, F, T, T, T, F, F, F], Order::LsfLe);
        assert_eq!(i, 0b111_0001);
        i.assign_digits(&[F, F, F, T, F, F, F, T, T, T], Order::MsfLe);
        assert_eq!(i, 0b100_0111);
        i.assign_digits(&[T, F, F, F, T, T, T, F, F, F], Order::LsfBe);
        assert_eq!(i, 0b111_0001);
        i.assign_digits(&[F, F, F, T, F, F, F, T, T, T], Order::MsfBe);
        assert_eq!(i, 0b100_0111);
    }

    #[test]
    fn check_to_digits_u8() {
        let i = Integer::from(0x01_02_03_04_05_06_07_08u64);
        assert_eq!(i.significant_digits::<u8>(), 8);
        let mut buf: [u8; 10] = [0xff; 10];

        i.write_digits(&mut buf, Order::Lsf);
        assert_eq!(buf, [8, 7, 6, 5, 4, 3, 2, 1, 0, 0]);
        i.write_digits(&mut buf, Order::LsfLe);
        assert_eq!(buf, [8, 7, 6, 5, 4, 3, 2, 1, 0, 0]);
        i.write_digits(&mut buf, Order::LsfBe);
        assert_eq!(buf, [8, 7, 6, 5, 4, 3, 2, 1, 0, 0]);
        i.write_digits(&mut buf, Order::Msf);
        assert_eq!(buf, [0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        i.write_digits(&mut buf, Order::MsfLe);
        assert_eq!(buf, [0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        i.write_digits(&mut buf, Order::MsfBe);
        assert_eq!(buf, [0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);

        let vec: Vec<u8> = i.to_digits(Order::MsfBe);
        assert_eq!(vec, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn check_from_digits_u8() {
        let mut i = Integer::from_digits(&[0u8, 0, 1, 2, 3, 4, 5, 6, 7, 8], Order::MsfBe);
        assert_eq!(i, 0x01_02_03_04_05_06_07_08u64);

        i.assign_digits(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0u8], Order::Lsf);
        assert_eq!(i, 0x08_07_06_05_04_03_02_01u64);
        i.assign_digits(&[0u8, 0, 1, 2, 3, 4, 5, 6, 7, 8], Order::Msf);
        assert_eq!(i, 0x01_02_03_04_05_06_07_08u64);
        i.assign_digits(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0u8], Order::LsfLe);
        assert_eq!(i, 0x08_07_06_05_04_03_02_01u64);
        i.assign_digits(&[0u8, 0, 1, 2, 3, 4, 5, 6, 7, 8], Order::MsfLe);
        assert_eq!(i, 0x01_02_03_04_05_06_07_08u64);
        i.assign_digits(&[1, 2, 3, 4, 5, 6, 7, 8, 0, 0u8], Order::LsfBe);
        assert_eq!(i, 0x08_07_06_05_04_03_02_01u64);
        i.assign_digits(&[0u8, 0, 1, 2, 3, 4, 5, 6, 7, 8], Order::MsfBe);
        assert_eq!(i, 0x01_02_03_04_05_06_07_08u64);
    }

    #[test]
    fn check_from_digits_resize() {
        // Ensure that we correctly handle increasing capacity
        let mut i = Integer::new();
        i.assign_digits(
            &[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8],
            Order::Lsf,
        );
    }

    #[test]
    fn check_to_digits_u16() {
        let le_0708 = 0x0708u16.to_le();
        let le_0506 = 0x0506u16.to_le();
        let le_0304 = 0x0304u16.to_le();
        let le_0102 = 0x0102u16.to_le();
        let be_0708 = 0x0708u16.to_be();
        let be_0506 = 0x0506u16.to_be();
        let be_0304 = 0x0304u16.to_be();
        let be_0102 = 0x0102u16.to_be();

        let i = Integer::from(0x0102_0304_0506_0708u64);
        assert_eq!(i.significant_digits::<u16>(), 4);
        let mut buf: [u16; 5] = [0xffff; 5];

        i.write_digits(&mut buf, Order::Lsf);
        assert_eq!(buf, [0x0708, 0x0506, 0x0304, 0x0102, 0]);
        i.write_digits(&mut buf, Order::LsfLe);
        assert_eq!(buf, [le_0708, le_0506, le_0304, le_0102, 0]);
        i.write_digits(&mut buf, Order::LsfBe);
        assert_eq!(buf, [be_0708, be_0506, be_0304, be_0102, 0]);
        i.write_digits(&mut buf, Order::Msf);
        assert_eq!(buf, [0, 0x0102, 0x0304, 0x0506, 0x0708]);
        i.write_digits(&mut buf, Order::MsfLe);
        assert_eq!(buf, [0, le_0102, le_0304, le_0506, le_0708]);
        i.write_digits(&mut buf, Order::MsfBe);
        assert_eq!(buf, [0, be_0102, be_0304, be_0506, be_0708]);

        let vec: Vec<u16> = i.to_digits(Order::MsfBe);
        assert_eq!(*vec, [be_0102, be_0304, be_0506, be_0708]);
    }

    #[test]
    fn check_from_digits_u16() {
        let le_0708 = 0x0708u16.to_le();
        let le_0506 = 0x0506u16.to_le();
        let le_0304 = 0x0304u16.to_le();
        let le_0102 = 0x0102u16.to_le();
        let be_0708 = 0x0708u16.to_be();
        let be_0506 = 0x0506u16.to_be();
        let be_0304 = 0x0304u16.to_be();
        let be_0102 = 0x0102u16.to_be();

        let mut i = Integer::from_digits(&[0u16, be_0102, be_0304, be_0506, be_0708], Order::MsfBe);
        assert_eq!(i, 0x0102_0304_0506_0708u64);

        i.assign_digits(&[0x0102, 0x0304, 0x0506, 0x0708, 0u16], Order::Lsf);
        assert_eq!(i, 0x0708_0506_0304_0102u64);
        i.assign_digits(&[0u16, 0x0102, 0x0304, 0x0506, 0x0708], Order::Msf);
        assert_eq!(i, 0x0102_0304_0506_0708u64);
        i.assign_digits(&[le_0102, le_0304, le_0506, le_0708, 0u16], Order::LsfLe);
        assert_eq!(i, 0x0708_0506_0304_0102u64);
        i.assign_digits(&[0u16, le_0102, le_0304, le_0506, le_0708], Order::MsfLe);
        assert_eq!(i, 0x0102_0304_0506_0708u64);
        i.assign_digits(&[be_0102, be_0304, be_0506, be_0708, 0u16], Order::LsfBe);
        assert_eq!(i, 0x0708_0506_0304_0102u64);
        i.assign_digits(&[0u16, be_0102, be_0304, be_0506, be_0708], Order::MsfBe);
        assert_eq!(i, 0x0102_0304_0506_0708u64);
    }

    #[test]
    fn check_to_digits_u128() {
        let le_2222 = 0x2222u128.to_le();
        let le_1111 = 0x1111u128.to_le();
        let be_2222 = 0x2222u128.to_be();
        let be_1111 = 0x1111u128.to_be();

        let i: Integer = (Integer::from(0x1111) << 256) | 0x2222;
        assert_eq!(i.significant_digits::<u128>(), 3);
        let mut buf: [u128; 5] = [0xffff; 5];

        i.write_digits(&mut buf, Order::Lsf);
        assert_eq!(buf, [0x2222, 0, 0x1111, 0, 0]);
        i.write_digits(&mut buf, Order::LsfLe);
        assert_eq!(buf, [le_2222, 0, le_1111, 0, 0]);
        i.write_digits(&mut buf, Order::LsfBe);
        assert_eq!(buf, [be_2222, 0, be_1111, 0, 0]);
        i.write_digits(&mut buf, Order::Msf);
        assert_eq!(buf, [0, 0, 0x1111, 0, 0x2222]);
        i.write_digits(&mut buf, Order::MsfLe);
        assert_eq!(buf, [0, 0, le_1111, 0, le_2222]);
        i.write_digits(&mut buf, Order::MsfBe);
        assert_eq!(buf, [0, 0, be_1111, 0, be_2222]);

        let vec: Vec<u128> = i.to_digits(Order::MsfBe);
        assert_eq!(*vec, [be_1111, 0, be_2222]);
    }

    #[test]
    fn check_from_digits_u128() {
        let le_2222 = 0x2222u128.to_le();
        let le_1111 = 0x1111u128.to_le();
        let be_2222 = 0x2222u128.to_be();
        let be_1111 = 0x1111u128.to_be();

        let i102: Integer = (Integer::from(0x1111) << 256) | 0x2222;
        let i201: Integer = (Integer::from(0x2222) << 256) | 0x1111;

        let mut i = Integer::from_digits(&[0u128, 0, be_1111, 0, be_2222], Order::MsfBe);
        assert_eq!(i, i102);

        i.assign_digits(&[0x1111, 0, 0x2222, 0, 0u128], Order::Lsf);
        assert_eq!(i, i201);
        i.assign_digits(&[0u128, 0, 0x1111, 0, 0x2222], Order::Msf);
        assert_eq!(i, i102);
        i.assign_digits(&[le_1111, 0, le_2222, 0, 0u128], Order::LsfLe);
        assert_eq!(i, i201);
        i.assign_digits(&[0u128, 0, le_1111, 0, le_2222], Order::MsfLe);
        assert_eq!(i, i102);
        i.assign_digits(&[be_1111, 0, be_2222, 0, 0u128], Order::LsfBe);
        assert_eq!(i, i201);
        i.assign_digits(&[0u128, 0, be_1111, 0, be_2222], Order::MsfBe);
        assert_eq!(i, i102);
    }
}
