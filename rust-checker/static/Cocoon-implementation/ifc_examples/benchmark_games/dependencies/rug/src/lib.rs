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
# Arbitrary-precision numbers

Rug provides integers and floating-point numbers with arbitrary
precision and correct rounding:

  * [`Integer`] is a bignum integer with arbitrary precision,
  * [`Rational`] is a bignum rational number with arbitrary precision,
  * [`Float`] is a multi-precision floating-point number with correct
    rounding, and
  * [`Complex`] is a multi-precision complex number with correct
    rounding.

Rug is a high-level interface to the following [GNU] libraries:

  * [GMP] for integers and rational numbers,
  * [MPFR] for floating-point numbers, and
  * [MPC] for complex numbers.

Rug is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version. See the full text of the [GNU LGPL] and
[GNU GPL] for details.

You are also free to use the examples in this documentation without
any restrictions; the examples are in the public domain.

## Quick example

```rust
# #[cfg(feature = "integer")] {
use rug::{Assign, Integer};
let mut int = Integer::new();
assert_eq!(int, 0);
int.assign(14);
assert_eq!(int, 14);

let decimal = "98_765_432_109_876_543_210";
int.assign(Integer::parse(decimal).unwrap());
assert!(int > 100_000_000);

let hex_160 = "ffff0000ffff0000ffff0000ffff0000ffff0000";
int.assign(Integer::parse_radix(hex_160, 16).unwrap());
assert_eq!(int.significant_bits(), 160);
int = (int >> 128) - 1;
assert_eq!(int, 0xfffe_ffff_u32);
# }
```

  * <code>[Integer][`Integer`]::[new][`new`]</code> creates a new
    [`Integer`] intialized to zero.
  * To assign values to Rug types, we use the [`Assign`] trait and its
    method [`Assign::assign`]. We do not use the
    [assignment operator `=`][assignment] as that would drop the
    left-hand-side operand and replace it with a right-hand-side
    operand of the same type, which is not what we want here.
  * Arbitrary precision numbers can hold numbers that are too large to
    fit in a primitive type. To assign such a number to the large
    types, we use strings rather than primitives; in the example this
    is done using <code>[Integer][`Integer`]::[parse][`parse`]</code>
    and
    <code>[Integer][`Integer`]::[parse_radix][`parse_radix`]</code>.
  * We can compare Rug types to primitive types or to other Rug types
    using the normal comparison operators, for example
    `int > 100_000_000`.
  * Most arithmetic operations are supported with Rug types and
    primitive types on either side of the operator, for example
    `int >> 128`.

## Using with primitive types

With Rust primitive types, arithmetic operators usually operate on two
values of the same type, for example `12i32 + 5i32`. Unlike primitive
types, conversion to and from Rug types can be expensive, so the
arithmetic operators are overloaded to work on many combinations of
Rug types and primitives. The following are provided:

 1. Where they make sense, all arithmetic operators are overloaded to
    work with Rug types and the primitives [`i8`], [`i16`], [`i32`],
    [`i64`], [`i128`], [`u8`], [`u16`], [`u32`], [`u64`], [`u128`],
    [`f32`] and [`f64`].
 2. Where they make sense, conversions using the [`From`] trait and
    assignments using the [`Assign`] trait are supported for all the
    primitives in 1 above as well as [`bool`], [`isize`] and
    [`usize`].
 3. Comparisons between Rug types and all the numeric primitives
    listed in 1 and 2 above are supported.
 4. For [`Rational`] numbers, conversions and comparisons are also
    supported for tuples containing two integer primitives: the first
    is the numerator and the second is the denominator which must not
    be zero. The two primitives do not need to be of the same type.
 5. For [`Complex`] numbers, conversions and comparisons are also
    supported for tuples containing two primitives: the first is the
    real part and the second is the imaginary part. The two primitives
    do not need to be of the same type.

## Operators

Operators are overloaded to work on Rug types alone or on a
combination of Rug types and Rust primitives. When at least one
operand is an owned value of a Rug type, the operation will consume
that value and return a value of the Rug type. For example

```rust
# #[cfg(feature = "integer")] {
use rug::Integer;
let a = Integer::from(10);
let b = 5 - a;
assert_eq!(b, 5 - 10);
# }
```

Here `a` is consumed by the subtraction, and `b` is an owned
[`Integer`].

If on the other hand there are no owned Rug types and there are
references instead, the returned value is not the final value, but an
incomplete-computation value. For example

```rust
# #[cfg(feature = "integer")] {
use rug::Integer;
let (a, b) = (Integer::from(10), Integer::from(20));
let incomplete = &a - &b;
// This would fail to compile: assert_eq!(incomplete, -10);
let sub = Integer::from(incomplete);
assert_eq!(sub, -10);
# }
```

Here `a` and `b` are not consumed, and `incomplete` is not the final
value. It still needs to be converted or assigned into an [`Integer`].
This is covered in more detail in the
[*Incomplete-computation values*] section.

### Shifting operations

The left shift `<<` and right shift `>>` operators support shifting by
negative values, for example `a << 5` is equivalent to `a >> -5`.

The shifting operators are also supported for the [`Float`] and
[`Complex`] number types, where they are equivalent to multiplication
or division by a power of two. Only the exponent of the value is
affected; the mantissa is unchanged.

### Exponentiation

Exponentiation (raising to a power) does not have a dedicated operator
in Rust. In order to perform exponentiation of Rug types, the [`Pow`]
trait has to be brought into scope, for example

```rust
# #[cfg(feature = "integer")] {
use rug::{ops::Pow, Integer};
let base = Integer::from(10);
let power = base.pow(5);
assert_eq!(power, 100_000);
# }
```

### Compound assignments to right-hand-side operands

Traits are provided for compound assignment to right-hand-side
operands. This can be useful for non-commutative operations like
subtraction. The names of the traits and their methods are similar to
Rust compound assignment traits, with the suffix “`Assign`” replaced
with “`From`”. For example the counterpart to [`SubAssign`] is
[`SubFrom`]:

```rust
# #[cfg(feature = "integer")] {
use rug::{ops::SubFrom, Integer};
let mut rhs = Integer::from(10);
// set rhs = 100 − rhs
rhs.sub_from(100);
assert_eq!(rhs, 90);
# }
```

## Incomplete-computation values

There are two main reasons why operations like `&a - &b` do not
perform a complete computation and return a Rug type:

 1. Sometimes we need to assign the result to an object that already
    exists. Since Rug types require memory allocations, this can help
    reduce the number of allocations. (While the allocations might not
    affect performance noticeably for computationally intensive
    functions, they can have a much more significant effect on faster
    functions like addition.)
 2. For the [`Float`] and [`Complex`] number types, we need to know
    the precision when we create a value, and the operation itself
    does not convey information about what precision is desired for
    the result.

There are two things that can be done with incomplete-computation
values:

 1. Assign them to an existing object without unnecessary allocations.
    This is usually achieved using the [`Assign`] trait or a similar
    method, for example
    <code>int.[assign][`Assign::assign`](incomplete)</code> and
    <code>float.[assign_round][`assign_round`](incomplete, [Round][`Round`]::[Up][`Up`])</code>.
 2. Convert them to the final value using the [`From`] trait or a
    similar method, for example
    <code>[Integer][`Integer`]::[from][`From::from`](incomplete)</code>
    and
    <code>[Float][`Float`]::[with_val][`with_val`](53, incomplete)</code>.

Let us consider a couple of examples.

```rust
# #[cfg(feature = "integer")] {
use rug::{Assign, Integer};
let mut buffer = Integer::new();
// ... buffer can be used and reused ...
let (a, b) = (Integer::from(10), Integer::from(20));
let incomplete = &a - &b;
buffer.assign(incomplete);
assert_eq!(buffer, -10);
# }
```

Here the assignment from `incomplete` into `buffer` does not require
an allocation unless the result does not fit in the current capacity
of `buffer`. If `&a - &b` returned an [`Integer`] instead, then an
allocation would take place even if it is not necessary.

```rust
# #[cfg(feature = "float")] {
use rug::{float::Constant, Float};
// x has a precision of 10 bits
let x = Float::with_val(10, 180);
// y has a precision of 50 bits
let y = Float::with_val(50, Constant::Pi);
let incomplete = &x / &y;
// z has a precision of 45 bits
let z = Float::with_val(45, incomplete);
assert!(57.295 < z && z < 57.296);
# }
```

The precision to use for the result depends on the requirements of the
algorithm being implemented. Here `z` is created with a precision
of 45.

Many operations can return incomplete-computation values, for example

  * unary operators applied to references, for example `-&int`
  * binary operators applied to two references, for example
    `&int1 + &int2`
  * binary operators applied to a primitive and a reference, for
    example `&int * 10`
  * methods that take a reference, for example
    <code>int.[abs_ref][`abs_ref`]()</code>
  * methods that take two references, for example
    <code>int1.[gcd_ref][`gcd_ref`](&amp;int2)</code>
  * string parsing, for example
    <code>[Integer][`Integer`]::[parse][`parse`]("12")</code>

These operations return objects that can be stored in temporary
variables like `incomplete` in the last few code examples. However,
the names of the types are not public, and consequently, the
incomplete-computation values cannot be for example stored in a
struct. If you need to store the value in a struct, convert it to its
final type and value.

## Using Rug

Rug is available on [crates.io][rug crate]. To use Rug in your crate,
add it as a dependency inside [*Cargo.toml*]:

```toml
[dependencies]
rug = "1.12"
```

Rug requires rustc version 1.37.0 or later.

Rug also depends on the [GMP], [MPFR] and [MPC] libraries through the
low-level FFI bindings in the [gmp-mpfr-sys crate][sys crate], which
needs some setup to build; the [gmp-mpfr-sys documentation][sys] has
some details on usage under [GNU/Linux][sys gnu], [macOS][sys mac] and
[Windows][sys win].

## Optional features

The Rug crate has six optional features:

 1. `integer`, enabled by default. Required for the [`Integer`] type
    and its supporting features.
 2. `rational`, enabled by default. Required for the [`Rational`]
    number type and its supporting features. This feature requires the
    `integer` feature.
 3. `float`, enabled by default. Required for the [`Float`] type and
    its supporting features.
 4. `complex`, enabled by default. Required for the [`Complex`] number
    type and its supporting features. This feature requires the
    `float` feature.
 5. `rand`, enabled by default. Required for the [`RandState`] type
    and its supporting features. This feature requires the `integer`
    feature.
 6. `serde`, disabled by default. This provides serialization support
    for the [`Integer`], [`Rational`], [`Float`] and [`Complex`]
    number types, providing that they are enabled. This feature
    requires the [serde crate].

The first five optional features are enabled by default; to use
features selectively, you can add the dependency like this to
[*Cargo.toml*]:

```toml
[dependencies.rug]
version = "1.12"
default-features = false
features = ["integer", "float", "rand"]
```

Here only the `integer`, `float` and `rand` features are enabled. If
none of the features are selected, the [gmp-mpfr-sys crate][sys crate]
is not required and thus not enabled. In that case, only the
[`Assign`] trait and the traits that are in the [`ops`] module are
provided by the crate.

[*Cargo.toml*]: https://doc.rust-lang.org/cargo/guide/dependencies.html
[*Incomplete-computation values*]: #incomplete-computation-values
[GMP]: https://gmplib.org/
[GNU GPL]: https://www.gnu.org/licenses/gpl-3.0.html
[GNU LGPL]: https://www.gnu.org/licenses/lgpl-3.0.en.html
[GNU]: https://www.gnu.org/
[MPC]: http://www.multiprecision.org/mpc/
[MPFR]: https://www.mpfr.org/
[`Assign::assign`]: trait.Assign.html#tymethod.assign
[`Assign`]: trait.Assign.html
[`Complex`]: struct.Complex.html
[`Float`]: struct.Float.html
[`From::from`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from
[`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
[`Integer`]: struct.Integer.html
[`Pow`]: ops/trait.Pow.html
[`RandState`]: rand/struct.RandState.html
[`Rational`]: struct.Rational.html
[`Round`]: float/enum.Round.html
[`SubAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.SubAssign.html
[`SubFrom`]: ops/trait.SubFrom.html
[`Up`]: float/enum.Round.html#variant.Up
[`abs_ref`]: struct.Integer.html#method.abs_ref
[`assign_round`]: ops/trait.AssignRound.html#tymethod.assign_round
[`bool`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
[`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
[`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
[`gcd_ref`]: struct.Integer.html#method.gcd_ref
[`i128`]: https://doc.rust-lang.org/nightly/std/primitive.i128.html
[`i16`]: https://doc.rust-lang.org/nightly/std/primitive.i16.html
[`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
[`i64`]: https://doc.rust-lang.org/nightly/std/primitive.i64.html
[`i8`]: https://doc.rust-lang.org/nightly/std/primitive.i8.html
[`isize`]: https://doc.rust-lang.org/nightly/std/primitive.isize.html
[`new`]: struct.Integer.html#method.new
[`ops`]: ops/index.html
[`parse_radix`]: struct.Integer.html#method.parse_radix
[`parse`]: struct.Integer.html#method.parse
[`u128`]: https://doc.rust-lang.org/nightly/std/primitive.u128.html
[`u16`]: https://doc.rust-lang.org/nightly/std/primitive.u16.html
[`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
[`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
[`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
[`usize`]: https://doc.rust-lang.org/nightly/std/primitive.usize.html
[`with_val`]: struct.Float.html#method.with_val
[assignment]: https://doc.rust-lang.org/reference/expressions/operator-expr.html#assignment-expressions
[rug crate]: https://crates.io/crates/rug
[serde crate]: https://crates.io/crates/serde
[sys crate]: https://crates.io/crates/gmp-mpfr-sys
[sys gnu]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/index.html#building-on-gnulinux
[sys mac]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/index.html#building-on-macos
[sys win]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/index.html#building-on-windows
[sys]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/index.html
*/
#![warn(missing_docs)]
#![doc(html_root_url = "https://docs.rs/rug/~1.12")]
#![doc(html_logo_url = "https://tspiteri.gitlab.io/rug/rug.svg")]
#![doc(test(attr(deny(warnings))))]
#![cfg_attr(feature = "fail-on-warnings", deny(warnings))]
// allowed to deal with e.g. 1i32.into(): c_long which can be i32 or i64
#![allow(clippy::useless_conversion)]
// matches! requires rustc 1.42
#![allow(clippy::match_like_matches_macro)]
#[macro_use]
mod macros;
mod ext;
#[cfg(any(feature = "integer", feature = "float"))]
mod misc;
mod ops_prim;
#[cfg(all(feature = "serde", any(feature = "integer", feature = "float")))]
mod serdeize;

pub mod ops;

/**
Assigns to a number from another value.

# Examples

```rust
use rug::Assign;
struct I(i32);
impl Assign<i16> for I {
    fn assign(&mut self, rhs: i16) {
        self.0 = rhs.into();
    }
}
let mut i = I(0);
i.assign(42_i16);
assert_eq!(i.0, 42);
```
*/
pub trait Assign<Src = Self> {
    /// Peforms the assignement.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "integer")] {
    /// use rug::{Assign, Integer};
    /// let mut i = Integer::from(15);
    /// assert_eq!(i, 15);
    /// i.assign(23);
    /// assert_eq!(i, 23);
    /// # }
    /// ```
    fn assign(&mut self, src: Src);
}

#[cfg(feature = "integer")]
pub mod integer;
#[cfg(feature = "integer")]
pub use crate::integer::big::Integer;

#[cfg(feature = "rational")]
pub mod rational;
#[cfg(feature = "rational")]
pub use crate::rational::big::Rational;

#[cfg(feature = "float")]
pub mod float;
#[cfg(feature = "float")]
pub use crate::float::big::Float;

#[cfg(feature = "complex")]
pub mod complex;
#[cfg(feature = "complex")]
pub use crate::complex::big::Complex;

#[cfg(feature = "rand")]
pub mod rand;

#[cfg(any(feature = "integer", feature = "float"))]
mod static_assertions {
    use core::mem;
    use gmp_mpfr_sys::gmp::{limb_t, LIMB_BITS, NAIL_BITS, NUMB_BITS};

    static_assert!(NAIL_BITS == 0);
    static_assert!(NUMB_BITS == LIMB_BITS);
    static_assert!(cfg!(target_pointer_width = "32") ^ cfg!(target_pointer_width = "64"));
    static_assert!(cfg!(gmp_limb_bits_32) ^ cfg!(gmp_limb_bits_64));
    #[cfg(gmp_limb_bits_64)]
    static_assert!(NUMB_BITS == 64);
    #[cfg(gmp_limb_bits_32)]
    static_assert!(NUMB_BITS == 32);
    static_assert!(NUMB_BITS % 8 == 0);
    static_assert!(mem::size_of::<limb_t>() == NUMB_BITS as usize / 8);
}

#[cfg(all(test, any(feature = "integer", feature = "float")))]
mod tests {
    #[cfg(any(feature = "rational", feature = "float"))]
    use core::{f32, f64};
    use core::{i128, i16, i32, i64, i8, u128, u16, u32, u64, u8};

    pub const U8: &[u8] = &[0, 1, 100, 101, i8::MAX as u8 + 1, u8::MAX];
    pub const I8: &[i8] = &[i8::MIN, -101, -100, -1, 0, 1, 100, 101, i8::MAX];
    pub const U16: &[u16] = &[0, 1, 1000, 1001, i16::MAX as u16 + 1, u16::MAX];
    pub const I16: &[i16] = &[i16::MIN, -1001, -1000, -1, 0, 1, 1000, 1001, i16::MAX];
    pub const U32: &[u32] = &[0, 1, 1000, 1001, i32::MAX as u32 + 1, u32::MAX];
    pub const I32: &[i32] = &[i32::MIN, -1001, -1000, -1, 0, 1, 1000, 1001, i32::MAX];
    pub const U64: &[u64] = &[
        0,
        1,
        1000,
        1001,
        i32::MAX as u64 + 1,
        u32::MAX as u64 + 1,
        u64::MAX,
    ];
    pub const I64: &[i64] = &[
        i64::MIN,
        -(u32::MAX as i64) - 1,
        i32::MIN as i64 - 1,
        -1001,
        -1000,
        -1,
        0,
        1,
        1000,
        1001,
        i32::MAX as i64 + 1,
        u32::MAX as i64 + 1,
        i64::MAX,
    ];
    pub const U128: &[u128] = &[
        0,
        1,
        1000,
        1001,
        i32::MAX as u128 + 1,
        u32::MAX as u128 + 1,
        i64::MAX as u128 + 1,
        u64::MAX as u128 + 1,
        u128::MAX,
    ];
    pub const I128: &[i128] = &[
        i128::MIN,
        -(u64::MAX as i128) - 1,
        i64::MIN as i128 - 1,
        -(u32::MAX as i128) - 1,
        i32::MIN as i128 - 1,
        -1001,
        -1000,
        -1,
        0,
        1,
        1000,
        1001,
        i32::MAX as i128 + 1,
        u32::MAX as i128 + 1,
        i64::MAX as i128 + 1,
        u64::MAX as i128 + 1,
        i128::MAX,
    ];
    #[cfg(any(feature = "rational", feature = "float"))]
    pub const F32: &[f32] = &[
        -f32::NAN,
        f32::NEG_INFINITY,
        f32::MIN,
        -12.0e30,
        -2.0,
        -1.0 - f32::EPSILON,
        -1.0,
        -f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE * f32::EPSILON,
        -0.0,
        0.0,
        f32::MIN_POSITIVE * f32::EPSILON,
        f32::MIN_POSITIVE,
        1.0,
        1.0 + f32::EPSILON,
        2.0,
        12.0e30,
        f32::MAX,
        f32::INFINITY,
        f32::NAN,
    ];
    #[cfg(any(feature = "rational", feature = "float"))]
    pub const F64: &[f64] = &[
        -f64::NAN,
        f64::NEG_INFINITY,
        f64::MIN,
        -12.0e43,
        -2.0,
        -1.0 - f64::EPSILON,
        -1.0,
        -f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE * f64::EPSILON,
        -0.0,
        0.0,
        f64::MIN_POSITIVE * f64::EPSILON,
        f64::MIN_POSITIVE,
        1.0,
        1.0 + f64::EPSILON,
        2.0,
        12.0e43,
        f64::MAX,
        f64::INFINITY,
        f64::NAN,
    ];
}
