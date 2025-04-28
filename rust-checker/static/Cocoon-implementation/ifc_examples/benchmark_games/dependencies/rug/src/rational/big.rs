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

use crate::{
    ext::{xmpq, xmpz},
    integer::big as big_integer,
    Assign, Integer,
};
use az::{Cast, CheckedCast, UnwrappedAs, UnwrappedCast};
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ops::{Add, AddAssign, Deref, Mul, MulAssign},
};
use gmp_mpfr_sys::gmp::{self, mpq_t};
use std::error::Error;

/**
An arbitrary-precision rational number.

A `Rational` number is made up of a numerator [`Integer`] and
denominator [`Integer`]. After `Rational` number functions, the number
is always in canonical form, that is the denominator is always greater
than zero, and there are no common factors. Zero is stored as 0/1.

# Examples

```rust
use rug::Rational;
let r = Rational::from((-12, 15));
let recip = Rational::from(r.recip_ref());
assert_eq!(recip, (-5, 4));
assert_eq!(recip.to_f32(), -1.25);
// The numerator and denominator are stored in canonical form.
let (num, den) = r.into_numer_denom();
assert_eq!(num, -4);
assert_eq!(den, 5);
```

The `Rational` number type supports various functions. Most methods
have three versions:

 1. The first method consumes the operand.
 2. The second method has a “`_mut`” suffix and mutates the operand.
 3. The third method has a “`_ref`” suffix and borrows the operand.
    The returned item is an [incomplete-computation value][icv] that
    can be assigned to a `Rational` number.

```rust
use rug::Rational;

// 1. consume the operand
let a = Rational::from((-15, 2));
let abs_a = a.abs();
assert_eq!(abs_a, (15, 2));

// 2. mutate the operand
let mut b = Rational::from((-17, 2));
b.abs_mut();
assert_eq!(b, (17, 2));

// 3. borrow the operand
let c = Rational::from((-19, 2));
let r = c.abs_ref();
let abs_c = Rational::from(r);
assert_eq!(abs_c, (19, 2));
// c was not consumed
assert_eq!(c, (-19, 2));
```

[`Integer`]: struct.Integer.html
[icv]: index.html#incomplete-computation-values
*/
#[repr(transparent)]
pub struct Rational {
    inner: mpq_t,
}

static_assert_same_layout!(Rational, mpq_t);
static_assert_same_layout!(BorrowRational<'_>, mpq_t);

static_assert_same_size!(Rational, Option<Rational>);

macro_rules! ref_rat_op_int {
    (
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
         $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a Rational,
            $($param: $T,)*
        }

        impl Assign<$Incomplete<'_>> for Integer {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self, src.ref_self, $(src.$param),*);
            }
        }

        from_assign! { $Incomplete<'_> => Integer }
    };
}

macro_rules! ref_rat_op_rat_int {
    (
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
         $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a Rational,
            $($param: $T,)*
        }

        impl Assign<$Incomplete<'_>> for (&mut Rational, & mut Integer) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self.0, self.1, src.ref_self, $(src.$param),*);
            }
        }

        impl Assign<$Incomplete<'_>> for (Rational, Integer) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                Assign::assign(&mut (&mut self.0, &mut self.1), src);
            }
        }

        impl From<$Incomplete<'_>> for (Rational, Integer) {
            #[inline]
            fn from(src: $Incomplete<'_>) -> Self {
                let mut dst = Self::default();
                Assign::assign(&mut dst, src);
                dst
            }
        }
    };
}

impl Rational {
    /// Constructs a new arbitrary-precision [`Rational`] number with
    /// value 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::new();
    /// assert_eq!(r, 0);
    /// ```
    ///
    /// [`Rational`]: #
    #[inline]
    pub fn new() -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            gmp::mpq_init(cast_ptr_mut!(ret.as_mut_ptr(), mpq_t));
            ret.assume_init()
        }
    }

    /// Creates a [`Rational`] number from an initialized
    /// [GMP rational number][`mpq_t`].
    ///
    /// # Safety
    ///
    ///   * The function must *not* be used to create a constant
    ///     [`Rational`] number, though it can be used to create a
    ///     static [`Rational`] number. This is because constant
    ///     values are *copied* on use, leading to undefined behaviour
    ///     when they are dropped.
    ///   * The value must be initialized.
    ///   * The [`mpq_t`] type can be considered as a kind of pointer,
    ///     so there can be multiple copies of it. Since this function
    ///     takes over ownership, no other copies of the passed value
    ///     should exist.
    ///   * The numerator and denominator must be in canonical form,
    ///     as the rest of the library assumes that they are. Most GMP
    ///     functions leave the rational number in canonical form, but
    ///     assignment functions do not. Check the
    ///     [GMP documentation][gmp mpq] for details.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::mem::MaybeUninit;
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Rational;
    /// let r = unsafe {
    ///     let mut q = MaybeUninit::uninit();
    ///     gmp::mpq_init(q.as_mut_ptr());
    ///     let mut q = q.assume_init();
    ///     gmp::mpq_set_si(&mut q, -145, 10);
    ///     gmp::mpq_canonicalize(&mut q);
    ///     // q is initialized and unique
    ///     Rational::from_raw(q)
    /// };
    /// assert_eq!(r, (-145, 10));
    /// // since r is a Rational now, deallocation is automatic
    /// ```
    ///
    /// This can be used to create a static [`Rational`] number using
    /// [`MPZ_ROINIT_N`] to initialize the raw numerator and
    /// denominator values. See the [GMP documentation][gmp roinit]
    /// for details.
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp::{self, limb_t, mpq_t};
    /// use rug::{Integer, Rational};
    /// const NUMER_LIMBS: [limb_t; 2] = [0, 5];
    /// const DENOM_LIMBS: [limb_t; 1] = [3];
    /// const MPQ: mpq_t = unsafe {
    ///     mpq_t {
    ///         num: gmp::MPZ_ROINIT_N(NUMER_LIMBS.as_ptr() as *mut limb_t, -2),
    ///         den: gmp::MPZ_ROINIT_N(DENOM_LIMBS.as_ptr() as *mut limb_t, 1),
    ///     }
    /// };
    /// // Must *not* be const, otherwise it would lead to undefined
    /// // behavior on use, as it would create a copy that is dropped.
    /// static R: Rational = unsafe { Rational::from_raw(MPQ) };
    /// let numer_check =
    ///     -((Integer::from(NUMER_LIMBS[1]) << gmp::NUMB_BITS) + NUMER_LIMBS[0]);
    /// let denom_check = Integer::from(DENOM_LIMBS[0]);
    /// assert_eq!(*R.numer(), numer_check);
    /// assert_eq!(*R.denom(), denom_check);
    /// let check = Rational::from((&numer_check, &denom_check));
    /// assert_eq!(R, check);
    /// assert_eq!(*R.numer(), *check.numer());
    /// assert_eq!(*R.denom(), *check.denom());
    /// ```
    ///
    /// [`MPZ_ROINIT_N`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/fn.MPZ_ROINIT_N.html
    /// [`Rational`]: #
    /// [`mpq_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpq_t.html
    /// [gmp mpq]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/C/GMP/constant.Rational_Number_Functions.html#index-Rational-number-functions
    /// [gmp roinit]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/C/GMP/constant.Integer_Functions.html#index-MPZ_005fROINIT_005fN
    #[inline]
    pub const unsafe fn from_raw(raw: mpq_t) -> Self {
        Rational { inner: raw }
    }

    /// Converts a [`Rational`] number into a
    /// [GMP rational number][`mpq_t`].
    ///
    /// The returned object should be freed to avoid memory leaks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Rational;
    /// let r = Rational::from((-145, 10));
    /// let mut q = r.into_raw();
    /// unsafe {
    ///     let d = gmp::mpq_get_d(&q);
    ///     assert_eq!(d, -14.5);
    ///     // free object to prevent memory leak
    ///     gmp::mpq_clear(&mut q);
    /// }
    /// ```
    ///
    /// [`Rational`]: #
    /// [`mpq_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpq_t.html
    #[inline]
    pub fn into_raw(self) -> mpq_t {
        let m = ManuallyDrop::new(self);
        m.inner
    }

    /// Returns a pointer to the inner [GMP rational number][`mpq_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Rational;
    /// let r = Rational::from((-145, 10));
    /// let q_ptr = r.as_raw();
    /// unsafe {
    ///     let d = gmp::mpq_get_d(q_ptr);
    ///     assert_eq!(d, -14.5);
    /// }
    /// // r is still valid
    /// assert_eq!(r, (-145, 10));
    /// ```
    ///
    /// [`mpq_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpq_t.html
    #[inline]
    pub fn as_raw(&self) -> *const mpq_t {
        &self.inner
    }

    /// Returns an unsafe mutable pointer to the inner
    /// [GMP rational number][`mpq_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Rational;
    /// let mut r = Rational::from((-145, 10));
    /// let q_ptr = r.as_raw_mut();
    /// unsafe {
    ///     gmp::mpq_inv(q_ptr, q_ptr);
    /// }
    /// assert_eq!(r, (-10, 145));
    /// ```
    ///
    /// [`mpq_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpq_t.html
    #[inline]
    pub fn as_raw_mut(&mut self) -> *mut mpq_t {
        &mut self.inner
    }

    /// Creates a [`Rational`] number from an [`f32`] if it is
    /// [finite][`is_finite`], losing no precision.
    ///
    /// This conversion can also be performed using
    ///   * <code>[Rational][`Rational`]::[try_from][`try_from`](value)</code>
    ///   * <code>value.[checked\_as][`checked_as`]::&lt;[Rational][`Rational`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::Rational;
    /// // −17.125 can be stored exactly as f32
    /// let r = Rational::from_f32(-17.125).unwrap();
    /// assert_eq!(r, (-17125, 1000));
    /// let inf = Rational::from_f32(f32::INFINITY);
    /// assert!(inf.is_none());
    /// ```
    ///
    /// [`Rational`]: #
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html#method.is_finite
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn from_f32(value: f32) -> Option<Self> {
        value.checked_cast()
    }

    /// Creates a [`Rational`] number from an [`f64`] if it is
    /// [finite][`is_finite`], losing no precision.
    ///
    /// This conversion can also be performed using
    ///   * <code>[Rational][`Rational`]::[try_from][`try_from`](value)</code>
    ///   * <code>value.[checked\_as][`checked_as`]::&lt;[Rational][`Rational`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Rational;
    /// // −17.125 can be stored exactly as f64
    /// let r = Rational::from_f64(-17.125).unwrap();
    /// assert_eq!(r, (-17125, 1000));
    /// let inf = Rational::from_f64(f64::INFINITY);
    /// assert!(inf.is_none());
    /// ```
    ///
    /// [`Rational`]: #
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html#method.is_finite
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn from_f64(value: f64) -> Option<Self> {
        value.checked_cast()
    }

    /// Parses a [`Rational`] number.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r1 = Rational::from_str_radix("ff/a", 16).unwrap();
    /// assert_eq!(r1, (255, 10));
    /// let r2 = Rational::from_str_radix("+ff0/a0", 16).unwrap();
    /// assert_eq!(r2, (0xff0, 0xa0));
    /// assert_eq!(*r2.numer(), 51);
    /// assert_eq!(*r2.denom(), 2);
    /// ```
    ///
    /// [`Rational`]: #
    #[inline]
    pub fn from_str_radix(src: &str, radix: i32) -> Result<Self, ParseRationalError> {
        Ok(Rational::from(Rational::parse_radix(src, radix)?))
    }

    /// Parses a decimal string slice (<code>&amp;[str]</code>) or
    /// byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into a
    /// [`Rational`] number.
    ///
    /// The following are implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// The string must contain a numerator, and may contain a
    /// denominator; the numerator and denominator are separated with
    /// a “`/`”. The numerator can start with an optional minus or
    /// plus sign.
    ///
    /// ASCII whitespace is ignored everywhere in the string.
    /// Underscores are ignored anywhere except before the first digit
    /// of the numerator and between the “`/`” and the the first digit
    /// of the denominator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// let valid1 = Rational::parse("-12/23");
    /// let r1 = Rational::from(valid1.unwrap());
    /// assert_eq!(r1, (-12, 23));
    /// let valid2 = Rational::parse("+ 12 / 23");
    /// let r2 = Rational::from(valid2.unwrap());
    /// assert_eq!(r2, (12, 23));
    ///
    /// let invalid = Rational::parse("12/");
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse<S: AsRef<[u8]>>(src: S) -> Result<ParseIncomplete, ParseRationalError> {
        parse(src.as_ref(), 10)
    }

    /// Parses a string slice (<code>&amp;[str]</code>) or byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into a
    /// [`Rational`] number.
    ///
    /// The following are implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// The string must contain a numerator, and may contain a
    /// denominator; the numerator and denominator are separated with
    /// a “`/`”. The numerator can start with an optional minus or
    /// plus sign.
    ///
    /// ASCII whitespace is ignored everywhere in the string.
    /// Underscores are ignored anywhere except before the first digit
    /// of the numerator and between the “`/`” and the the first digit
    /// of the denominator.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// let valid1 = Rational::parse_radix("12/23", 4);
    /// let r1 = Rational::from(valid1.unwrap());
    /// assert_eq!(r1, (2 + 4 * 1, 3 + 4 * 2));
    /// let valid2 = Rational::parse_radix("12 / yz", 36);
    /// let r2 = Rational::from(valid2.unwrap());
    /// assert_eq!(r2, (2 + 36 * 1, 35 + 36 * 34));
    ///
    /// let invalid = Rational::parse_radix("12/", 10);
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse_radix<S: AsRef<[u8]>>(
        src: S,
        radix: i32,
    ) -> Result<ParseIncomplete, ParseRationalError> {
        parse(src.as_ref(), radix)
    }

    /// Converts to an [`f32`], rounding towards zero.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;rational).[az][`az`]::&lt;[f32][`f32`]&gt;()</code>
    ///   * <code>rational.[borrow][`borrow`]().[az][`az`]::&lt;[f32][`f32`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::{rational::SmallRational, Rational};
    /// let min = Rational::from_f32(f32::MIN).unwrap();
    /// let minus_small = min - &*SmallRational::from((7, 2));
    /// // minus_small is truncated to f32::MIN
    /// assert_eq!(minus_small.to_f32(), f32::MIN);
    /// let times_three_two = minus_small * &*SmallRational::from((3, 2));
    /// // times_three_two is too small
    /// assert_eq!(times_three_two.to_f32(), f32::NEG_INFINITY);
    /// ```
    ///
    /// [`az`]: https://docs.rs/az/1/az/trait.Az.html#tymethod.az
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    #[inline]
    pub fn to_f32(&self) -> f32 {
        self.cast()
    }

    /// Converts to an [`f64`], rounding towards zero.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;rational).[az][`az`]::&lt;[f64][`f64`]&gt;()</code>
    ///   * <code>rational.[borrow][`borrow`]().[az][`az`]::&lt;[f64][`f64`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::{rational::SmallRational, Rational};
    ///
    /// // An `f64` has 53 bits of precision.
    /// let exact = 0x1f_1234_5678_9aff_u64;
    /// let den = 0x1000_u64;
    /// let r = Rational::from((exact, den));
    /// assert_eq!(r.to_f64(), exact as f64 / den as f64);
    ///
    /// // large has 56 ones
    /// let large = 0xff_1234_5678_9aff_u64;
    /// // trunc has 53 ones followed by 3 zeros
    /// let trunc = 0xff_1234_5678_9af8_u64;
    /// let j = Rational::from((large, den));
    /// assert_eq!(j.to_f64(), trunc as f64 / den as f64);
    ///
    /// let max = Rational::from_f64(f64::MAX).unwrap();
    /// let plus_small = max + &*SmallRational::from((7, 2));
    /// // plus_small is truncated to f64::MAX
    /// assert_eq!(plus_small.to_f64(), f64::MAX);
    /// let times_three_two = plus_small * &*SmallRational::from((3, 2));
    /// // times_three_two is too large
    /// assert_eq!(times_three_two.to_f64(), f64::INFINITY);
    /// ```
    ///
    /// [`az`]: https://docs.rs/az/1/az/trait.Az.html#tymethod.az
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    #[inline]
    pub fn to_f64(&self) -> f64 {
        self.cast()
    }

    /// Returns a string representation for the specified `radix`.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r1 = Rational::from(0);
    /// assert_eq!(r1.to_string_radix(10), "0");
    /// let r2 = Rational::from((15, 5));
    /// assert_eq!(r2.to_string_radix(10), "3");
    /// let r3 = Rational::from((10, -6));
    /// assert_eq!(r3.to_string_radix(10), "-5/3");
    /// assert_eq!(r3.to_string_radix(5), "-10/3");
    /// ```
    #[inline]
    pub fn to_string_radix(&self, radix: i32) -> String {
        let mut s = String::new();
        append_to_string(&mut s, self, radix, false);
        s
    }

    /// Assigns from an [`f32`] if it is [finite][`is_finite`], losing
    /// no precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::Rational;
    /// let mut r = Rational::new();
    /// let ret = r.assign_f32(12.75);
    /// assert!(ret.is_ok());
    /// assert_eq!(r, (1275, 100));
    /// let ret = r.assign_f32(f32::NAN);
    /// assert!(ret.is_err());
    /// assert_eq!(r, (1275, 100));
    /// ```
    ///
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html#method.is_finite
    #[inline]
    #[allow(clippy::result_unit_err)]
    pub fn assign_f32(&mut self, val: f32) -> Result<(), ()> {
        self.assign_f64(val.into())
    }

    /// Assigns from an [`f64`] if it is [finite][`is_finite`], losing
    /// no precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::new();
    /// let ret = r.assign_f64(12.75);
    /// assert!(ret.is_ok());
    /// assert_eq!(r, (1275, 100));
    /// let ret = r.assign_f64(1.0 / 0.0);
    /// assert!(ret.is_err());
    /// assert_eq!(r, (1275, 100));
    /// ```
    ///
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html#method.is_finite
    #[inline]
    #[allow(clippy::result_unit_err)]
    pub fn assign_f64(&mut self, val: f64) -> Result<(), ()> {
        if val.is_finite() {
            xmpq::set_f64(self, val);
            Ok(())
        } else {
            Err(())
        }
    }

    /// Creates a new [`Rational`] number from a numerator and
    /// denominator without canonicalizing aftwerwards.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not canonicalize the
    /// [`Rational`] number. The caller must ensure that the numerator
    /// and denominator are in canonical form, as the rest of the
    /// library assumes that they are.
    ///
    /// There are a few methods that can be called on [`Rational`]
    /// numbers that are not in canonical form:
    ///
    ///   * [`numer`] and [`denom`], which treat the numerator and
    ///     denominator separately
    ///   * assignment methods, which overwrite the previous value and
    ///     leave the number in canonical form
    ///   * [`mutate_numer_denom`], which treats the numerator and
    ///     denominator seprarately, and leaves the number in
    ///     canoncial form
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// // −3/5 is in canonical form
    /// let r = unsafe { Rational::from_canonical(-3, 5) };
    /// assert_eq!(r, (-3, 5));
    /// ```
    ///
    /// [`Rational`]: #
    /// [`denom`]: #method.denom
    /// [`mutate_numer_denom`]: #method.mutate_numer_denom
    /// [`numer`]: #method.numer
    pub unsafe fn from_canonical<Num, Den>(num: Num, den: Den) -> Self
    where
        Integer: From<Num> + From<Den>,
    {
        let (num, den) = (Integer::from(num), Integer::from(den));
        let mut dst = MaybeUninit::uninit();
        xmpq::write_num_den_unchecked(&mut dst, num, den);
        dst.assume_init()
    }

    /// Assigns to the numerator and denominator without
    /// canonicalizing aftwerwards.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not canonicalize the
    /// [`Rational`] number after the assignment. The caller must
    /// ensure that the numerator and denominator are in canonical
    /// form, as the rest of the library assumes that they are.
    ///
    /// There are a few methods that can be called on [`Rational`]
    /// numbers that are not in canonical form:
    ///
    ///   * [`numer`] and [`denom`], which treat the numerator and
    ///     denominator separately
    ///   * assignment methods, which overwrite the previous value and
    ///     leave the number in canonical form
    ///   * [`mutate_numer_denom`], which treats the numerator and
    ///     denominator seprarately, and leaves the number in
    ///     canoncial form
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// let mut r = Rational::new();
    /// // −3/5 is in canonical form
    /// unsafe {
    ///     r.assign_canonical(-3, 5);
    /// }
    /// assert_eq!(r, (-3, 5));
    /// ```
    ///
    /// [`Rational`]: #
    /// [`denom`]: #method.denom
    /// [`mutate_numer_denom`]: #method.mutate_numer_denom
    /// [`numer`]: #method.numer
    pub unsafe fn assign_canonical<Num, Den>(&mut self, num: Num, den: Den)
    where
        Integer: Assign<Num> + Assign<Den>,
    {
        let (dst_num, dst_den) = self.as_mut_numer_denom_no_canonicalization();
        dst_num.assign(num);
        dst_den.assign(den);
    }

    /// Borrows the numerator as an [`Integer`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((12, -20));
    /// // r will be canonicalized to −3/5
    /// assert_eq!(*r.numer(), -3)
    /// ```
    ///
    /// [`Integer`]: struct.Integer.html
    #[inline]
    pub fn numer(&self) -> &Integer {
        xmpq::numref_const(self)
    }

    /// Borrows the denominator as an [`Integer`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((12, -20));
    /// // r will be canonicalized to −3/5
    /// assert_eq!(*r.denom(), 5);
    /// ```
    ///
    /// [`Integer`]: struct.Integer.html
    #[inline]
    pub fn denom(&self) -> &Integer {
        xmpq::denref_const(self)
    }

    /// Calls a function with mutable references to the numerator and
    /// denominator, then canonicalizes the number.
    ///
    /// The denominator must not be zero when the function returns.
    ///
    /// # Panics
    ///
    /// Panics if the denominator is zero when the function returns.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::from((3, 5));
    /// r.mutate_numer_denom(|num, den| {
    ///     // change r from 3/5 to 4/8, which is equal to 1/2
    ///     *num += 1;
    ///     *den += 3;
    /// });
    /// assert_eq!(*r.numer(), 1);
    /// assert_eq!(*r.denom(), 2);
    /// ```
    ///
    /// This method does not check that the numerator and denominator
    /// are in canonical form before calling `func`. This means that
    /// this method can be used to canonicalize the number after some
    /// unsafe methods that do not leave the number in cononical form.
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::from((3, 5));
    /// unsafe {
    ///     // leave r in non-canonical form
    ///     *r.as_mut_numer_denom_no_canonicalization().0 += 1;
    ///     *r.as_mut_numer_denom_no_canonicalization().1 -= 13;
    /// }
    /// // At this point, r is still not canonical: 4 / −8
    /// assert_eq!(*r.numer(), 4);
    /// assert_eq!(*r.denom(), -8);
    /// r.mutate_numer_denom(|_, _| {});
    /// // Now r is in canonical form: −1 / 2
    /// assert_eq!(*r.numer(), -1);
    /// assert_eq!(*r.denom(), 2);
    /// ```
    pub fn mutate_numer_denom<F>(&mut self, func: F)
    where
        F: FnOnce(&mut Integer, &mut Integer),
    {
        unsafe {
            let (num, den) = xmpq::numref_denref(self);
            func(num, den);
        }
        xmpq::canonicalize(self);
    }

    /// Borrows the numerator and denominator mutably without
    /// canonicalizing aftwerwards.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not canonicalize the
    /// [`Rational`] number when the borrow ends. The caller must
    /// ensure that the numerator and denominator are left in
    /// canonical form, as the rest of the library assumes that they
    /// are.
    ///
    /// There are a few methods that can be called on [`Rational`]
    /// numbers that are not in canonical form:
    ///
    ///   * [`numer`] and [`denom`], which treat the numerator and
    ///     denominator separately
    ///   * assignment methods, which overwrite the previous value and
    ///     leave the number in canonical form
    ///   * [`mutate_numer_denom`], which treats the numerator and
    ///     denominator seprarately, and leaves the number in
    ///     canoncial form
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// let mut r = Rational::from((3, 5));
    /// {
    ///     let (num, den) = unsafe { r.as_mut_numer_denom_no_canonicalization() };
    ///     // Add one to r by adding den to num. Since num and den
    ///     // are relatively prime, r remains in canonical form.
    ///     *num += &*den;
    /// }
    /// assert_eq!(r, (8, 5));
    /// ```
    ///
    /// This method can also be used to group some operations before
    /// canonicalization. This is usually not beneficial, as early
    /// canonicalization usually means subsequent arithmetic
    /// operations have less work to do.
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::from((3, 5));
    /// unsafe {
    ///     // first operation: add 1 to numerator
    ///     *r.as_mut_numer_denom_no_canonicalization().0 += 1;
    ///     // second operation: subtract 13 from denominator
    ///     *r.as_mut_numer_denom_no_canonicalization().1 -= 13;
    /// }
    /// // At this point, r is still not canonical: 4 / −8
    /// assert_eq!(*r.numer(), 4);
    /// assert_eq!(*r.denom(), -8);
    /// r.mutate_numer_denom(|_, _| {});
    /// // Now r is in canonical form: −1 / 2
    /// assert_eq!(*r.numer(), -1);
    /// assert_eq!(*r.denom(), 2);
    /// ```
    ///
    /// [`Rational`]: #
    /// [`denom`]: #method.denom
    /// [`mutate_numer_denom`]: #method.mutate_numer_denom
    /// [`numer`]: #method.numer
    #[inline]
    pub unsafe fn as_mut_numer_denom_no_canonicalization(
        &mut self,
    ) -> (&mut Integer, &mut Integer) {
        xmpq::numref_denref(self)
    }

    /// Converts into numerator and denominator [`Integer`] values.
    ///
    /// This function reuses the allocated memory and does not
    /// allocate any new memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((12, -20));
    /// // r will be canonicalized to −3/5
    /// let (num, den) = r.into_numer_denom();
    /// assert_eq!(num, -3);
    /// assert_eq!(den, 5);
    /// ```
    ///
    /// [`Integer`]: struct.Integer.html
    #[inline]
    pub fn into_numer_denom(self) -> (Integer, Integer) {
        let raw = self.into_raw();
        // Safety: raw contains two valid Integers.
        unsafe { (Integer::from_raw(raw.num), Integer::from_raw(raw.den)) }
    }

    /// Borrows a negated copy of the [`Rational`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Rational][`Rational`]&gt;</code>.
    ///
    /// This method performs a shallow copy and negates it, and
    /// negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((7, 11));
    /// let neg_r = r.as_neg();
    /// assert_eq!(*neg_r, (-7, 11));
    /// // methods taking &self can be used on the returned object
    /// let reneg_r = neg_r.as_neg();
    /// assert_eq!(*reneg_r, (7, 11));
    /// assert_eq!(*reneg_r, r);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Rational`]: #
    pub fn as_neg(&self) -> BorrowRational<'_> {
        let mut raw = self.inner;
        raw.num.size = raw.num.size.checked_neg().expect("overflow");
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        // Safety: the number is in canonical form as only the sign of the numerator was changed.
        unsafe { BorrowRational::from_raw(raw) }
    }

    /// Borrows an absolute copy of the [`Rational`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Rational][`Rational`]&gt;</code>.
    ///
    /// This method performs a shallow copy and possibly negates it,
    /// and negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-7, 11));
    /// let abs_r = r.as_abs();
    /// assert_eq!(*abs_r, (7, 11));
    /// // methods taking &self can be used on the returned object
    /// let reabs_r = abs_r.as_abs();
    /// assert_eq!(*reabs_r, (7, 11));
    /// assert_eq!(*reabs_r, *abs_r);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Rational`]: #
    pub fn as_abs(&self) -> BorrowRational<'_> {
        let mut raw = self.inner;
        raw.num.size = raw.num.size.checked_abs().expect("overflow");
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        // Safety: the number is in canonical form as only the sign of the numerator was changed.
        unsafe { BorrowRational::from_raw(raw) }
    }

    /// Borrows a reciprocal copy of the [`Rational`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Rational][`Rational`]&gt;</code>.
    ///
    /// This method performs some shallow copying, swapping numerator
    /// and denominator and making sure the sign is in the numerator.
    ///
    /// # Panics
    ///
    /// Panics if the value is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-7, 11));
    /// let recip_r = r.as_recip();
    /// assert_eq!(*recip_r, (-11, 7));
    /// // methods taking &self can be used on the returned object
    /// let rerecip_r = recip_r.as_recip();
    /// assert_eq!(*rerecip_r, (-7, 11));
    /// assert_eq!(*rerecip_r, r);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Rational`]: #
    pub fn as_recip(&self) -> BorrowRational<'_> {
        assert_ne!(self.cmp0(), Ordering::Equal, "division by zero");
        let mut raw = mpq_t {
            num: self.inner.den,
            den: self.inner.num,
        };
        if raw.den.size < 0 {
            raw.den.size = raw.den.size.wrapping_neg();
            raw.num.size = raw.num.size.checked_neg().expect("overflow");
        }
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        // Safety: the number is in canonical form as the numerator and denominator are
        // still mutually prime, and the denominator was made positive.
        unsafe { BorrowRational::from_raw(raw) }
    }

    /// Returns the same result as
    /// <code>self.[cmp][`cmp`](&amp;0.[into][`into`]())</code>, but
    /// is faster.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::Rational;
    /// assert_eq!(Rational::from((-5, 7)).cmp0(), Ordering::Less);
    /// assert_eq!(Rational::from(0).cmp0(), Ordering::Equal);
    /// assert_eq!(Rational::from((5, 7)).cmp0(), Ordering::Greater);
    /// ```
    ///
    /// [`cmp`]: https://doc.rust-lang.org/nightly/core/cmp/trait.Ord.html#tymethod.cmp
    /// [`into`]: https://doc.rust-lang.org/nightly/core/convert/trait.Into.html#tymethod.into
    #[inline]
    pub fn cmp0(&self) -> Ordering {
        self.numer().cmp0()
    }

    /// Compares the absolute values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::Rational;
    /// let a = Rational::from((-23, 10));
    /// let b = Rational::from((-47, 5));
    /// assert_eq!(a.cmp(&b), Ordering::Greater);
    /// assert_eq!(a.cmp_abs(&b), Ordering::Less);
    /// ```
    #[inline]
    pub fn cmp_abs(&self, other: &Self) -> Ordering {
        self.as_abs().cmp(&*other.as_abs())
    }

    /// Adds a list of [`Rational`] values.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// let values = [
    ///     Rational::from((5, 2)),
    ///     Rational::from((-100_000, 7)),
    ///     Rational::from(-4),
    /// ];
    ///
    /// let r = Rational::sum(values.iter());
    /// let sum = Rational::from(r);
    /// let expected = (5 * 7 - 100_000 * 2 - 4 * 14, 14);
    /// assert_eq!(sum, expected);
    /// ```
    ///
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sum<'a, I>(values: I) -> SumIncomplete<'a, I>
    where
        I: Iterator<Item = &'a Self>,
    {
        SumIncomplete { values }
    }

    /// Finds the dot product of a list of [`Rational`] value pairs.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// let a = [Rational::from((270, 7)), Rational::from((-11, 10))];
    /// let b = [Rational::from(7), Rational::from((1, 2))];
    ///
    /// let r = Rational::dot(a.iter().zip(b.iter()));
    /// let dot = Rational::from(r);
    /// let expected = (270 * 20 - 11, 20);
    /// assert_eq!(dot, expected);
    /// ```
    ///
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn dot<'a, I>(values: I) -> DotIncomplete<'a, I>
    where
        I: Iterator<Item = (&'a Self, &'a Self)>,
    {
        DotIncomplete { values }
    }

    /// Multiplies a list of [`Rational`] values.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[MulAssign][`MulAssign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[Mul][`Mul`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    ///
    /// let values = [
    ///     Rational::from((5, 2)),
    ///     Rational::from((-100_000, 7)),
    ///     Rational::from(-4),
    /// ];
    ///
    /// let r = Rational::product(values.iter());
    /// let product = Rational::from(r);
    /// let expected = (5 * -100_000 * -4, 2 * 7);
    /// assert_eq!(product, expected);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`MulAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.MulAssign.html
    /// [`Mul`]: https://doc.rust-lang.org/nightly/core/ops/trait.Mul.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn product<'a, I>(values: I) -> ProductIncomplete<'a, I>
    where
        I: Iterator<Item = &'a Self>,
    {
        ProductIncomplete { values }
    }

    /// Computes the absolute value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-100, 17));
    /// let abs = r.abs();
    /// assert_eq!(abs, (100, 17));
    /// ```
    #[inline]
    pub fn abs(mut self) -> Self {
        self.abs_mut();
        self
    }

    /// Computes the absolute value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::from((-100, 17));
    /// r.abs_mut();
    /// assert_eq!(r, (100, 17));
    /// ```
    #[inline]
    pub fn abs_mut(&mut self) {
        xmpq::abs(self, ());
    }

    /// Computes the absolute value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-100, 17));
    /// let r_ref = r.abs_ref();
    /// let abs = Rational::from(r_ref);
    /// assert_eq!(abs, (100, 17));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn abs_ref(&self) -> AbsIncomplete<'_> {
        AbsIncomplete { ref_self: self }
    }

    /// Computes the signum.
    ///
    ///   * 0 if the value is zero
    ///   * 1 if the value is positive
    ///   * −1 if the value is negative
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-100, 17));
    /// let signum = r.signum();
    /// assert_eq!(signum, -1);
    /// ```
    #[inline]
    pub fn signum(mut self) -> Rational {
        self.signum_mut();
        self
    }

    /// Computes the signum.
    ///
    ///   * 0 if the value is zero
    ///   * 1 if the value is positive
    ///   * −1 if the value is negative
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::from((-100, 17));
    /// r.signum_mut();
    /// assert_eq!(r, -1);
    /// ```
    #[inline]
    pub fn signum_mut(&mut self) {
        xmpq::signum(self);
    }

    /// Computes the signum.
    ///
    ///   * 0 if the value is zero
    ///   * 1 if the value is positive
    ///   * −1 if the value is negative
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// let r = Rational::from((-100, 17));
    /// let r_ref = r.signum_ref();
    /// let signum = Integer::from(r_ref);
    /// assert_eq!(signum, -1);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn signum_ref(&self) -> SignumIncomplete<'_> {
        SignumIncomplete { ref_self: self }
    }

    /// Clamps the value within the specified bounds.
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let min = (-3, 2);
    /// let max = (3, 2);
    /// let too_small = Rational::from((-5, 2));
    /// let clamped1 = too_small.clamp(&min, &max);
    /// assert_eq!(clamped1, (-3, 2));
    /// let in_range = Rational::from((1, 2));
    /// let clamped2 = in_range.clamp(&min, &max);
    /// assert_eq!(clamped2, (1, 2));
    /// ```
    #[inline]
    pub fn clamp<Min, Max>(mut self, min: &Min, max: &Max) -> Self
    where
        Self: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
    {
        self.clamp_mut(min, max);
        self
    }

    /// Clamps the value within the specified bounds.
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let min = (-3, 2);
    /// let max = (3, 2);
    /// let mut too_small = Rational::from((-5, 2));
    /// too_small.clamp_mut(&min, &max);
    /// assert_eq!(too_small, (-3, 2));
    /// let mut in_range = Rational::from((1, 2));
    /// in_range.clamp_mut(&min, &max);
    /// assert_eq!(in_range, (1, 2));
    /// ```
    pub fn clamp_mut<Min, Max>(&mut self, min: &Min, max: &Max)
    where
        Self: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
    {
        if (&*self).lt(min) {
            self.assign(min);
            assert!(!(&*self).gt(max), "minimum larger than maximum");
        } else if (&*self).gt(max) {
            self.assign(max);
            assert!(!(&*self).lt(min), "minimum larger than maximum");
        }
    }

    /// Clamps the value within the specified bounds.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let min = (-3, 2);
    /// let max = (3, 2);
    /// let too_small = Rational::from((-5, 2));
    /// let r1 = too_small.clamp_ref(&min, &max);
    /// let clamped1 = Rational::from(r1);
    /// assert_eq!(clamped1, (-3, 2));
    /// let in_range = Rational::from((1, 2));
    /// let r2 = in_range.clamp_ref(&min, &max);
    /// let clamped2 = Rational::from(r2);
    /// assert_eq!(clamped2, (1, 2));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn clamp_ref<'min, 'max, Min, Max>(
        &self,
        min: &'min Min,
        max: &'max Max,
    ) -> ClampIncomplete<'_, 'min, 'max, Min, Max>
    where
        Self: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
    {
        ClampIncomplete {
            ref_self: self,
            min,
            max,
        }
    }

    /// Computes the reciprocal.
    ///
    /// # Panics
    ///
    /// Panics if the value is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-100, 17));
    /// let recip = r.recip();
    /// assert_eq!(recip, (-17, 100));
    /// ```
    #[inline]
    pub fn recip(mut self) -> Self {
        self.recip_mut();
        self
    }

    /// Computes the reciprocal.
    ///
    /// This method never reallocates or copies the heap data. It
    /// simply swaps the allocated data of the numerator and
    /// denominator and makes sure the denominator is stored as
    /// positive.
    ///
    /// # Panics
    ///
    /// Panics if the value is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::from((-100, 17));
    /// r.recip_mut();
    /// assert_eq!(r, (-17, 100));
    /// ```
    #[inline]
    pub fn recip_mut(&mut self) {
        xmpq::inv(self, ());
    }

    /// Computes the reciprocal.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-100, 17));
    /// let r_ref = r.recip_ref();
    /// let recip = Rational::from(r_ref);
    /// assert_eq!(recip, (-17, 100));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn recip_ref(&self) -> RecipIncomplete<'_> {
        RecipIncomplete { ref_self: self }
    }

    /// Rounds the number towards zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −3.7
    /// let r1 = Rational::from((-37, 10));
    /// let trunc1 = r1.trunc();
    /// assert_eq!(trunc1, -3);
    /// // 3.3
    /// let r2 = Rational::from((33, 10));
    /// let trunc2 = r2.trunc();
    /// assert_eq!(trunc2, 3);
    /// ```
    #[inline]
    pub fn trunc(mut self) -> Rational {
        self.trunc_mut();
        self
    }

    /// Rounds the number towards zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Rational};
    /// // −3.7
    /// let mut r = Rational::from((-37, 10));
    /// r.trunc_mut();
    /// assert_eq!(r, -3);
    /// // 3.3
    /// r.assign((33, 10));
    /// r.trunc_mut();
    /// assert_eq!(r, 3);
    /// ```
    #[inline]
    pub fn trunc_mut(&mut self) {
        xmpq::trunc(self);
    }

    /// Rounds the number towards zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// let mut trunc = Integer::new();
    /// // −3.7
    /// let r1 = Rational::from((-37, 10));
    /// trunc.assign(r1.trunc_ref());
    /// assert_eq!(trunc, -3);
    /// // 3.3
    /// let r2 = Rational::from((33, 10));
    /// trunc.assign(r2.trunc_ref());
    /// assert_eq!(trunc, 3);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn trunc_ref(&self) -> TruncIncomplete<'_> {
        TruncIncomplete { ref_self: self }
    }

    /// Computes the fractional part of the number.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −100/17 = −5 − 15/17
    /// let r = Rational::from((-100, 17));
    /// let rem = r.rem_trunc();
    /// assert_eq!(rem, (-15, 17));
    /// ```
    #[inline]
    pub fn rem_trunc(mut self) -> Self {
        self.rem_trunc_mut();
        self
    }

    /// Computes the fractional part of the number.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −100/17 = −5 − 15/17
    /// let mut r = Rational::from((-100, 17));
    /// r.rem_trunc_mut();
    /// assert_eq!(r, (-15, 17));
    /// ```
    #[inline]
    pub fn rem_trunc_mut(&mut self) {
        xmpq::trunc_fract(self, ());
    }

    /// Computes the fractional part of the number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −100/17 = −5 − 15/17
    /// let r = Rational::from((-100, 17));
    /// let r_ref = r.rem_trunc_ref();
    /// let rem = Rational::from(r_ref);
    /// assert_eq!(rem, (-15, 17));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn rem_trunc_ref(&self) -> RemTruncIncomplete<'_> {
        RemTruncIncomplete { ref_self: self }
    }

    /// Computes the fractional and truncated parts of the number.
    ///
    /// The initial value of `trunc` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // −100/17 = −5 − 15/17
    /// let r = Rational::from((-100, 17));
    /// let (fract, trunc) = r.fract_trunc(Integer::new());
    /// assert_eq!(fract, (-15, 17));
    /// assert_eq!(trunc, -5);
    /// ```
    #[inline]
    pub fn fract_trunc(mut self, mut trunc: Integer) -> (Self, Integer) {
        self.fract_trunc_mut(&mut trunc);
        (self, trunc)
    }

    /// Computes the fractional and truncated parts of the number.
    ///
    /// The initial value of `trunc` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // −100/17 = −5 − 15/17
    /// let mut r = Rational::from((-100, 17));
    /// let mut whole = Integer::new();
    /// r.fract_trunc_mut(&mut whole);
    /// assert_eq!(r, (-15, 17));
    /// assert_eq!(whole, -5);
    /// ```
    #[inline]
    pub fn fract_trunc_mut(&mut self, trunc: &mut Integer) {
        xmpq::trunc_fract_whole(self, trunc, ());
    }

    /// Computes the fractional and truncated parts of the number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Rational][`Rational`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// // −100/17 = −5 − 15/17
    /// let r = Rational::from((-100, 17));
    /// let r_ref = r.fract_trunc_ref();
    /// let (mut fract, mut trunc) = (Rational::new(), Integer::new());
    /// (&mut fract, &mut trunc).assign(r_ref);
    /// assert_eq!(fract, (-15, 17));
    /// assert_eq!(trunc, -5);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn fract_trunc_ref(&self) -> FractTruncIncomplete<'_> {
        FractTruncIncomplete { ref_self: self }
    }

    /// Rounds the number upwards (towards plus infinity).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −3.7
    /// let r1 = Rational::from((-37, 10));
    /// let ceil1 = r1.ceil();
    /// assert_eq!(ceil1, -3);
    /// // 3.3
    /// let r2 = Rational::from((33, 10));
    /// let ceil2 = r2.ceil();
    /// assert_eq!(ceil2, 4);
    /// ```
    #[inline]
    pub fn ceil(mut self) -> Rational {
        self.ceil_mut();
        self
    }

    /// Rounds the number upwards (towards plus infinity).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Rational};
    /// // −3.7
    /// let mut r = Rational::from((-37, 10));
    /// r.ceil_mut();
    /// assert_eq!(r, -3);
    /// // 3.3
    /// r.assign((33, 10));
    /// r.ceil_mut();
    /// assert_eq!(r, 4);
    /// ```
    #[inline]
    pub fn ceil_mut(&mut self) {
        xmpq::ceil(self);
    }

    /// Rounds the number upwards (towards plus infinity).
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// let mut ceil = Integer::new();
    /// // −3.7
    /// let r1 = Rational::from((-37, 10));
    /// ceil.assign(r1.ceil_ref());
    /// assert_eq!(ceil, -3);
    /// // 3.3
    /// let r2 = Rational::from((33, 10));
    /// ceil.assign(r2.ceil_ref());
    /// assert_eq!(ceil, 4);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ceil_ref(&self) -> CeilIncomplete<'_> {
        CeilIncomplete { ref_self: self }
    }

    /// Computes the non-positive remainder after rounding up.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // 100/17 = 6 − 2/17
    /// let r = Rational::from((100, 17));
    /// let rem = r.rem_ceil();
    /// assert_eq!(rem, (-2, 17));
    /// ```
    #[inline]
    pub fn rem_ceil(mut self) -> Self {
        self.rem_ceil_mut();
        self
    }

    /// Computes the non-positive remainder after rounding up.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // 100/17 = 6 − 2/17
    /// let mut r = Rational::from((100, 17));
    /// r.rem_ceil_mut();
    /// assert_eq!(r, (-2, 17));
    /// ```
    #[inline]
    pub fn rem_ceil_mut(&mut self) {
        xmpq::ceil_fract(self, ());
    }

    /// Computes the non-positive remainder after rounding up.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // 100/17 = 6 − 2/17
    /// let r = Rational::from((100, 17));
    /// let r_ref = r.rem_ceil_ref();
    /// let rem = Rational::from(r_ref);
    /// assert_eq!(rem, (-2, 17));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn rem_ceil_ref(&self) -> RemCeilIncomplete<'_> {
        RemCeilIncomplete { ref_self: self }
    }

    /// Computes the fractional and ceil parts of the number.
    ///
    /// The fractional part cannot greater than zero.
    ///
    /// The initial value of `ceil` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // 100/17 = 6 − 2/17
    /// let r = Rational::from((100, 17));
    /// let (fract, ceil) = r.fract_ceil(Integer::new());
    /// assert_eq!(fract, (-2, 17));
    /// assert_eq!(ceil, 6);
    /// ```
    #[inline]
    pub fn fract_ceil(mut self, mut ceil: Integer) -> (Self, Integer) {
        self.fract_ceil_mut(&mut ceil);
        (self, ceil)
    }

    /// Computes the fractional and ceil parts of the number.
    ///
    /// The fractional part cannot be greater than zero.
    ///
    /// The initial value of `ceil` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // 100/17 = 6 − 2/17
    /// let mut r = Rational::from((100, 17));
    /// let mut ceil = Integer::new();
    /// r.fract_ceil_mut(&mut ceil);
    /// assert_eq!(r, (-2, 17));
    /// assert_eq!(ceil, 6);
    /// ```
    #[inline]
    pub fn fract_ceil_mut(&mut self, ceil: &mut Integer) {
        xmpq::ceil_fract_whole(self, ceil, ());
    }

    /// Computes the fractional and ceil parts of the number.
    ///
    /// The fractional part cannot be greater than zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Rational][`Rational`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// // 100/17 = 6 − 2/17
    /// let r = Rational::from((100, 17));
    /// let r_ref = r.fract_ceil_ref();
    /// let (mut fract, mut ceil) = (Rational::new(), Integer::new());
    /// (&mut fract, &mut ceil).assign(r_ref);
    /// assert_eq!(fract, (-2, 17));
    /// assert_eq!(ceil, 6);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn fract_ceil_ref(&self) -> FractCeilIncomplete<'_> {
        FractCeilIncomplete { ref_self: self }
    }

    /// Rounds the number downwards (towards minus infinity).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −3.7
    /// let r1 = Rational::from((-37, 10));
    /// let floor1 = r1.floor();
    /// assert_eq!(floor1, -4);
    /// // 3.3
    /// let r2 = Rational::from((33, 10));
    /// let floor2 = r2.floor();
    /// assert_eq!(floor2, 3);
    /// ```
    #[inline]
    pub fn floor(mut self) -> Rational {
        self.floor_mut();
        self
    }

    /// Rounds the number downwards (towards minus infinity).
    ///
    /// ```rust
    /// use rug::{Assign, Rational};
    /// // −3.7
    /// let mut r = Rational::from((-37, 10));
    /// r.floor_mut();
    /// assert_eq!(r, -4);
    /// // 3.3
    /// r.assign((33, 10));
    /// r.floor_mut();
    /// assert_eq!(r, 3);
    /// ```
    #[inline]
    pub fn floor_mut(&mut self) {
        xmpq::floor(self);
    }

    /// Rounds the number downwards (towards minus infinity).
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// let mut floor = Integer::new();
    /// // −3.7
    /// let r1 = Rational::from((-37, 10));
    /// floor.assign(r1.floor_ref());
    /// assert_eq!(floor, -4);
    /// // 3.3
    /// let r2 = Rational::from((33, 10));
    /// floor.assign(r2.floor_ref());
    /// assert_eq!(floor, 3);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn floor_ref(&self) -> FloorIncomplete<'_> {
        FloorIncomplete { ref_self: self }
    }

    /// Computes the non-negative remainder after rounding down.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −100/17 = −6 + 2/17
    /// let r = Rational::from((-100, 17));
    /// let rem = r.rem_floor();
    /// assert_eq!(rem, (2, 17));
    /// ```
    #[inline]
    pub fn rem_floor(mut self) -> Self {
        self.rem_floor_mut();
        self
    }

    /// Computes the non-negative remainder after rounding down.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −100/17 = −6 + 2/17
    /// let mut r = Rational::from((-100, 17));
    /// r.rem_floor_mut();
    /// assert_eq!(r, (2, 17));
    /// ```
    #[inline]
    pub fn rem_floor_mut(&mut self) {
        xmpq::floor_fract(self, ());
    }

    /// Computes the non-negative remainder after rounding down.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −100/17 = −6 + 2/17
    /// let r = Rational::from((-100, 17));
    /// let r_ref = r.rem_floor_ref();
    /// let rem = Rational::from(r_ref);
    /// assert_eq!(rem, (2, 17));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn rem_floor_ref(&self) -> RemFloorIncomplete<'_> {
        RemFloorIncomplete { ref_self: self }
    }

    /// Computes the fractional and floor parts of the number.
    ///
    /// The fractional part cannot be negative.
    ///
    /// The initial value of `floor` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // −100/17 = −6 + 2/17
    /// let r = Rational::from((-100, 17));
    /// let (fract, floor) = r.fract_floor(Integer::new());
    /// assert_eq!(fract, (2, 17));
    /// assert_eq!(floor, -6);
    /// ```
    #[inline]
    pub fn fract_floor(mut self, mut floor: Integer) -> (Self, Integer) {
        self.fract_floor_mut(&mut floor);
        (self, floor)
    }

    /// Computes the fractional and floor parts of the number.
    ///
    /// The fractional part cannot be negative.
    ///
    /// The initial value of `floor` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // −100/17 = −6 + 2/17
    /// let mut r = Rational::from((-100, 17));
    /// let mut floor = Integer::new();
    /// r.fract_floor_mut(&mut floor);
    /// assert_eq!(r, (2, 17));
    /// assert_eq!(floor, -6);
    /// ```
    #[inline]
    pub fn fract_floor_mut(&mut self, floor: &mut Integer) {
        xmpq::floor_fract_whole(self, floor, ());
    }

    /// Computes the fractional and floor parts of the number.
    ///
    /// The fractional part cannot be negative.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Rational][`Rational`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// // −100/17 = −6 + 2/17
    /// let r = Rational::from((-100, 17));
    /// let r_ref = r.fract_floor_ref();
    /// let (mut fract, mut floor) = (Rational::new(), Integer::new());
    /// (&mut fract, &mut floor).assign(r_ref);
    /// assert_eq!(fract, (2, 17));
    /// assert_eq!(floor, -6);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn fract_floor_ref(&self) -> FractFloorIncomplete<'_> {
        FractFloorIncomplete { ref_self: self }
    }

    /// Rounds the number to the nearest integer.
    ///
    /// When the number lies exactly between two integers, it is
    /// rounded away from zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −3.5
    /// let r1 = Rational::from((-35, 10));
    /// let round1 = r1.round();
    /// assert_eq!(round1, -4);
    /// // 3.7
    /// let r2 = Rational::from((37, 10));
    /// let round2 = r2.round();
    /// assert_eq!(round2, 4);
    /// ```
    #[inline]
    pub fn round(mut self) -> Rational {
        self.round_mut();
        self
    }

    /// Rounds the number to the nearest integer.
    ///
    /// When the number lies exactly between two integers, it is
    /// rounded away from zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Rational};
    /// // −3.5
    /// let mut r = Rational::from((-35, 10));
    /// r.round_mut();
    /// assert_eq!(r, -4);
    /// // 3.7
    /// r.assign((37, 10));
    /// r.round_mut();
    /// assert_eq!(r, 4);
    /// ```
    #[inline]
    pub fn round_mut(&mut self) {
        xmpq::round(self);
    }

    /// Rounds the number to the nearest integer.
    ///
    /// When the number lies exactly between two integers, it is
    /// rounded away from zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// let mut round = Integer::new();
    /// // −3.5
    /// let r1 = Rational::from((-35, 10));
    /// round.assign(r1.round_ref());
    /// assert_eq!(round, -4);
    /// // 3.7
    /// let r2 = Rational::from((37, 10));
    /// round.assign(r2.round_ref());
    /// assert_eq!(round, 4);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn round_ref(&self) -> RoundIncomplete<'_> {
        RoundIncomplete { ref_self: self }
    }

    /// Computes the remainder after rounding to the nearest
    /// integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −3.5 = −4 + 0.5 = −4 + 1/2
    /// let r1 = Rational::from((-35, 10));
    /// let rem1 = r1.rem_round();
    /// assert_eq!(rem1, (1, 2));
    /// // 3.7 = 4 − 0.3 = 4 − 3/10
    /// let r2 = Rational::from((37, 10));
    /// let rem2 = r2.rem_round();
    /// assert_eq!(rem2, (-3, 10));
    /// ```
    #[inline]
    pub fn rem_round(mut self) -> Self {
        self.rem_round_mut();
        self
    }

    /// Computes the remainder after rounding to the nearest
    /// integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −3.5 = −4 + 0.5 = −4 + 1/2
    /// let mut r1 = Rational::from((-35, 10));
    /// r1.rem_round_mut();
    /// assert_eq!(r1, (1, 2));
    /// // 3.7 = 4 − 0.3 = 4 − 3/10
    /// let mut r2 = Rational::from((37, 10));
    /// r2.rem_round_mut();
    /// assert_eq!(r2, (-3, 10));
    /// ```
    #[inline]
    pub fn rem_round_mut(&mut self) {
        xmpq::round_fract(self, ());
    }

    /// Computes the remainder after rounding to the nearest
    /// integer.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// // −3.5 = −4 + 0.5 = −4 + 1/2
    /// let r1 = Rational::from((-35, 10));
    /// let r_ref1 = r1.rem_round_ref();
    /// let rem1 = Rational::from(r_ref1);
    /// assert_eq!(rem1, (1, 2));
    /// // 3.7 = 4 − 0.3 = 4 − 3/10
    /// let r2 = Rational::from((37, 10));
    /// let r_ref2 = r2.rem_round_ref();
    /// let rem2 = Rational::from(r_ref2);
    /// assert_eq!(rem2, (-3, 10));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn rem_round_ref(&self) -> RemRoundIncomplete<'_> {
        RemRoundIncomplete { ref_self: self }
    }

    /// Computes the fractional and rounded parts of the number.
    ///
    /// The fractional part is positive when the number is rounded
    /// down and negative when the number is rounded up. When the
    /// number lies exactly between two integers, it is rounded away
    /// from zero.
    ///
    /// The initial value of `round` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // −3.5 = −4 + 0.5 = −4 + 1/2
    /// let r1 = Rational::from((-35, 10));
    /// let (fract1, round1) = r1.fract_round(Integer::new());
    /// assert_eq!(fract1, (1, 2));
    /// assert_eq!(round1, -4);
    /// // 3.7 = 4 − 0.3 = 4 − 3/10
    /// let r2 = Rational::from((37, 10));
    /// let (fract2, round2) = r2.fract_round(Integer::new());
    /// assert_eq!(fract2, (-3, 10));
    /// assert_eq!(round2, 4);
    /// ```
    #[inline]
    pub fn fract_round(mut self, mut round: Integer) -> (Self, Integer) {
        self.fract_round_mut(&mut round);
        (self, round)
    }

    /// Computes the fractional and round parts of the number.
    ///
    /// The fractional part is positive when the number is rounded
    /// down and negative when the number is rounded up. When the
    /// number lies exactly between two integers, it is rounded away
    /// from zero.
    ///
    /// The initial value of `round` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Integer, Rational};
    /// // −3.5 = −4 + 0.5 = −4 + 1/2
    /// let mut r1 = Rational::from((-35, 10));
    /// let mut round1 = Integer::new();
    /// r1.fract_round_mut(&mut round1);
    /// assert_eq!(r1, (1, 2));
    /// assert_eq!(round1, -4);
    /// // 3.7 = 4 − 0.3 = 4 − 3/10
    /// let mut r2 = Rational::from((37, 10));
    /// let mut round2 = Integer::new();
    /// r2.fract_round_mut(&mut round2);
    /// assert_eq!(r2, (-3, 10));
    /// assert_eq!(round2, 4);
    /// ```
    #[inline]
    pub fn fract_round_mut(&mut self, round: &mut Integer) {
        xmpq::round_fract_whole(self, round, ());
    }

    /// Computes the fractional and round parts of the number.
    ///
    /// The fractional part is positive when the number is rounded
    /// down and negative when the number is rounded up. When the
    /// number lies exactly between two integers, it is rounded away
    /// from zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Rational][`Rational`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Rational][`Rational`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer, Rational};
    /// // −3.5 = −4 + 0.5 = −4 + 1/2
    /// let r1 = Rational::from((-35, 10));
    /// let r_ref1 = r1.fract_round_ref();
    /// let (mut fract1, mut round1) = (Rational::new(), Integer::new());
    /// (&mut fract1, &mut round1).assign(r_ref1);
    /// assert_eq!(fract1, (1, 2));
    /// assert_eq!(round1, -4);
    /// // 3.7 = 4 − 0.3 = 4 − 3/10
    /// let r2 = Rational::from((37, 10));
    /// let r_ref2 = r2.fract_round_ref();
    /// let (mut fract2, mut round2) = (Rational::new(), Integer::new());
    /// (&mut fract2, &mut round2).assign(r_ref2);
    /// assert_eq!(fract2, (-3, 10));
    /// assert_eq!(round2, 4);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: struct.Integer.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn fract_round_ref(&self) -> FractRoundIncomplete<'_> {
        FractRoundIncomplete { ref_self: self }
    }

    /// Computes the square.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-13, 2));
    /// let square = r.square();
    /// assert_eq!(square, (169, 4));
    /// ```
    #[inline]
    pub fn square(mut self) -> Self {
        self.square_mut();
        self
    }

    /// Computes the square.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let mut r = Rational::from((-13, 2));
    /// r.square_mut();
    /// assert_eq!(r, (169, 4));
    /// ```
    #[inline]
    pub fn square_mut(&mut self) {
        xmpq::square(self, ());
    }

    /// Computes the square.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Rational][`Rational`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Rational;
    /// let r = Rational::from((-13, 2));
    /// assert_eq!(Rational::from(r.square_ref()), (169, 4));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Rational`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn square_ref(&self) -> SquareIncomplete<'_> {
        SquareIncomplete { ref_self: self }
    }
}

#[derive(Debug)]
pub struct SumIncomplete<'a, I>
where
    I: Iterator<Item = &'a Rational>,
{
    values: I,
}

impl<'a, I> Assign<SumIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    fn assign(&mut self, mut src: SumIncomplete<'a, I>) {
        match src.values.next() {
            Some(first) => {
                self.assign(first);
            }
            None => {
                self.assign(0u32);
                return;
            }
        }
        self.add_assign(src);
    }
}

impl<'a, I> From<SumIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    fn from(mut src: SumIncomplete<'a, I>) -> Self {
        let mut dst = match src.values.next() {
            Some(first) => first.clone(),
            None => return Rational::new(),
        };
        dst.add_assign(src);
        dst
    }
}

impl<'a, I> Add<SumIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    type Output = Self;
    #[inline]
    fn add(mut self, rhs: SumIncomplete<'a, I>) -> Self {
        self.add_assign(rhs);
        self
    }
}

impl<'a, I> AddAssign<SumIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    fn add_assign(&mut self, src: SumIncomplete<'a, I>) {
        for i in src.values {
            self.add_assign(i);
        }
    }
}

#[derive(Debug)]
pub struct DotIncomplete<'a, I>
where
    I: Iterator<Item = (&'a Rational, &'a Rational)>,
{
    values: I,
}

impl<'a, I> Assign<DotIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = (&'a Rational, &'a Rational)>,
{
    fn assign(&mut self, mut src: DotIncomplete<'a, I>) {
        match src.values.next() {
            Some(first) => {
                self.assign(first.0 * first.1);
            }
            None => {
                self.assign(0u32);
                return;
            }
        }
        self.add_assign(src);
    }
}

impl<'a, I> From<DotIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = (&'a Rational, &'a Rational)>,
{
    fn from(mut src: DotIncomplete<'a, I>) -> Self {
        let mut dst = match src.values.next() {
            Some(first) => Rational::from(first.0 * first.1),
            None => return Rational::new(),
        };
        dst.add_assign(src);
        dst
    }
}

impl<'a, I> Add<DotIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = (&'a Rational, &'a Rational)>,
{
    type Output = Self;
    #[inline]
    fn add(mut self, rhs: DotIncomplete<'a, I>) -> Self {
        self.add_assign(rhs);
        self
    }
}

impl<'a, I> AddAssign<DotIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = (&'a Rational, &'a Rational)>,
{
    fn add_assign(&mut self, src: DotIncomplete<'a, I>) {
        let mut mul = Rational::new();
        for i in src.values {
            #[allow(clippy::suspicious_op_assign_impl)]
            mul.assign(i.0 * i.1);
            AddAssign::add_assign(self, &mul);
        }
    }
}

#[derive(Debug)]
pub struct ProductIncomplete<'a, I>
where
    I: Iterator<Item = &'a Rational>,
{
    values: I,
}

impl<'a, I> Assign<ProductIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    fn assign(&mut self, mut src: ProductIncomplete<'a, I>) {
        match src.values.next() {
            Some(first) => {
                self.assign(first);
            }
            None => {
                self.assign(1u32);
                return;
            }
        }
        self.mul_assign(src);
    }
}

impl<'a, I> From<ProductIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    fn from(mut src: ProductIncomplete<'a, I>) -> Self {
        let mut dst = match src.values.next() {
            Some(first) => first.clone(),
            None => return Rational::from(1),
        };
        dst.mul_assign(src);
        dst
    }
}

impl<'a, I> Mul<ProductIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    type Output = Self;
    #[inline]
    fn mul(mut self, rhs: ProductIncomplete<'a, I>) -> Self {
        self.mul_assign(rhs);
        self
    }
}

impl<'a, I> MulAssign<ProductIncomplete<'a, I>> for Rational
where
    I: Iterator<Item = &'a Self>,
{
    fn mul_assign(&mut self, mut src: ProductIncomplete<'a, I>) {
        let mut other = match src.values.next() {
            Some(next) => Rational::from(&*self * next),
            None => return,
        };
        loop {
            match src.values.next() {
                Some(next) => {
                    self.assign(&other * next);
                }
                None => {
                    self.assign(other);
                    return;
                }
            }
            match src.values.next() {
                Some(next) => {
                    other.assign(&*self * next);
                }
                None => {
                    return;
                }
            }
            if self.cmp0() == Ordering::Equal {
                return;
            }
        }
    }
}

ref_math_op1! { Rational; xmpq::abs; struct AbsIncomplete {} }
ref_rat_op_int! { xmpq::signum_int; struct SignumIncomplete {} }

#[derive(Debug)]
pub struct ClampIncomplete<'s, 'min, 'max, Min, Max>
where
    Rational: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
{
    ref_self: &'s Rational,
    min: &'min Min,
    max: &'max Max,
}

impl<Min, Max> Assign<ClampIncomplete<'_, '_, '_, Min, Max>> for Rational
where
    Self: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
{
    #[inline]
    fn assign(&mut self, src: ClampIncomplete<Min, Max>) {
        if src.ref_self.lt(src.min) {
            self.assign(src.min);
            assert!(!(&*self).gt(src.max), "minimum larger than maximum");
        } else if src.ref_self.gt(src.max) {
            self.assign(src.max);
            assert!(!(&*self).lt(src.min), "minimum larger than maximum");
        } else {
            self.assign(src.ref_self);
        }
    }
}

impl<Min, Max> From<ClampIncomplete<'_, '_, '_, Min, Max>> for Rational
where
    Self: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
{
    #[inline]
    fn from(src: ClampIncomplete<Min, Max>) -> Self {
        let mut dst = Rational::new();
        dst.assign(src);
        dst
    }
}

ref_math_op1! { Rational; xmpq::inv; struct RecipIncomplete {} }
ref_rat_op_int! { xmpq::trunc_int; struct TruncIncomplete {} }
ref_math_op1! { Rational; xmpq::trunc_fract; struct RemTruncIncomplete {} }
ref_rat_op_rat_int! { xmpq::trunc_fract_whole; struct FractTruncIncomplete {} }
ref_rat_op_int! { xmpq::ceil_int; struct CeilIncomplete {} }
ref_math_op1! { Rational; xmpq::ceil_fract; struct RemCeilIncomplete {} }
ref_rat_op_rat_int! { xmpq::ceil_fract_whole; struct FractCeilIncomplete {} }
ref_rat_op_int! { xmpq::floor_int; struct FloorIncomplete {} }
ref_math_op1! { Rational; xmpq::floor_fract; struct RemFloorIncomplete {} }
ref_rat_op_rat_int! { xmpq::floor_fract_whole; struct FractFloorIncomplete {} }
ref_rat_op_int! { xmpq::round_int; struct RoundIncomplete {} }
ref_math_op1! { Rational; xmpq::round_fract; struct RemRoundIncomplete {} }
ref_rat_op_rat_int! { xmpq::round_fract_whole; struct FractRoundIncomplete {} }
ref_math_op1! { Rational; xmpq::square; struct SquareIncomplete {} }

#[derive(Debug)]
#[repr(transparent)]
pub struct BorrowRational<'a> {
    inner: ManuallyDrop<Rational>,
    phantom: PhantomData<&'a Rational>,
}

impl BorrowRational<'_> {
    // unsafe because the lifetime is obtained from return type
    pub(crate) const unsafe fn from_raw<'a>(raw: mpq_t) -> BorrowRational<'a> {
        BorrowRational {
            inner: ManuallyDrop::new(Rational { inner: raw }),
            phantom: PhantomData,
        }
    }
}

impl Deref for BorrowRational<'_> {
    type Target = Rational;
    #[inline]
    fn deref(&self) -> &Rational {
        &*self.inner
    }
}

pub(crate) fn append_to_string(s: &mut String, r: &Rational, radix: i32, to_upper: bool) {
    let (num, den) = (r.numer(), r.denom());
    let is_whole = *den == 1;
    if !is_whole {
        // 2 for '/' and nul
        let cap_for_den_nul = big_integer::req_chars(den, radix, 2);
        let cap = big_integer::req_chars(num, radix, cap_for_den_nul);
        s.reserve(cap);
    };
    let reserved_ptr = s.as_ptr();
    big_integer::append_to_string(s, num, radix, to_upper);
    if !is_whole {
        s.push('/');
        big_integer::append_to_string(s, den, radix, to_upper);
        debug_assert_eq!(reserved_ptr, s.as_ptr());
        #[cfg(not(debug_assertions))]
        {
            let _ = reserved_ptr;
        }
    }
}

#[derive(Debug)]
pub struct ParseIncomplete {
    is_negative: bool,
    digits: Vec<u8>,
    den_start: usize,
    radix: i32,
}

impl Assign<ParseIncomplete> for Rational {
    fn assign(&mut self, src: ParseIncomplete) {
        let num_len = src.den_start;
        if num_len == 0 {
            xmpq::set_0(self);
            return;
        }
        let den_len = src.digits.len() - num_len;
        let num_str = src.digits.as_ptr();
        unsafe {
            let (num, den) = self.as_mut_numer_denom_no_canonicalization();
            xmpz::realloc_for_mpn_set_str(num, num_len, src.radix);
            let size = gmp::mpn_set_str(num.inner_mut().d.as_ptr(), num_str, num_len, src.radix);
            num.inner_mut().size = (if src.is_negative { -size } else { size }).unwrapped_cast();

            if den_len == 0 {
                // The number is in canonical form if the denominator is 1.
                xmpz::set_1(den);
                return;
            }
            let den_str = num_str.offset(num_len.unwrapped_cast());
            xmpz::realloc_for_mpn_set_str(den, den_len, src.radix);
            let size = gmp::mpn_set_str(den.inner_mut().d.as_ptr(), den_str, den_len, src.radix);
            den.inner_mut().size = size.unwrapped_cast();
            xmpq::canonicalize(self);
        }
    }
}

from_assign! { ParseIncomplete => Rational }

fn parse(bytes: &[u8], radix: i32) -> Result<ParseIncomplete, ParseRationalError> {
    use self::{ParseErrorKind as Kind, ParseRationalError as Error};

    assert!((2..=36).contains(&radix), "radix out of range");
    let bradix = radix.unwrapped_as::<u8>();

    let mut digits = Vec::with_capacity(bytes.len() + 1);
    let mut has_sign = false;
    let mut is_negative = false;
    let mut has_digits = false;
    let mut den_start = None;
    for &b in bytes {
        if b == b'/' {
            if den_start.is_some() {
                return Err(Error {
                    kind: Kind::TooManySlashes,
                });
            }
            if !has_digits {
                return Err(Error {
                    kind: Kind::NumerNoDigits,
                });
            }
            has_digits = false;
            den_start = Some(digits.len());
            continue;
        }
        let digit = match b {
            b'+' if den_start.is_none() && !has_sign && !has_digits => {
                has_sign = true;
                continue;
            }
            b'-' if den_start.is_none() && !has_sign && !has_digits => {
                is_negative = true;
                has_sign = true;
                continue;
            }
            b'_' if has_digits => continue,
            b' ' | b'\t' | b'\n' | 0x0b | 0x0c | 0x0d => continue,

            b'0'..=b'9' => b - b'0',
            b'a'..=b'z' => b - b'a' + 10,
            b'A'..=b'Z' => b - b'A' + 10,

            // error
            _ => bradix,
        };
        if digit >= bradix {
            return Err(Error {
                kind: Kind::InvalidDigit,
            });
        }
        has_digits = true;
        if digit > 0 || (!digits.is_empty() && den_start != Some(digits.len())) {
            digits.push(digit);
        }
    }
    if !has_digits {
        return Err(Error {
            kind: if den_start.is_some() {
                Kind::DenomNoDigits
            } else {
                Kind::NoDigits
            },
        });
    }
    if den_start == Some(digits.len()) {
        return Err(Error {
            kind: Kind::DenomZero,
        });
    }
    let den_start = den_start.unwrap_or_else(|| digits.len());
    Ok(ParseIncomplete {
        is_negative,
        digits,
        den_start,
        radix,
    })
}

#[derive(Debug)]
/**
An error which can be returned when parsing a [`Rational`] number.

See the
<code>[Rational][`Rational`]::[parse_radix][`parse_radix`]</code>
method for details on what strings are accepted.

# Examples

```rust
use rug::{rational::ParseRationalError, Rational};
// This string is not a rational number.
let s = "something completely different (_!_!_)";
let error: ParseRationalError = match Rational::parse_radix(s, 4) {
    Ok(_) => unreachable!(),
    Err(error) => error,
};
println!("Parse error: {}", error);
```

[`Rational`]: ../struct.Rational.html
[`parse_radix`]: ../struct.Rational.html#method.parse_radix
*/
pub struct ParseRationalError {
    kind: ParseErrorKind,
}

#[derive(Debug)]
enum ParseErrorKind {
    InvalidDigit,
    NoDigits,
    NumerNoDigits,
    DenomNoDigits,
    TooManySlashes,
    DenomZero,
}

impl ParseRationalError {
    fn desc(&self) -> &str {
        use self::ParseErrorKind::*;
        match self.kind {
            InvalidDigit => "invalid digit found in string",
            NoDigits => "string has no digits",
            NumerNoDigits => "string has no digits for numerator",
            DenomNoDigits => "string has no digits for denominator",
            TooManySlashes => "more than one / found in string",
            DenomZero => "string has zero denominator",
        }
    }
}

impl Error for ParseRationalError {
    fn description(&self) -> &str {
        self.desc()
    }
}

impl Display for ParseRationalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(self.desc(), f)
    }
}
