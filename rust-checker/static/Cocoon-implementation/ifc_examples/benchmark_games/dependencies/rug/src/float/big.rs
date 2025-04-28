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

#[cfg(feature = "rand")]
use crate::rand::MutRandState;
#[cfg(feature = "rational")]
use crate::Rational;
use crate::{
    ext::xmpfr::{self, ordering1, raw_round},
    float::{
        self,
        arith::{AddMulIncomplete, MulAddMulIncomplete, MulSubMulIncomplete, SubMulFromIncomplete},
        OrdFloat, Round, SmallFloat, Special,
    },
    misc,
    ops::{AddAssignRound, AssignRound, DivRounding, NegAssign},
    Assign,
};
use az::{Az, CheckedCast, SaturatingCast, UnwrappedAs, UnwrappedCast, WrappingAs};
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    i32,
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    num::FpCategory,
    ops::{Add, AddAssign, Deref},
    slice, str, u32,
};
use gmp_mpfr_sys::{
    gmp::{self, limb_t},
    mpfr::{self, exp_t, mpfr_t},
};
use libc::c_char;
use std::{
    error::Error,
    ffi::{CStr, CString},
};
#[cfg(feature = "complex")]
use {crate::complex::big::BorrowComplex, gmp_mpfr_sys::mpc::mpc_t};
#[cfg(feature = "integer")]
use {
    crate::{integer::big::BorrowInteger, Integer},
    gmp_mpfr_sys::{gmp::mpz_t, mpfr::prec_t},
};

/**
A multi-precision floating-point number with arbitrarily large
precision and correct rounding

The precision has to be set during construction. The rounding method
of the required operations can be specified, and the direction of the
rounding is returned.

# Examples

```rust
use core::cmp::Ordering;
use rug::{float::Round, ops::DivAssignRound, Float};
// A precision of 32 significant bits is specified here.
// (The primitive `f32` has a precision of 24 and
// `f64` has a precision of 53.)
let mut two_thirds_down = Float::with_val(32, 2.0);
let dir = two_thirds_down.div_assign_round(3.0, Round::Down);
// since we rounded down, direction is Ordering::Less
assert_eq!(dir, Ordering::Less);
let mut two_thirds_up = Float::with_val(32, 2.0);
let dir = two_thirds_up.div_assign_round(3.0, Round::Up);
// since we rounded up, direction is Ordering::Greater
assert_eq!(dir, Ordering::Greater);
let diff_expected = 2.0_f64.powi(-32);
let diff = two_thirds_up - two_thirds_down;
assert_eq!(diff, diff_expected);
```

Operations on two borrowed `Float` numbers result in an
[incomplete-computation value][icv] that has to be assigned to a new
`Float` value.

```rust
use rug::Float;
let a = Float::with_val(53, 10.5);
let b = Float::with_val(53, -1.25);
let a_b_ref = &a + &b;
let a_b = Float::with_val(53, a_b_ref);
assert_eq!(a_b, 9.25);
```

As a special case, when an [incomplete-computation value][icv] is
obtained from multiplying two `Float` references, it can be added to
or subtracted from another `Float` (or reference). This will result in
a fused multiply-accumulate operation, with only one rounding
operation taking place.

```rust
use rug::Float;
// Use only 4 bits of precision for demonstration purposes.
// 24 in binary is 11000.
let a = Float::with_val(4, 24);
// 1.5 in binary is 1.1.
let mul1 = Float::with_val(4, 1.5);
// −13 in binary is −1101.
let mul2 = Float::with_val(4, -13);
// 24 + 1.5 × −13 = 4.5
let add = Float::with_val(4, &a + &mul1 * &mul2);
assert_eq!(add, 4.5);
// 24 − 1.5 × −13 = 43.5, rounded to 44 using four bits of precision.
let sub = a - &mul1 * &mul2;
assert_eq!(sub, 44);

// With separate addition and multiplication:
let a = Float::with_val(4, 24);
// No borrows, so multiplication is computed immediately.
// 1.5 × −13 = −19.5 (binary −10011.1), rounded to −20.
let separate_add = a + mul1 * mul2;
assert_eq!(separate_add, 4);
```

The [incomplete-computation value][icv] obtained from multiplying two
`Float` references can also be added to or subtracted from another
such [incomplete-computation value][icv], so that two muliplications
and an addition are fused with only one rounding operation taking
place.

```rust
use rug::Float;
let a = Float::with_val(53, 24);
let b = Float::with_val(53, 1.5);
let c = Float::with_val(53, 12);
let d = Float::with_val(53, 2);
// 24 × 1.5 + 12 × 2 = 60
let add = Float::with_val(53, &a * &b + &c * &d);
assert_eq!(add, 60);
// 24 × 1.5 − 12 × 2 = 12
let sub = Float::with_val(53, &a * &b - &c * &d);
assert_eq!(sub, 12);
```

The `Float` type supports various functions. Most methods have four
versions:

 1. The first method consumes the operand and rounds the returned
    `Float` to the [nearest][`Nearest`] representable value.
 2. The second method has a “`_mut`” suffix, mutates the operand and
    rounds it the nearest representable value.
 3. The third method has a “`_round`” suffix, mutates the operand,
    applies the specified [rounding method][`Round`], and returns the
    rounding direction:
      * <code>[Ordering][`Ordering`]::[Less][`Less`]</code> if the
        stored value is less than the exact result,
      * <code>[Ordering][`Ordering`]::[Equal][`Equal`]</code> if the
        stored value is equal to the exact result,
      * <code>[Ordering][`Ordering`]::[Greater][`Greater`]</code> if
        the stored value is greater than the exact result.
 4. The fourth method has a “`_ref`” suffix and borrows the operand.
    The returned item is an [incomplete-computation value][icv] that
    can be assigned to a `Float`; the rounding method is selected
    during the assignment.

```rust
use core::cmp::Ordering;
use rug::{float::Round, Float};
let expected = 0.9490_f64;

// 1. consume the operand, round to nearest
let a = Float::with_val(53, 1.25);
let sin_a = a.sin();
assert!((sin_a - expected).abs() < 0.0001);

// 2. mutate the operand, round to nearest
let mut b = Float::with_val(53, 1.25);
b.sin_mut();
assert!((b - expected).abs() < 0.0001);

// 3. mutate the operand, apply specified rounding
let mut c = Float::with_val(4, 1.25);
// using 4 significant bits, 0.9490 is rounded down to 0.9375
let dir = c.sin_round(Round::Nearest);
assert_eq!(c, 0.9375);
assert_eq!(dir, Ordering::Less);

// 4. borrow the operand
let d = Float::with_val(53, 1.25);
let r = d.sin_ref();
let sin_d = Float::with_val(53, r);
assert!((sin_d - expected).abs() < 0.0001);
// d was not consumed
assert_eq!(d, 1.25);
```

The following example is a translation of the [MPFR sample] found on
the MPFR website. The program computes a lower bound on 1 + 1/1! +
1/2! + … + 1/100! using 200-bit precision. The program writes:

`Sum is 2.7182818284590452353602874713526624977572470936999595749669131`

```rust
use rug::{
    float::{self, FreeCache, Round},
    ops::{AddAssignRound, AssignRound, MulAssignRound},
    Float,
};

let mut t = Float::with_val(200, 1.0);
let mut s = Float::with_val(200, 1.0);
let mut u = Float::new(200);
for i in 1..=100_u32 {
    // multiply t by i in place, round towards +∞
    t.mul_assign_round(i, Round::Up);
    // set u to 1/t, round towards −∞
    u.assign_round(t.recip_ref(), Round::Down);
    // increase s by u in place, round towards −∞
    s.add_assign_round(&u, Round::Down);
}
// `None` means the number of printed digits depends on the precision
let sr = s.to_string_radix_round(10, None, Round::Down);
println!("Sum is {}", sr);
# let good = "2.7182818284590452353602874713526624977572470936999595749669131";
# assert_eq!(sr, good);

float::free_cache(FreeCache::All);
```

[MPFR sample]: https://www.mpfr.org/sample.html
[`Equal`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Equal
[`Greater`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Greater
[`Less`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Less
[`Nearest`]: float/enum.Round.html#variant.Nearest
[`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
[`Round`]: float/enum.Round.html
[icv]: index.html#incomplete-computation-values
*/
#[repr(transparent)]
pub struct Float {
    inner: mpfr_t,
}

impl Float {
    #[inline]
    pub(crate) fn inner(&self) -> &mpfr_t {
        &self.inner
    }
    #[inline]
    pub(crate) unsafe fn inner_mut(&mut self) -> &mut mpfr_t {
        &mut self.inner
    }
    #[inline]
    pub(crate) fn inner_data(&self) -> &[limb_t] {
        if self.is_normal() {
            let prec = self.inner.prec.unwrapped_as::<usize>();
            let limbs = prec.div_ceil(gmp::LIMB_BITS.az::<usize>());
            unsafe { slice::from_raw_parts(self.inner.d.as_ptr(), limbs) }
        } else {
            &[]
        }
    }
}

static_assert_same_layout!(Float, mpfr_t);
static_assert_same_layout!(BorrowFloat<'_>, mpfr_t);

static_assert_same_size!(Float, Option<Float>);

macro_rules! ref_math_op0_float {
    ($($rest:tt)*) => {
        ref_math_op0_round! {
            Float, Round, Round::Nearest, Ordering;
            $($rest)*
        }
    };
}

macro_rules! ref_math_op1_float {
    ($($rest:tt)*) => {
        ref_math_op1_round! {
            Float, Round, Round::Nearest, Ordering;
            $($rest)*
        }
    };
}

macro_rules! ref_math_op1_2_float {
    ($($rest:tt)*) => {
        ref_math_op1_2_round! {
            Float, Round, Round::Nearest, (Ordering, Ordering);
            $($rest)*
        }
    };
}

macro_rules! ref_math_op2_float {
    ($($rest:tt)*) => {
        ref_math_op2_round! {
            Float, Round, Round::Nearest, Ordering;
            $($rest)*
        }
    };
}

impl Float {
    /// Create a new [`Float`] with the specified precision and with
    /// value 0.
    ///
    /// # Panics
    ///
    /// Panics if `prec` is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::new(53);
    /// assert_eq!(f.prec(), 53);
    /// assert_eq!(f, 0);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn new(prec: u32) -> Self {
        Self::with_val(prec, Special::Zero)
    }

    /// Create a new [`Float`] with the specified precision and with
    /// the given value, rounding to the nearest.
    ///
    /// # Panics
    ///
    /// Panics if `prec` is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.3);
    /// assert_eq!(f.prec(), 53);
    /// assert_eq!(f, 1.3);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn with_val<T>(prec: u32, val: T) -> Self
    where
        Float: Assign<T>,
    {
        let mut ret = Float::new_nan(prec);
        ret.assign(val);
        ret
    }

    /// Create a new [`Float`] with the specified precision and with
    /// the given value, applying the specified rounding method.
    ///
    /// # Panics
    ///
    /// Panics if `prec` is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let (f1, dir) = Float::with_val_round(4, 3.3, Round::Nearest);
    /// // 3.3 with precision 4 is rounded down to 3.25
    /// assert_eq!(f1.prec(), 4);
    /// assert_eq!(f1, 3.25);
    /// assert_eq!(dir, Ordering::Less);
    /// let (f2, dir) = Float::with_val_round(4, 3.3, Round::Up);
    /// // 3.3 rounded up to 3.5
    /// assert_eq!(f2.prec(), 4);
    /// assert_eq!(f2, 3.5);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn with_val_round<T>(prec: u32, val: T, round: Round) -> (Self, Ordering)
    where
        Self: AssignRound<T, Round = Round, Ordering = Ordering>,
    {
        let mut ret = Float::new_nan(prec);
        let ord = ret.assign_round(val, round);
        (ret, ord)
    }

    #[inline]
    pub(crate) fn new_nan(prec: u32) -> Self {
        assert!(
            prec >= float::prec_min() && prec <= float::prec_max(),
            "precision out of range"
        );
        let mut ret = MaybeUninit::uninit();
        xmpfr::write_new_nan(&mut ret, prec.unwrapped_cast());
        // Safety: write_new_nan initializes ret.
        unsafe { ret.assume_init() }
    }

    /// Returns the precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::new(53);
    /// assert_eq!(f.prec(), 53);
    /// ```
    #[inline]
    pub fn prec(&self) -> u32 {
        xmpfr::get_prec(self).unwrapped_cast()
    }

    /// Sets the precision, rounding to the nearest.
    ///
    /// # Panics
    ///
    /// Panics if `prec` is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // 16.25 has seven significant bits (binary 10000.01)
    /// let mut f = Float::with_val(53, 16.25);
    /// f.set_prec(5);
    /// assert_eq!(f, 16);
    /// assert_eq!(f.prec(), 5);
    /// ```
    #[inline]
    pub fn set_prec(&mut self, prec: u32) {
        self.set_prec_round(prec, Round::Nearest);
    }

    /// Sets the precision, applying the specified rounding method.
    ///
    /// # Panics
    ///
    /// Panics if `prec` is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 16.25 has seven significant bits (binary 10000.01)
    /// let mut f = Float::with_val(53, 16.25);
    /// let dir = f.set_prec_round(5, Round::Up);
    /// assert_eq!(f, 17);
    /// assert_eq!(dir, Ordering::Greater);
    /// assert_eq!(f.prec(), 5);
    /// ```
    #[inline]
    pub fn set_prec_round(&mut self, prec: u32, round: Round) -> Ordering {
        assert!(
            prec >= float::prec_min() && prec <= float::prec_max(),
            "precision out of range"
        );
        xmpfr::prec_round(self, prec.unwrapped_cast(), round)
    }

    /// Creates a [`Float`] from an initialized
    /// [MPFR floating-point number][`mpfr_t`].
    ///
    /// # Safety
    ///
    ///   * The value must be initialized.
    ///   * The [`mpfr_t`] type can be considered as a kind of
    ///     pointer, so there can be multiple copies of it. Since this
    ///     function takes over ownership, no other copies of the
    ///     passed value should exist.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::mem::MaybeUninit;
    /// use gmp_mpfr_sys::mpfr::{self, rnd_t};
    /// use rug::Float;
    /// let f = unsafe {
    ///     let mut m = MaybeUninit::uninit();
    ///     mpfr::init2(m.as_mut_ptr(), 53);
    ///     let mut m = m.assume_init();
    ///     mpfr::set_d(&mut m, -14.5, rnd_t::RNDN);
    ///     // m is initialized and unique
    ///     Float::from_raw(m)
    /// };
    /// assert_eq!(f, -14.5);
    /// // since f is a Float now, deallocation is automatic
    /// ```
    ///
    /// [`Float`]: #
    /// [`mpfr_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpfr/struct.mpfr_t.html
    #[inline]
    pub unsafe fn from_raw(raw: mpfr_t) -> Self {
        Float { inner: raw }
    }

    /// Converts a [`Float`] into an
    /// [MPFR floating-point number][`mpfr_t`].
    ///
    /// The returned object should be freed to avoid memory leaks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::mpfr::{self, rnd_t};
    /// use rug::Float;
    /// let f = Float::with_val(53, -14.5);
    /// let mut m = f.into_raw();
    /// unsafe {
    ///     let d = mpfr::get_d(&m, rnd_t::RNDN);
    ///     assert_eq!(d, -14.5);
    ///     // free object to prevent memory leak
    ///     mpfr::clear(&mut m);
    /// }
    /// ```
    ///
    /// [`Float`]: #
    /// [`mpfr_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpfr/struct.mpfr_t.html
    #[inline]
    pub fn into_raw(self) -> mpfr_t {
        let m = ManuallyDrop::new(self);
        m.inner
    }

    /// Returns a pointer to the inner
    /// [MPFR floating-point number][`mpfr_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::mpfr::{self, rnd_t};
    /// use rug::Float;
    /// let f = Float::with_val(53, -14.5);
    /// let m_ptr = f.as_raw();
    /// unsafe {
    ///     let d = mpfr::get_d(m_ptr, rnd_t::RNDN);
    ///     assert_eq!(d, -14.5);
    /// }
    /// // f is still valid
    /// assert_eq!(f, -14.5);
    /// ```
    ///
    /// [`mpfr_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpfr/struct.mpfr_t.html
    #[inline]
    pub fn as_raw(&self) -> *const mpfr_t {
        &self.inner
    }

    /// Returns an unsafe mutable pointer to the inner
    /// [MPFR floating-point number][`mpfr_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::mpfr::{self, rnd_t};
    /// use rug::Float;
    /// let mut f = Float::with_val(53, -14.5);
    /// let m_ptr = f.as_raw_mut();
    /// unsafe {
    ///     mpfr::add_ui(m_ptr, m_ptr, 10, rnd_t::RNDN);
    /// }
    /// assert_eq!(f, -4.5);
    /// ```
    ///
    /// [`mpfr_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpfr/struct.mpfr_t.html
    #[inline]
    pub fn as_raw_mut(&mut self) -> *mut mpfr_t {
        &mut self.inner
    }

    /// Parses a decimal string slice (<code>&amp;[str]</code>) or
    /// byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into a
    /// [`Float`].
    ///
    /// <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    /// is implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`.
    ///
    /// The string can start with an optional minus or plus sign and
    /// must then have one or more significant digits with an optional
    /// decimal point. This can optionally be followed by an exponent;
    /// the exponent can start with a separator “`e`”, “`E`” or “`@`”,
    /// and is followed by an optional minus or plus sign and by one
    /// or more decimal digits.
    ///
    /// Alternatively, the string can indicate the special values
    /// infinity or NaN. Infinity can be represented as `"inf"`,
    /// `"infinity"`, `"@inf@"` or `"@infinity@"`,and NaN can be
    /// represented as `"nan"` or `"@nan@"`. All of these special
    /// representations are case insensitive. The NaN representation
    /// may also include a possibly-empty string of ASCII letters,
    /// digits and underscores enclosed in brackets, for example
    /// `"nan(char_sequence_1)"`.
    ///
    /// ASCII whitespace is ignored everywhere in the string except in
    /// the substrings specified above for special values; for example
    /// `" @inf@ "` is accepted but `"@ inf @"` is not. Underscores
    /// are ignored anywhere in digit strings except before the first
    /// digit and between the exponent separator and the first digit
    /// of the exponent.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    ///
    /// let valid = Float::parse("12.25e-4");
    /// let f = Float::with_val(53, valid.unwrap());
    /// assert_eq!(f, 12.25e-4);
    ///
    /// let invalid = Float::parse(".e-4");
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Float`]: #
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse<S: AsRef<[u8]>>(src: S) -> Result<ParseIncomplete, ParseFloatError> {
        parse(src.as_ref(), 10)
    }

    /// Parses a string slice (<code>&amp;[str]</code>) or byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into a
    /// [`Float`].
    ///
    /// <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    /// is implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`.
    ///
    /// The string can start with an optional minus or plus sign and
    /// must then have one or more significant digits with an optional
    /// point. This can optionally be followed by an exponent; the
    /// exponent can start with a separator “`e`” or “`E`” if the
    /// radix ≤ 10, or “`@`” for any radix, and is followed by an
    /// optional minus or plus sign and by one or more decimal digits.
    ///
    /// Alternatively, the string can indicate the special values
    /// infinity or NaN. If the radix ≤ 10, infinity can be
    /// represented as `"inf"` or `"infinity"`, and NaN can be
    /// represented as `"nan"`. For any radix, infinity can also be
    /// represented as `"@inf@"` or `"@infinity@"`, and NaN can be
    /// represented as `"@nan@"`. All of these special representations
    /// are case insensitive. The NaN representation may also include
    /// a possibly-empty string of ASCII letters, digits and
    /// underscores enclosed in brackets, for example
    /// `"nan(char_sequence_1)"`.
    ///
    /// ASCII whitespace is ignored everywhere in the string except in
    /// the substrings specified above for special values; for example
    /// `" @inf@ "` is accepted but `"@ inf @"` is not. Underscores
    /// are ignored anywhere in digit strings except before the first
    /// digit and between the exponent separator and the first digit
    /// of the exponent.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    ///
    /// let valid1 = Float::parse_radix("12.23e-4", 4);
    /// let f1 = Float::with_val(53, valid1.unwrap());
    /// assert_eq!(f1, (2.0 + 4.0 * 1.0 + 0.25 * (2.0 + 0.25 * 3.0)) / 256.0);
    /// let valid2 = Float::parse_radix("12.yz@2", 36);
    /// let f2 = Float::with_val(53, valid2.unwrap());
    /// assert_eq!(f2, 35 + 36 * (34 + 36 * (2 + 36 * 1)));
    ///
    /// let invalid = Float::parse_radix("ffe-2", 16);
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Float`]: #
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse_radix<S: AsRef<[u8]>>(
        src: S,
        radix: i32,
    ) -> Result<ParseIncomplete, ParseFloatError> {
        parse(src.as_ref(), radix)
    }

    #[cfg(feature = "integer")]
    /// If the value is a [finite number][`is_finite`], converts it to
    /// an [`Integer`] rounding to the nearest.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;float).[checked\_as][`checked_as`]::&lt;[Integer][`Integer`]&gt;()</code>
    ///   * <code>float.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[Integer][`Integer`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 13.7);
    /// let i = match f.to_integer() {
    ///     Some(i) => i,
    ///     None => unreachable!(),
    /// };
    /// assert_eq!(i, 14);
    /// ```
    ///
    /// [`Integer`]: struct.Integer.html
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`is_finite`]: #method.is_finite
    #[inline]
    pub fn to_integer(&self) -> Option<Integer> {
        self.checked_cast()
    }

    #[cfg(feature = "integer")]
    /// If the value is a [finite number][`is_finite`], converts it to
    /// an [`Integer`] applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let f = Float::with_val(53, 13.7);
    /// let (i, dir) = match f.to_integer_round(Round::Down) {
    ///     Some(i_dir) => i_dir,
    ///     None => unreachable!(),
    /// };
    /// assert_eq!(i, 13);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    ///
    /// [`Integer`]: struct.Integer.html
    /// [`is_finite`]: #method.is_finite
    #[inline]
    pub fn to_integer_round(&self, round: Round) -> Option<(Integer, Ordering)> {
        if !self.is_finite() {
            return None;
        }
        let mut i = Integer::new();
        let ret = unsafe { mpfr::get_z(i.as_raw_mut(), self.as_raw(), raw_round(round)) };
        Some((i, ordering1(ret)))
    }

    #[cfg(feature = "integer")]
    /// If the value is a [finite number][`is_finite`], returns an
    /// [`Integer`] and exponent such that it is exactly equal to the
    /// integer multiplied by two raised to the power of the exponent.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Special, Assign, Float};
    /// let mut float = Float::with_val(16, 6.5);
    /// // 6.5 in binary is 110.1
    /// // Since the precision is 16 bits, this becomes
    /// // 1101_0000_0000_0000 times two to the power of −12
    /// let (int, exp) = float.to_integer_exp().unwrap();
    /// assert_eq!(int, 0b1101_0000_0000_0000);
    /// assert_eq!(exp, -13);
    ///
    /// float.assign(0);
    /// let (zero, _) = float.to_integer_exp().unwrap();
    /// assert_eq!(zero, 0);
    ///
    /// float.assign(Special::Infinity);
    /// assert!(float.to_integer_exp().is_none());
    /// ```
    ///
    /// [`Integer`]: struct.Integer.html
    /// [`is_finite`]: #method.is_finite
    #[inline]
    pub fn to_integer_exp(&self) -> Option<(Integer, i32)> {
        if !self.is_finite() {
            return None;
        }
        let mut i = Integer::new();
        let exp = unsafe { mpfr::get_z_2exp(i.as_raw_mut(), self.as_raw()) };
        Some((i, exp.unwrapped_cast()))
    }

    #[cfg(feature = "rational")]
    /// If the value is a [finite number][`is_finite`], returns a
    /// [`Rational`] number preserving all the precision of the value.
    ///
    /// This conversion can also be performed using
    ///   * <code>[Rational][`Rational`]::[try_from][`try_from`](&amp;float)</code>
    ///   * <code>[Rational][`Rational`]::[try_from][`try_from`](float)</code>
    ///   * <code>(&amp;float).[checked\_as][`checked_as`]::&lt;[Rational][`Rational`]&gt;()</code>
    ///   * <code>float.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[Rational][`Rational`]&gt;()</code>
    ///
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::{cmp::Ordering, str::FromStr};
    /// use rug::{float::Round, Float, Rational};
    ///
    /// // Consider the number 123,456,789 / 10,000,000,000.
    /// let parse = Float::parse("0.0123456789").unwrap();
    /// let (f, f_rounding) = Float::with_val_round(35, parse, Round::Down);
    /// assert_eq!(f_rounding, Ordering::Less);
    /// let r = Rational::from_str("123456789/10000000000").unwrap();
    /// // Set fr to the value of f exactly.
    /// let fr = f.to_rational().unwrap();
    /// // Since f == fr and f was rounded down, r != fr.
    /// assert_ne!(r, fr);
    /// let (frf, frf_rounding) = Float::with_val_round(35, &fr, Round::Down);
    /// assert_eq!(frf_rounding, Ordering::Equal);
    /// assert_eq!(frf, f);
    /// assert_eq!(format!("{:.9}", frf), "1.23456789e-2");
    /// ```
    ///
    /// In the following example, the [`Float`] values can be
    /// represented exactly.
    ///
    /// ```rust
    /// use rug::Float;
    ///
    /// let large_f = Float::with_val(16, 6.5);
    /// let large_r = large_f.to_rational().unwrap();
    /// let small_f = Float::with_val(16, -0.125);
    /// let small_r = small_f.to_rational().unwrap();
    ///
    /// assert_eq!(*large_r.numer(), 13);
    /// assert_eq!(*large_r.denom(), 2);
    /// assert_eq!(*small_r.numer(), -1);
    /// assert_eq!(*small_r.denom(), 8);
    /// ```
    ///
    /// [`Float`]: #
    /// [`Rational`]: struct.Rational.html
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`is_finite`]: #method.is_finite
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_rational(&self) -> Option<Rational> {
        self.checked_cast()
    }

    /// Converts to an [`i32`], rounding to the nearest.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    /// If the value is a NaN, [`None`] is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::{i32, u32};
    /// use rug::{Assign, Float};
    /// let mut f = Float::with_val(53, -13.7);
    /// assert_eq!(f.to_i32_saturating(), Some(-14));
    /// f.assign(-1e40);
    /// assert_eq!(f.to_i32_saturating(), Some(i32::MIN));
    /// f.assign(u32::MAX);
    /// assert_eq!(f.to_i32_saturating(), Some(i32::MAX));
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
    #[inline]
    pub fn to_i32_saturating(&self) -> Option<i32> {
        self.to_i32_saturating_round(Round::Nearest)
    }

    /// Converts to an [`i32`], applying the specified rounding method.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    /// If the value is a NaN, [`None`] is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Round, Float};
    /// let f = Float::with_val(53, -13.7);
    /// assert_eq!(f.to_i32_saturating_round(Round::Up), Some(-13));
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
    #[inline]
    pub fn to_i32_saturating_round(&self, round: Round) -> Option<i32> {
        if self.is_nan() {
            None
        } else {
            Some(xmpfr::get_si(self, round).saturating_cast())
        }
    }

    /// Converts to a [`u32`], rounding to the nearest.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    /// If the value is a NaN, [`None`] is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::u32;
    /// use rug::{Assign, Float};
    /// let mut f = Float::with_val(53, 13.7);
    /// assert_eq!(f.to_u32_saturating(), Some(14));
    /// f.assign(-1);
    /// assert_eq!(f.to_u32_saturating(), Some(0));
    /// f.assign(1e40);
    /// assert_eq!(f.to_u32_saturating(), Some(u32::MAX));
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
    #[inline]
    pub fn to_u32_saturating(&self) -> Option<u32> {
        self.to_u32_saturating_round(Round::Nearest)
    }

    /// Converts to a [`u32`], applying the specified rounding method.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    /// If the value is a NaN, [`None`] is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Round, Float};
    /// let f = Float::with_val(53, 13.7);
    /// assert_eq!(f.to_u32_saturating_round(Round::Down), Some(13));
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
    #[inline]
    pub fn to_u32_saturating_round(&self, round: Round) -> Option<u32> {
        if self.is_nan() {
            None
        } else {
            Some(xmpfr::get_ui(self, round).saturating_cast())
        }
    }

    /// Converts to an [`f32`], rounding to the nearest.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::{Assign, Float};
    /// let mut f = Float::with_val(53, 13.7);
    /// assert_eq!(f.to_f32(), 13.7);
    /// f.assign(1e300);
    /// assert_eq!(f.to_f32(), f32::INFINITY);
    /// f.assign(1e-300);
    /// assert_eq!(f.to_f32(), 0.0);
    /// ```
    ///
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    #[inline]
    pub fn to_f32(&self) -> f32 {
        self.to_f32_round(Round::Nearest)
    }

    /// Converts to an [`f32`], applying the specified rounding
    /// method.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::{float::Round, Float};
    /// let f = Float::with_val(53, 1.0 + (-50f64).exp2());
    /// assert_eq!(f.to_f32_round(Round::Up), 1.0 + f32::EPSILON);
    /// ```
    ///
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    #[inline]
    pub fn to_f32_round(&self, round: Round) -> f32 {
        xmpfr::get_f32(self, round)
    }

    /// Converts to an [`f64`], rounding to the nearest.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::{Assign, Float};
    /// let mut f = Float::with_val(53, 13.7);
    /// assert_eq!(f.to_f64(), 13.7);
    /// f.assign(1e300);
    /// f.square_mut();
    /// assert_eq!(f.to_f64(), f64::INFINITY);
    /// ```
    ///
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    #[inline]
    pub fn to_f64(&self) -> f64 {
        self.to_f64_round(Round::Nearest)
    }

    /// Converts to an [`f64`], applying the specified rounding
    /// method.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::{float::Round, Float};
    /// // (2.0 ^ −90) + 1
    /// let f: Float = Float::with_val(100, -90).exp2() + 1;
    /// assert_eq!(f.to_f64_round(Round::Up), 1.0 + f64::EPSILON);
    /// ```
    ///
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    #[inline]
    pub fn to_f64_round(&self, round: Round) -> f64 {
        xmpfr::get_f64(self, round)
    }

    /// Converts to an [`f32`] and an exponent, rounding to the
    /// nearest.
    ///
    /// The returned [`f32`] is in the range 0.5 ≤ <i>x</i> < 1.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let zero = Float::new(64);
    /// let (d0, exp0) = zero.to_f32_exp();
    /// assert_eq!((d0, exp0), (0.0, 0));
    /// let three_eighths = Float::with_val(64, 0.375);
    /// let (d3_8, exp3_8) = three_eighths.to_f32_exp();
    /// assert_eq!((d3_8, exp3_8), (0.75, -1));
    /// ```
    ///
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    #[inline]
    pub fn to_f32_exp(&self) -> (f32, i32) {
        self.to_f32_exp_round(Round::Nearest)
    }

    /// Converts to an [`f32`] and an exponent, applying the specified
    /// rounding method.
    ///
    /// The returned [`f32`] is in the range 0.5 ≤ <i>x</i> < 1.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Round, Float};
    /// let frac_10_3 = Float::with_val(64, 10) / 3u32;
    /// let (f_down, exp_down) = frac_10_3.to_f32_exp_round(Round::Down);
    /// assert_eq!((f_down, exp_down), (0.8333333, 2));
    /// let (f_up, exp_up) = frac_10_3.to_f32_exp_round(Round::Up);
    /// assert_eq!((f_up, exp_up), (0.8333334, 2));
    /// ```
    ///
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    #[inline]
    pub fn to_f32_exp_round(&self, round: Round) -> (f32, i32) {
        let mut sf = SmallFloat::from(0.0f32);
        assert_eq!(sf.prec(), 24);
        // Safety: xmpfr::set will not change precision of sf, so we
        // can use the unsafe as_nonreallocating_float function.
        unsafe {
            xmpfr::set(sf.as_nonreallocating_float(), self, round);
        }
        let (f, exp) = xmpfr::get_f64_2exp(&*sf, Round::Zero);
        (f as f32, exp.unwrapped_cast())
    }

    /// Converts to an [`f64`] and an exponent, rounding to the
    /// nearest.
    ///
    /// The returned [`f64`] is in the range 0.5 ≤ <i>x</i> < 1.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let zero = Float::new(64);
    /// let (d0, exp0) = zero.to_f64_exp();
    /// assert_eq!((d0, exp0), (0.0, 0));
    /// let three_eighths = Float::with_val(64, 0.375);
    /// let (d3_8, exp3_8) = three_eighths.to_f64_exp();
    /// assert_eq!((d3_8, exp3_8), (0.75, -1));
    /// ```
    ///
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    #[inline]
    pub fn to_f64_exp(&self) -> (f64, i32) {
        self.to_f64_exp_round(Round::Nearest)
    }

    /// Converts to an [`f64`] and an exponent, applying the specified
    /// rounding method.
    ///
    /// The returned [`f64`] is in the range 0.5 ≤ <i>x</i> < 1.
    ///
    /// If the value is too small or too large for the target type,
    /// the minimum or maximum value allowed is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Round, Float};
    /// let frac_10_3 = Float::with_val(64, 10) / 3u32;
    /// let (f_down, exp_down) = frac_10_3.to_f64_exp_round(Round::Down);
    /// assert_eq!((f_down, exp_down), (0.8333333333333333, 2));
    /// let (f_up, exp_up) = frac_10_3.to_f64_exp_round(Round::Up);
    /// assert_eq!((f_up, exp_up), (0.8333333333333334, 2));
    /// ```
    ///
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    #[inline]
    pub fn to_f64_exp_round(&self, round: Round) -> (f64, i32) {
        let (f, exp) = xmpfr::get_f64_2exp(self, round);
        (f, exp.unwrapped_cast())
    }

    /// Returns a string representation of `self` for the specified
    /// `radix` rounding to the nearest.
    ///
    /// The exponent is encoded in decimal. If the number of digits is
    /// not specified, the output string will have enough precision
    /// such that reading it again will give the exact same number.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Special, Float};
    /// let neg_inf = Float::with_val(53, Special::NegInfinity);
    /// assert_eq!(neg_inf.to_string_radix(10, None), "-inf");
    /// assert_eq!(neg_inf.to_string_radix(16, None), "-@inf@");
    /// let twentythree = Float::with_val(8, 23);
    /// assert_eq!(twentythree.to_string_radix(10, None), "23.00");
    /// assert_eq!(twentythree.to_string_radix(16, None), "17.0");
    /// assert_eq!(twentythree.to_string_radix(10, Some(2)), "23");
    /// assert_eq!(twentythree.to_string_radix(16, Some(4)), "17.00");
    /// // 2 raised to the power of 80 in hex is 1 followed by 20 zeros
    /// let two_to_80 = Float::with_val(53, 80f64.exp2());
    /// assert_eq!(two_to_80.to_string_radix(10, Some(3)), "1.21e24");
    /// assert_eq!(two_to_80.to_string_radix(16, Some(3)), "1.00@20");
    /// ```
    #[inline]
    pub fn to_string_radix(&self, radix: i32, num_digits: Option<usize>) -> String {
        self.to_string_radix_round(radix, num_digits, Round::Nearest)
    }

    /// Returns a string representation of `self` for the specified
    /// `radix` applying the specified rounding method.
    ///
    /// The exponent is encoded in decimal. If the number of digits is
    /// not specified, the output string will have enough precision
    /// such that reading it again will give the exact same number.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Round, Float};
    /// let twentythree = Float::with_val(8, 23.3);
    /// let down = twentythree.to_string_radix_round(10, Some(2), Round::Down);
    /// assert_eq!(down, "23");
    /// let up = twentythree.to_string_radix_round(10, Some(2), Round::Up);
    /// assert_eq!(up, "24");
    /// ```
    #[inline]
    pub fn to_string_radix_round(
        &self,
        radix: i32,
        num_digits: Option<usize>,
        round: Round,
    ) -> String {
        let mut s = String::new();
        let format = Format {
            radix,
            precision: num_digits,
            round,
            ..Format::default()
        };
        append_to_string(&mut s, self, format);
        s
    }

    /// Returns a string representation of `self` together with a sign
    /// and an exponent for the specified `radix`, rounding to the
    /// nearest.
    ///
    /// The returned exponent is [`None`] if the [`Float`] is zero,
    /// infinite or NaN, that is if the value is not [normal].
    ///
    /// For [normal] values, the returned string has an implicit radix
    /// point before the first digit. If the number of digits is not
    /// specified, the output string will have enough precision such
    /// that reading it again will give the exact same number.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Special, Float};
    /// let inf = Float::with_val(53, Special::Infinity);
    /// let (sign, s, exp) = inf.to_sign_string_exp(10, None);
    /// assert_eq!((sign, &*s, exp), (false, "inf", None));
    /// let (sign, s, exp) = (-inf).to_sign_string_exp(16, None);
    /// assert_eq!((sign, &*s, exp), (true, "@inf@", None));
    ///
    /// let (sign, s, exp) = Float::with_val(8, -0.0625).to_sign_string_exp(10, None);
    /// assert_eq!((sign, &*s, exp), (true, "6250", Some(-1)));
    /// let (sign, s, exp) = Float::with_val(8, -0.625).to_sign_string_exp(10, None);
    /// assert_eq!((sign, &*s, exp), (true, "6250", Some(0)));
    /// let (sign, s, exp) = Float::with_val(8, -6.25).to_sign_string_exp(10, None);
    /// assert_eq!((sign, &*s, exp), (true, "6250", Some(1)));
    /// // −4.8e4 = 48_000, which is rounded to 48_128 using 8 bits of precision
    /// let (sign, s, exp) = Float::with_val(8, -4.8e4).to_sign_string_exp(10, None);
    /// assert_eq!((sign, &*s, exp), (true, "4813", Some(5)));
    /// ```
    ///
    /// [`Float`]: #
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [normal]: #method.is_normal
    #[inline]
    pub fn to_sign_string_exp(
        &self,
        radix: i32,
        num_digits: Option<usize>,
    ) -> (bool, String, Option<i32>) {
        self.to_sign_string_exp_round(radix, num_digits, Round::Nearest)
    }

    /// Returns a string representation of `self` together with a sign
    /// and an exponent for the specified `radix`, applying the
    /// specified rounding method.
    ///
    /// The returned exponent is [`None`] if the [`Float`] is zero,
    /// infinite or NaN, that is if the value is not [normal].
    ///
    /// For [normal] values, the returned string has an implicit radix
    /// point before the first digit. If the number of digits is not
    /// specified, the output string will have enough precision such
    /// that reading it again will give the exact same number.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Round, Float};
    /// let val = Float::with_val(53, -0.0625);
    /// // rounding −0.0625 to two significant digits towards −∞ gives −0.063
    /// let (sign, s, exp) = val.to_sign_string_exp_round(10, Some(2), Round::Down);
    /// assert_eq!((sign, &*s, exp), (true, "63", Some(-1)));
    /// // rounding −0.0625 to two significant digits towards +∞ gives −0.062
    /// let (sign, s, exp) = val.to_sign_string_exp_round(10, Some(2), Round::Up);
    /// assert_eq!((sign, &*s, exp), (true, "62", Some(-1)));
    ///
    /// let val = Float::with_val(53, 6.25e4);
    /// // rounding 6.25e4 to two significant digits towards −∞ gives 6.2e4
    /// let (sign, s, exp) = val.to_sign_string_exp_round(10, Some(2), Round::Down);
    /// assert_eq!((sign, &*s, exp), (false, "62", Some(5)));
    /// // rounding 6.25e4 to two significant digits towards +∞ gives 6.3e4
    /// let (sign, s, exp) = val.to_sign_string_exp_round(10, Some(2), Round::Up);
    /// assert_eq!((sign, &*s, exp), (false, "63", Some(5)));
    /// ```
    ///
    /// [`Float`]: #
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [normal]: #method.is_normal
    pub fn to_sign_string_exp_round(
        &self,
        radix: i32,
        num_digits: Option<usize>,
        round: Round,
    ) -> (bool, String, Option<i32>) {
        assert!((2..=36).contains(&radix), "radix {} out of range", radix);
        let sign = self.is_sign_negative();
        if self.is_zero() {
            return (sign, String::from("0"), None);
        }
        if self.is_infinite() {
            let s = String::from(if radix > 10 { "@inf@" } else { "inf" });
            return (sign, s, None);
        }
        if self.is_nan() {
            let s = String::from(if radix > 10 { "@NaN@" } else { "NaN" });
            return (sign, s, None);
        }
        let neg_self;
        let (f, round) = if sign {
            neg_self = self.as_neg();
            let reverse_round = match round {
                Round::Up => Round::Down,
                Round::Down => Round::Up,
                unchanged => unchanged,
            };
            (&*neg_self, reverse_round)
        } else {
            (self, round)
        };
        let format = Format {
            radix,
            precision: num_digits,
            round,
            ..Format::default()
        };
        // add 1 for nul terminator
        let size = req_digits(f, format) + 1;
        let mut s = String::with_capacity(size);
        let digits = format.precision.unwrap_or(0);
        let exp: exp_t;
        unsafe {
            let vec = s.as_mut_vec();
            let write_ptr = vec.as_mut_ptr();
            let mut maybe_exp = MaybeUninit::uninit();
            let c_buf = mpfr::get_str(
                write_ptr as *mut c_char,
                maybe_exp.as_mut_ptr(),
                format.radix.unwrapped_cast(),
                digits,
                f.as_raw(),
                raw_round(format.round),
            );
            assert_eq!(c_buf, write_ptr as *mut c_char);
            exp = maybe_exp.assume_init();
            let c_len = CStr::from_ptr(write_ptr as *mut c_char).to_bytes().len();
            // there is also 1 byte for nul character, so use < rather than <=
            assert!(c_len < size, "buffer overflow");
            vec.set_len(c_len);
        }
        let exp = exp.unwrapped_cast();
        (sign, s, Some(exp))
    }

    /// Borrows a negated copy of the [`Float`].
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Float][`Float`]&gt;</code>.
    ///
    /// This method performs a shallow copy and negates it, and
    /// negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 4.2);
    /// let neg_f = f.as_neg();
    /// assert_eq!(*neg_f, -4.2);
    /// // methods taking &self can be used on the returned object
    /// let reneg_f = neg_f.as_neg();
    /// assert_eq!(*reneg_f, 4.2);
    /// assert_eq!(*reneg_f, f);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Float`]: #
    pub fn as_neg(&self) -> BorrowFloat<'_> {
        let mut raw = self.inner;
        raw.sign = -raw.sign;
        if self.is_nan() {
            xmpfr::set_nanflag();
        }
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowFloat::from_raw(raw) }
    }

    /// Borrows an absolute copy of the [`Float`].
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Float][`Float`]&gt;</code>.
    ///
    /// This method performs a shallow copy and possibly negates it,
    /// and negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -4.2);
    /// let abs_f = f.as_abs();
    /// assert_eq!(*abs_f, 4.2);
    /// // methods taking &self can be used on the returned object
    /// let reabs_f = abs_f.as_abs();
    /// assert_eq!(*reabs_f, 4.2);
    /// assert_eq!(*reabs_f, *abs_f);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Float`]: #
    pub fn as_abs(&self) -> BorrowFloat<'_> {
        let mut raw = self.inner;
        raw.sign = 1;
        if self.is_nan() {
            xmpfr::set_nanflag();
        }
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowFloat::from_raw(raw) }
    }

    /// Borrows the [`Float`] as an ordered floating-point number of
    /// type [`OrdFloat`].
    ///
    /// The same result can be obtained using the implementation of
    /// <code>[AsRef][`AsRef`]&lt;[OrdFloat][`OrdFloat`]&gt;</code>
    /// which is provided for [`Float`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Special, Float};
    ///
    /// let nan_f = Float::with_val(53, Special::Nan);
    /// let nan = nan_f.as_ord();
    /// assert_eq!(nan.cmp(nan), Ordering::Equal);
    ///
    /// let neg_inf_f = Float::with_val(53, Special::NegInfinity);
    /// let neg_inf = neg_inf_f.as_ord();
    /// assert_eq!(nan.cmp(neg_inf), Ordering::Less);
    ///
    /// let zero_f = Float::with_val(53, Special::Zero);
    /// let zero = zero_f.as_ord();
    /// let neg_zero_f = Float::with_val(53, Special::NegZero);
    /// let neg_zero = neg_zero_f.as_ord();
    /// assert_eq!(zero.cmp(neg_zero), Ordering::Greater);
    /// ```
    ///
    /// [`AsRef`]: https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html
    /// [`Float`]: #
    /// [`OrdFloat`]: float/struct.OrdFloat.html
    #[inline]
    pub fn as_ord(&self) -> &OrdFloat {
        // Safety: OrdFloat is repr(transparent) over Float
        unsafe { &*cast_ptr!(self, OrdFloat) }
    }

    #[cfg(feature = "complex")]
    /// Borrows a copy of the [`Float`] as a [`Complex`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Complex][`Complex`]&gt;</code>.
    ///
    /// The imaginary part of the return value has the same precision
    /// as the real part. While this has no effect for the zero value
    /// of the returned complex number, it could have an effect if the
    /// return value is cloned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 4.2);
    /// let c = f.as_complex();
    /// assert_eq!(*c, (4.2, 0.0));
    /// // methods taking &self can be used on the returned object
    /// let c_mul_i = c.as_mul_i(false);
    /// assert_eq!(*c_mul_i, (0.0, 4.2));
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Complex`]: struct.Complex.html
    /// [`Float`]: #
    pub fn as_complex(&self) -> BorrowComplex<'_> {
        // im.d is set to be the same as re.d since the precision is equal;
        // though it will not be read as the imaginary part is 0 (which is singular).
        let raw_complex = mpc_t {
            re: self.inner,
            im: mpfr_t {
                prec: self.inner.prec,
                sign: 1,
                exp: xmpfr::EXP_ZERO,
                d: self.inner.d,
            },
        };
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowComplex::from_raw(raw_complex) }
    }

    /// Returns [`true`] if `self` is an integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 13.5);
    /// assert!(!f.is_integer());
    /// f *= 2;
    /// assert!(f.is_integer());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_integer(&self) -> bool {
        xmpfr::integer_p(self)
    }

    /// Returns [`true`] if `self` is not a number.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 0);
    /// assert!(!f.is_nan());
    /// f /= 0;
    /// assert!(f.is_nan());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_nan(&self) -> bool {
        xmpfr::nan_p(self)
    }

    /// Returns [`true`] if `self` is plus or minus infinity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1);
    /// assert!(!f.is_infinite());
    /// f /= 0;
    /// assert!(f.is_infinite());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_infinite(&self) -> bool {
        xmpfr::inf_p(self)
    }

    /// Returns [`true`] if `self` is a finite number, that is neither
    /// NaN nor infinity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1);
    /// assert!(f.is_finite());
    /// f /= 0;
    /// assert!(!f.is_finite());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_finite(&self) -> bool {
        xmpfr::number_p(self)
    }

    /// Returns [`true`] if `self` is plus or minus zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Special, Assign, Float};
    /// let mut f = Float::with_val(53, Special::Zero);
    /// assert!(f.is_zero());
    /// f.assign(Special::NegZero);
    /// assert!(f.is_zero());
    /// f += 1;
    /// assert!(!f.is_zero());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_zero(&self) -> bool {
        xmpfr::zero_p(self)
    }

    /// Returns [`true`] if `self` is a normal number, that is neither
    /// NaN, nor infinity, nor zero. Note that [`Float`] cannot be
    /// subnormal.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Special, Assign, Float};
    /// let mut f = Float::with_val(53, Special::Zero);
    /// assert!(!f.is_normal());
    /// f += 5.2;
    /// assert!(f.is_normal());
    /// f.assign(Special::Infinity);
    /// assert!(!f.is_normal());
    /// f.assign(Special::Nan);
    /// assert!(!f.is_normal());
    /// ```
    ///
    /// [`Float`]: #
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_normal(&self) -> bool {
        xmpfr::regular_p(self)
    }

    /// Returns the floating-point category of the number. Note that
    /// [`Float`] cannot be subnormal.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::num::FpCategory;
    /// use rug::{float::Special, Float};
    /// let nan = Float::with_val(53, Special::Nan);
    /// let infinite = Float::with_val(53, Special::Infinity);
    /// let zero = Float::with_val(53, Special::Zero);
    /// let normal = Float::with_val(53, 2.3);
    /// assert_eq!(nan.classify(), FpCategory::Nan);
    /// assert_eq!(infinite.classify(), FpCategory::Infinite);
    /// assert_eq!(zero.classify(), FpCategory::Zero);
    /// assert_eq!(normal.classify(), FpCategory::Normal);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn classify(&self) -> FpCategory {
        if xmpfr::nan_p(self) {
            FpCategory::Nan
        } else if xmpfr::inf_p(self) {
            FpCategory::Infinite
        } else if xmpfr::zero_p(self) {
            FpCategory::Zero
        } else {
            FpCategory::Normal
        }
    }

    /// Returns the same result as
    /// <code>self.[partial_cmp][`partial_cmp`](&amp;0)</code>, but is
    /// faster.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Special, Assign, Float};
    /// let mut f = Float::with_val(53, Special::NegZero);
    /// assert_eq!(f.cmp0(), Some(Ordering::Equal));
    /// f += 5.2;
    /// assert_eq!(f.cmp0(), Some(Ordering::Greater));
    /// f.assign(Special::NegInfinity);
    /// assert_eq!(f.cmp0(), Some(Ordering::Less));
    /// f.assign(Special::Nan);
    /// assert_eq!(f.cmp0(), None);
    /// ```
    ///
    /// [`partial_cmp`]: https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html#tymethod.partial_cmp
    #[inline]
    pub fn cmp0(&self) -> Option<Ordering> {
        if self.is_nan() {
            None
        } else {
            Some(xmpfr::sgn(self))
        }
    }

    /// Compares the absolute values of `self` and `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::Float;
    /// let a = Float::with_val(53, -10);
    /// let b = Float::with_val(53, 4);
    /// assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
    /// assert_eq!(a.cmp_abs(&b), Some(Ordering::Greater));
    /// ```
    #[inline]
    pub fn cmp_abs(&self, other: &Self) -> Option<Ordering> {
        if xmpfr::unordered_p(self, other) {
            None
        } else {
            Some(xmpfr::cmpabs(self, other))
        }
    }

    /// If the value is a [normal number][`is_normal`], returns its
    /// exponent.
    ///
    /// The significand is assumed to be in the range
    /// 0.5 ≤ <i>x</i> < 1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Float};
    /// // −(2.0 ^ 32) == −(0.5 × 2 ^ 33)
    /// let mut f = Float::with_val(53, -32f64.exp2());
    /// assert_eq!(f.get_exp(), Some(33));
    /// // 0.8 × 2 ^ −39
    /// f.assign(0.8 * (-39f64).exp2());
    /// assert_eq!(f.get_exp(), Some(-39));
    /// f.assign(0);
    /// assert_eq!(f.get_exp(), None);
    /// ```
    ///
    /// [`is_normal`]: #method.is_normal
    #[inline]
    pub fn get_exp(&self) -> Option<i32> {
        if self.is_normal() {
            Some(xmpfr::get_exp(self).unwrapped_cast())
        } else {
            None
        }
    }

    /// Clamps the exponent of a [`Float`] within a specified range if
    /// the range is valid.
    ///
    /// This method returns [`None`] if the specified exponent range
    /// is outside the allowed exponent range obtained using
    /// [`exp_min`] and [`exp_max`].
    ///
    /// This method assumes that `self` is the correctly rounded value
    /// of some exact result <i>exact</i>, rounded according to
    /// `round` in the direction `dir`. If necessary, this function
    /// then modifies `self` to be within the specified exponent
    /// range. If the exponent of `self` is outside the specified
    /// range, an underflow or overflow occurs, and the value of the
    /// input parameter `dir` is used to avoid double rounding.
    ///
    /// Unlike most methods functions, the direction is obtained by
    /// comparing the output `self` to the unknown result
    /// <i>exact</i>, not to the input value of `self`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::DivAssignRound, Float};
    /// // use precision 4 for sake of example
    /// let mut f = Float::with_val(4, 1.0);
    /// // 1/115_000 is 8.696e-6, rounded down to 0.5625 >> 16 = 8.583e-6
    /// let dir = f.div_assign_round(115_000, Round::Nearest);
    /// assert_eq!(f, 0.5625 / 16f32.exp2());
    /// assert_eq!(dir, Ordering::Less);
    /// // Limiting exponent range to [-16, 16] leaves f unchanged
    /// let dir = f.clamp_exp(dir, Round::Nearest, -16, 16).unwrap();
    /// assert_eq!(f, 0.5625 / 16f32.exp2());
    /// assert_eq!(dir, Ordering::Less);
    /// // Limiting exponent range to [-15, 15] pushes f up to 0.5 >> 15
    /// let dir = f.clamp_exp(dir, Round::Nearest, -15, 15).unwrap();
    /// assert_eq!(f, 0.5 / 15f32.exp2());
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    ///
    /// The `dir` parameter can be required to avoid double rounding.
    /// In the following example, `f` is 1/16, which is a tie between
    /// 0 and 1/8. With ties rounding to even, this would be double
    /// rounded to 0, but the exact result was actually > 1/16 as
    /// indicated by `dir` saying that `f` is less than its exact
    /// value. `f` can thus be rounded correctly to 1/8.
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::DivAssignRound, Float};
    /// let mut f = Float::with_val(4, 1.0);
    /// // 1/15.999 is > 1/16, rounded down to 0.5 >> 3 = 1/16
    /// let dir = f.div_assign_round(15.999, Round::Nearest);
    /// assert_eq!(f, 0.5 / 3f32.exp2());
    /// assert_eq!(dir, Ordering::Less);
    /// // Limiting exponent range to [-2, 2] pushes f correctly away from zero.
    /// let dir = f.clamp_exp(dir, Round::Nearest, -2, 2).unwrap();
    /// assert_eq!(f, 0.5 / 2f32.exp2());
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    ///
    /// [`Float`]: #
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`exp_max`]: float/fn.exp_max.html
    /// [`exp_min`]: float/fn.exp_min.html
    pub fn clamp_exp(
        &mut self,
        dir: Ordering,
        round: Round,
        exp_min: i32,
        exp_max: i32,
    ) -> Option<Ordering> {
        unsafe {
            let save_emin = mpfr::get_emin();
            if mpfr::set_emin(exp_min.checked_cast()?) != 0 {
                return None;
            }
            let save_emax = mpfr::get_emax();
            if exp_max
                .checked_cast()
                .map(|x| mpfr::set_emax(x) != 0)
                .unwrap_or(true)
            {
                mpfr::set_emin(save_emin);
                return None;
            }
            let dir = xmpfr::check_range(self, dir, round);
            mpfr::set_emax(save_emax);
            mpfr::set_emin(save_emin);
            Some(dir)
        }
    }

    #[cfg(feature = "integer")]
    /// If the value is a [normal number][`is_normal`], returns a
    /// reference to its significand as an [`Integer`].
    ///
    /// The unwrapped returned object implements
    /// <code>[Deref]&lt;[Target] = [Integer][`Integer`]&gt;</code>.
    ///
    /// The number of [significant bits][`significant_bits`] of a
    /// returned significand is at least equal to the
    /// [precision][`prec`], but can be larger. It is usually rounded
    /// up to a multiple of 32 or 64 depending on the implementation;
    /// in this case, the extra least significant bits will be zero.
    /// The value of `self` is exactly equal to the returned
    /// [`Integer`] divided by two raised to the power of the number
    /// of [significant bits][`significant_bits`] and multiplied by
    /// two raised to the power of the [exponent][`get_exp`] of
    /// `self`.
    ///
    /// Unlike the [`to_integer_exp`] method which returns an owned
    /// [`Integer`], this method only performs a shallow copy and does
    /// not allocate any memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let float = Float::with_val(16, 6.5);
    /// // 6.5 in binary is 110.1 = 0.1101 times two to the power of 3
    /// let exp = float.get_exp().unwrap();
    /// assert_eq!(exp, 3);
    /// let significand = float.get_significand().unwrap();
    /// let sig_bits = significand.significant_bits();
    /// // sig_bits must be greater or equal to precision
    /// assert!(sig_bits >= 16);
    /// let (check_int, check_exp) = float.to_integer_exp().unwrap();
    /// assert_eq!(check_int << sig_bits << (check_exp - exp), *significand);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Integer`]: struct.Integer.html
    /// [`get_exp`]: #method.get_exp
    /// [`is_normal`]: #method.is_normal
    /// [`prec`]: #method.prec
    /// [`significant_bits`]: struct.Integer.html#method.significant_bits
    /// [`to_integer_exp`]: #method.to_integer_exp
    #[inline]
    pub fn get_significand(&self) -> Option<BorrowInteger<'_>> {
        if self.is_normal() {
            let limb_bits = prec_t::from(gmp::LIMB_BITS);
            let limbs = (self.inner.prec - 1) / limb_bits + 1;
            let raw_int = mpz_t {
                alloc: limbs.unwrapped_cast(),
                size: limbs.unwrapped_cast(),
                d: self.inner.d,
            };
            // Safety: the lifetime of the return type is equal to the lifetime of self.
            Some(unsafe { BorrowInteger::from_raw(raw_int) })
        } else {
            None
        }
    }

    /// Returns [`true`] if the value is positive, +0 or NaN without a
    /// negative sign.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let pos = Float::with_val(53, 1.0);
    /// let neg = Float::with_val(53, -1.0);
    /// assert!(pos.is_sign_positive());
    /// assert!(!neg.is_sign_positive());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_sign_positive(&self) -> bool {
        !self.is_sign_negative()
    }

    /// Returns [`true`] if the value is negative, −0 or NaN with a
    /// negative sign.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let neg = Float::with_val(53, -1.0);
    /// let pos = Float::with_val(53, 1.0);
    /// assert!(neg.is_sign_negative());
    /// assert!(!pos.is_sign_negative());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_sign_negative(&self) -> bool {
        xmpfr::signbit(self)
    }

    /// Sets to the next value towards `to`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let to = Float::with_val(8, 100);
    /// // 32.5 in binary is 100000.10
    /// // 32.75 in binary is 100000.11
    /// let mut f = Float::with_val(8, 32.5);
    /// f.next_toward(&to);
    /// assert_eq!(f, 32.75);
    /// ```
    #[inline]
    pub fn next_toward(&mut self, to: &Self) {
        xmpfr::nexttoward(self, to);
    }

    /// Sets to the next value towards +∞.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // 32.5 in binary is 100000.10
    /// // 32.75 in binary is 100000.11
    /// let mut f = Float::with_val(8, 32.5);
    /// f.next_up();
    /// assert_eq!(f, 32.75);
    /// ```
    #[inline]
    pub fn next_up(&mut self) {
        xmpfr::nextabove(self);
    }

    /// Sets to the next value towards −∞.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // 32.5 in binary is 100000.10
    /// // 32.25 in binary is 100000.01
    /// let mut f = Float::with_val(8, 32.5);
    /// f.next_down();
    /// assert_eq!(f, 32.25);
    /// ```
    #[inline]
    pub fn next_down(&mut self) {
        xmpfr::nextbelow(self);
    }

    /// Emulate subnormal numbers for precisions specified in IEEE
    /// 754, rounding to the nearest.
    ///
    /// Subnormalization is only performed for precisions specified in
    /// IEEE 754:
    ///
    ///   * binary16 with 16 storage bits and a precision of 11 bits,
    ///   * binary32 (single precision) with 32 storage bits and a
    ///     precision of 24 bits,
    ///   * binary64 (double precision) with 64 storage bits and a
    ///     precision of 53 bits,
    ///   * binary{<i>k</i>} with <i>k</i> storage bits where <i>k</i>
    ///     is a multiple of 32 and <i>k</i> ≥ 128, and a precision of
    ///     <i>k</i> − round(4 × log<sub>2</sub> <i>k</i>) + 13 bits.
    ///
    /// This method has no effect if the value is not in the subnormal
    /// range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::Float;
    /// // minimum single subnormal is 0.5 × 2 ^ −148 = 2 ^ −149
    /// let single_min_subnormal = (-149f64).exp2();
    /// assert_eq!(single_min_subnormal, single_min_subnormal as f32 as f64);
    /// let single_cannot = single_min_subnormal * 1.25;
    /// assert_eq!(single_min_subnormal, single_cannot as f32 as f64);
    /// let mut f = Float::with_val(24, single_cannot);
    /// assert_eq!(f.to_f64(), single_cannot);
    /// f.subnormalize_ieee();
    /// assert_eq!(f.to_f64(), single_min_subnormal);
    /// ```
    #[inline]
    pub fn subnormalize_ieee(&mut self) -> &mut Self {
        self.subnormalize_ieee_round(Ordering::Equal, Round::Nearest);
        self
    }

    /// Emulate subnormal numbers for precisions specified in IEEE
    /// 754, applying the specified rounding method.
    ///
    /// Subnormalization is only performed for precisions specified in
    /// IEEE 754:
    ///
    ///   * binary16 with 16 storage bits and a precision of 11 bits,
    ///   * binary32 (single precision) with 32 storage bits and a
    ///     precision of 24 bits,
    ///   * binary64 (double precision) with 64 storage bits and a
    ///     precision of 53 bits,
    ///   * binary{<i>k</i>} with <i>k</i> storage bits where <i>k</i>
    ///     is a multiple of 32 and <i>k</i> ≥ 128, and a precision of
    ///     <i>k</i> − round(4 × log<sub>2</sub> <i>k</i>) + 13 bits.
    ///
    /// This method simply propagates `prev_rounding` if the value is
    /// not in the subnormal range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // minimum single subnormal is 0.5 × 2 ^ −148 = 2 ^ −149
    /// let single_min_subnormal = (-149f64).exp2();
    /// assert_eq!(single_min_subnormal, single_min_subnormal as f32 as f64);
    /// let single_cannot = single_min_subnormal * 1.25;
    /// assert_eq!(single_min_subnormal, single_cannot as f32 as f64);
    /// let mut f = Float::with_val(24, single_cannot);
    /// assert_eq!(f.to_f64(), single_cannot);
    /// let dir = f.subnormalize_ieee_round(Ordering::Equal, Round::Up);
    /// assert_eq!(f.to_f64(), single_min_subnormal * 2.0);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    pub fn subnormalize_ieee_round(&mut self, prev_rounding: Ordering, round: Round) -> Ordering {
        let prec = self.prec();
        let exp_bits = match ieee_storage_bits_for_prec(prec) {
            Some(storage_bits) => storage_bits - prec,
            None => return prev_rounding,
        };
        let normal_exp_min = (-1i32 << (exp_bits - 1)) + 3;
        self.subnormalize_round(normal_exp_min, prev_rounding, round)
    }

    /// Emulate subnormal numbers, rounding to the nearest.
    ///
    /// Subnormalization is only performed when the exponent lies
    /// within the subnormal range, that is when
    ///
    /// `normal_exp_min` − <i>precision</i> + 1 ≤ <i>exponent</i> < `normal_exp_min`
    ///
    /// For example, for IEEE 754 single precision, the precision is
    /// 24 and `normal_exp_min` is −125, so the subnormal range would
    /// be −148 ≤ <i>exponent</i> < −125.
    ///
    /// This method has no effect if the value is not in the subnormal
    /// range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // minimum single subnormal is 0.5 × 2 ^ −148 = 2 ^ −149
    /// let single_min_subnormal = (-149f64).exp2();
    /// assert_eq!(single_min_subnormal, single_min_subnormal as f32 as f64);
    /// let single_cannot = single_min_subnormal * 1.25;
    /// assert_eq!(single_min_subnormal, single_cannot as f32 as f64);
    /// let mut f = Float::with_val(24, single_cannot);
    /// assert_eq!(f.to_f64(), single_cannot);
    /// f.subnormalize(-125);
    /// assert_eq!(f.to_f64(), single_min_subnormal);
    /// ```
    #[inline]
    pub fn subnormalize(&mut self, normal_exp_min: i32) -> &mut Self {
        self.subnormalize_round(normal_exp_min, Ordering::Equal, Round::Nearest);
        self
    }

    /// Emulate subnormal numbers, applying the specified rounding
    /// method.
    ///
    /// Subnormalization is only performed when the exponent lies
    /// within the subnormal range, that is when
    ///
    /// `normal_exp_min` − <i>precision</i> + 1 ≤ <i>exponent</i> < `normal_exp_min`
    ///
    /// For example, for IEEE 754 single precision, the precision is
    /// 24 and `normal_exp_min` is −125, so the subnormal range would
    /// be −148 ≤ <i>exponent</i> < −125.
    ///
    /// This method simply propagates `prev_rounding` if the value is
    /// not in the subnormal range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // minimum single subnormal is 0.5 × 2 ^ −148 = 2 ^ −149
    /// let single_min_subnormal = (-149f64).exp2();
    /// assert_eq!(single_min_subnormal, single_min_subnormal as f32 as f64);
    /// let single_cannot = single_min_subnormal * 1.25;
    /// assert_eq!(single_min_subnormal, single_cannot as f32 as f64);
    /// let mut f = Float::with_val(24, single_cannot);
    /// assert_eq!(f.to_f64(), single_cannot);
    /// let dir = f.subnormalize_round(-125, Ordering::Equal, Round::Up);
    /// assert_eq!(f.to_f64(), single_min_subnormal * 2.0);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    pub fn subnormalize_round(
        &mut self,
        normal_exp_min: i32,
        prev_rounding: Ordering,
        round: Round,
    ) -> Ordering {
        if !self.is_normal() {
            return prev_rounding;
        }
        let exp_min = exp_t::from(normal_exp_min);
        let sub_exp_min = exp_min
            .checked_sub((self.prec() - 1).unwrapped_as::<exp_t>())
            .expect("overflow");
        let exp = xmpfr::get_exp(self);
        if exp < sub_exp_min || exp >= exp_min {
            return prev_rounding;
        }
        let prev = match prev_rounding {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        };
        unsafe {
            let save_emin = mpfr::get_emin();
            let save_emax = mpfr::get_emax();
            assert!(save_emax >= exp_min, "`normal_exp_min` too large");
            mpfr::set_emin(sub_exp_min);
            mpfr::set_emax(exp_min);
            let ret = mpfr::subnormalize(self.as_raw_mut(), prev, raw_round(round));
            mpfr::set_emin(save_emin);
            mpfr::set_emax(save_emax);
            ordering1(ret)
        }
    }

    /// Adds a list of [`Float`] values with correct rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AddAssignRound][`AddAssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::AddAssignRound, Float};
    ///
    /// // Give each value only 4 bits of precision for example purposes.
    /// let values = [
    ///     Float::with_val(4, 5.0),
    ///     Float::with_val(4, 1024.0),
    ///     Float::with_val(4, -1024.0),
    ///     Float::with_val(4, -4.5),
    /// ];
    ///
    /// // The result should still be exact if it fits.
    /// let r = Float::sum(values.iter());
    /// let sum = Float::with_val(4, r);
    /// assert_eq!(sum, 0.5);
    ///
    /// let mut f = Float::with_val(4, 15.0);
    /// // 15.5 using 4 bits of precision becomes 16.0
    /// let r = Float::sum(values.iter());
    /// let dir = f.add_assign_round(r, Round::Nearest);
    /// assert_eq!(f, 16.0);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    ///
    /// [`AddAssignRound`]: ops/trait.AddAssignRound.html
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sum<'a, I>(values: I) -> SumIncomplete<'a, I>
    where
        I: Iterator<Item = &'a Self>,
    {
        SumIncomplete { values }
    }

    /// Finds the dot product of a list of [`Float`] value pairs with
    /// correct rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AddAssignRound][`AddAssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// This method will produce a result with correct rounding,
    /// except for some cases where underflow or overflow occurs in
    /// intermediate products.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    ///
    /// let a = [Float::with_val(53, 2.75), Float::with_val(53, -1.25)];
    /// let b = [Float::with_val(53, 10.5), Float::with_val(53, 0.5)];
    ///
    /// let r = Float::dot(a.iter().zip(b.iter()));
    /// let dot = Float::with_val(53, r);
    /// let expected = 2.75 * 10.5 - 1.25 * 0.5;
    /// assert_eq!(dot, expected);
    /// let r = Float::dot(b.iter().zip(a.iter()));
    /// let twice = dot + r;
    /// assert_eq!(twice, expected * 2.0);
    /// ```
    ///
    /// [`AddAssignRound`]: ops/trait.AddAssignRound.html
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn dot<'a, I>(values: I) -> DotIncomplete<'a, I>
    where
        I: Iterator<Item = (&'a Self, &'a Self)>,
    {
        DotIncomplete { values }
    }

    /// Computes the remainder, rounding to the nearest.
    ///
    /// The remainder is the value of `self` − <i>n</i> × `divisor`,
    /// where <i>n</i> is the integer quotient of `self` / `divisor`
    /// rounded to the nearest integer (ties rounded to even). This is
    /// different from the remainder obtained using the `%` operator
    /// or the [`Rem`] trait, where <i>n</i> is truncated instead of
    /// rounded to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let num = Float::with_val(53, 589.4);
    /// let den = Float::with_val(53, 100);
    /// let remainder = num.remainder(&den);
    /// let expected = -10.6_f64;
    /// assert!((remainder - expected).abs() < 0.0001);
    ///
    /// // compare to % operator
    /// let num = Float::with_val(53, 589.4);
    /// let den = Float::with_val(53, 100);
    /// let rem_op = num % &den;
    /// let expected = 89.4_f64;
    /// assert!((rem_op - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`Rem`]: https://doc.rust-lang.org/nightly/core/ops/trait.Rem.html
    #[inline]
    pub fn remainder(mut self, divisor: &Self) -> Self {
        self.remainder_round(divisor, Round::Nearest);
        self
    }

    /// Computes the remainder, rounding to the nearest.
    ///
    /// The remainder is the value of `self` − <i>n</i> × `divisor`,
    /// where <i>n</i> is the integer quotient of `self` / `divisor`
    /// rounded to the nearest integer (ties rounded to even). This is
    /// different from the remainder obtained using the `%=` operator
    /// or the [`RemAssign`] trait, where <i>n</i> is truncated instead of
    /// rounded to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 589.4);
    /// let g = Float::with_val(53, 100);
    /// f.remainder_mut(&g);
    /// let expected = -10.6_f64;
    /// assert!((f - expected).abs() < 0.0001);
    ///
    /// // compare to %= operator
    /// let mut f = Float::with_val(53, 589.4);
    /// let g = Float::with_val(53, 100);
    /// f %= &g;
    /// let expected = 89.4_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`RemAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.RemAssign.html
    #[inline]
    pub fn remainder_mut(&mut self, divisor: &Self) {
        self.remainder_round(divisor, Round::Nearest);
    }

    /// Computes the remainder, applying the specified rounding
    /// method.
    ///
    /// The remainder is the value of `self` − <i>n</i> × `divisor`,
    /// where <i>n</i> is the integer quotient of `self` / `divisor`
    /// rounded to the nearest integer (ties rounded to even). This is
    /// different from the remainder obtained using the
    /// [`RemAssignRound`] trait, where <i>n</i> is truncated instead
    /// of rounded to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::RemAssignRound, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 128);
    /// let g = Float::with_val(6, 49);
    /// // remainder of 128 / 49 is 128 − 3 × 49 = −19
    /// // using 4 significant bits: −20
    /// let dir = f.remainder_round(&g, Round::Nearest);
    /// assert_eq!(f, -20.0);
    /// assert_eq!(dir, Ordering::Less);
    ///
    /// // compare to RemAssignRound::rem_assign_round
    /// let mut f = Float::with_val(4, 128);
    /// let g = Float::with_val(6, 49);
    /// // with RemAssignRound, remainder of 128 / 49 is 128 − 2 × 49 = 30
    /// // using 4 significant bits: 30
    /// let dir = f.rem_assign_round(&g, Round::Nearest);
    /// assert_eq!(f, 30.0);
    /// assert_eq!(dir, Ordering::Equal);
    /// ```
    ///
    /// [`RemAssignRound`]: ops/trait.RemAssignRound.html
    #[inline]
    pub fn remainder_round(&mut self, divisor: &Self, round: Round) -> Ordering {
        xmpfr::remainder(self, (), divisor, round)
    }

    /// Computes the remainder, rounding to the nearest.
    ///
    /// The remainder is the value of `dividend` − <i>n</i> × `self`,
    /// where <i>n</i> is the integer quotient of `dividend` / `self`
    /// rounded to the nearest integer (ties rounded to even). This is
    /// different from the remainder obtained using the [`RemFrom`]
    /// trait, where <i>n</i> is truncated instead of rounded to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{ops::RemFrom, Float};
    /// let f = Float::with_val(53, 589.4);
    /// let mut g = Float::with_val(53, 100);
    /// g.remainder_from(&f);
    /// let expected = -10.6_f64;
    /// assert!((g - expected).abs() < 0.0001);
    ///
    /// // compare to RemFrom::rem_from
    /// let f = Float::with_val(53, 589.4);
    /// let mut g = Float::with_val(53, 100);
    /// g.rem_from(&f);
    /// let expected = 89.4_f64;
    /// assert!((g - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`RemFrom`]: ops/trait.RemFrom.html
    #[inline]
    pub fn remainder_from(&mut self, dividend: &Self) {
        self.remainder_from_round(dividend, Round::Nearest);
    }

    /// Computes the remainder, applying the specified rounding
    /// method.
    ///
    /// The remainder is the value of `dividend` − <i>n</i> × `self`,
    /// where <i>n</i> is the integer quotient of `dividend` / `self`
    /// rounded to the nearest integer (ties rounded to even). This is
    /// different from the remainder obtained using the
    /// [`RemFromRound`] trait, where <i>n</i> is truncated instead of
    /// rounded to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::RemFromRound, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let f = Float::with_val(8, 171);
    /// let mut g = Float::with_val(4, 64);
    /// // remainder of 171 / 64 is 171 − 3 × 64 = −21
    /// // using 4 significant bits: −20
    /// let dir = g.remainder_from_round(&f, Round::Nearest);
    /// assert_eq!(g, -20.0);
    /// assert_eq!(dir, Ordering::Greater);
    ///
    /// // compare to RemFromRound::rem_from_round
    /// let f = Float::with_val(8, 171);
    /// let mut g = Float::with_val(4, 64);
    /// // with RemFromRound, remainder of 171 / 64 is 171 − 2 × 64 = 43
    /// // using 4 significant bits: 44
    /// let dir = g.rem_from_round(&f, Round::Nearest);
    /// assert_eq!(g, 44.0);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    ///
    /// [`RemFromRound`]: ops/trait.RemFromRound.html
    #[inline]
    pub fn remainder_from_round(&mut self, dividend: &Self, round: Round) -> Ordering {
        xmpfr::remainder(self, dividend, (), round)
    }

    /// Computes the remainder.
    ///
    /// The remainder is the value of `self` − <i>n</i> × `divisor`,
    /// where <i>n</i> is the integer quotient of `self` / `divisor`
    /// rounded to the nearest integer (ties rounded to even). This is
    /// different from the remainder obtained using the `%` operator
    /// or the [`Rem`] trait, where <i>n</i> is truncated instead of
    /// rounded to the nearest.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 589.4);
    /// let g = Float::with_val(53, 100);
    /// let remainder = Float::with_val(53, f.remainder_ref(&g));
    /// let expected = -10.6_f64;
    /// assert!((remainder - expected).abs() < 0.0001);
    ///
    /// // compare to % operator
    /// let f = Float::with_val(53, 589.4);
    /// let g = Float::with_val(53, 100);
    /// let rem_op = Float::with_val(53, &f % &g);
    /// let expected = 89.4_f64;
    /// assert!((rem_op - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [`Rem`]: https://doc.rust-lang.org/nightly/core/ops/trait.Rem.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn remainder_ref<'a>(&'a self, divisor: &'a Self) -> RemainderIncomplete<'_> {
        RemainderIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Multiplies and adds in one fused operation, rounding to the
    /// nearest with only one rounding error.
    ///
    /// `a.mul_add(&b, &c)` produces a result like `&a * &b + &c`, but
    /// `a` is consumed and the result produced uses its precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let add = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 + 24 = 4.5
    /// let mul_add = mul1.mul_add(&mul2, &add);
    /// assert_eq!(mul_add, 4.5);
    /// ```
    #[inline]
    pub fn mul_add(mut self, mul: &Self, add: &Self) -> Self {
        self.mul_add_round(mul, add, Round::Nearest);
        self
    }

    /// Multiplies and adds in one fused operation, rounding to the
    /// nearest with only one rounding error.
    ///
    /// `a.mul_add_mut(&b, &c)` produces a result like `&a * &b + &c`,
    /// but stores the result in `a` using its precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mut mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let add = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 + 24 = 4.5
    /// mul1.mul_add_mut(&mul2, &add);
    /// assert_eq!(mul1, 4.5);
    /// ```
    #[inline]
    pub fn mul_add_mut(&mut self, mul: &Self, add: &Self) {
        self.mul_add_round(mul, add, Round::Nearest);
    }

    /// Multiplies and adds in one fused operation, applying the
    /// specified rounding method with only one rounding error.
    ///
    /// `a.mul_add_round(&b, &c, round)` produces a result like
    /// `ans.assign_round(&a * &b + &c, round)`, but stores the result
    /// in `a` using its precision rather than in another [`Float`]
    /// like `ans`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mut mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let add = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 + 24 = 4.5
    /// let dir = mul1.mul_add_round(&mul2, &add, Round::Nearest);
    /// assert_eq!(mul1, 4.5);
    /// assert_eq!(dir, Ordering::Equal);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn mul_add_round(&mut self, mul: &Self, add: &Self, round: Round) -> Ordering {
        xmpfr::fma(self, (), mul, add, round)
    }

    /// Multiplies and adds in one fused operation.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// `a.mul_add_ref(&b, &c)` produces the exact same result as
    /// `&a * &b + &c`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let add = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 + 24 = 4.5
    /// let ans = Float::with_val(4, mul1.mul_add_ref(&mul2, &add));
    /// assert_eq!(ans, 4.5);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn mul_add_ref<'a>(&'a self, mul: &'a Self, add: &'a Self) -> AddMulIncomplete<'a> {
        self * mul + add
    }

    /// Multiplies and subtracts in one fused operation, rounding to
    /// the nearest with only one rounding error.
    ///
    /// `a.mul_sub(&b, &c)` produces a result like `&a * &b - &c`, but
    /// `a` is consumed and the result produced uses its precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let sub = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 − 24 = −43.5, rounded to 44 using four bits of precision.
    /// let mul_sub = mul1.mul_sub(&mul2, &sub);
    /// assert_eq!(mul_sub, -44);
    /// ```
    #[inline]
    pub fn mul_sub(mut self, mul: &Self, sub: &Self) -> Self {
        self.mul_sub_round(mul, sub, Round::Nearest);
        self
    }

    /// Multiplies and subtracts in one fused operation, rounding to
    /// the nearest with only one rounding error.
    ///
    /// `a.mul_sub_mut(&b, &c)` produces a result like `&a * &b - &c`,
    /// but stores the result in `a` using its precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mut mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let sub = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 − 24 = −43.5, rounded to 44 using four bits of precision.
    /// mul1.mul_sub_mut(&mul2, &sub);
    /// assert_eq!(mul1, -44);
    /// ```
    #[inline]
    pub fn mul_sub_mut(&mut self, mul: &Self, sub: &Self) {
        self.mul_sub_round(mul, sub, Round::Nearest);
    }

    /// Multiplies and subtracts in one fused operation, applying the
    /// specified rounding method with only one rounding error.
    ///
    /// `a.mul_sub_round(&b, &c, round)` produces a result like
    /// `ans.assign_round(&a * &b - &c, round)`, but stores the result
    /// in `a` using its precision rather than in another [`Float`]
    /// like `ans`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mut mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let sub = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 − 24 = −43.5, rounded to 44 using four bits of precision.
    /// let dir = mul1.mul_sub_round(&mul2, &sub, Round::Nearest);
    /// assert_eq!(mul1, -44);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn mul_sub_round(&mut self, mul: &Self, sub: &Self, round: Round) -> Ordering {
        xmpfr::fms(self, (), mul, sub, round)
    }

    /// Multiplies and subtracts in one fused operation.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// `a.mul_sub_ref(&b, &c)` produces the exact same result as
    /// `&a * &b - &c`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // Use only 4 bits of precision for demonstration purposes.
    /// // 1.5 in binary is 1.1.
    /// let mul1 = Float::with_val(4, 1.5);
    /// // −13 in binary is −1101.
    /// let mul2 = Float::with_val(4, -13);
    /// // 24 in binary is 11000.
    /// let sub = Float::with_val(4, 24);
    ///
    /// // 1.5 × −13 − 24 = −43.5, rounded to 44 using four bits of precision.
    /// let ans = Float::with_val(4, mul1.mul_sub_ref(&mul2, &sub));
    /// assert_eq!(ans, -44);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn mul_sub_ref<'a>(&'a self, mul: &'a Self, sub: &'a Self) -> SubMulFromIncomplete<'a> {
        self * mul - sub
    }

    /// Multiplies two products and adds them in one fused operation,
    /// rounding to the nearest with only one rounding error.
    ///
    /// `a.mul_add_mul(&b, &c, &d)` produces a result like
    /// `&a * &b + &c * &d`, but `a` is consumed and the result
    /// produced uses its precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 + 12 × 2 = 60
    /// let mul_add_mul = a.mul_add_mul(&b, &c, &d);
    /// assert_eq!(mul_add_mul, 60);
    /// ```
    #[inline]
    pub fn mul_add_mul(mut self, mul: &Self, add_mul1: &Self, add_mul2: &Self) -> Self {
        self.mul_add_mul_round(mul, add_mul1, add_mul2, Round::Nearest);
        self
    }

    /// Multiplies two products and adds them in one fused operation,
    /// rounding to the nearest with only one rounding error.
    ///
    /// `a.mul_add_mul_mut(&b, &c, &d)` produces a result like
    /// `&a * &b + &c * &d`, but stores the result in `a` using its
    /// precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 + 12 × 2 = 60
    /// a.mul_add_mul_mut(&b, &c, &d);
    /// assert_eq!(a, 60);
    /// ```
    #[inline]
    pub fn mul_add_mul_mut(&mut self, mul: &Self, add_mul1: &Self, add_mul2: &Self) {
        self.mul_add_mul_round(mul, add_mul1, add_mul2, Round::Nearest);
    }

    /// Multiplies two produces and adds them in one fused operation,
    /// applying the specified rounding method with only one rounding
    /// error.
    ///
    /// `a.mul_add_mul_round(&b, &c, &d, round)` produces a result
    /// like `ans.assign_round(&a * &b + &c * &d, round)`, but stores
    /// the result in `a` using its precision rather than in another
    /// [`Float`] like `ans`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let mut a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 + 12 × 2 = 60
    /// let dir = a.mul_add_mul_round(&b, &c, &d, Round::Nearest);
    /// assert_eq!(a, 60);
    /// assert_eq!(dir, Ordering::Equal);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn mul_add_mul_round(
        &mut self,
        mul: &Self,
        add_mul1: &Self,
        add_mul2: &Self,
        round: Round,
    ) -> Ordering {
        xmpfr::fmma(self, (), mul, add_mul1, add_mul2, round)
    }

    /// Multiplies two products and adds them in one fused operation.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// `a.mul_add_mul_ref(&b, &c, &d)` produces the exact same result
    /// as `&a * &b + &c * &d`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 + 12 × 2 = 60
    /// let ans = Float::with_val(53, a.mul_add_mul_ref(&b, &c, &d));
    /// assert_eq!(ans, 60);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn mul_add_mul_ref<'a>(
        &'a self,
        mul: &'a Self,
        add_mul1: &'a Self,
        add_mul2: &'a Self,
    ) -> MulAddMulIncomplete<'a> {
        self * mul + add_mul1 * add_mul2
    }

    /// Multiplies two products and subtracts them in one fused
    /// operation, rounding to the nearest with only one rounding
    /// error.
    ///
    /// `a.mul_sub_mul(&b, &c, &d)` produces a result like
    /// `&a * &b - &c * &d`, but `a` is consumed and the result
    /// produced uses its precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 − 12 × 2 = 12
    /// let mul_sub_mul = a.mul_sub_mul(&b, &c, &d);
    /// assert_eq!(mul_sub_mul, 12);
    /// ```
    #[inline]
    pub fn mul_sub_mul(mut self, mul: &Self, sub_mul1: &Self, sub_mul2: &Self) -> Self {
        self.mul_sub_mul_round(mul, sub_mul1, sub_mul2, Round::Nearest);
        self
    }

    /// Multiplies two products and subtracts them in one fused
    /// operation, rounding to the nearest with only one rounding
    /// error.
    ///
    /// `a.mul_sub_mul_mut(&b, &c, &d)` produces a result like
    /// `&a * &b - &c * &d`, but stores the result in `a` using its
    /// precision.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 − 12 × 2 = 12
    /// a.mul_sub_mul_mut(&b, &c, &d);
    /// assert_eq!(a, 12);
    /// ```
    #[inline]
    pub fn mul_sub_mul_mut(&mut self, mul: &Self, sub_mul1: &Self, sub_mul2: &Self) {
        self.mul_sub_mul_round(mul, sub_mul1, sub_mul2, Round::Nearest);
    }

    /// Multiplies two produces and subtracts them in one fused
    /// operation, applying the specified rounding method with only
    /// one rounding error.
    ///
    /// `a.mul_sub_mul_round(&b, &c, &d, round)` produces a result
    /// like `ans.assign_round(&a * &b - &c * &d, round)`, but stores
    /// the result in `a` using its precision rather than in another
    /// [`Float`] like `ans`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let mut a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 − 12 × 2 = 12
    /// let dir = a.mul_sub_mul_round(&b, &c, &d, Round::Nearest);
    /// assert_eq!(a, 12);
    /// assert_eq!(dir, Ordering::Equal);
    /// ```
    ///
    /// [`Float`]: #
    #[inline]
    pub fn mul_sub_mul_round(
        &mut self,
        mul: &Self,
        sub_mul1: &Self,
        sub_mul2: &Self,
        round: Round,
    ) -> Ordering {
        xmpfr::fmms(self, (), mul, sub_mul1, sub_mul2, round)
    }

    /// Multiplies two products and subtracts them in one fused
    /// operation.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// `a.mul_sub_mul_ref(&b, &c, &d)` produces the exact same result
    /// as `&a * &b - &c * &d`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 24);
    /// let b = Float::with_val(53, 1.5);
    /// let c = Float::with_val(53, 12);
    /// let d = Float::with_val(53, 2);
    /// // 24 × 1.5 − 12 × 2 = 12
    /// let ans = Float::with_val(53, a.mul_sub_mul_ref(&b, &c, &d));
    /// assert_eq!(ans, 12);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn mul_sub_mul_ref<'a>(
        &'a self,
        mul: &'a Self,
        sub_mul1: &'a Self,
        sub_mul2: &'a Self,
    ) -> MulSubMulIncomplete<'a> {
        self * mul - sub_mul1 * sub_mul2
    }

    /// Multiplies `u` by 2<sup>`exp`</sup>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// You can also compare the returned value to a [`Float`];
    /// the following are also implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[PartialEq][`PartialEq`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[PartialEq][`PartialEq`]&lt;[Float][`Float`]&gt; for Src</code>
    ///   * <code>[PartialOrd][`PartialOrd`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[PartialOrd][`PartialOrd`]&lt;[Float][`Float`]&gt; for Src</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let v = Float::u_exp(120, -100);
    /// let f = Float::with_val(53, v);
    /// assert_eq!(f, 120.0 * (-100f64).exp2());
    /// let same = Float::u_exp(120 << 2, -100 - 2);
    /// assert_eq!(f, same);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [`PartialEq`]: https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html
    /// [`PartialOrd`]: https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn u_exp(u: u32, exp: i32) -> UExpIncomplete {
        UExpIncomplete { u, exp }
    }

    /// Multiplies `i` by 2<sup>`exp`</sup>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// You can also compare the returned value to a [`Float`];
    /// the following are also implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[PartialEq][`PartialEq`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[PartialEq][`PartialEq`]&lt;[Float][`Float`]&gt; for Src</code>
    ///   * <code>[PartialOrd][`PartialOrd`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[PartialOrd][`PartialOrd`]&lt;[Float][`Float`]&gt; for Src</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let v = Float::i_exp(-120, -100);
    /// let f = Float::with_val(53, v);
    /// assert_eq!(f, -120.0 * (-100f64).exp2());
    /// let same = Float::i_exp(-120 << 2, -100 - 2);
    /// assert_eq!(f, same);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [`PartialEq`]: https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html
    /// [`PartialOrd`]: https://doc.rust-lang.org/nightly/core/cmp/trait.PartialOrd.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn i_exp(i: i32, exp: i32) -> IExpIncomplete {
        IExpIncomplete { i, exp }
    }

    /// Raises `base` to the power of `exponent`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let p = Float::u_pow_u(13, 6);
    /// let f = Float::with_val(53, p);
    /// assert_eq!(f, 13u32.pow(6));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn u_pow_u(base: u32, exponent: u32) -> UPowUIncomplete {
        UPowUIncomplete { base, exponent }
    }

    /// Raises `base` to the power of `exponent`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let p = Float::i_pow_u(-13, 5);
    /// let f = Float::with_val(53, p);
    /// assert_eq!(f, -13i32.pow(5));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn i_pow_u(base: i32, exponent: u32) -> IPowUIncomplete {
        IPowUIncomplete { base, exponent }
    }

    /// Computes the square, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 5.0);
    /// let square = f.square();
    /// assert_eq!(square, 25.0);
    /// ```
    #[inline]
    pub fn square(mut self) -> Self {
        self.square_round(Round::Nearest);
        self
    }

    /// Computes the square, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 5.0);
    /// f.square_mut();
    /// assert_eq!(f, 25.0);
    /// ```
    #[inline]
    pub fn square_mut(&mut self) {
        self.square_round(Round::Nearest);
    }

    /// Computes the square, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 5 in binary is 101
    /// let mut f = Float::with_val(3, 5.0);
    /// // 25 in binary is 11001 (more than 3 bits of precision).
    /// // 25 (11001) is rounded up to 28 (11100).
    /// let dir = f.square_round(Round::Up);
    /// assert_eq!(f, 28.0);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn square_round(&mut self, round: Round) -> Ordering {
        xmpfr::sqr(self, (), round)
    }

    /// Computes the square.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 5.0);
    /// let r = f.square_ref();
    /// let square = Float::with_val(53, r);
    /// assert_eq!(square, 25.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn square_ref(&self) -> SquareIncomplete<'_> {
        SquareIncomplete { ref_self: self }
    }

    /// Computes the square root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 25.0);
    /// let sqrt = f.sqrt();
    /// assert_eq!(sqrt, 5.0);
    /// ```
    #[inline]
    pub fn sqrt(mut self) -> Self {
        self.sqrt_round(Round::Nearest);
        self
    }

    /// Computes the square root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 25.0);
    /// f.sqrt_mut();
    /// assert_eq!(f, 5.0);
    /// ```
    #[inline]
    pub fn sqrt_mut(&mut self) {
        self.sqrt_round(Round::Nearest);
    }

    /// Computes the square root, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 5 in binary is 101
    /// let mut f = Float::with_val(4, 5.0);
    /// // sqrt(5) in binary is 10.00111100...
    /// // sqrt(5) is rounded to 2.25 (10.01).
    /// let dir = f.sqrt_round(Round::Nearest);
    /// assert_eq!(f, 2.25);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn sqrt_round(&mut self, round: Round) -> Ordering {
        xmpfr::sqrt(self, (), round)
    }

    /// Computes the square root.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 25.0);
    /// let r = f.sqrt_ref();
    /// let sqrt = Float::with_val(53, r);
    /// assert_eq!(sqrt, 5.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sqrt_ref(&self) -> SqrtIncomplete<'_> {
        SqrtIncomplete { ref_self: self }
    }

    /// Computes the square root of `u`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let s = Float::sqrt_u(25);
    /// let f = Float::with_val(53, s);
    /// assert_eq!(f, 5.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sqrt_u(u: u32) -> SqrtUIncomplete {
        SqrtUIncomplete { u }
    }

    /// Computes the reciprocal square root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 16.0);
    /// let recip_sqrt = f.recip_sqrt();
    /// assert_eq!(recip_sqrt, 0.25);
    /// ```
    #[inline]
    pub fn recip_sqrt(mut self) -> Self {
        self.recip_sqrt_round(Round::Nearest);
        self
    }

    /// Computes the reciprocal square root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 16.0);
    /// f.recip_sqrt_mut();
    /// assert_eq!(f, 0.25);
    /// ```
    #[inline]
    pub fn recip_sqrt_mut(&mut self) {
        self.recip_sqrt_round(Round::Nearest);
    }

    /// Computes the reciprocal square root, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 5 in binary is 101
    /// let mut f = Float::with_val(4, 5.0);
    /// // 1 / √5 in binary is 0.01110010...
    /// // 1 / √5 is rounded to 0.4375 (0.01110).
    /// let dir = f.recip_sqrt_round(Round::Nearest);
    /// assert_eq!(f, 0.4375);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn recip_sqrt_round(&mut self, round: Round) -> Ordering {
        xmpfr::rec_sqrt(self, (), round)
    }

    /// Computes the reciprocal square root.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 16.0);
    /// let r = f.recip_sqrt_ref();
    /// let recip_sqrt = Float::with_val(53, r);
    /// assert_eq!(recip_sqrt, 0.25);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn recip_sqrt_ref(&self) -> RecipSqrtIncomplete<'_> {
        RecipSqrtIncomplete { ref_self: self }
    }

    /// Computes the cube root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 125.0);
    /// let cbrt = f.cbrt();
    /// assert_eq!(cbrt, 5.0);
    /// ```
    #[inline]
    pub fn cbrt(mut self) -> Self {
        self.cbrt_round(Round::Nearest);
        self
    }

    /// Computes the cube root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 125.0);
    /// f.cbrt_mut();
    /// assert_eq!(f, 5.0);
    /// ```
    #[inline]
    pub fn cbrt_mut(&mut self) {
        self.cbrt_round(Round::Nearest);
    }

    /// Computes the cube root, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 5 in binary is 101
    /// let mut f = Float::with_val(4, 5.0);
    /// // cbrt(5) in binary is 1.101101...
    /// // cbrt(5) is rounded to 1.75 (1.110).
    /// let dir = f.cbrt_round(Round::Nearest);
    /// assert_eq!(f, 1.75);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn cbrt_round(&mut self, round: Round) -> Ordering {
        xmpfr::cbrt(self, (), round)
    }

    /// Computes the cube root.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 125.0);
    /// let r = f.cbrt_ref();
    /// let cbrt = Float::with_val(53, r);
    /// assert_eq!(cbrt, 5.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn cbrt_ref(&self) -> CbrtIncomplete<'_> {
        CbrtIncomplete { ref_self: self }
    }

    /// Computes the <i>k</i>th root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 625.0);
    /// let root = f.root(4);
    /// assert_eq!(root, 5.0);
    /// ```
    #[inline]
    pub fn root(mut self, k: u32) -> Self {
        self.root_round(k, Round::Nearest);
        self
    }

    /// Computes the <i>k</i>th root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 625.0);
    /// f.root_mut(4);
    /// assert_eq!(f, 5.0);
    /// ```
    #[inline]
    pub fn root_mut(&mut self, k: u32) {
        self.root_round(k, Round::Nearest);
    }

    /// Computes the <i>k</i>th root, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 5 in binary is 101
    /// let mut f = Float::with_val(4, 5.0);
    /// // fourth root of 5 in binary is 1.01111...
    /// // fourth root of 5 is rounded to 1.5 (1.100).
    /// let dir = f.root_round(4, Round::Nearest);
    /// assert_eq!(f, 1.5);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn root_round(&mut self, k: u32, round: Round) -> Ordering {
        xmpfr::rootn_ui(self, (), k, round)
    }

    /// Computes the <i>k</i>th root.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 625.0);
    /// let r = f.root_ref(4);
    /// let root = Float::with_val(53, r);
    /// assert_eq!(root, 5.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn root_ref(&self, k: u32) -> RootIncomplete<'_> {
        RootIncomplete { ref_self: self, k }
    }

    /// Computes the absolute value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -23.5);
    /// let abs = f.abs();
    /// assert_eq!(abs, 23.5);
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
    /// use rug::Float;
    /// let mut f = Float::with_val(53, -23.5);
    /// f.abs_mut();
    /// assert_eq!(f, 23.5);
    /// ```
    #[inline]
    pub fn abs_mut(&mut self) {
        xmpfr::abs(self, (), Round::Nearest);
    }

    /// Computes the absolute value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -23.5);
    /// let r = f.abs_ref();
    /// let abs = Float::with_val(53, r);
    /// assert_eq!(abs, 23.5);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn abs_ref(&self) -> AbsIncomplete<'_> {
        AbsIncomplete { ref_self: self }
    }

    /// Computes the signum.
    ///
    ///   * 1.0 if the value is positive, +0.0 or +∞
    ///   * −1.0 if the value is negative, −0.0 or −∞
    ///   * NaN if the value is NaN
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// assert_eq!(Float::with_val(53, -23.5).signum(), -1);
    /// assert_eq!(Float::with_val(53, -0.0).signum(), -1);
    /// assert_eq!(Float::with_val(53, 0.0).signum(), 1);
    /// assert_eq!(Float::with_val(53, 23.5).signum(), 1);
    /// ```
    #[inline]
    pub fn signum(mut self) -> Self {
        self.signum_mut();
        self
    }

    /// Computes the signum.
    ///
    ///   * 1.0 if the value is positive, +0.0 or +∞
    ///   * −1.0 if the value is negative, −0.0 or −∞
    ///   * NaN if the value is NaN
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, -23.5);
    /// f.signum_mut();
    /// assert_eq!(f, -1);
    /// ```
    #[inline]
    pub fn signum_mut(&mut self) {
        xmpfr::signum(self, (), Round::Nearest);
    }

    /// Computes the signum.
    ///
    ///   * 1.0 if the value is positive, +0.0 or +∞
    ///   * −1.0 if the value is negative, −0.0 or −∞
    ///   * NaN if the value is NaN
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -23.5);
    /// let r = f.signum_ref();
    /// let signum = Float::with_val(53, r);
    /// assert_eq!(signum, -1);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn signum_ref(&self) -> SignumIncomplete<'_> {
        SignumIncomplete { ref_self: self }
    }

    /// Returns a number with the magnitude of `self` and the sign
    /// of `y`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let x = Float::with_val(53, 23.0);
    /// let y = Float::with_val(53, -1.0);
    /// let copysign = x.copysign(&y);
    /// assert_eq!(copysign, -23.0);
    /// ```
    #[inline]
    pub fn copysign(mut self, y: &Self) -> Self {
        self.copysign_mut(y);
        self
    }

    /// Retains the magnitude of `self` and copies the sign of
    /// `y`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut x = Float::with_val(53, 23.0);
    /// let y = Float::with_val(53, -1.0);
    /// x.copysign_mut(&y);
    /// assert_eq!(x, -23.0);
    /// ```
    #[inline]
    pub fn copysign_mut(&mut self, y: &Self) {
        xmpfr::copysign(self, (), y, Round::Nearest);
    }

    /// Computes a number with the magnitude of `self` and the
    /// sign of `y`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let x = Float::with_val(53, 23.0);
    /// let y = Float::with_val(53, -1.0);
    /// let r = x.copysign_ref(&y);
    /// let copysign = Float::with_val(53, r);
    /// assert_eq!(copysign, -23.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn copysign_ref<'a>(&'a self, y: &'a Self) -> CopysignIncomplete<'_> {
        CopysignIncomplete { ref_self: self, y }
    }

    /// Clamps the value within the specified bounds, rounding to the
    /// nearest.
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value,
    /// unless assigning any of them to `self` produces the same value
    /// with the same rounding direction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let min = -1.5;
    /// let max = 1.5;
    /// let too_small = Float::with_val(53, -2.5);
    /// let clamped1 = too_small.clamp(&min, &max);
    /// assert_eq!(clamped1, -1.5);
    /// let in_range = Float::with_val(53, 0.5);
    /// let clamped2 = in_range.clamp(&min, &max);
    /// assert_eq!(clamped2, 0.5);
    /// ```
    #[inline]
    pub fn clamp<Min, Max>(mut self, min: &Min, max: &Max) -> Self
    where
        Self: PartialOrd<Min>
            + PartialOrd<Max>
            + for<'a> AssignRound<&'a Min, Round = Round, Ordering = Ordering>
            + for<'a> AssignRound<&'a Max, Round = Round, Ordering = Ordering>,
    {
        self.clamp_round(min, max, Round::Nearest);
        self
    }

    /// Clamps the value within the specified bounds, rounding to the
    /// nearest.
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value,
    /// unless assigning any of them to `self` produces the same value
    /// with the same rounding direction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let min = -1.5;
    /// let max = 1.5;
    /// let mut too_small = Float::with_val(53, -2.5);
    /// too_small.clamp_mut(&min, &max);
    /// assert_eq!(too_small, -1.5);
    /// let mut in_range = Float::with_val(53, 0.5);
    /// in_range.clamp_mut(&min, &max);
    /// assert_eq!(in_range, 0.5);
    /// ```
    #[inline]
    pub fn clamp_mut<Min, Max>(&mut self, min: &Min, max: &Max)
    where
        Self: PartialOrd<Min>
            + PartialOrd<Max>
            + for<'a> AssignRound<&'a Min, Round = Round, Ordering = Ordering>
            + for<'a> AssignRound<&'a Max, Round = Round, Ordering = Ordering>,
    {
        self.clamp_round(min, max, Round::Nearest);
    }

    /// Clamps the value within the specified bounds, applying the
    /// specified rounding method.
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value,
    /// unless assigning any of them to `self` produces the same value
    /// with the same rounding direction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let min = Float::with_val(53, -1.5);
    /// let max = Float::with_val(53, 1.5);
    /// let mut too_small = Float::with_val(53, -2.5);
    /// let dir1 = too_small.clamp_round(&min, &max, Round::Nearest);
    /// assert_eq!(too_small, -1.5);
    /// assert_eq!(dir1, Ordering::Equal);
    /// let mut in_range = Float::with_val(53, 0.5);
    /// let dir2 = in_range.clamp_round(&min, &max, Round::Nearest);
    /// assert_eq!(in_range, 0.5);
    /// assert_eq!(dir2, Ordering::Equal);
    /// ```
    pub fn clamp_round<Min, Max>(&mut self, min: &Min, max: &Max, round: Round) -> Ordering
    where
        Self: PartialOrd<Min>
            + PartialOrd<Max>
            + for<'a> AssignRound<&'a Min, Round = Round, Ordering = Ordering>
            + for<'a> AssignRound<&'a Max, Round = Round, Ordering = Ordering>,
    {
        if (*self).lt(min) {
            let dir = self.assign_round(min, round);
            if (*self).gt(max) {
                let dir2 = self.assign_round(max, round);
                assert!(
                    dir == dir2 && !(*self).lt(min),
                    "minimum larger than maximum"
                );
                dir
            } else {
                dir
            }
        } else if (*self).gt(max) {
            let dir = self.assign_round(max, round);
            if (*self).lt(min) {
                let dir2 = self.assign_round(min, round);
                assert!(
                    dir == dir2 && !(*self).gt(max),
                    "minimum larger than maximum"
                );
                dir
            } else {
                dir
            }
        } else {
            if self.is_nan() {
                xmpfr::set_nanflag();
            }
            Ordering::Equal
        }
    }

    /// Clamps the value within the specified bounds.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value,
    /// unless assigning any of them to the target produces the same
    /// value with the same rounding direction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let min = -1.5;
    /// let max = 1.5;
    /// let too_small = Float::with_val(53, -2.5);
    /// let r1 = too_small.clamp_ref(&min, &max);
    /// let clamped1 = Float::with_val(53, r1);
    /// assert_eq!(clamped1, -1.5);
    /// let in_range = Float::with_val(53, 0.5);
    /// let r2 = in_range.clamp_ref(&min, &max);
    /// let clamped2 = Float::with_val(53, r2);
    /// assert_eq!(clamped2, 0.5);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn clamp_ref<'min, 'max, Min, Max>(
        &self,
        min: &'min Min,
        max: &'max Max,
    ) -> ClampIncomplete<'_, 'min, 'max, Min, Max>
    where
        Self: PartialOrd<Min>
            + PartialOrd<Max>
            + for<'a> AssignRound<&'a Min, Round = Round, Ordering = Ordering>
            + for<'a> AssignRound<&'a Max, Round = Round, Ordering = Ordering>,
    {
        ClampIncomplete {
            ref_self: self,
            min,
            max,
        }
    }

    /// Computes the reciprocal, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.25);
    /// let recip = f.recip();
    /// assert_eq!(recip, -4.0);
    /// ```
    #[inline]
    pub fn recip(mut self) -> Self {
        self.recip_round(Round::Nearest);
        self
    }

    /// Computes the reciprocal, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, -0.25);
    /// f.recip_mut();
    /// assert_eq!(f, -4.0);
    /// ```
    #[inline]
    pub fn recip_mut(&mut self) {
        self.recip_round(Round::Nearest);
    }

    /// Computes the reciprocal, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 5 in binary is 101
    /// let mut f = Float::with_val(4, -5.0);
    /// // 1/5 in binary is 0.00110011...
    /// // 1/5 is rounded to 0.203125 (0.001101).
    /// let dir = f.recip_round(Round::Nearest);
    /// assert_eq!(f, -0.203125);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn recip_round(&mut self, round: Round) -> Ordering {
        xmpfr::recip(self, (), round)
    }

    /// Computes the reciprocal.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.25);
    /// let r = f.recip_ref();
    /// let recip = Float::with_val(53, r);
    /// assert_eq!(recip, -4.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn recip_ref(&self) -> RecipIncomplete<'_> {
        RecipIncomplete { ref_self: self }
    }

    /// Finds the minimum, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, -2);
    /// let min = a.min(&b);
    /// assert_eq!(min, -2);
    /// ```
    #[inline]
    pub fn min(mut self, other: &Self) -> Self {
        self.min_round(other, Round::Nearest);
        self
    }

    /// Finds the minimum, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, -2);
    /// a.min_mut(&b);
    /// assert_eq!(a, -2);
    /// ```
    #[inline]
    pub fn min_mut(&mut self, other: &Self) {
        self.min_round(other, Round::Nearest);
    }

    /// Finds the minimum, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let mut a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, -2);
    /// let dir = a.min_round(&b, Round::Nearest);
    /// assert_eq!(a, -2);
    /// assert_eq!(dir, Ordering::Equal);
    /// ```
    #[inline]
    pub fn min_round(&mut self, other: &Self, round: Round) -> Ordering {
        xmpfr::min(self, (), other, round)
    }

    /// Finds the minimum.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, -2);
    /// let r = a.min_ref(&b);
    /// let min = Float::with_val(53, r);
    /// assert_eq!(min, -2);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn min_ref<'a>(&'a self, other: &'a Self) -> MinIncomplete<'_> {
        MinIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Finds the maximum, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, 12.5);
    /// let max = a.max(&b);
    /// assert_eq!(max, 12.5);
    /// ```
    #[inline]
    pub fn max(mut self, other: &Self) -> Self {
        self.max_round(other, Round::Nearest);
        self
    }

    /// Finds the maximum, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, 12.5);
    /// a.max_mut(&b);
    /// assert_eq!(a, 12.5);
    /// ```
    #[inline]
    pub fn max_mut(&mut self, other: &Self) {
        self.max_round(other, Round::Nearest);
    }

    /// Finds the maximum, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let mut a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, 12.5);
    /// let dir = a.max_round(&b, Round::Nearest);
    /// assert_eq!(a, 12.5);
    /// assert_eq!(dir, Ordering::Equal);
    /// ```
    #[inline]
    pub fn max_round(&mut self, other: &Self, round: Round) -> Ordering {
        xmpfr::max(self, (), other, round)
    }

    /// Finds the maximum.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 5.2);
    /// let b = Float::with_val(53, 12.5);
    /// let r = a.max_ref(&b);
    /// let max = Float::with_val(53, r);
    /// assert_eq!(max, 12.5);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn max_ref<'a>(&'a self, other: &'a Self) -> MaxIncomplete<'_> {
        MaxIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Computes the positive difference between `self` and
    /// `other`, rounding to the nearest.
    ///
    /// The positive difference is `self` − `other` if `self` >
    /// `other`, zero if `self` ≤ `other`, or NaN if any operand
    /// is NaN.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 12.5);
    /// let b = Float::with_val(53, 7.3);
    /// let diff1 = a.positive_diff(&b);
    /// assert_eq!(diff1, 5.2);
    /// let diff2 = diff1.positive_diff(&b);
    /// assert_eq!(diff2, 0);
    /// ```
    #[inline]
    pub fn positive_diff(mut self, other: &Self) -> Self {
        self.positive_diff_round(other, Round::Nearest);
        self
    }

    /// Computes the positive difference between `self` and
    /// `other`, rounding to the nearest.
    ///
    /// The positive difference is `self` − `other` if `self` >
    /// `other`, zero if `self` ≤ `other`, or NaN if any operand
    /// is NaN.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut a = Float::with_val(53, 12.5);
    /// let b = Float::with_val(53, 7.3);
    /// a.positive_diff_mut(&b);
    /// assert_eq!(a, 5.2);
    /// a.positive_diff_mut(&b);
    /// assert_eq!(a, 0);
    /// ```
    #[inline]
    pub fn positive_diff_mut(&mut self, other: &Self) {
        self.positive_diff_round(other, Round::Nearest);
    }

    /// Computes the positive difference between `self` and
    /// `other`, applying the specified rounding method.
    ///
    /// The positive difference is `self` − `other` if `self` >
    /// `other`, zero if `self` ≤ `other`, or NaN if any operand
    /// is NaN.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let mut a = Float::with_val(53, 12.5);
    /// let b = Float::with_val(53, 7.3);
    /// let dir = a.positive_diff_round(&b, Round::Nearest);
    /// assert_eq!(a, 5.2);
    /// assert_eq!(dir, Ordering::Equal);
    /// let dir = a.positive_diff_round(&b, Round::Nearest);
    /// assert_eq!(a, 0);
    /// assert_eq!(dir, Ordering::Equal);
    /// ```
    #[inline]
    pub fn positive_diff_round(&mut self, other: &Self, round: Round) -> Ordering {
        xmpfr::dim(self, (), other, round)
    }

    /// Computes the positive difference.
    ///
    /// The positive difference is `self` − `other` if `self` >
    /// `other`, zero if `self` ≤ `other`, or NaN if any operand
    /// is NaN.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let a = Float::with_val(53, 12.5);
    /// let b = Float::with_val(53, 7.3);
    /// let rab = a.positive_diff_ref(&b);
    /// let ab = Float::with_val(53, rab);
    /// assert_eq!(ab, 5.2);
    /// let rba = b.positive_diff_ref(&a);
    /// let ba = Float::with_val(53, rba);
    /// assert_eq!(ba, 0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn positive_diff_ref<'a>(&'a self, other: &'a Self) -> PositiveDiffIncomplete<'_> {
        PositiveDiffIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Computes the natural logarithm, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let ln = f.ln();
    /// let expected = 0.4055_f64;
    /// assert!((ln - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn ln(mut self) -> Self {
        self.ln_round(Round::Nearest);
        self
    }

    /// Computes the natural logarithm, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.5);
    /// f.ln_mut();
    /// let expected = 0.4055_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn ln_mut(&mut self) {
        self.ln_round(Round::Nearest);
    }

    /// Computes the natural logarithm, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5);
    /// // ln(1.5) = 0.4055
    /// // using 4 significant bits: 0.40625
    /// let dir = f.ln_round(Round::Nearest);
    /// assert_eq!(f, 0.40625);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn ln_round(&mut self, round: Round) -> Ordering {
        xmpfr::log(self, (), round)
    }

    /// Computes the natural logarithm.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let ln = Float::with_val(53, f.ln_ref());
    /// let expected = 0.4055_f64;
    /// assert!((ln - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ln_ref(&self) -> LnIncomplete<'_> {
        LnIncomplete { ref_self: self }
    }

    /// Computes the natural logarithm of `u`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let l = Float::ln_u(3);
    /// let f = Float::with_val(53, l);
    /// let expected = 1.0986f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ln_u(u: u32) -> LnUIncomplete {
        LnUIncomplete { u }
    }

    /// Computes the logarithm to base 2, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let log2 = f.log2();
    /// let expected = 0.5850_f64;
    /// assert!((log2 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn log2(mut self) -> Self {
        self.log2_round(Round::Nearest);
        self
    }

    /// Computes the logarithm to base 2, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.5);
    /// f.log2_mut();
    /// let expected = 0.5850_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn log2_mut(&mut self) {
        self.log2_round(Round::Nearest);
    }

    /// Computes the logarithm to base 2, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5);
    /// // log2(1.5) = 0.5850
    /// // using 4 significant bits: 0.5625
    /// let dir = f.log2_round(Round::Nearest);
    /// assert_eq!(f, 0.5625);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn log2_round(&mut self, round: Round) -> Ordering {
        xmpfr::log2(self, (), round)
    }

    /// Computes the logarithm to base 2.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let log2 = Float::with_val(53, f.log2_ref());
    /// let expected = 0.5850_f64;
    /// assert!((log2 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn log2_ref(&self) -> Log2Incomplete<'_> {
        Log2Incomplete { ref_self: self }
    }

    /// Computes the logarithm to base 10, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let log10 = f.log10();
    /// let expected = 0.1761_f64;
    /// assert!((log10 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn log10(mut self) -> Self {
        self.log10_round(Round::Nearest);
        self
    }

    /// Computes the logarithm to base 10, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.5);
    /// f.log10_mut();
    /// let expected = 0.1761_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn log10_mut(&mut self) {
        self.log10_round(Round::Nearest);
    }

    /// Computes the logarithm to base 10, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5);
    /// // log10(1.5) = 0.1761
    /// // using 4 significant bits: 0.171875
    /// let dir = f.log10_round(Round::Nearest);
    /// assert_eq!(f, 0.171875);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn log10_round(&mut self, round: Round) -> Ordering {
        xmpfr::log10(self, (), round)
    }

    /// Computes the logarithm to base 10.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let log10 = Float::with_val(53, f.log10_ref());
    /// let expected = 0.1761_f64;
    /// assert!((log10 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn log10_ref(&self) -> Log10Incomplete<'_> {
        Log10Incomplete { ref_self: self }
    }

    /// Computes the exponential, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let exp = f.exp();
    /// let expected = 4.4817_f64;
    /// assert!((exp - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn exp(mut self) -> Self {
        self.exp_round(Round::Nearest);
        self
    }

    /// Computes the exponential, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.5);
    /// f.exp_mut();
    /// let expected = 4.4817_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn exp_mut(&mut self) {
        self.exp_round(Round::Nearest);
    }

    /// Computes the exponential, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5);
    /// // exp(1.5) = 4.4817
    /// // using 4 significant bits: 4.5
    /// let dir = f.exp_round(Round::Nearest);
    /// assert_eq!(f, 4.5);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn exp_round(&mut self, round: Round) -> Ordering {
        xmpfr::exp(self, (), round)
    }

    /// Computes the exponential.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let exp = Float::with_val(53, f.exp_ref());
    /// let expected = 4.4817_f64;
    /// assert!((exp - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn exp_ref(&self) -> ExpIncomplete<'_> {
        ExpIncomplete { ref_self: self }
    }

    /// Computes 2 to the power of `self`, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let exp2 = f.exp2();
    /// let expected = 2.8284_f64;
    /// assert!((exp2 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn exp2(mut self) -> Self {
        self.exp2_round(Round::Nearest);
        self
    }

    /// Computes 2 to the power of `self`, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.5);
    /// f.exp2_mut();
    /// let expected = 2.8284_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn exp2_mut(&mut self) {
        self.exp2_round(Round::Nearest);
    }

    /// Computes 2 to the power of `self`, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5);
    /// // exp2(1.5) = 2.8284
    /// // using 4 significant bits: 2.75
    /// let dir = f.exp2_round(Round::Nearest);
    /// assert_eq!(f, 2.75);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn exp2_round(&mut self, round: Round) -> Ordering {
        xmpfr::exp2(self, (), round)
    }

    /// Computes 2 to the power of the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let exp2 = Float::with_val(53, f.exp2_ref());
    /// let expected = 2.8284_f64;
    /// assert!((exp2 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn exp2_ref(&self) -> Exp2Incomplete<'_> {
        Exp2Incomplete { ref_self: self }
    }

    /// Computes 10 to the power of `self`, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let exp10 = f.exp10();
    /// let expected = 31.6228_f64;
    /// assert!((exp10 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn exp10(mut self) -> Self {
        self.exp10_round(Round::Nearest);
        self
    }

    /// Computes 10 to the power of `self`, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.5);
    /// f.exp10_mut();
    /// let expected = 31.6228_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn exp10_mut(&mut self) {
        self.exp10_round(Round::Nearest);
    }

    /// Computes 10 to the power of `self`, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5);
    /// // exp10(1.5) = 31.6228
    /// // using 4 significant bits: 32
    /// let dir = f.exp10_round(Round::Nearest);
    /// assert_eq!(f, 32);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn exp10_round(&mut self, round: Round) -> Ordering {
        xmpfr::exp10(self, (), round)
    }

    /// Computes 10 to the power of the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.5);
    /// let exp10 = Float::with_val(53, f.exp10_ref());
    /// let expected = 31.6228_f64;
    /// assert!((exp10 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn exp10_ref(&self) -> Exp10Incomplete<'_> {
        Exp10Incomplete { ref_self: self }
    }

    /// Computes the sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sin = f.sin();
    /// let expected = 0.9490_f64;
    /// assert!((sin - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sin(mut self) -> Self {
        self.sin_round(Round::Nearest);
        self
    }

    /// Computes the sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.sin_mut();
    /// let expected = 0.9490_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sin_mut(&mut self) {
        self.sin_round(Round::Nearest);
    }

    /// Computes the sine, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // sin(1.25) = 0.9490
    /// // using 4 significant bits: 0.9375
    /// let dir = f.sin_round(Round::Nearest);
    /// assert_eq!(f, 0.9375);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn sin_round(&mut self, round: Round) -> Ordering {
        xmpfr::sin(self, (), round)
    }

    /// Computes the sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sin = Float::with_val(53, f.sin_ref());
    /// let expected = 0.9490_f64;
    /// assert!((sin - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sin_ref(&self) -> SinIncomplete<'_> {
        SinIncomplete { ref_self: self }
    }

    /// Computes the cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let cos = f.cos();
    /// let expected = 0.3153_f64;
    /// assert!((cos - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn cos(mut self) -> Self {
        self.cos_round(Round::Nearest);
        self
    }

    /// Computes the cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.cos_mut();
    /// let expected = 0.3153_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn cos_mut(&mut self) {
        self.cos_round(Round::Nearest);
    }

    /// Computes the cosine, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // cos(1.25) = 0.3153
    /// // using 4 significant bits: 0.3125
    /// let dir = f.cos_round(Round::Nearest);
    /// assert_eq!(f, 0.3125);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn cos_round(&mut self, round: Round) -> Ordering {
        xmpfr::cos(self, (), round)
    }

    /// Computes the cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let cos = Float::with_val(53, f.cos_ref());
    /// let expected = 0.3153_f64;
    /// assert!((cos - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn cos_ref(&self) -> CosIncomplete<'_> {
        CosIncomplete { ref_self: self }
    }

    /// Computes the tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let tan = f.tan();
    /// let expected = 3.0096_f64;
    /// assert!((tan - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn tan(mut self) -> Self {
        self.tan_round(Round::Nearest);
        self
    }

    /// Computes the tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.tan_mut();
    /// let expected = 3.0096_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn tan_mut(&mut self) {
        self.tan_round(Round::Nearest);
    }

    /// Computes the tangent, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // tan(1.25) = 3.0096
    /// // using 4 significant bits: 3.0
    /// let dir = f.tan_round(Round::Nearest);
    /// assert_eq!(f, 3.0);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn tan_round(&mut self, round: Round) -> Ordering {
        xmpfr::tan(self, (), round)
    }

    /// Computes the tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let tan = Float::with_val(53, f.tan_ref());
    /// let expected = 3.0096_f64;
    /// assert!((tan - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn tan_ref(&self) -> TanIncomplete<'_> {
        TanIncomplete { ref_self: self }
    }

    /// Computes the sine and cosine of `self`, rounding to the
    /// nearest.
    ///
    /// The sine is stored in `self` and keeps its precision,
    /// while the cosine is stored in `cos` keeping its precision.
    ///
    /// The initial value of `cos` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let (sin, cos) = f.sin_cos(Float::new(53));
    /// let expected_sin = 0.9490_f64;
    /// let expected_cos = 0.3153_f64;
    /// assert!((sin - expected_sin).abs() < 0.0001);
    /// assert!((cos - expected_cos).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sin_cos(mut self, mut cos: Self) -> (Self, Self) {
        self.sin_cos_round(&mut cos, Round::Nearest);
        (self, cos)
    }

    /// Computes the sine and cosine of `self`, rounding to the
    /// nearest.
    ///
    /// The sine is stored in `self` and keeps its precision,
    /// while the cosine is stored in `cos` keeping its precision.
    ///
    /// The initial value of `cos` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut sin = Float::with_val(53, 1.25);
    /// let mut cos = Float::new(53);
    /// sin.sin_cos_mut(&mut cos);
    /// let expected_sin = 0.9490_f64;
    /// let expected_cos = 0.3153_f64;
    /// assert!((sin - expected_sin).abs() < 0.0001);
    /// assert!((cos - expected_cos).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sin_cos_mut(&mut self, cos: &mut Self) {
        self.sin_cos_round(cos, Round::Nearest);
    }

    /// Computes the sine and cosine of `self`, applying the specified
    /// rounding method.
    ///
    /// The sine is stored in `self` and keeps its precision,
    /// while the cosine is stored in `cos` keeping its precision.
    ///
    /// The initial value of `cos` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut sin = Float::with_val(4, 1.25);
    /// let mut cos = Float::new(4);
    /// // sin(1.25) = 0.9490, using 4 significant bits: 0.9375
    /// // cos(1.25) = 0.3153, using 4 significant bits: 0.3125
    /// let (dir_sin, dir_cos) =
    ///     sin.sin_cos_round(&mut cos, Round::Nearest);
    /// assert_eq!(sin, 0.9375);
    /// assert_eq!(dir_sin, Ordering::Less);
    /// assert_eq!(cos, 0.3125);
    /// assert_eq!(dir_cos, Ordering::Less);
    /// ```
    #[inline]
    pub fn sin_cos_round(&mut self, cos: &mut Self, round: Round) -> (Ordering, Ordering) {
        xmpfr::sin_cos(self, cos, (), round)
    }

    /// Computes the sine and cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Float][`Float`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Float][`Float`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Float][`Float`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Float][`Float`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::AssignRound, Assign, Float};
    /// let phase = Float::with_val(53, 1.25);
    ///
    /// let (mut sin, mut cos) = (Float::new(53), Float::new(53));
    /// let sin_cos = phase.sin_cos_ref();
    /// (&mut sin, &mut cos).assign(sin_cos);
    /// let expected_sin = 0.9490_f64;
    /// let expected_cos = 0.3153_f64;
    /// assert!((sin - expected_sin).abs() < 0.0001);
    /// assert!((cos - expected_cos).abs() < 0.0001);
    ///
    /// // using 4 significant bits: sin = 0.9375
    /// // using 4 significant bits: cos = 0.3125
    /// let (mut sin_4, mut cos_4) = (Float::new(4), Float::new(4));
    /// let sin_cos = phase.sin_cos_ref();
    /// let (dir_sin, dir_cos) = (&mut sin_4, &mut cos_4)
    ///     .assign_round(sin_cos, Round::Nearest);
    /// assert_eq!(sin_4, 0.9375);
    /// assert_eq!(dir_sin, Ordering::Less);
    /// assert_eq!(cos_4, 0.3125);
    /// assert_eq!(dir_cos, Ordering::Less);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn sin_cos_ref(&self) -> SinCosIncomplete<'_> {
        SinCosIncomplete { ref_self: self }
    }

    /// Computes the secant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sec = f.sec();
    /// let expected = 3.1714_f64;
    /// assert!((sec - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sec(mut self) -> Self {
        self.sec_round(Round::Nearest);
        self
    }

    /// Computes the secant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.sec_mut();
    /// let expected = 3.1714_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sec_mut(&mut self) {
        self.sec_round(Round::Nearest);
    }

    /// Computes the secant, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // sec(1.25) = 3.1714
    /// // using 4 significant bits: 3.25
    /// let dir = f.sec_round(Round::Nearest);
    /// assert_eq!(f, 3.25);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn sec_round(&mut self, round: Round) -> Ordering {
        xmpfr::sec(self, (), round)
    }

    /// Computes the secant.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sec = Float::with_val(53, f.sec_ref());
    /// let expected = 3.1714_f64;
    /// assert!((sec - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sec_ref(&self) -> SecIncomplete<'_> {
        SecIncomplete { ref_self: self }
    }

    /// Computes the cosecant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let csc = f.csc();
    /// let expected = 1.0538_f64;
    /// assert!((csc - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn csc(mut self) -> Self {
        self.csc_round(Round::Nearest);
        self
    }

    /// Computes the cosecant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.csc_mut();
    /// let expected = 1.0538_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn csc_mut(&mut self) {
        self.csc_round(Round::Nearest);
    }

    /// Computes the cosecant, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // csc(1.25) = 1.0538
    /// // using 4 significant bits: 1.0
    /// let dir = f.csc_round(Round::Nearest);
    /// assert_eq!(f, 1.0);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn csc_round(&mut self, round: Round) -> Ordering {
        xmpfr::csc(self, (), round)
    }

    /// Computes the cosecant.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let csc = Float::with_val(53, f.csc_ref());
    /// let expected = 1.0538_f64;
    /// assert!((csc - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn csc_ref(&self) -> CscIncomplete<'_> {
        CscIncomplete { ref_self: self }
    }

    /// Computes the cotangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let cot = f.cot();
    /// let expected = 0.3323_f64;
    /// assert!((cot - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn cot(mut self) -> Self {
        self.cot_round(Round::Nearest);
        self
    }

    /// Computes the cotangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.cot_mut();
    /// let expected = 0.3323_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn cot_mut(&mut self) {
        self.cot_round(Round::Nearest);
    }

    /// Computes the cotangent, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // cot(1.25) = 0.3323
    /// // using 4 significant bits: 0.34375
    /// let dir = f.cot_round(Round::Nearest);
    /// assert_eq!(f, 0.34375);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn cot_round(&mut self, round: Round) -> Ordering {
        xmpfr::cot(self, (), round)
    }

    /// Computes the cotangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let cot = Float::with_val(53, f.cot_ref());
    /// let expected = 0.3323_f64;
    /// assert!((cot - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn cot_ref(&self) -> CotIncomplete<'_> {
        CotIncomplete { ref_self: self }
    }

    /// Computes the arc-sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.75);
    /// let asin = f.asin();
    /// let expected = -0.8481_f64;
    /// assert!((asin - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn asin(mut self) -> Self {
        self.asin_round(Round::Nearest);
        self
    }

    /// Computes the arc-sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, -0.75);
    /// f.asin_mut();
    /// let expected = -0.8481_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn asin_mut(&mut self) {
        self.asin_round(Round::Nearest);
    }

    /// Computes the arc-sine, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, -0.75);
    /// // asin(−0.75) = −0.8481
    /// // using 4 significant bits: −0.875
    /// let dir = f.asin_round(Round::Nearest);
    /// assert_eq!(f, -0.875);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn asin_round(&mut self, round: Round) -> Ordering {
        xmpfr::asin(self, (), round)
    }

    /// Computes the arc-sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.75);
    /// let asin = Float::with_val(53, f.asin_ref());
    /// let expected = -0.8481_f64;
    /// assert!((asin - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn asin_ref(&self) -> AsinIncomplete<'_> {
        AsinIncomplete { ref_self: self }
    }

    /// Computes the arc-cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.75);
    /// let acos = f.acos();
    /// let expected = 2.4189_f64;
    /// assert!((acos - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn acos(mut self) -> Self {
        self.acos_round(Round::Nearest);
        self
    }

    /// Computes the arc-cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, -0.75);
    /// f.acos_mut();
    /// let expected = 2.4189_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn acos_mut(&mut self) {
        self.acos_round(Round::Nearest);
    }

    /// Computes the arc-cosine, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, -0.75);
    /// // acos(−0.75) = 2.4189
    /// // using 4 significant bits: 2.5
    /// let dir = f.acos_round(Round::Nearest);
    /// assert_eq!(f, 2.5);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn acos_round(&mut self, round: Round) -> Ordering {
        xmpfr::acos(self, (), round)
    }

    /// Computes the arc-cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.75);
    /// let acos = Float::with_val(53, f.acos_ref());
    /// let expected = 2.4189_f64;
    /// assert!((acos - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn acos_ref(&self) -> AcosIncomplete<'_> {
        AcosIncomplete { ref_self: self }
    }

    /// Computes the arc-tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.75);
    /// let atan = f.atan();
    /// let expected = -0.6435_f64;
    /// assert!((atan - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn atan(mut self) -> Self {
        self.atan_round(Round::Nearest);
        self
    }

    /// Computes the arc-tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, -0.75);
    /// f.atan_mut();
    /// let expected = -0.6435_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn atan_mut(&mut self) {
        self.atan_round(Round::Nearest);
    }

    /// Computes the arc-tangent, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, -0.75);
    /// // atan(−0.75) = −0.6435
    /// // using 4 significant bits: −0.625
    /// let dir = f.atan_round(Round::Nearest);
    /// assert_eq!(f, -0.625);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn atan_round(&mut self, round: Round) -> Ordering {
        xmpfr::atan(self, (), round)
    }

    /// Computes the arc-tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, -0.75);
    /// let atan = Float::with_val(53, f.atan_ref());
    /// let expected = -0.6435_f64;
    /// assert!((atan - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn atan_ref(&self) -> AtanIncomplete<'_> {
        AtanIncomplete { ref_self: self }
    }

    /// Computes the arc-tangent2 of `self` and `x`, rounding to
    /// the nearest.
    ///
    /// This is similar to the arc-tangent of `self / x`, but
    /// has an output range of 2π rather than π.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let y = Float::with_val(53, 3.0);
    /// let x = Float::with_val(53, -4.0);
    /// let atan2 = y.atan2(&x);
    /// let expected = 2.4981_f64;
    /// assert!((atan2 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn atan2(mut self, x: &Self) -> Self {
        self.atan2_round(x, Round::Nearest);
        self
    }

    /// Computes the arc-tangent2 of `self` and `x`, rounding to
    /// the nearest.
    ///
    /// This is similar to the arc-tangent of `self / x`, but
    /// has an output range of 2π rather than π.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut y = Float::with_val(53, 3.0);
    /// let x = Float::with_val(53, -4.0);
    /// y.atan2_mut(&x);
    /// let expected = 2.4981_f64;
    /// assert!((y - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn atan2_mut(&mut self, x: &Self) {
        self.atan2_round(x, Round::Nearest);
    }

    /// Computes the arc-tangent2 of `self` and `x`, applying the
    /// specified rounding method.
    ///
    /// This is similar to the arc-tangent of `self / x`, but
    /// has an output range of 2π rather than π.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut y = Float::with_val(4, 3.0);
    /// let x = Float::with_val(4, -4.0);
    /// // atan2(3.0, −4.0) = 2.4981
    /// // using 4 significant bits: 2.5
    /// let dir = y.atan2_round(&x, Round::Nearest);
    /// assert_eq!(y, 2.5);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn atan2_round(&mut self, x: &Self, round: Round) -> Ordering {
        xmpfr::atan2(self, (), x, round)
    }

    /// Computes the arc-tangent.
    ///
    /// This is similar to the arc-tangent of `self / x`, but
    /// has an output range of 2π rather than π.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let y = Float::with_val(53, 3.0);
    /// let x = Float::with_val(53, -4.0);
    /// let r = y.atan2_ref(&x);
    /// let atan2 = Float::with_val(53, r);
    /// let expected = 2.4981_f64;
    /// assert!((atan2 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn atan2_ref<'a>(&'a self, x: &'a Self) -> Atan2Incomplete<'_> {
        Atan2Incomplete { ref_self: self, x }
    }

    /// Computes the hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sinh = f.sinh();
    /// let expected = 1.6019_f64;
    /// assert!((sinh - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sinh(mut self) -> Self {
        self.sinh_round(Round::Nearest);
        self
    }

    /// Computes the hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.sinh_mut();
    /// let expected = 1.6019_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sinh_mut(&mut self) {
        self.sinh_round(Round::Nearest);
    }

    /// Computes the hyperbolic sine, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // sinh(1.25) = 1.6019
    /// // using 4 significant bits: 1.625
    /// let dir = f.sinh_round(Round::Nearest);
    /// assert_eq!(f, 1.625);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn sinh_round(&mut self, round: Round) -> Ordering {
        xmpfr::sinh(self, (), round)
    }

    /// Computes the hyperbolic sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sinh = Float::with_val(53, f.sinh_ref());
    /// let expected = 1.6019_f64;
    /// assert!((sinh - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sinh_ref(&self) -> SinhIncomplete<'_> {
        SinhIncomplete { ref_self: self }
    }

    /// Computes the hyperbolic cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let cosh = f.cosh();
    /// let expected = 1.8884_f64;
    /// assert!((cosh - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn cosh(mut self) -> Self {
        self.cosh_round(Round::Nearest);
        self
    }

    /// Computes the hyperbolic cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.cosh_mut();
    /// let expected = 1.8884_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn cosh_mut(&mut self) {
        self.cosh_round(Round::Nearest);
    }

    /// Computes the hyperbolic cosine, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // cosh(1.25) = 1.8884
    /// // using 4 significant bits: 1.875
    /// let dir = f.cosh_round(Round::Nearest);
    /// assert_eq!(f, 1.875);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn cosh_round(&mut self, round: Round) -> Ordering {
        xmpfr::cosh(self, (), round)
    }

    /// Computes the hyperbolic cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let cosh = Float::with_val(53, f.cosh_ref());
    /// let expected = 1.8884_f64;
    /// assert!((cosh - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn cosh_ref(&self) -> CoshIncomplete<'_> {
        CoshIncomplete { ref_self: self }
    }

    /// Computes the hyperbolic tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let tanh = f.tanh();
    /// let expected = 0.8483_f64;
    /// assert!((tanh - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn tanh(mut self) -> Self {
        self.tanh_round(Round::Nearest);
        self
    }

    /// Computes the hyperbolic tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.tanh_mut();
    /// let expected = 0.8483_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn tanh_mut(&mut self) {
        self.tanh_round(Round::Nearest);
    }

    /// Computes the hyperbolic tangent, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // tanh(1.25) = 0.8483
    /// // using 4 significant bits: 0.875
    /// let dir = f.tanh_round(Round::Nearest);
    /// assert_eq!(f, 0.875);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn tanh_round(&mut self, round: Round) -> Ordering {
        xmpfr::tanh(self, (), round)
    }

    /// Computes the hyperbolic tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let tanh = Float::with_val(53, f.tanh_ref());
    /// let expected = 0.8483_f64;
    /// assert!((tanh - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn tanh_ref(&self) -> TanhIncomplete<'_> {
        TanhIncomplete { ref_self: self }
    }

    /// Computes the hyperbolic sine and cosine of `self`,
    /// rounding to the nearest.
    ///
    /// The sine is stored in `self` and keeps its precision,
    /// while the cosine is stored in `cos` keeping its precision.
    ///
    /// The initial value of `cos` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let (sinh, cosh) = f.sinh_cosh(Float::new(53));
    /// let expected_sinh = 1.6019_f64;
    /// let expected_cosh = 1.8884_f64;
    /// assert!((sinh - expected_sinh).abs() < 0.0001);
    /// assert!((cosh - expected_cosh).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sinh_cosh(mut self, mut cos: Self) -> (Self, Self) {
        self.sinh_cosh_round(&mut cos, Round::Nearest);
        (self, cos)
    }

    /// Computes the hyperbolic sine and cosine of `self`,
    /// rounding to the nearest.
    ///
    /// The sine is stored in `self` and keeps its precision,
    /// while the cosine is stored in `cos` keeping its precision.
    ///
    /// The initial value of `cos` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut sinh = Float::with_val(53, 1.25);
    /// let mut cosh = Float::new(53);
    /// sinh.sinh_cosh_mut(&mut cosh);
    /// let expected_sinh = 1.6019_f64;
    /// let expected_cosh = 1.8884_f64;
    /// assert!((sinh - expected_sinh).abs() < 0.0001);
    /// assert!((cosh - expected_cosh).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sinh_cosh_mut(&mut self, cos: &mut Self) {
        self.sinh_cosh_round(cos, Round::Nearest);
    }

    /// Computes the hyperbolic sine and cosine of `self`,
    /// applying the specified rounding method.
    ///
    /// The sine is stored in `self` and keeps its precision,
    /// while the cosine is stored in `cos` keeping its precision.
    ///
    /// The initial value of `cos` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut sinh = Float::with_val(4, 1.25);
    /// let mut cosh = Float::new(4);
    /// // sinh(1.25) = 1.6019, using 4 significant bits: 1.625
    /// // cosh(1.25) = 1.8884, using 4 significant bits: 1.875
    /// let (dir_sinh, dir_cosh) =
    ///     sinh.sinh_cosh_round(&mut cosh, Round::Nearest);
    /// assert_eq!(sinh, 1.625);
    /// assert_eq!(dir_sinh, Ordering::Greater);
    /// assert_eq!(cosh, 1.875);
    /// assert_eq!(dir_cosh, Ordering::Less);
    /// ```
    #[inline]
    pub fn sinh_cosh_round(&mut self, cos: &mut Self, round: Round) -> (Ordering, Ordering) {
        xmpfr::sinh_cosh(self, cos, (), round)
    }

    /// Computes the hyperbolic sine and cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Float][`Float`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Float][`Float`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Float][`Float`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Float][`Float`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::AssignRound, Assign, Float};
    /// let phase = Float::with_val(53, 1.25);
    ///
    /// let (mut sinh, mut cosh) = (Float::new(53), Float::new(53));
    /// let sinh_cosh = phase.sinh_cosh_ref();
    /// (&mut sinh, &mut cosh).assign(sinh_cosh);
    /// let expected_sinh = 1.6019_f64;
    /// let expected_cosh = 1.8884_f64;
    /// assert!((sinh - expected_sinh).abs() < 0.0001);
    /// assert!((cosh - expected_cosh).abs() < 0.0001);
    ///
    /// // using 4 significant bits: sin = 1.625
    /// // using 4 significant bits: cos = 1.875
    /// let (mut sinh_4, mut cosh_4) = (Float::new(4), Float::new(4));
    /// let sinh_cosh = phase.sinh_cosh_ref();
    /// let (dir_sinh, dir_cosh) = (&mut sinh_4, &mut cosh_4)
    ///     .assign_round(sinh_cosh, Round::Nearest);
    /// assert_eq!(sinh_4, 1.625);
    /// assert_eq!(dir_sinh, Ordering::Greater);
    /// assert_eq!(cosh_4, 1.875);
    /// assert_eq!(dir_cosh, Ordering::Less);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn sinh_cosh_ref(&self) -> SinhCoshIncomplete<'_> {
        SinhCoshIncomplete { ref_self: self }
    }

    /// Computes the hyperbolic secant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sech = f.sech();
    /// let expected = 0.5295_f64;
    /// assert!((sech - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sech(mut self) -> Self {
        self.sech_round(Round::Nearest);
        self
    }

    /// Computes the hyperbolic secant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.sech_mut();
    /// let expected = 0.5295_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn sech_mut(&mut self) {
        self.sech_round(Round::Nearest);
    }

    /// Computes the hyperbolic secant, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // sech(1.25) = 0.5295
    /// // using 4 significant bits: 0.5
    /// let dir = f.sech_round(Round::Nearest);
    /// assert_eq!(f, 0.5);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn sech_round(&mut self, round: Round) -> Ordering {
        xmpfr::sech(self, (), round)
    }

    /// Computes the hyperbolic secant.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let sech = Float::with_val(53, f.sech_ref());
    /// let expected = 0.5295_f64;
    /// assert!((sech - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sech_ref(&self) -> SechIncomplete<'_> {
        SechIncomplete { ref_self: self }
    }

    /// Computes the hyperbolic cosecant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let csch = f.csch();
    /// let expected = 0.6243_f64;
    /// assert!((csch - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn csch(mut self) -> Self {
        self.csch_round(Round::Nearest);
        self
    }

    /// Computes the hyperbolic cosecant, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.csch_mut();
    /// let expected = 0.6243_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn csch_mut(&mut self) {
        self.csch_round(Round::Nearest);
    }

    /// Computes the hyperbolic cosecant, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // csch(1.25) = 0.6243
    /// // using 4 significant bits: 0.625
    /// let dir = f.csch_round(Round::Nearest);
    /// assert_eq!(f, 0.625);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn csch_round(&mut self, round: Round) -> Ordering {
        xmpfr::csch(self, (), round)
    }

    /// Computes the hyperbolic cosecant.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let csch = Float::with_val(53, f.csch_ref());
    /// let expected = 0.6243_f64;
    /// assert!((csch - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn csch_ref(&self) -> CschIncomplete<'_> {
        CschIncomplete { ref_self: self }
    }

    /// Computes the hyperbolic cotangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let coth = f.coth();
    /// let expected = 1.1789_f64;
    /// assert!((coth - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn coth(mut self) -> Self {
        self.coth_round(Round::Nearest);
        self
    }

    /// Computes the hyperbolic cotangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.coth_mut();
    /// let expected = 1.1789_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn coth_mut(&mut self) {
        self.coth_round(Round::Nearest);
    }

    /// Computes the hyperbolic cotangent, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // coth(1.25) = 1.1789
    /// // using 4 significant bits: 1.125
    /// let dir = f.coth_round(Round::Nearest);
    /// assert_eq!(f, 1.125);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn coth_round(&mut self, round: Round) -> Ordering {
        xmpfr::coth(self, (), round)
    }

    /// Computes the hyperbolic cotangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let coth = Float::with_val(53, f.coth_ref());
    /// let expected = 1.1789_f64;
    /// assert!((coth - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn coth_ref(&self) -> CothIncomplete<'_> {
        CothIncomplete { ref_self: self }
    }

    /// Computes the inverse hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let asinh = f.asinh();
    /// let expected = 1.0476_f64;
    /// assert!((asinh - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn asinh(mut self) -> Self {
        self.asinh_round(Round::Nearest);
        self
    }

    /// Computes the inverse hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.asinh_mut();
    /// let expected = 1.0476_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn asinh_mut(&mut self) {
        self.asinh_round(Round::Nearest);
    }

    /// Computes the inverse hyperbolic sine, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // asinh(1.25) = 1.0476
    /// // using 4 significant bits: 1.0
    /// let dir = f.asinh_round(Round::Nearest);
    /// assert_eq!(f, 1.0);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn asinh_round(&mut self, round: Round) -> Ordering {
        xmpfr::asinh(self, (), round)
    }

    /// Computes the inverse hyperbolic sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let asinh = Float::with_val(53, f.asinh_ref());
    /// let expected = 1.0476_f64;
    /// assert!((asinh - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn asinh_ref(&self) -> AsinhIncomplete<'_> {
        AsinhIncomplete { ref_self: self }
    }

    /// Computes the inverse hyperbolic cosine, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let acosh = f.acosh();
    /// let expected = 0.6931_f64;
    /// assert!((acosh - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn acosh(mut self) -> Self {
        self.acosh_round(Round::Nearest);
        self
    }

    /// Computes the inverse hyperbolic cosine, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.acosh_mut();
    /// let expected = 0.6931_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn acosh_mut(&mut self) {
        self.acosh_round(Round::Nearest);
    }

    /// Computes the inverse hyperbolic cosine, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // acosh(1.25) = 0.6931
    /// // using 4 significant bits: 0.6875
    /// let dir = f.acosh_round(Round::Nearest);
    /// assert_eq!(f, 0.6875);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn acosh_round(&mut self, round: Round) -> Ordering {
        xmpfr::acosh(self, (), round)
    }

    /// Computes the inverse hyperbolic cosine
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let acosh = Float::with_val(53, f.acosh_ref());
    /// let expected = 0.6931_f64;
    /// assert!((acosh - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn acosh_ref(&self) -> AcoshIncomplete<'_> {
        AcoshIncomplete { ref_self: self }
    }

    /// Computes the inverse hyperbolic tangent, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 0.75);
    /// let atanh = f.atanh();
    /// let expected = 0.9730_f64;
    /// assert!((atanh - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn atanh(mut self) -> Self {
        self.atanh_round(Round::Nearest);
        self
    }

    /// Computes the inverse hyperbolic tangent, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 0.75);
    /// f.atanh_mut();
    /// let expected = 0.9730_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn atanh_mut(&mut self) {
        self.atanh_round(Round::Nearest);
    }

    /// Computes the inverse hyperbolic tangent, applying the
    /// specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 0.75);
    /// // atanh(0.75) = 0.9730
    /// // using 4 significant bits: 1.0
    /// let dir = f.atanh_round(Round::Nearest);
    /// assert_eq!(f, 1.0);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn atanh_round(&mut self, round: Round) -> Ordering {
        xmpfr::atanh(self, (), round)
    }

    /// Computes the inverse hyperbolic tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 0.75);
    /// let atanh = Float::with_val(53, f.atanh_ref());
    /// let expected = 0.9730_f64;
    /// assert!((atanh - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn atanh_ref(&self) -> AtanhIncomplete<'_> {
        AtanhIncomplete { ref_self: self }
    }

    /// Computes the factorial of <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// // 10 × 9 × 8 × 7 × 6 × 5 × 4 × 3 × 2 × 1
    /// let n = Float::factorial(10);
    /// let f = Float::with_val(53, n);
    /// assert_eq!(f, 3628800.0);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn factorial(n: u32) -> FactorialIncomplete {
        FactorialIncomplete { n }
    }

    /// Computes the natural logarithm of one plus `self`, rounding to
    /// the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let two_to_m10 = (-10f64).exp2();
    /// let f = Float::with_val(53, 1.5 * two_to_m10);
    /// let ln_1p = f.ln_1p();
    /// let expected = 1.4989_f64 * two_to_m10;
    /// assert!((ln_1p - expected).abs() < 0.0001 * two_to_m10);
    /// ```
    #[inline]
    pub fn ln_1p(mut self) -> Self {
        self.ln_1p_round(Round::Nearest);
        self
    }

    /// Computes the natural logarithm of one plus `self`, rounding to
    /// the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let two_to_m10 = (-10f64).exp2();
    /// let mut f = Float::with_val(53, 1.5 * two_to_m10);
    /// f.ln_1p_mut();
    /// let expected = 1.4989_f64 * two_to_m10;
    /// assert!((f - expected).abs() < 0.0001 * two_to_m10);
    /// ```
    #[inline]
    pub fn ln_1p_mut(&mut self) {
        self.ln_1p_round(Round::Nearest);
    }

    /// Computes the natural logarithm of one plus `self`, applying
    /// the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let two_to_m10 = (-10f64).exp2();
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5 * two_to_m10);
    /// // ln_1p(1.5 × 2 ^ −10) = 1.4989 × 2 ^ −10
    /// // using 4 significant bits: 1.5 × 2 ^ −10
    /// let dir = f.ln_1p_round(Round::Nearest);
    /// assert_eq!(f, 1.5 * two_to_m10);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn ln_1p_round(&mut self, round: Round) -> Ordering {
        xmpfr::log1p(self, (), round)
    }

    /// Computes the natural logorithm of one plus the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let two_to_m10 = (-10f64).exp2();
    /// let f = Float::with_val(53, 1.5 * two_to_m10);
    /// let ln_1p = Float::with_val(53, f.ln_1p_ref());
    /// let expected = 1.4989_f64 * two_to_m10;
    /// assert!((ln_1p - expected).abs() < 0.0001 * two_to_m10);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ln_1p_ref(&self) -> Ln1pIncomplete<'_> {
        Ln1pIncomplete { ref_self: self }
    }

    /// Subtracts one from the exponential of `self`, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let two_to_m10 = (-10f64).exp2();
    /// let f = Float::with_val(53, 1.5 * two_to_m10);
    /// let exp_m1 = f.exp_m1();
    /// let expected = 1.5011_f64 * two_to_m10;
    /// assert!((exp_m1 - expected).abs() < 0.0001 * two_to_m10);
    /// ```
    #[inline]
    pub fn exp_m1(mut self) -> Self {
        self.exp_m1_round(Round::Nearest);
        self
    }

    /// Subtracts one from the exponential of `self`, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let two_to_m10 = (-10f64).exp2();
    /// let mut f = Float::with_val(53, 1.5 * two_to_m10);
    /// f.exp_m1_mut();
    /// let expected = 1.5011_f64 * two_to_m10;
    /// assert!((f - expected).abs() < 0.0001 * two_to_m10);
    /// ```
    #[inline]
    pub fn exp_m1_mut(&mut self) {
        self.exp_m1_round(Round::Nearest);
    }

    /// Subtracts one from the exponential of `self`, applying the
    /// specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// let two_to_m10 = (-10f64).exp2();
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.5 * two_to_m10);
    /// // exp_m1(1.5 × 2 ^ −10) = 1.5011 × 2 ^ −10
    /// // using 4 significant bits: 1.5 × 2 ^ −10
    /// let dir = f.exp_m1_round(Round::Nearest);
    /// assert_eq!(f, 1.5 * two_to_m10);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn exp_m1_round(&mut self, round: Round) -> Ordering {
        xmpfr::expm1(self, (), round)
    }

    /// Computes one less than the exponential of the
    /// value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let two_to_m10 = (-10f64).exp2();
    /// let f = Float::with_val(53, 1.5 * two_to_m10);
    /// let exp_m1 = Float::with_val(53, f.exp_m1_ref());
    /// let expected = 1.5011_f64 * two_to_m10;
    /// assert!((exp_m1 - expected).abs() < 0.0001 * two_to_m10);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn exp_m1_ref(&self) -> ExpM1Incomplete<'_> {
        ExpM1Incomplete { ref_self: self }
    }

    /// Computes the exponential integral, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let eint = f.eint();
    /// let expected = 2.5810_f64;
    /// assert!((eint - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn eint(mut self) -> Self {
        self.eint_round(Round::Nearest);
        self
    }

    /// Computes the exponential integral, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.eint_mut();
    /// let expected = 2.5810_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn eint_mut(&mut self) {
        self.eint_round(Round::Nearest);
    }

    /// Computes the exponential integral, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // eint(1.25) = 2.5810
    /// // using 4 significant bits: 2.5
    /// let dir = f.eint_round(Round::Nearest);
    /// assert_eq!(f, 2.5);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn eint_round(&mut self, round: Round) -> Ordering {
        xmpfr::eint(self, (), round)
    }

    /// Computes the exponential integral.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let eint = Float::with_val(53, f.eint_ref());
    /// let expected = 2.5810_f64;
    /// assert!((eint - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn eint_ref(&self) -> EintIncomplete<'_> {
        EintIncomplete { ref_self: self }
    }

    /// Computes the real part of the dilogarithm of `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let li2 = f.li2();
    /// let expected = 2.1902_f64;
    /// assert!((li2 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn li2(mut self) -> Self {
        self.li2_round(Round::Nearest);
        self
    }

    /// Computes the real part of the dilogarithm of `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.li2_mut();
    /// let expected = 2.1902_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn li2_mut(&mut self) {
        self.li2_round(Round::Nearest);
    }

    /// Computes the real part of the dilogarithm of `self`, applying
    /// the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // li2(1.25) = 2.1902
    /// // using 4 significant bits: 2.25
    /// let dir = f.li2_round(Round::Nearest);
    /// assert_eq!(f, 2.25);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn li2_round(&mut self, round: Round) -> Ordering {
        xmpfr::li2(self, (), round)
    }

    /// Computes the real part of the dilogarithm of the
    /// value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let li2 = Float::with_val(53, f.li2_ref());
    /// let expected = 2.1902_f64;
    /// assert!((li2 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn li2_ref(&self) -> Li2Incomplete<'_> {
        Li2Incomplete { ref_self: self }
    }

    /// Computes the value of the gamma function on `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let gamma = f.gamma();
    /// let expected = 0.9064_f64;
    /// assert!((gamma - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn gamma(mut self) -> Self {
        self.gamma_round(Round::Nearest);
        self
    }

    /// Computes the value of the gamma function on `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.gamma_mut();
    /// let expected = 0.9064_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn gamma_mut(&mut self) {
        self.gamma_round(Round::Nearest);
    }

    /// Computes the value of the gamma function on `self`, applying
    /// the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // gamma(1.25) = 0.9064
    /// // using 4 significant bits: 0.9375
    /// let dir = f.gamma_round(Round::Nearest);
    /// assert_eq!(f, 0.9375);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn gamma_round(&mut self, round: Round) -> Ordering {
        xmpfr::gamma(self, (), round)
    }

    /// Computes the gamma function on the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let gamma = Float::with_val(53, f.gamma_ref());
    /// let expected = 0.9064_f64;
    /// assert!((gamma - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn gamma_ref(&self) -> GammaIncomplete<'_> {
        GammaIncomplete { ref_self: self }
    }

    /// Computes the value of the upper incomplete gamma function
    /// on `self` and `x`, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let x = Float::with_val(53, 2.5);
    /// let gamma_inc = f.gamma_inc(&x);
    /// let expected = 0.1116_f64;
    /// assert!((gamma_inc - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn gamma_inc(mut self, x: &Self) -> Self {
        self.gamma_inc_round(x, Round::Nearest);
        self
    }

    /// Computes the value of the upper incomplete gamma function
    /// on `self`, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// let x = Float::with_val(53, 2.5);
    /// f.gamma_inc_mut(&x);
    /// let expected = 0.1116_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn gamma_inc_mut(&mut self, x: &Self) {
        self.gamma_inc_round(x, Round::Nearest);
    }

    /// Computes the value of the upper incomplete gamma function
    /// on `self`, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// let x = Float::with_val(53, 2.5);
    /// // gamma_inc(1.25, 2.5) = 0.1116
    /// // using 4 significant bits: 0.109375
    /// let dir = f.gamma_inc_round(&x, Round::Nearest);
    /// assert_eq!(f, 0.109375);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn gamma_inc_round(&mut self, x: &Self, round: Round) -> Ordering {
        xmpfr::gamma_inc(self, (), x, round)
    }

    /// Computes the upper incomplete gamma function on the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let x = Float::with_val(53, 2.5);
    /// let gamma_inc = Float::with_val(53, f.gamma_inc_ref(&x));
    /// let expected = 0.1116_f64;
    /// assert!((gamma_inc - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn gamma_inc_ref<'a>(&'a self, x: &'a Self) -> GammaIncIncomplete<'_> {
        GammaIncIncomplete { ref_self: self, x }
    }

    /// Computes the logarithm of the gamma function on `self`,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let ln_gamma = f.ln_gamma();
    /// let expected = -0.0983_f64;
    /// assert!((ln_gamma - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn ln_gamma(mut self) -> Self {
        self.ln_gamma_round(Round::Nearest);
        self
    }

    /// Computes the logarithm of the gamma function on `self`,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.ln_gamma_mut();
    /// let expected = -0.0983_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn ln_gamma_mut(&mut self) {
        self.ln_gamma_round(Round::Nearest);
    }

    /// Computes the logarithm of the gamma function on `self`,
    /// applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // ln_gamma(1.25) = −0.0983
    /// // using 4 significant bits: −0.1015625
    /// let dir = f.ln_gamma_round(Round::Nearest);
    /// assert_eq!(f, -0.1015625);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn ln_gamma_round(&mut self, round: Round) -> Ordering {
        xmpfr::lngamma(self, (), round)
    }

    /// Computes the logarithm of the gamma function on
    /// the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let ln_gamma = Float::with_val(53, f.ln_gamma_ref());
    /// let expected = -0.0983_f64;
    /// assert!((ln_gamma - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ln_gamma_ref(&self) -> LnGammaIncomplete<'_> {
        LnGammaIncomplete { ref_self: self }
    }

    /// Computes the logarithm of the absolute value of the gamma
    /// function on `self`, rounding to the nearest.
    ///
    /// Returns <code>[Ordering][`Ordering`]::[Less][`Less`]</code> if
    /// the gamma function is negative, or
    /// <code>[Ordering][`Ordering`]::[Greater][`Greater`]</code> if
    /// the gamma function is positive.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Constant, Float};
    ///
    /// // gamma of 1/2 is √π
    /// let ln_gamma_64 = Float::with_val(64, Constant::Pi).sqrt().ln();
    ///
    /// let f = Float::with_val(53, 0.5);
    /// let (ln_gamma, sign) = f.ln_abs_gamma();
    /// // gamma of 1/2 is positive
    /// assert_eq!(sign, Ordering::Greater);
    /// // check to 53 significant bits
    /// assert_eq!(ln_gamma, Float::with_val(53, &ln_gamma_64));
    /// ```
    ///
    /// If the gamma function is negative, the sign returned is
    /// <code>[Ordering][`Ordering`]::[Less][`Less`]</code>.
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Constant, Float};
    ///
    /// // gamma of −1/2 is −2√π
    /// let abs_gamma_64 = Float::with_val(64, Constant::Pi).sqrt() * 2u32;
    /// let ln_gamma_64 = abs_gamma_64.ln();
    ///
    /// let f = Float::with_val(53, -0.5);
    /// let (ln_gamma, sign) = f.ln_abs_gamma();
    /// // gamma of −1/2 is negative
    /// assert_eq!(sign, Ordering::Less);
    /// // check to 53 significant bits
    /// assert_eq!(ln_gamma, Float::with_val(53, &ln_gamma_64));
    /// ```
    ///
    /// [`Greater`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Greater
    /// [`Less`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Less
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    #[inline]
    pub fn ln_abs_gamma(mut self) -> (Self, Ordering) {
        let sign = self.ln_abs_gamma_round(Round::Nearest).0;
        (self, sign)
    }

    /// Computes the logarithm of the absolute value of the gamma
    /// function on `self`, rounding to the nearest.
    ///
    /// Returns <code>[Ordering][`Ordering`]::[Less][`Less`]</code> if
    /// the gamma function is negative, or
    /// <code>[Ordering][`Ordering`]::[Greater][`Greater`]</code> if
    /// the gamma function is positive.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Constant, Float};
    ///
    /// // gamma of −1/2 is −2√π
    /// let abs_gamma_64 = Float::with_val(64, Constant::Pi).sqrt() * 2u32;
    /// let ln_gamma_64 = abs_gamma_64.ln();
    ///
    /// let mut f = Float::with_val(53, -0.5);
    /// let sign = f.ln_abs_gamma_mut();
    /// // gamma of −1/2 is negative
    /// assert_eq!(sign, Ordering::Less);
    /// // check to 53 significant bits
    /// assert_eq!(f, Float::with_val(53, &ln_gamma_64));
    /// ```
    ///
    /// [`Greater`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Greater
    /// [`Less`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Less
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    #[inline]
    pub fn ln_abs_gamma_mut(&mut self) -> Ordering {
        self.ln_abs_gamma_round(Round::Nearest).0
    }

    /// Computes the logarithm of the absolute value of the gamma
    /// function on `self`, applying the specified rounding method.
    ///
    /// The returned tuple contains:
    ///
    ///  1. The logarithm of the absolute value of the gamma function.
    ///  2. The rounding direction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{
    ///     float::{Constant, Round},
    ///     Float,
    /// };
    ///
    /// // gamma of −1/2 is −2√π
    /// let abs_gamma_64 = Float::with_val(64, Constant::Pi).sqrt() * 2u32;
    /// let ln_gamma_64 = abs_gamma_64.ln();
    ///
    /// let mut f = Float::with_val(53, -0.5);
    /// let (sign, dir) = f.ln_abs_gamma_round(Round::Nearest);
    /// // gamma of −1/2 is negative
    /// assert_eq!(sign, Ordering::Less);
    /// // check is correct to 53 significant bits
    /// let (check, check_dir) =
    ///     Float::with_val_round(53, &ln_gamma_64, Round::Nearest);
    /// assert_eq!(f, check);
    /// assert_eq!(dir, check_dir);
    /// ```
    #[inline]
    pub fn ln_abs_gamma_round(&mut self, round: Round) -> (Ordering, Ordering) {
        xmpfr::lgamma(self, (), round)
    }

    /// Computes the logarithm of the absolute value of the gamma
    /// function on `val`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Ordering][`Ordering`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Ordering][`Ordering`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Ordering][`Ordering`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Ordering][`Ordering`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Constant, Assign, Float};
    ///
    /// let neg1_2 = Float::with_val(53, -0.5);
    /// // gamma of −1/2 is −2√π
    /// let abs_gamma_64 = Float::with_val(64, Constant::Pi).sqrt() * 2u32;
    /// let ln_gamma_64 = abs_gamma_64.ln();
    ///
    /// // Assign rounds to the nearest
    /// let r = neg1_2.ln_abs_gamma_ref();
    /// let (mut f, mut sign) = (Float::new(53), Ordering::Equal);
    /// (&mut f, &mut sign).assign(r);
    /// // gamma of −1/2 is negative
    /// assert_eq!(sign, Ordering::Less);
    /// // check to 53 significant bits
    /// assert_eq!(f, Float::with_val(53, &ln_gamma_64));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn ln_abs_gamma_ref(&self) -> LnAbsGammaIncomplete<'_> {
        LnAbsGammaIncomplete { ref_self: self }
    }

    /// Computes the value of the Digamma function on `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let digamma = f.digamma();
    /// let expected = -0.2275_f64;
    /// assert!((digamma - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn digamma(mut self) -> Self {
        self.digamma_round(Round::Nearest);
        self
    }

    /// Computes the value of the Digamma function on `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.digamma_mut();
    /// let expected = -0.2275_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn digamma_mut(&mut self) {
        self.digamma_round(Round::Nearest);
    }

    /// Computes the value of the Digamma function on `self`, applying
    /// the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // digamma(1.25) = −0.2275
    /// // using 4 significant bits: −0.234375
    /// let dir = f.digamma_round(Round::Nearest);
    /// assert_eq!(f, -0.234375);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn digamma_round(&mut self, round: Round) -> Ordering {
        xmpfr::digamma(self, (), round)
    }

    /// Computes the Digamma function on the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let digamma = Float::with_val(53, f.digamma_ref());
    /// let expected = -0.2275_f64;
    /// assert!((digamma - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn digamma_ref(&self) -> DigammaIncomplete<'_> {
        DigammaIncomplete { ref_self: self }
    }

    /// Computes the value of the Riemann Zeta function on `self`,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let zeta = f.zeta();
    /// let expected = 4.5951_f64;
    /// assert!((zeta - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn zeta(mut self) -> Self {
        self.zeta_round(Round::Nearest);
        self
    }

    /// Computes the value of the Riemann Zeta function on `self`,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.zeta_mut();
    /// let expected = 4.5951_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn zeta_mut(&mut self) {
        self.zeta_round(Round::Nearest);
    }

    /// Computes the value of the Riemann Zeta function on `self`,
    /// applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // zeta(1.25) = 4.5951
    /// // using 4 significant bits: 4.5
    /// let dir = f.zeta_round(Round::Nearest);
    /// assert_eq!(f, 4.5);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn zeta_round(&mut self, round: Round) -> Ordering {
        xmpfr::zeta(self, (), round)
    }

    /// Computes the Riemann Zeta function on the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let zeta = Float::with_val(53, f.zeta_ref());
    /// let expected = 4.5951_f64;
    /// assert!((zeta - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn zeta_ref(&self) -> ZetaIncomplete<'_> {
        ZetaIncomplete { ref_self: self }
    }

    /// Computes the Riemann Zeta function on <i>u</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let z = Float::zeta_u(3);
    /// let f = Float::with_val(53, z);
    /// let expected = 1.2021_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn zeta_u(u: u32) -> ZetaUIncomplete {
        ZetaUIncomplete { u }
    }

    /// Computes the value of the error function, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let erf = f.erf();
    /// let expected = 0.9229_f64;
    /// assert!((erf - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn erf(mut self) -> Self {
        self.erf_round(Round::Nearest);
        self
    }

    /// Computes the value of the error function, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.erf_mut();
    /// let expected = 0.9229_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn erf_mut(&mut self) {
        self.erf_round(Round::Nearest);
    }

    /// Computes the value of the error function, applying the
    /// specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // erf(1.25) = 0.9229
    /// // using 4 significant bits: 0.9375
    /// let dir = f.erf_round(Round::Nearest);
    /// assert_eq!(f, 0.9375);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn erf_round(&mut self, round: Round) -> Ordering {
        xmpfr::erf(self, (), round)
    }

    /// Computes the error function.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let erf = Float::with_val(53, f.erf_ref());
    /// let expected = 0.9229_f64;
    /// assert!((erf - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn erf_ref(&self) -> ErfIncomplete<'_> {
        ErfIncomplete { ref_self: self }
    }

    /// Computes the value of the complementary error function,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let erfc = f.erfc();
    /// let expected = 0.0771_f64;
    /// assert!((erfc - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn erfc(mut self) -> Self {
        self.erfc_round(Round::Nearest);
        self
    }

    /// Computes the value of the complementary error function,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.erfc_mut();
    /// let expected = 0.0771_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn erfc_mut(&mut self) {
        self.erfc_round(Round::Nearest);
    }

    /// Computes the value of the complementary error function,
    /// applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // erfc(1.25) = 0.0771
    /// // using 4 significant bits: 0.078125
    /// let dir = f.erfc_round(Round::Nearest);
    /// assert_eq!(f, 0.078125);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn erfc_round(&mut self, round: Round) -> Ordering {
        xmpfr::erfc(self, (), round)
    }

    /// Computes the complementary error function.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let erfc = Float::with_val(53, f.erfc_ref());
    /// let expected = 0.0771_f64;
    /// assert!((erfc - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn erfc_ref(&self) -> ErfcIncomplete<'_> {
        ErfcIncomplete { ref_self: self }
    }

    /// Computes the value of the first kind Bessel function of
    /// order 0, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let j0 = f.j0();
    /// let expected = 0.6459_f64;
    /// assert!((j0 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn j0(mut self) -> Self {
        self.j0_round(Round::Nearest);
        self
    }

    /// Computes the value of the first kind Bessel function of
    /// order 0, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.j0_mut();
    /// let expected = 0.6459_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn j0_mut(&mut self) {
        self.j0_round(Round::Nearest);
    }

    /// Computes the value of the first kind Bessel function of
    /// order 0, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // j0(1.25) = 0.6459
    /// // using 4 significant bits: 0.625
    /// let dir = f.j0_round(Round::Nearest);
    /// assert_eq!(f, 0.625);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn j0_round(&mut self, round: Round) -> Ordering {
        xmpfr::j0(self, (), round)
    }

    /// Computes the first kind Bessel function of order 0.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let j0 = Float::with_val(53, f.j0_ref());
    /// let expected = 0.6459_f64;
    /// assert!((j0 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn j0_ref(&self) -> J0Incomplete<'_> {
        J0Incomplete { ref_self: self }
    }

    /// Computes the value of the first kind Bessel function of
    /// order 1, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let j1 = f.j1();
    /// let expected = 0.5106_f64;
    /// assert!((j1 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn j1(mut self) -> Self {
        self.j1_round(Round::Nearest);
        self
    }

    /// Computes the value of the first kind Bessel function of
    /// order 1, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.j1_mut();
    /// let expected = 0.5106_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn j1_mut(&mut self) {
        self.j1_round(Round::Nearest);
    }

    /// Computes the value of the first kind Bessel function of
    /// order 1, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // j1(1.25) = 0.5106
    /// // using 4 significant bits: 0.5
    /// let dir = f.j1_round(Round::Nearest);
    /// assert_eq!(f, 0.5);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn j1_round(&mut self, round: Round) -> Ordering {
        xmpfr::j1(self, (), round)
    }

    /// Computes the first kind Bessel function of order 1.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let j1 = Float::with_val(53, f.j1_ref());
    /// let expected = 0.5106_f64;
    /// assert!((j1 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn j1_ref(&self) -> J1Incomplete<'_> {
        J1Incomplete { ref_self: self }
    }

    /// Computes the value of the first kind Bessel function of
    /// order <i>n</i>, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let j2 = f.jn(2);
    /// let expected = 0.1711_f64;
    /// assert!((j2 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn jn(mut self, n: i32) -> Self {
        self.jn_round(n, Round::Nearest);
        self
    }

    /// Computes the value of the first kind Bessel function of
    /// order <i>n</i>, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.jn_mut(2);
    /// let expected = 0.1711_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn jn_mut(&mut self, n: i32) {
        self.jn_round(n, Round::Nearest);
    }

    /// Computes the value of the first kind Bessel function of
    /// order <i>n</i>, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // j2(1.25) = 0.1711
    /// // using 4 significant bits: 0.171875
    /// let dir = f.jn_round(2, Round::Nearest);
    /// assert_eq!(f, 0.171875);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn jn_round(&mut self, n: i32, round: Round) -> Ordering {
        xmpfr::jn(self, (), n, round)
    }

    /// Computes the first kind Bessel function of order <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let j2 = Float::with_val(53, f.jn_ref(2));
    /// let expected = 0.1711_f64;
    /// assert!((j2 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn jn_ref(&self, n: i32) -> JnIncomplete<'_> {
        JnIncomplete { ref_self: self, n }
    }

    /// Computes the value of the second kind Bessel function of
    /// order 0, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let y0 = f.y0();
    /// let expected = 0.2582_f64;
    /// assert!((y0 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn y0(mut self) -> Self {
        self.y0_round(Round::Nearest);
        self
    }

    /// Computes the value of the second kind Bessel function of
    /// order 0, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.y0_mut();
    /// let expected = 0.2582_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn y0_mut(&mut self) {
        self.y0_round(Round::Nearest);
    }

    /// Computes the value of the second kind Bessel function of
    /// order 0, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // y0(1.25) = 0.2582
    /// // using 4 significant bits: 0.25
    /// let dir = f.y0_round(Round::Nearest);
    /// assert_eq!(f, 0.25);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn y0_round(&mut self, round: Round) -> Ordering {
        xmpfr::y0(self, (), round)
    }

    /// Computes the second kind Bessel function of order 0.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let y0 = Float::with_val(53, f.y0_ref());
    /// let expected = 0.2582_f64;
    /// assert!((y0 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn y0_ref(&self) -> Y0Incomplete<'_> {
        Y0Incomplete { ref_self: self }
    }

    /// Computes the value of the second kind Bessel function of
    /// order 1, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let y1 = f.y1();
    /// let expected = -0.5844_f64;
    /// assert!((y1 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn y1(mut self) -> Self {
        self.y1_round(Round::Nearest);
        self
    }

    /// Computes the value of the second kind Bessel function of
    /// order 1, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.y1_mut();
    /// let expected = -0.5844_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn y1_mut(&mut self) {
        self.y1_round(Round::Nearest);
    }

    /// Computes the value of the second kind Bessel function of
    /// order 1, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // y1(1.25) = −0.5844
    /// // using 4 significant bits: −0.5625
    /// let dir = f.y1_round(Round::Nearest);
    /// assert_eq!(f, -0.5625);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn y1_round(&mut self, round: Round) -> Ordering {
        xmpfr::y1(self, (), round)
    }

    /// Computes the second kind Bessel function of order 1.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let y1 = Float::with_val(53, f.y1_ref());
    /// let expected = -0.5844_f64;
    /// assert!((y1 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn y1_ref(&self) -> Y1Incomplete<'_> {
        Y1Incomplete { ref_self: self }
    }

    /// Computes the value of the second kind Bessel function of
    /// order <i>n</i>, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let y2 = f.yn(2);
    /// let expected = -1.1932_f64;
    /// assert!((y2 - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn yn(mut self, n: i32) -> Self {
        self.yn_round(n, Round::Nearest);
        self
    }

    /// Computes the value of the second kind Bessel function of
    /// order <i>n</i>, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.yn_mut(2);
    /// let expected = -1.1932_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn yn_mut(&mut self, n: i32) {
        self.yn_round(n, Round::Nearest);
    }

    /// Computes the value of the second kind Bessel function of
    /// order <i>n</i>, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // y2(1.25) = −1.1932
    /// // using 4 significant bits: −1.25
    /// let dir = f.yn_round(2, Round::Nearest);
    /// assert_eq!(f, -1.25);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn yn_round(&mut self, n: i32, round: Round) -> Ordering {
        xmpfr::yn(self, (), n, round)
    }

    /// Computes the second kind Bessel function of order <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let y2 = Float::with_val(53, f.yn_ref(2));
    /// let expected = -1.1932_f64;
    /// assert!((y2 - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn yn_ref(&self, n: i32) -> YnIncomplete<'_> {
        YnIncomplete { ref_self: self, n }
    }

    /// Computes the arithmetic-geometric mean of `self` and `other`,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let g = Float::with_val(53, 3.75);
    /// let agm = f.agm(&g);
    /// let expected = 2.3295_f64;
    /// assert!((agm - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn agm(mut self, other: &Self) -> Self {
        self.agm_round(other, Round::Nearest);
        self
    }

    /// Computes the arithmetic-geometric mean of `self` and `other`,
    /// rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// let g = Float::with_val(53, 3.75);
    /// f.agm_mut(&g);
    /// let expected = 2.3295_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn agm_mut(&mut self, other: &Self) {
        self.agm_round(other, Round::Nearest);
    }

    /// Computes the arithmetic-geometric mean of `self` and `other`,
    /// applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// let g = Float::with_val(4, 3.75);
    /// // agm(1.25, 3.75) = 2.3295
    /// // using 4 significant bits: 2.25
    /// let dir = f.agm_round(&g, Round::Nearest);
    /// assert_eq!(f, 2.25);
    /// assert_eq!(dir, Ordering::Less);
    /// ```
    #[inline]
    pub fn agm_round(&mut self, other: &Self, round: Round) -> Ordering {
        xmpfr::agm(self, (), other, round)
    }

    /// Computes the arithmetic-geometric mean.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let g = Float::with_val(53, 3.75);
    /// let agm = Float::with_val(53, f.agm_ref(&g));
    /// let expected = 2.3295_f64;
    /// assert!((agm - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn agm_ref<'a>(&'a self, other: &'a Self) -> AgmIncomplete<'_> {
        AgmIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Computes the Euclidean norm of `self` and `other`, rounding to
    /// the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let g = Float::with_val(53, 3.75);
    /// let hypot = f.hypot(&g);
    /// let expected = 3.9528_f64;
    /// assert!((hypot - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn hypot(mut self, other: &Self) -> Self {
        self.hypot_round(other, Round::Nearest);
        self
    }

    /// Computes the Euclidean norm of `self` and `other`, rounding to
    /// the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// let g = Float::with_val(53, 3.75);
    /// f.hypot_mut(&g);
    /// let expected = 3.9528_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn hypot_mut(&mut self, other: &Self) {
        self.hypot_round(other, Round::Nearest);
    }

    /// Computes the Euclidean norm of `self` and `other`, applying
    /// the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// let g = Float::with_val(4, 3.75);
    /// // hypot(1.25) = 3.9528
    /// // using 4 significant bits: 4.0
    /// let dir = f.hypot_round(&g, Round::Nearest);
    /// assert_eq!(f, 4.0);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn hypot_round(&mut self, other: &Self, round: Round) -> Ordering {
        xmpfr::hypot(self, (), other, round)
    }

    /// Computes the Euclidean norm.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let g = Float::with_val(53, 3.75);
    /// let hypot = Float::with_val(53, f.hypot_ref(&g));
    /// let expected = 3.9528_f64;
    /// assert!((hypot - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn hypot_ref<'a>(&'a self, other: &'a Self) -> HypotIncomplete<'_> {
        HypotIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Computes the value of the Airy function Ai on `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let ai = f.ai();
    /// let expected = 0.0996_f64;
    /// assert!((ai - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn ai(mut self) -> Self {
        self.ai_round(Round::Nearest);
        self
    }

    /// Computes the value of the Airy function Ai on `self`, rounding
    /// to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f = Float::with_val(53, 1.25);
    /// f.ai_mut();
    /// let expected = 0.0996_f64;
    /// assert!((f - expected).abs() < 0.0001);
    /// ```
    #[inline]
    pub fn ai_mut(&mut self) {
        self.ai_round(Round::Nearest);
    }

    /// Computes the value of the Airy function Ai on `self`, applying
    /// the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut f = Float::with_val(4, 1.25);
    /// // ai(1.25) = 0.0996
    /// // using 4 significant bits: 0.1015625
    /// let dir = f.ai_round(Round::Nearest);
    /// assert_eq!(f, 0.1015625);
    /// assert_eq!(dir, Ordering::Greater);
    /// ```
    #[inline]
    pub fn ai_round(&mut self, round: Round) -> Ordering {
        xmpfr::ai(self, (), round)
    }

    /// Computes the Airy function Ai on the value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f = Float::with_val(53, 1.25);
    /// let ai = Float::with_val(53, f.ai_ref());
    /// let expected = 0.0996_f64;
    /// assert!((ai - expected).abs() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ai_ref(&self) -> AiIncomplete<'_> {
        AiIncomplete { ref_self: self }
    }

    /// Rounds up to the next higher integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let ceil1 = f1.ceil();
    /// assert_eq!(ceil1, -23);
    /// let f2 = Float::with_val(53, 23.75);
    /// let ceil2 = f2.ceil();
    /// assert_eq!(ceil2, 24);
    /// ```
    #[inline]
    pub fn ceil(mut self) -> Self {
        self.ceil_mut();
        self
    }

    /// Rounds up to the next higher integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f1 = Float::with_val(53, -23.75);
    /// f1.ceil_mut();
    /// assert_eq!(f1, -23);
    /// let mut f2 = Float::with_val(53, 23.75);
    /// f2.ceil_mut();
    /// assert_eq!(f2, 24);
    /// ```
    #[inline]
    pub fn ceil_mut(&mut self) {
        xmpfr::rint_ceil(self, (), Round::Nearest);
    }

    /// Rounds up to the next higher integer. The result may be
    /// rounded again when assigned to the target.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let ceil1 = Float::with_val(53, f1.ceil_ref());
    /// assert_eq!(ceil1, -23);
    /// let f2 = Float::with_val(53, 23.75);
    /// let ceil2 = Float::with_val(53, f2.ceil_ref());
    /// assert_eq!(ceil2, 24);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ceil_ref(&self) -> CeilIncomplete<'_> {
        CeilIncomplete { ref_self: self }
    }

    /// Rounds down to the next lower integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let floor1 = f1.floor();
    /// assert_eq!(floor1, -24);
    /// let f2 = Float::with_val(53, 23.75);
    /// let floor2 = f2.floor();
    /// assert_eq!(floor2, 23);
    /// ```
    #[inline]
    pub fn floor(mut self) -> Self {
        self.floor_mut();
        self
    }

    /// Rounds down to the next lower integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f1 = Float::with_val(53, -23.75);
    /// f1.floor_mut();
    /// assert_eq!(f1, -24);
    /// let mut f2 = Float::with_val(53, 23.75);
    /// f2.floor_mut();
    /// assert_eq!(f2, 23);
    /// ```
    #[inline]
    pub fn floor_mut(&mut self) {
        xmpfr::rint_floor(self, (), Round::Nearest);
    }

    /// Rounds down to the next lower integer. The result may be
    /// rounded again when assigned to the target.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let floor1 = Float::with_val(53, f1.floor_ref());
    /// assert_eq!(floor1, -24);
    /// let f2 = Float::with_val(53, 23.75);
    /// let floor2 = Float::with_val(53, f2.floor_ref());
    /// assert_eq!(floor2, 23);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn floor_ref(&self) -> FloorIncomplete<'_> {
        FloorIncomplete { ref_self: self }
    }

    /// Rounds to the nearest integer, rounding half-way cases
    /// away from zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let round1 = f1.round();
    /// assert_eq!(round1, -24);
    /// let f2 = Float::with_val(53, 23.75);
    /// let round2 = f2.round();
    /// assert_eq!(round2, 24);
    /// ```
    #[inline]
    pub fn round(mut self) -> Self {
        self.round_mut();
        self
    }

    /// Rounds to the nearest integer, rounding half-way cases
    /// away from zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f1 = Float::with_val(53, -23.75);
    /// f1.round_mut();
    /// assert_eq!(f1, -24);
    /// let mut f2 = Float::with_val(53, 23.75);
    /// f2.round_mut();
    /// assert_eq!(f2, 24);
    /// ```
    #[inline]
    pub fn round_mut(&mut self) {
        xmpfr::rint_round(self, (), Round::Nearest);
    }

    /// Rounds to the nearest integer, rounding half-way cases
    /// away from zero. The result may be rounded again when
    /// assigned to the target.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let round1 = Float::with_val(53, f1.round_ref());
    /// assert_eq!(round1, -24);
    /// let f2 = Float::with_val(53, 23.75);
    /// let round2 = Float::with_val(53, f2.round_ref());
    /// assert_eq!(round2, 24);
    /// ```
    ///
    /// Double rounding may happen when assigning to a target with
    /// a precision less than the number of significant bits for
    /// the truncated integer.
    ///
    /// ```rust
    /// use rug::{float::Round, Float};
    /// use rug::ops::AssignRound;
    /// let f = Float::with_val(53, 6.5);
    /// // 6.5 (binary 110.1) is rounded to 7 (binary 111)
    /// let r = f.round_ref();
    /// // use only 2 bits of precision in destination
    /// let mut dst = Float::new(2);
    /// // 7 (binary 111) is rounded to 8 (binary 1000) by
    /// // round-even rule in order to store in 2-bit Float, even
    /// // though 6 (binary 110) is closer to original 6.5).
    /// dst.assign_round(r, Round::Nearest);
    /// assert_eq!(dst, 8);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn round_ref(&self) -> RoundIncomplete<'_> {
        RoundIncomplete { ref_self: self }
    }

    /// Rounds to the nearest integer, rounding half-way cases to
    /// even.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, 23.5);
    /// let round1 = f1.round_even();
    /// assert_eq!(round1, 24);
    /// let f2 = Float::with_val(53, 24.5);
    /// let round2 = f2.round_even();
    /// assert_eq!(round2, 24);
    /// ```
    #[inline]
    pub fn round_even(mut self) -> Self {
        self.round_even_mut();
        self
    }

    /// Rounds to the nearest integer, rounding half-way cases to
    /// even.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f1 = Float::with_val(53, 23.5);
    /// f1.round_even_mut();
    /// assert_eq!(f1, 24);
    /// let mut f2 = Float::with_val(53, 24.5);
    /// f2.round_even_mut();
    /// assert_eq!(f2, 24);
    /// ```
    #[inline]
    pub fn round_even_mut(&mut self) {
        xmpfr::rint_roundeven(self, (), Round::Nearest);
    }

    /// Rounds to the nearest integer, rounding half-way cases to
    /// even. The result may be rounded again when assigned to the
    /// target.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, 23.5);
    /// let round1 = Float::with_val(53, f1.round_even_ref());
    /// assert_eq!(round1, 24);
    /// let f2 = Float::with_val(53, 24.5);
    /// let round2 = Float::with_val(53, f2.round_even_ref());
    /// assert_eq!(round2, 24);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn round_even_ref(&self) -> RoundEvenIncomplete<'_> {
        RoundEvenIncomplete { ref_self: self }
    }

    /// Rounds to the next integer towards zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let trunc1 = f1.trunc();
    /// assert_eq!(trunc1, -23);
    /// let f2 = Float::with_val(53, 23.75);
    /// let trunc2 = f2.trunc();
    /// assert_eq!(trunc2, 23);
    /// ```
    #[inline]
    pub fn trunc(mut self) -> Self {
        self.trunc_mut();
        self
    }

    /// Rounds to the next integer towards zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f1 = Float::with_val(53, -23.75);
    /// f1.trunc_mut();
    /// assert_eq!(f1, -23);
    /// let mut f2 = Float::with_val(53, 23.75);
    /// f2.trunc_mut();
    /// assert_eq!(f2, 23);
    /// ```
    #[inline]
    pub fn trunc_mut(&mut self) {
        xmpfr::rint_trunc(self, (), Round::Nearest);
    }

    /// Rounds to the next integer towards zero. The result may be
    /// rounded again when assigned to the target.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let trunc1 = Float::with_val(53, f1.trunc_ref());
    /// assert_eq!(trunc1, -23);
    /// let f2 = Float::with_val(53, 23.75);
    /// let trunc2 = Float::with_val(53, f2.trunc_ref());
    /// assert_eq!(trunc2, 23);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn trunc_ref(&self) -> TruncIncomplete<'_> {
        TruncIncomplete { ref_self: self }
    }

    /// Gets the fractional part of the number.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let fract1 = f1.fract();
    /// assert_eq!(fract1, -0.75);
    /// let f2 = Float::with_val(53, 23.75);
    /// let fract2 = f2.fract();
    /// assert_eq!(fract2, 0.75);
    /// ```
    #[inline]
    pub fn fract(mut self) -> Self {
        self.fract_mut();
        self
    }

    /// Gets the fractional part of the number.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f1 = Float::with_val(53, -23.75);
    /// f1.fract_mut();
    /// assert_eq!(f1, -0.75);
    /// let mut f2 = Float::with_val(53, 23.75);
    /// f2.fract_mut();
    /// assert_eq!(f2, 0.75);
    /// ```
    #[inline]
    pub fn fract_mut(&mut self) {
        xmpfr::frac(self, (), Round::Nearest);
    }

    /// Gets the fractional part of the number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let fract1 = Float::with_val(53, f1.fract_ref());
    /// assert_eq!(fract1, -0.75);
    /// let f2 = Float::with_val(53, 23.75);
    /// let fract2 = Float::with_val(53, f2.fract_ref());
    /// assert_eq!(fract2, 0.75);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn fract_ref(&self) -> FractIncomplete<'_> {
        FractIncomplete { ref_self: self }
    }

    /// Gets the integer and fractional parts of the number,
    /// rounding to the nearest.
    ///
    /// The integer part is stored in `self` and keeps its
    /// precision, while the fractional part is stored in `fract`
    /// keeping its precision.
    ///
    /// The initial value of `fract` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let f1 = Float::with_val(53, -23.75);
    /// let (trunc1, fract1) = f1.trunc_fract(Float::new(53));
    /// assert_eq!(trunc1, -23);
    /// assert_eq!(fract1, -0.75);
    /// let f2 = Float::with_val(53, 23.75);
    /// let (trunc2, fract2) = f2.trunc_fract(Float::new(53));
    /// assert_eq!(trunc2, 23);
    /// assert_eq!(fract2, 0.75);
    /// ```
    #[inline]
    pub fn trunc_fract(mut self, mut fract: Self) -> (Self, Self) {
        self.trunc_fract_round(&mut fract, Round::Nearest);
        (self, fract)
    }

    /// Gets the integer and fractional parts of the number,
    /// rounding to the nearest.
    ///
    /// The integer part is stored in `self` and keeps its
    /// precision, while the fractional part is stored in `fract`
    /// keeping its precision.
    ///
    /// The initial value of `fract` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Float;
    /// let mut f1 = Float::with_val(53, -23.75);
    /// let mut fract1 = Float::new(53);
    /// f1.trunc_fract_mut(&mut fract1);
    /// assert_eq!(f1, -23);
    /// assert_eq!(fract1, -0.75);
    /// let mut f2 = Float::with_val(53, 23.75);
    /// let mut fract2 = Float::new(53);
    /// f2.trunc_fract_mut(&mut fract2);
    /// assert_eq!(f2, 23);
    /// assert_eq!(fract2, 0.75);
    /// ```
    #[inline]
    pub fn trunc_fract_mut(&mut self, fract: &mut Self) {
        self.trunc_fract_round(fract, Round::Nearest);
    }

    /// Gets the integer and fractional parts of the number,
    /// applying the specified rounding method.
    ///
    /// The first element of the returned tuple of rounding
    /// directions is always
    /// <code>[Ordering][`Ordering`]::[Equal][`Equal`]</code>, as
    /// truncating a value in place will always be exact.
    ///
    /// The integer part is stored in `self` and keeps its
    /// precision, while the fractional part is stored in `fract`
    /// keeping its precision.
    ///
    /// The initial value of `fract` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Float};
    /// // 0.515625 in binary is 0.100001
    /// let mut f1 = Float::with_val(53, -23.515625);
    /// let mut fract1 = Float::new(4);
    /// let dir1 = f1.trunc_fract_round(&mut fract1, Round::Nearest);
    /// assert_eq!(f1, -23);
    /// assert_eq!(fract1, -0.5);
    /// assert_eq!(dir1, (Ordering::Equal, Ordering::Greater));
    /// let mut f2 = Float::with_val(53, 23.515625);
    /// let mut fract2 = Float::new(4);
    /// let dir2 = f2.trunc_fract_round(&mut fract2, Round::Nearest);
    /// assert_eq!(f2, 23);
    /// assert_eq!(fract2, 0.5);
    /// assert_eq!(dir2, (Ordering::Equal, Ordering::Less));
    /// ```
    ///
    /// [`Equal`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Equal
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    #[inline]
    pub fn trunc_fract_round(&mut self, fract: &mut Self, round: Round) -> (Ordering, Ordering) {
        xmpfr::modf(self, fract, (), round)
    }

    /// Gets the integer and fractional parts of the number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Float][`Float`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Float][`Float`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple][Float][`Float`],
    ///     [Float][`Float`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Float][`Float`],
    ///     &amp;mut [Float][`Float`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Float};
    /// let f1 = Float::with_val(53, -23.75);
    /// let r1 = f1.trunc_fract_ref();
    /// let (mut trunc1, mut fract1) = (Float::new(53), Float::new(53));
    /// (&mut trunc1, &mut fract1).assign(r1);
    /// assert_eq!(trunc1, -23);
    /// assert_eq!(fract1, -0.75);
    /// let f2 = Float::with_val(53, -23.75);
    /// let r2 = f2.trunc_fract_ref();
    /// let (mut trunc2, mut fract2) = (Float::new(53), Float::new(53));
    /// (&mut trunc2, &mut fract2).assign(r2);
    /// assert_eq!(trunc2, -23);
    /// assert_eq!(fract2, -0.75);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn trunc_fract_ref(&self) -> TruncFractIncomplete<'_> {
        TruncFractIncomplete { ref_self: self }
    }

    #[cfg(feature = "rand")]
    /// Generates a random number in the range 0 ≤ <i>x</i> < 1.
    ///
    /// This is equivalent to generating a random integer in the range
    /// 0 ≤ <i>x</i> < 2<sup><i>p</i></sup>, where
    /// 2<sup><i>p</i></sup> is two raised to the power of the
    /// precision, and then dividing the integer by
    /// 2<sup><i>p</i></sup>. The smallest non-zero result will thus
    /// be 2<sup>−<i>p</i></sup>, and will only have one bit set. In
    /// the smaller possible results, many bits will be zero, and not
    /// all the precision will be used.
    ///
    /// There is a corner case where the generated random number is
    /// converted to NaN: if the precision is very large, the
    /// generated random number could have an exponent less than the
    /// allowed minimum exponent, and NaN is used to indicate this.
    /// For this to occur in practice, the minimum exponent has to be
    /// set to have a very small magnitude using the low-level MPFR
    /// interface, or the random number generator has to be designed
    /// specifically to trigger this case.
    ///
    /// <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    /// is implemented with the returned
    /// [incomplete-computation value][icv] as `Src`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Assign, Float};
    /// let mut rand = RandState::new();
    /// let mut f = Float::new(2);
    /// f.assign(Float::random_bits(&mut rand));
    /// assert!(f == 0.0 || f == 0.25 || f == 0.5 || f == 0.75);
    /// println!("0.0 ≤ {} < 1.0", f);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`Float`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_bits(rng: &mut dyn MutRandState) -> RandomBitsIncomplete {
        RandomBitsIncomplete { rng }
    }

    #[cfg(feature = "rand")]
    /// Generates a random number in the continuous range 0 ≤ <i>x</i> < 1.
    ///
    /// The result can be rounded up to be equal to one. Unlike the
    /// [`random_bits`] method which generates a discrete random
    /// number at intervals depending on the precision, this method is
    /// equivalent to generating a continuous random number with
    /// infinite precision and then rounding the result. This means
    /// that even the smaller numbers will be using all the available
    /// precision bits, and rounding is performed in all cases, not in
    /// some corner case.
    ///
    /// Rounding directions for generated random numbers cannot be
    /// <code>[Ordering][`Ordering`]::[Equal][`Equal`]</code>, as the
    /// random numbers generated can be considered to have infinite
    /// precision before rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Float};
    /// let mut rand = RandState::new();
    /// let f = Float::with_val(2, Float::random_cont(&mut rand));
    /// // The significand is either 0b10 or 0b11
    /// assert!(
    ///     f == 1.0
    ///         || f == 0.75
    ///         || f == 0.5
    ///         || f == 0.375
    ///         || f == 0.25
    ///         || f <= 0.1875
    /// );
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Equal`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Equal
    /// [`Float`]: #
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    /// [`random_bits`]: #method.random_bits
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_cont(rng: &mut dyn MutRandState) -> RandomContIncomplete {
        RandomContIncomplete { rng }
    }

    #[cfg(feature = "rand")]
    /// Generates a random number according to a standard normal
    /// Gaussian distribution, rounding to the nearest.
    ///
    /// Rounding directions for generated random numbers cannot be
    /// <code>[Ordering][`Ordering`]::[Equal][`Equal`]</code>, as the
    /// random numbers generated can be considered to have infinite
    /// precision before rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Float};
    /// let mut rand = RandState::new();
    /// let f = Float::with_val(53, Float::random_normal(&mut rand));
    /// println!("Normal random number: {}", f);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Equal`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Equal
    /// [`Float`]: #
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_normal(rng: &mut dyn MutRandState) -> RandomNormalIncomplete {
        RandomNormalIncomplete { rng }
    }

    #[cfg(feature = "rand")]
    /// Generates a random number according to an exponential
    /// distribution with mean one, rounding to the nearest.
    ///
    /// Rounding directions for generated random numbers cannot be
    /// <code>[Ordering][`Ordering`]::[Equal][`Equal`]</code>, as the
    /// random numbers generated can be considered to have infinite
    /// precision before rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Float};
    /// let mut rand = RandState::new();
    /// let f = Float::with_val(53, Float::random_exp(&mut rand));
    /// println!("Exponential random number: {}", f);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Equal`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Equal
    /// [`Float`]: #
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_exp(rng: &mut dyn MutRandState) -> RandomExpIncomplete {
        RandomExpIncomplete { rng }
    }
}

#[derive(Debug)]
pub struct SumIncomplete<'a, I>
where
    I: Iterator<Item = &'a Float>,
{
    values: I,
}

impl<'a, I> AssignRound<SumIncomplete<'a, I>> for Float
where
    I: Iterator<Item = &'a Self>,
{
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: SumIncomplete<'a, I>, round: Round) -> Ordering {
        xmpfr::sum(self, src.values, round)
    }
}

impl<'a, I> Add<SumIncomplete<'a, I>> for Float
where
    I: Iterator<Item = &'a Self>,
{
    type Output = Self;
    #[inline]
    fn add(mut self, rhs: SumIncomplete<'a, I>) -> Self {
        self.add_assign_round(rhs, Round::Nearest);
        self
    }
}

impl<'a, I> AddAssign<SumIncomplete<'a, I>> for Float
where
    I: Iterator<Item = &'a Self>,
{
    #[inline]
    fn add_assign(&mut self, rhs: SumIncomplete<'a, I>) {
        self.add_assign_round(rhs, Round::Nearest);
    }
}

impl<'a, I> AddAssignRound<SumIncomplete<'a, I>> for Float
where
    I: Iterator<Item = &'a Self>,
{
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn add_assign_round(&mut self, src: SumIncomplete<'a, I>, round: Round) -> Ordering {
        xmpfr::sum_including_old(self, src.values, round)
    }
}

#[derive(Debug)]
pub struct DotIncomplete<'a, I>
where
    I: Iterator<Item = (&'a Float, &'a Float)>,
{
    values: I,
}

impl<'a, I> AssignRound<DotIncomplete<'a, I>> for Float
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: DotIncomplete<'a, I>, round: Round) -> Ordering {
        xmpfr::dot(self, src.values, round)
    }
}

impl<'a, I> Add<DotIncomplete<'a, I>> for Float
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    type Output = Self;
    #[inline]
    fn add(mut self, rhs: DotIncomplete<'a, I>) -> Self {
        self.add_assign_round(rhs, Round::Nearest);
        self
    }
}

impl<'a, I> AddAssign<DotIncomplete<'a, I>> for Float
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    #[inline]
    fn add_assign(&mut self, rhs: DotIncomplete<'a, I>) {
        self.add_assign_round(rhs, Round::Nearest);
    }
}

impl<'a, I> AddAssignRound<DotIncomplete<'a, I>> for Float
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn add_assign_round(&mut self, src: DotIncomplete<'a, I>, round: Round) -> Ordering {
        xmpfr::dot_including_old(self, src.values, round)
    }
}

ref_math_op2_float! { xmpfr::remainder; struct RemainderIncomplete { divisor } }
ref_math_op0_float! { xmpfr::ui_2exp; struct UExpIncomplete { u: u32, exp: i32 } }
ref_math_op0_float! { xmpfr::si_2exp; struct IExpIncomplete { i: i32, exp: i32 } }
ref_math_op0_float! { xmpfr::ui_pow_ui; struct UPowUIncomplete { base: u32, exponent: u32 } }
ref_math_op0_float! { xmpfr::si_pow_ui; struct IPowUIncomplete { base: i32, exponent: u32 } }
ref_math_op1_float! { xmpfr::sqr; struct SquareIncomplete {} }
ref_math_op1_float! { xmpfr::sqrt; struct SqrtIncomplete {} }
ref_math_op0_float! { xmpfr::sqrt_ui; struct SqrtUIncomplete { u: u32 } }
ref_math_op1_float! { xmpfr::rec_sqrt; struct RecipSqrtIncomplete {} }
ref_math_op1_float! { xmpfr::cbrt; struct CbrtIncomplete {} }
ref_math_op1_float! { xmpfr::rootn_ui; struct RootIncomplete { k: u32 } }
ref_math_op1_float! { xmpfr::abs; struct AbsIncomplete {} }
ref_math_op1_float! { xmpfr::signum; struct SignumIncomplete {} }
ref_math_op2_float! { xmpfr::copysign; struct CopysignIncomplete { y } }

#[derive(Debug)]
pub struct ClampIncomplete<'s, 'min, 'max, Min, Max>
where
    Float: PartialOrd<Min>
        + PartialOrd<Max>
        + for<'a> AssignRound<&'a Min, Round = Round, Ordering = Ordering>
        + for<'a> AssignRound<&'a Max, Round = Round, Ordering = Ordering>,
{
    ref_self: &'s Float,
    min: &'min Min,
    max: &'max Max,
}

impl<Min, Max> AssignRound<ClampIncomplete<'_, '_, '_, Min, Max>> for Float
where
    Self: PartialOrd<Min>
        + PartialOrd<Max>
        + for<'a> AssignRound<&'a Min, Round = Round, Ordering = Ordering>
        + for<'a> AssignRound<&'a Max, Round = Round, Ordering = Ordering>,
{
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: ClampIncomplete<Min, Max>, round: Round) -> Ordering {
        if src.ref_self.lt(src.min) {
            let dir = self.assign_round(src.min, round);
            if (*self).gt(src.max) {
                let dir2 = self.assign_round(src.max, round);
                assert!(
                    dir == dir2 && !(*self).lt(src.min),
                    "minimum larger than maximum"
                );
                dir
            } else {
                dir
            }
        } else if src.ref_self.gt(src.max) {
            let dir = self.assign_round(src.max, round);
            if (*self).lt(src.min) {
                let dir2 = self.assign_round(src.min, round);
                assert!(
                    dir == dir2 && !(*self).gt(src.max),
                    "minimum larger than maximum"
                );
                dir
            } else {
                dir
            }
        } else {
            self.assign_round(src.ref_self, round)
        }
    }
}

ref_math_op1_float! { xmpfr::recip; struct RecipIncomplete {} }
ref_math_op2_float! { xmpfr::min; struct MinIncomplete { other } }
ref_math_op2_float! { xmpfr::max; struct MaxIncomplete { other } }
ref_math_op2_float! { xmpfr::dim; struct PositiveDiffIncomplete { other } }
ref_math_op1_float! { xmpfr::log; struct LnIncomplete {} }
ref_math_op0_float! { xmpfr::log_ui; struct LnUIncomplete { u: u32 } }
ref_math_op1_float! { xmpfr::log2; struct Log2Incomplete {} }
ref_math_op1_float! { xmpfr::log10; struct Log10Incomplete {} }
ref_math_op1_float! { xmpfr::exp; struct ExpIncomplete {} }
ref_math_op1_float! { xmpfr::exp2; struct Exp2Incomplete {} }
ref_math_op1_float! { xmpfr::exp10; struct Exp10Incomplete {} }
ref_math_op1_float! { xmpfr::sin; struct SinIncomplete {} }
ref_math_op1_float! { xmpfr::cos; struct CosIncomplete {} }
ref_math_op1_float! { xmpfr::tan; struct TanIncomplete {} }
ref_math_op1_2_float! { xmpfr::sin_cos; struct SinCosIncomplete {} }
ref_math_op1_float! { xmpfr::sec; struct SecIncomplete {} }
ref_math_op1_float! { xmpfr::csc; struct CscIncomplete {} }
ref_math_op1_float! { xmpfr::cot; struct CotIncomplete {} }
ref_math_op1_float! { xmpfr::acos; struct AcosIncomplete {} }
ref_math_op1_float! { xmpfr::asin; struct AsinIncomplete {} }
ref_math_op1_float! { xmpfr::atan; struct AtanIncomplete {} }
ref_math_op2_float! { xmpfr::atan2; struct Atan2Incomplete { x } }
ref_math_op1_float! { xmpfr::cosh; struct CoshIncomplete {} }
ref_math_op1_float! { xmpfr::sinh; struct SinhIncomplete {} }
ref_math_op1_float! { xmpfr::tanh; struct TanhIncomplete {} }
ref_math_op1_2_float! { xmpfr::sinh_cosh; struct SinhCoshIncomplete {} }
ref_math_op1_float! { xmpfr::sech; struct SechIncomplete {} }
ref_math_op1_float! { xmpfr::csch; struct CschIncomplete {} }
ref_math_op1_float! { xmpfr::coth; struct CothIncomplete {} }
ref_math_op1_float! { xmpfr::acosh; struct AcoshIncomplete {} }
ref_math_op1_float! { xmpfr::asinh; struct AsinhIncomplete {} }
ref_math_op1_float! { xmpfr::atanh; struct AtanhIncomplete {} }
ref_math_op0_float! { xmpfr::fac_ui; struct FactorialIncomplete { n: u32 } }
ref_math_op1_float! { xmpfr::log1p; struct Ln1pIncomplete {} }
ref_math_op1_float! { xmpfr::expm1; struct ExpM1Incomplete {} }
ref_math_op1_float! { xmpfr::eint; struct EintIncomplete {} }
ref_math_op1_float! { xmpfr::li2; struct Li2Incomplete {} }
ref_math_op1_float! { xmpfr::gamma; struct GammaIncomplete {} }
ref_math_op2_float! { xmpfr::gamma_inc; struct GammaIncIncomplete { x } }
ref_math_op1_float! { xmpfr::lngamma; struct LnGammaIncomplete {} }

pub struct LnAbsGammaIncomplete<'a> {
    ref_self: &'a Float,
}

impl AssignRound<LnAbsGammaIncomplete<'_>> for (&mut Float, &mut Ordering) {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: LnAbsGammaIncomplete<'_>, round: Round) -> Ordering {
        let (sign_ord, ord) = xmpfr::lgamma(self.0, src.ref_self, round);
        *self.1 = sign_ord;
        ord
    }
}

impl AssignRound<LnAbsGammaIncomplete<'_>> for (Float, Ordering) {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: LnAbsGammaIncomplete<'_>, round: Round) -> Ordering {
        (&mut self.0, &mut self.1).assign_round(src, round)
    }
}

impl Assign<LnAbsGammaIncomplete<'_>> for (&mut Float, &mut Ordering) {
    #[inline]
    fn assign(&mut self, src: LnAbsGammaIncomplete<'_>) {
        self.assign_round(src, Round::Nearest);
    }
}

impl Assign<LnAbsGammaIncomplete<'_>> for (Float, Ordering) {
    #[inline]
    fn assign(&mut self, src: LnAbsGammaIncomplete<'_>) {
        (&mut self.0, &mut self.1).assign_round(src, Round::Nearest);
    }
}

ref_math_op1_float! { xmpfr::digamma; struct DigammaIncomplete {} }
ref_math_op1_float! { xmpfr::zeta; struct ZetaIncomplete {} }
ref_math_op0_float! { xmpfr::zeta_ui; struct ZetaUIncomplete { u: u32 } }
ref_math_op1_float! { xmpfr::erf; struct ErfIncomplete {} }
ref_math_op1_float! { xmpfr::erfc; struct ErfcIncomplete {} }
ref_math_op1_float! { xmpfr::j0; struct J0Incomplete {} }
ref_math_op1_float! { xmpfr::j1; struct J1Incomplete {} }
ref_math_op1_float! { xmpfr::jn; struct JnIncomplete { n: i32 } }
ref_math_op1_float! { xmpfr::y0; struct Y0Incomplete {} }
ref_math_op1_float! { xmpfr::y1; struct Y1Incomplete {} }
ref_math_op1_float! { xmpfr::yn; struct YnIncomplete { n: i32 } }
ref_math_op2_float! { xmpfr::agm; struct AgmIncomplete { other } }
ref_math_op2_float! { xmpfr::hypot; struct HypotIncomplete { other } }
ref_math_op1_float! { xmpfr::ai; struct AiIncomplete {} }
ref_math_op1_float! { xmpfr::rint_ceil; struct CeilIncomplete {} }
ref_math_op1_float! { xmpfr::rint_floor; struct FloorIncomplete {} }
ref_math_op1_float! { xmpfr::rint_round; struct RoundIncomplete {} }
ref_math_op1_float! { xmpfr::rint_roundeven; struct RoundEvenIncomplete {} }
ref_math_op1_float! { xmpfr::rint_trunc; struct TruncIncomplete {} }
ref_math_op1_float! { xmpfr::frac; struct FractIncomplete {} }
ref_math_op1_2_float! { xmpfr::modf; struct TruncFractIncomplete {} }

#[cfg(feature = "rand")]
pub struct RandomBitsIncomplete<'a> {
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl Assign<RandomBitsIncomplete<'_>> for Float {
    #[inline]
    fn assign(&mut self, src: RandomBitsIncomplete) {
        xmpfr::urandomb(self, src.rng);
    }
}

#[cfg(feature = "rand")]
pub struct RandomContIncomplete<'a> {
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl AssignRound<RandomContIncomplete<'_>> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: RandomContIncomplete, round: Round) -> Ordering {
        xmpfr::urandom(self, src.rng, round)
    }
}

#[cfg(feature = "rand")]
pub struct RandomNormalIncomplete<'a> {
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl AssignRound<RandomNormalIncomplete<'_>> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: RandomNormalIncomplete, round: Round) -> Ordering {
        xmpfr::nrandom(self, src.rng, round)
    }
}

#[cfg(feature = "rand")]
pub struct RandomExpIncomplete<'a> {
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl AssignRound<RandomExpIncomplete<'_>> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: RandomExpIncomplete, round: Round) -> Ordering {
        xmpfr::erandom(self, src.rng, round)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct BorrowFloat<'a> {
    inner: ManuallyDrop<Float>,
    phantom: PhantomData<&'a Float>,
}

impl BorrowFloat<'_> {
    // unsafe because the lifetime is obtained from return type
    unsafe fn from_raw<'a>(raw: mpfr_t) -> BorrowFloat<'a> {
        BorrowFloat {
            inner: ManuallyDrop::new(Float::from_raw(raw)),
            phantom: PhantomData,
        }
    }
}

impl Deref for BorrowFloat<'_> {
    type Target = Float;
    #[inline]
    fn deref(&self) -> &Float {
        &*self.inner
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpFormat {
    Exp,
    Point,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Format {
    pub radix: i32,
    pub precision: Option<usize>,
    pub round: Round,
    pub to_upper: bool,
    pub exp: ExpFormat,
}

impl Default for Format {
    #[inline]
    fn default() -> Format {
        Format {
            radix: 10,
            precision: None,
            round: Round::default(),
            to_upper: false,
            exp: ExpFormat::Point,
        }
    }
}

pub(crate) fn req_chars(f: &Float, format: Format, extra: usize) -> usize {
    assert!(
        format.radix >= 2 && format.radix <= 36,
        "radix {} out of range",
        format.radix
    );
    // Although append_str processess singular values before calling
    // req_chars, req_chars is called from outside append_str too.
    let size_no_sign = if f.is_zero() {
        1
    } else if f.is_infinite() || f.is_nan() {
        if format.radix > 10 {
            5
        } else {
            3
        }
    } else {
        let digits = req_digits(f, format);
        let log2_radix = f64::from(format.radix).log2();
        #[allow(clippy::approx_constant)]
        const LOG10_2: f64 = 0.301_029_995_663_981_2f64;
        let exp = (xmpfr::get_exp(f).az::<f64>() / log2_radix - 1.0).abs();
        // add 1 for '-' and an extra 1 in case of rounding errors
        let exp_digits = (exp * LOG10_2).ceil().az::<usize>() + 2;
        // '.', exp separator, exp_digits
        digits.checked_add(2 + exp_digits).expect("overflow")
    };
    let size = if f.is_sign_negative() {
        size_no_sign.checked_add(1).expect("overflow")
    } else {
        size_no_sign
    };
    size.checked_add(extra).expect("overflow")
}

pub(crate) fn req_digits(f: &Float, format: Format) -> usize {
    let digits = format.precision.unwrap_or(0);
    if digits > 0 {
        digits
    } else {
        let m = xmpfr::get_str_ndigits(format.radix, xmpfr::get_prec(f));
        m.checked_add(1).expect("overflow")
    }
}

pub(crate) fn append_to_string(s: &mut String, f: &Float, format: Format) {
    use core::fmt::Write;

    if f.is_zero() {
        s.push_str(if f.is_sign_negative() { "-0" } else { "0" });
        return;
    }
    if f.is_infinite() {
        s.push_str(match (format.radix > 10, f.is_sign_negative()) {
            (false, false) => "inf",
            (false, true) => "-inf",
            (true, false) => "@inf@",
            (true, true) => "-@inf@",
        });
        return;
    }
    if f.is_nan() {
        s.push_str(match (format.radix > 10, f.is_sign_negative()) {
            (false, false) => "NaN",
            (false, true) => "-NaN",
            (true, false) => "@NaN@",
            (true, true) => "-@NaN@",
        });
        return;
    }

    // no need to add 1 for nul, as req_chars includes an allocation for '.'
    let size = req_chars(f, format, 0);
    s.reserve(size);
    let reserved_ptr = s.as_ptr();

    let radix_with_case = if format.to_upper {
        -format.radix
    } else {
        format.radix
    };
    let digits = format.precision.unwrap_or(0);
    let mut exp: exp_t;
    unsafe {
        let vec = s.as_mut_vec();
        let write_ptr = vec.as_mut_ptr().add(vec.len());
        let mut maybe_exp = MaybeUninit::uninit();
        let c_buf = mpfr::get_str(
            write_ptr as *mut c_char,
            maybe_exp.as_mut_ptr(),
            radix_with_case.unwrapped_cast(),
            digits,
            f.as_raw(),
            raw_round(format.round),
        );
        assert_eq!(c_buf, write_ptr as *mut c_char);
        exp = maybe_exp.assume_init();
        let c_len = CStr::from_ptr(write_ptr as *mut c_char).to_bytes().len();
        // there is also 1 byte for nul character, which will be used for point
        assert!(c_len + 1 < size, "buffer overflow");
        let added_sign = *write_ptr == b'-';
        let added_digits = c_len - if added_sign { 1 } else { 0 };
        let digits_before_point = if format.exp == ExpFormat::Exp
            || exp <= 0
            || exp.unwrapped_as::<usize>() > added_digits
        {
            exp = exp.checked_sub(1).expect("overflow");
            1
        } else {
            let e = exp.wrapping_as::<usize>();
            exp = 0;
            e
        };
        let bytes_before_point = digits_before_point + if added_sign { 1 } else { 0 };
        if bytes_before_point == c_len {
            // no point
            vec.set_len(vec.len() + c_len)
        } else {
            let point_ptr = write_ptr.add(bytes_before_point);
            point_ptr.copy_to(point_ptr.offset(1), c_len - bytes_before_point);
            *point_ptr = b'.';
            vec.set_len(vec.len() + c_len + 1);
        }
    }
    if format.exp == ExpFormat::Exp || exp != 0 {
        s.push(if format.radix > 10 {
            '@'
        } else if format.to_upper {
            'E'
        } else {
            'e'
        });
        write!(s, "{}", exp).unwrap();
    }
    debug_assert_eq!(reserved_ptr, s.as_ptr());
}

#[derive(Debug)]
pub enum ParseIncomplete {
    CString { c_string: CString, radix: i32 },
    Special(Special),
    NegNan,
}

impl AssignRound<ParseIncomplete> for Float {
    type Round = Round;
    type Ordering = Ordering;
    fn assign_round(&mut self, src: ParseIncomplete, round: Round) -> Ordering {
        let (c_string, radix) = match src {
            ParseIncomplete::CString { c_string, radix } => (c_string, radix),
            ParseIncomplete::Special(special) => {
                self.assign(special);
                return Ordering::Equal;
            }
            ParseIncomplete::NegNan => {
                self.assign(Special::Nan);
                self.neg_assign();
                return Ordering::Equal;
            }
        };
        let mut c_str_end = MaybeUninit::uninit();
        let ret = unsafe {
            mpfr::strtofr(
                self.as_raw_mut(),
                c_string.as_ptr(),
                c_str_end.as_mut_ptr(),
                radix.unwrapped_cast(),
                raw_round(round),
            )
        };
        let nul = cast_ptr!(c_string.as_bytes_with_nul().last().unwrap(), c_char);
        assert_eq!(unsafe { c_str_end.assume_init() } as *const c_char, nul);
        ordering1(ret)
    }
}

macro_rules! parse_error {
    ($kind:expr) => {
        Err(ParseFloatError { kind: $kind })
    };
}

fn parse(mut bytes: &[u8], radix: i32) -> Result<ParseIncomplete, ParseFloatError> {
    assert!((2..=36).contains(&radix), "radix {} out of range", radix);
    let bradix = radix.unwrapped_as::<u8>();
    let small_bound = b'a' - 10 + bradix;
    let capital_bound = b'A' - 10 + bradix;
    let digit_bound = b'0' + bradix;

    bytes = misc::trim_start(bytes);
    bytes = misc::trim_end(bytes);
    if bytes.is_empty() {
        return parse_error!(ParseErrorKind::NoDigits);
    }

    let mut has_sign = false;
    let mut has_minus = false;
    if bytes[0] == b'+' || bytes[0] == b'-' {
        has_sign = true;
        has_minus = bytes[0] == b'-';
        bytes = misc::trim_start(&bytes[1..]);
        if bytes.is_empty() {
            return parse_error!(ParseErrorKind::NoDigits);
        }
    }

    if let Some(special) = parse_special(bytes, radix, has_minus) {
        return special;
    }

    let mut v = Vec::with_capacity(bytes.len() + 2);
    if has_minus {
        v.push(b'-');
    }
    let mut has_digits = false;
    let mut has_point = false;
    let mut exp = false;
    for &b in bytes {
        let b = if radix <= 10 && (b == b'e' || b == b'E') {
            b'@'
        } else {
            b
        };
        let valid_digit = match b {
            b'.' if exp => return parse_error!(ParseErrorKind::PointInExp),
            b'.' if has_point => return parse_error!(ParseErrorKind::TooManyPoints),
            b'.' => {
                v.push(b'.');
                has_point = true;
                continue;
            }
            b'@' if exp => return parse_error!(ParseErrorKind::TooManyExp),
            b'@' if !has_digits => return parse_error!(ParseErrorKind::SignifNoDigits),
            b'@' => {
                v.push(b'@');
                exp = true;
                has_sign = false;
                has_digits = false;
                continue;
            }
            b'+' if exp && !has_sign && !has_digits => {
                has_sign = true;
                continue;
            }
            b'-' if exp && !has_sign && !has_digits => {
                v.push(b'-');
                has_sign = true;
                continue;
            }
            b'_' if has_digits => continue,
            b' ' | b'\t' | b'\n' | 0x0b | 0x0c | 0x0d => continue,

            b'0'..=b'9' => exp || b < digit_bound,
            b'a'..=b'z' => !exp && b < small_bound,
            b'A'..=b'Z' => !exp && b < capital_bound,
            _ => false,
        };
        if !valid_digit {
            return parse_error!(ParseErrorKind::InvalidDigit);
        }
        v.push(b);
        has_digits = true;
    }
    if !has_digits {
        if exp {
            return parse_error!(ParseErrorKind::ExpNoDigits);
        } else {
            return parse_error!(ParseErrorKind::NoDigits);
        }
    }
    // we've only added checked bytes, so we know there are no nuls
    let c_string = unsafe { CString::from_vec_unchecked(v) };
    Ok(ParseIncomplete::CString { c_string, radix })
}

fn parse_special(
    bytes: &[u8],
    radix: i32,
    negative: bool,
) -> Option<Result<ParseIncomplete, ParseFloatError>> {
    let small = if radix <= 10 { Some(()) } else { None };

    // "infinity" must precede "inf" in inf10, otherwise "infinity"
    // will be parsed as "inf" with trailing characters.
    let inf10: &[&[u8]] = &[b"infinity", b"inf"];
    let inf: &[&[u8]] = &[b"@inf@", b"@infinity@"];
    if let Some(after_inf) = small
        .and_then(|()| misc::skip_lcase_match(bytes, inf10))
        .or_else(|| misc::skip_lcase_match(bytes, inf))
        .map(misc::trim_start)
    {
        if !after_inf.is_empty() {
            return Some(parse_error!(ParseErrorKind::InvalidDigit));
        }
        return if negative {
            Some(Ok(ParseIncomplete::Special(Special::NegInfinity)))
        } else {
            Some(Ok(ParseIncomplete::Special(Special::Infinity)))
        };
    }

    let nan10: &[&[u8]] = &[b"nan", b"+nan"];
    let nan: &[&[u8]] = &[b"@nan@", b"+@nan@"];
    if let Some(after_nan) = small
        .and_then(|()| misc::skip_lcase_match(bytes, nan10))
        .or_else(|| misc::skip_lcase_match(bytes, nan))
        .map(misc::trim_start)
    {
        let trailing = if let Some(after_extra) = skip_nan_extra(after_nan).map(misc::trim_start) {
            after_extra
        } else {
            after_nan
        };
        if !trailing.is_empty() {
            return Some(parse_error!(ParseErrorKind::InvalidDigit));
        }
        return if negative {
            Some(Ok(ParseIncomplete::NegNan))
        } else {
            Some(Ok(ParseIncomplete::Special(Special::Nan)))
        };
    }
    None
}

// If bytes starts with nan extras e.g. b"(stuff)", return bytes with
// the match skipped.
fn skip_nan_extra(bytes: &[u8]) -> Option<&[u8]> {
    let mut iter = bytes.iter().enumerate();
    match iter.next() {
        Some((_, &b'(')) => {}
        _ => return None,
    }
    for (i, &b) in iter {
        match b {
            b')' => return Some(&bytes[i + 1..]),
            b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'_'
            | b' '
            | b'\t'
            | b'\n'
            | 0x0b
            | 0x0c
            | 0x0d => {}
            _ => return None,
        }
    }
    None
}

#[derive(Debug)]
/**
An error which can be returned when parsing a [`Float`].

See the <code>[Float][`Float`]::[parse_radix][`parse_radix`]</code>
method for details on what strings are accepted.

# Examples

```rust
use rug::{float::ParseFloatError, Float};
// This string is not a floating-point number.
let s = "something completely different (_!_!_)";
let error: ParseFloatError = match Float::parse_radix(s, 4) {
    Ok(_) => unreachable!(),
    Err(error) => error,
};
println!("Parse error: {}", error);
```

[`Float`]: ../struct.Float.html
[`parse_radix`]: ../struct.Float.html#method.parse_radix
*/
pub struct ParseFloatError {
    kind: ParseErrorKind,
}

#[derive(Debug)]
enum ParseErrorKind {
    InvalidDigit,
    NoDigits,
    SignifNoDigits,
    ExpNoDigits,
    PointInExp,
    TooManyPoints,
    TooManyExp,
}

impl ParseFloatError {
    fn desc(&self) -> &str {
        use self::ParseErrorKind::*;
        match self.kind {
            InvalidDigit => "invalid digit found in string",
            NoDigits => "string has no digits",
            SignifNoDigits => "string has no digits for significand",
            ExpNoDigits => "string has no digits for exponent",
            PointInExp => "string has point in exponent",
            TooManyPoints => "more than one point found in string",
            TooManyExp => "more than one exponent found in string",
        }
    }
}

impl Error for ParseFloatError {
    fn description(&self) -> &str {
        self.desc()
    }
}

impl Display for ParseFloatError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(self.desc(), f)
    }
}

fn ieee_storage_bits_for_prec(prec: u32) -> Option<u32> {
    // p = prec, k = storage bits
    match prec {
        11 => return Some(16),
        24 => return Some(32),
        53 => return Some(64),
        _ => {}
    }
    // When k > 64, k must be a multiple of 32 ≥ 128 (96 is skipped by the standard).
    // p = k - round(4 log2 k) + 13
    // When k = 128, p = 113.
    // When k = 2^32 (overflow), p = 2^32 - 115 = MAX - 114.
    // When k = max allowed = 2^32 - 32, p = 2^32 - 32 - 115 = MAX - 146.
    if prec < 113 || prec > u32::max_value() - 146 {
        return None;
    }

    // k = p - 13 + round(4 log2 k)
    // But we only need to find an approximation for k with error < 16,
    // and log2 k - log2 p < 1/5 when p ≥ 113.
    // estimate = p - 13 + 4 * log2 p
    // log2 p is approximately 31.5 - prec.leading_zeros()
    // estimate = p - 13 + 4 * (31.5 - zeros) = p - 4 * zeros + 113.
    // Since we already checked that p <= MAX - 146, p + 113 never overflows.
    let estimate = prec - 4 * prec.leading_zeros() + 113;
    // k must be a multiple of 32
    let k = (estimate + 16) & !31;
    let p = k - (f64::from(k).log2() * 4.0).round().unwrapped_as::<u32>() + 13;
    if p == prec {
        Some(k)
    } else {
        None
    }
}

impl PartialOrd<UExpIncomplete> for Float {
    #[inline]
    fn partial_cmp(&self, other: &UExpIncomplete) -> Option<Ordering> {
        if self.is_nan() {
            None
        } else {
            Some(xmpfr::cmp_u32_2exp(self, other.u, other.exp))
        }
    }
}

impl PartialOrd<IExpIncomplete> for Float {
    #[inline]
    fn partial_cmp(&self, other: &IExpIncomplete) -> Option<Ordering> {
        if self.is_nan() {
            None
        } else {
            Some(xmpfr::cmp_i32_2exp(self, other.i, other.exp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ieee_storage_bits_for_prec;

    #[test]
    fn check_ieee_storage_bits() {
        assert_eq!(ieee_storage_bits_for_prec(0), None);
        assert_eq!(ieee_storage_bits_for_prec(11), Some(16));
        assert_eq!(ieee_storage_bits_for_prec(24), Some(32));
        assert_eq!(ieee_storage_bits_for_prec(53), Some(64));
        assert_eq!(ieee_storage_bits_for_prec(83), None); // no 96
        assert_eq!(ieee_storage_bits_for_prec(113), Some(128));
        assert_eq!(ieee_storage_bits_for_prec(144), Some(160));
        assert_eq!(ieee_storage_bits_for_prec(237), Some(256));
        assert_eq!(
            ieee_storage_bits_for_prec(u32::max_value() - 178),
            Some(u32::max_value() - 63)
        );
        assert_eq!(ieee_storage_bits_for_prec(u32::max_value() - 145), None);
        assert_eq!(
            ieee_storage_bits_for_prec(u32::max_value() - 146),
            Some(u32::max_value() - 31)
        );
        assert_eq!(ieee_storage_bits_for_prec(u32::max_value() - 147), None);
        assert_eq!(ieee_storage_bits_for_prec(u32::max_value() - 114), None);
        assert_eq!(ieee_storage_bits_for_prec(u32::max_value()), None);
    }
}
