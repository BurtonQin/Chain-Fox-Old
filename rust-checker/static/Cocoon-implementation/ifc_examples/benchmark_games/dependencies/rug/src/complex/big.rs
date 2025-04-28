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
use crate::{
    complex::{
        arith::{AddMulIncomplete, SubMulFromIncomplete},
        OrdComplex, Prec,
    },
    ext::{
        xmpc::{self, Ordering2, Round2, NEAREST2},
        xmpfr,
    },
    float::{
        self,
        big::{
            self as big_float, ExpFormat, Format as FloatFormat,
            ParseIncomplete as FloatParseIncomplete,
        },
        ParseFloatError, Round, Special,
    },
    misc,
    ops::{AddAssignRound, AssignRound},
    Assign, Float,
};
use az::UnwrappedCast;
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ops::{Add, AddAssign, Deref},
    slice,
};
use gmp_mpfr_sys::mpc::mpc_t;
use std::error::Error;

/**
A multi-precision complex number with arbitrarily large precision and
correct rounding.

The precision has to be set during construction. The rounding method
of the required operations can be specified, and the direction of the
rounding is returned.

# Examples

```rust
use rug::{Assign, Complex, Float};
let c = Complex::with_val(53, (40, 30));
assert_eq!(format!("{:.3}", c), "(40.0 30.0)");
let mut f = Float::with_val(53, c.abs_ref());
assert_eq!(f, 50);
f.assign(c.arg_ref());
assert_eq!(f, 0.75_f64.atan());
```

Operations on two borrowed `Complex` numbers result in an
[incomplete-computation value][icv] that has to be assigned to a new
`Complex` number.

```rust
use rug::Complex;
let a = Complex::with_val(53, (10.5, -11));
let b = Complex::with_val(53, (-1.25, -1.5));
let a_b_ref = &a + &b;
let a_b = Complex::with_val(53, a_b_ref);
assert_eq!(a_b, (9.25, -12.5));
```

As a special case, when an [incomplete-computation value][icv] is
obtained from multiplying two `Complex` number references, it can be
added to or subtracted from another `Complex` number (or reference).
This will result in a fused multiply-accumulate operation, with only
one rounding operation taking place.

```rust
use rug::Complex;
let mut acc = Complex::with_val(53, (1000, 1000));
let m1 = Complex::with_val(53, (10, 0));
let m2 = Complex::with_val(53, (1, -1));
// (1000 + 1000i) − (10 + 0i) × (1 − i) = (990 + 1010i)
acc -= &m1 * &m2;
assert_eq!(acc, (990, 1010));
```

The `Complex` number type supports various functions. Most methods
have four versions:

 1. The first method consumes the operand and rounds the returned
    `Complex` number to the [nearest][`Nearest`] representable value.
 2. The second method has a “`_mut`” suffix, mutates the operand and
    rounds it the nearest representable value.
 3. The third method has a “`_round`” suffix, mutates the operand,
    applies the specified [rounding method][`Round`] to the real and
    imaginary parts, and returns the rounding direction for both:
      * <code>[Ordering][`Ordering`]::[Less][`Less`]</code> if the
        stored part is less than the exact result,
      * <code>[Ordering][`Ordering`]::[Equal][`Equal`]</code> if the
        stored part is equal to the exact result,
      * <code>[Ordering][`Ordering`]::[Greater][`Greater`]</code> if
        the stored part is greater than the exact result.
 4. The fourth method has a “`_ref`” suffix and borrows the operand.
    The returned item is an [incomplete-computation value][icv] that
    can be assigned to a `Complex` number; the rounding method is
    selected during the assignment.

```rust
use core::cmp::Ordering;
use rug::{float::Round, Complex};
let expected = Complex::with_val(53, (1.2985, 0.6350));

// 1. consume the operand, round to nearest
let a = Complex::with_val(53, (1, 1));
let sin_a = a.sin();
assert!(*(sin_a - &expected).abs().real() < 0.0001);

// 2. mutate the operand, round to nearest
let mut b = Complex::with_val(53, (1, 1));
b.sin_mut();
assert!(*(b - &expected).abs().real() < 0.0001);

// 3. mutate the operand, apply specified rounding
let mut c = Complex::with_val(4, (1, 1));
// using 4 significant bits, 1.2985 is rounded down to 1.25
// and 0.6350 is rounded down to 0.625.
let dir = c.sin_round((Round::Nearest, Round::Nearest));
assert_eq!(c, (1.25, 0.625));
assert_eq!(dir, (Ordering::Less, Ordering::Less));

// 4. borrow the operand
let d = Complex::with_val(53, (1, 1));
let r = d.sin_ref();
let sin_d = Complex::with_val(53, r);
assert!(*(sin_d - &expected).abs().real() < 0.0001);
// d was not consumed
assert_eq!(d, (1, 1));
```

[`Equal`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Equal
[`Greater`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Greater
[`Less`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Less
[`Nearest`]: float/enum.Round.html#variant.Nearest
[`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
[`Round`]: float/enum.Round.html
[icv]: index.html#incomplete-computation-values
*/
#[repr(transparent)]
pub struct Complex {
    inner: mpc_t,
}

static_assert_same_layout!(Complex, mpc_t);
static_assert_same_layout!(BorrowComplex<'_>, mpc_t);

static_assert_same_size!(Complex, Option<Complex>);

macro_rules! ref_math_op0_complex {
    ($($rest:tt)*) => {
        ref_math_op0_round! {
            Complex, Round2, NEAREST2, Ordering2;
            $($rest)*
        }
    };
}

macro_rules! ref_math_op1_complex {
    ($($rest:tt)*) => {
        ref_math_op1_round! {
            Complex, Round2, NEAREST2, Ordering2;
            $($rest)*
        }
    };
}

macro_rules! ref_math_op1_2_complex {
    ($($rest:tt)*) => {
        ref_math_op1_2_round! {
            Complex, Round2, NEAREST2, (Ordering2, Ordering2);
            $($rest)*
        }
    };
}

impl Complex {
    #[inline]
    pub(crate) fn new_nan<P: Prec>(prec: P) -> Self {
        let p = prec.prec();
        assert!(
            p.0 >= float::prec_min()
                && p.0 <= float::prec_max()
                && p.1 >= float::prec_min()
                && p.1 <= float::prec_max(),
            "precision out of range"
        );
        let mut ret = MaybeUninit::uninit();
        xmpc::write_new_nan(&mut ret, p.0.unwrapped_cast(), p.1.unwrapped_cast());
        // Safety: write_new_nan initializes ret.
        unsafe { ret.assume_init() }
    }

    /// Create a new [`Complex`] number with the specified precisions
    /// for the real and imaginary parts and with value 0.
    ///
    /// # Panics
    ///
    /// Panics if the precision is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c1 = Complex::new(32);
    /// assert_eq!(c1.prec(), (32, 32));
    /// assert_eq!(c1, 0);
    /// let c2 = Complex::new((32, 64));
    /// assert_eq!(c2.prec(), (32, 64));
    /// assert_eq!(c2, 0);
    /// ```
    ///
    /// [`Complex`]: #
    #[inline]
    pub fn new<P: Prec>(prec: P) -> Self {
        Self::with_val(prec, (Special::Zero, Special::Zero))
    }

    /// Create a new [`Complex`] number with the specified precision
    /// and with the given value, rounding to the nearest.
    ///
    /// # Panics
    ///
    /// Panics if `prec` is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c1 = Complex::with_val(53, (1.3f64, -12));
    /// assert_eq!(c1.prec(), (53, 53));
    /// assert_eq!(c1, (1.3f64, -12));
    /// let c2 = Complex::with_val(53, 42.0);
    /// assert_eq!(c2.prec(), (53, 53));
    /// assert_eq!(c2, 42);
    /// assert_eq!(c2, (42, 0));
    /// ```
    ///
    /// [`Complex`]: #
    #[inline]
    pub fn with_val<P, T>(prec: P, val: T) -> Self
    where
        Self: Assign<T>,
        P: Prec,
    {
        let mut ret = Complex::new_nan(prec);
        ret.assign(val);
        ret
    }

    /// Create a new [`Complex`] number with the specified precision
    /// and with the given value, applying the specified rounding
    /// method.
    ///
    /// # Panics
    ///
    /// Panics if `prec` is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let round = (Round::Down, Round::Up);
    /// let (c, dir) = Complex::with_val_round(4, (3.3, 2.3), round);
    /// // 3.3 is rounded down to 3.25, 2.3 is rounded up to 2.5
    /// assert_eq!(c.prec(), (4, 4));
    /// assert_eq!(c, (3.25, 2.5));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Greater));
    /// ```
    ///
    /// [`Complex`]: #
    #[inline]
    pub fn with_val_round<P, T>(prec: P, val: T, round: Round2) -> (Self, Ordering2)
    where
        Self: AssignRound<T, Round = Round2, Ordering = Ordering2>,
        P: Prec,
    {
        let mut ret = Complex::new_nan(prec);
        let ord = ret.assign_round(val, round);
        (ret, ord)
    }

    /// Returns the precision of the real and imaginary parts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let r = Complex::new((24, 53));
    /// assert_eq!(r.prec(), (24, 53));
    /// ```
    #[inline]
    pub fn prec(&self) -> (u32, u32) {
        (self.real().prec(), self.imag().prec())
    }

    /// Sets the precision of the real and imaginary parts, rounding
    /// to the nearest.
    ///
    /// # Panics
    ///
    /// Panics if the precision is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut r = Complex::with_val(6, (4.875, 4.625));
    /// assert_eq!(r, (4.875, 4.625));
    /// r.set_prec(4);
    /// assert_eq!(r, (5.0, 4.5));
    /// ```
    #[inline]
    pub fn set_prec<P: Prec>(&mut self, prec: P) {
        self.set_prec_round(prec, NEAREST2);
    }

    /// Sets the precision of the real and imaginary parts, applying
    /// the specified rounding method.
    ///
    /// # Panics
    ///
    /// Panics if the precision is out of the allowed range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let mut r = Complex::with_val(6, (4.875, 4.625));
    /// assert_eq!(r, (4.875, 4.625));
    /// let dir = r.set_prec_round(4, (Round::Down, Round::Up));
    /// assert_eq!(r, (4.5, 5.0));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Greater));
    /// ```
    #[inline]
    pub fn set_prec_round<P: Prec>(&mut self, prec: P, round: Round2) -> Ordering2 {
        let p = prec.prec();
        let (real, imag) = self.as_mut_real_imag();
        (
            real.set_prec_round(p.0, round.0),
            imag.set_prec_round(p.1, round.1),
        )
    }

    /// Creates a [`Complex`] number from an initialized
    /// [MPC complex number][`mpc_t`].
    ///
    /// # Safety
    ///
    ///   * The value must be initialized.
    ///   * The [`mpc_t`] type can be considered as a kind of pointer,
    ///     so there can be multiple copies of it. Since this function
    ///     takes over ownership, no other copies of the passed value
    ///     should exist.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::mpc;
    /// use core::mem::MaybeUninit;
    /// use rug::Complex;
    /// let c = unsafe {
    ///     let mut m = MaybeUninit::uninit();
    ///     mpc::init3(m.as_mut_ptr(), 53, 53);
    ///     let mut m = m.assume_init();
    ///     mpc::set_d_d(&mut m, -14.5, 3.25, mpc::RNDNN);
    ///     // m is initialized and unique
    ///     Complex::from_raw(m)
    /// };
    /// assert_eq!(c, (-14.5, 3.25));
    /// // since c is a Complex now, deallocation is automatic
    /// ```
    ///
    /// [`Complex`]: #
    /// [`mpc_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpc/struct.mpc_t.html
    #[inline]
    pub unsafe fn from_raw(raw: mpc_t) -> Self {
        Complex { inner: raw }
    }

    /// Converts a [`Complex`] number into an
    /// [MPC complex number][`mpc_t`].
    ///
    /// The returned object should be freed to avoid memory leaks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::{
    ///     mpc,
    ///     mpfr::{self, rnd_t},
    /// };
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (-14.5, 3.25));
    /// let mut m = c.into_raw();
    /// unsafe {
    ///     let re_ptr = mpc::realref_const(&m);
    ///     let re = mpfr::get_d(re_ptr, rnd_t::RNDN);
    ///     assert_eq!(re, -14.5);
    ///     let im_ptr = mpc::imagref_const(&m);
    ///     let im = mpfr::get_d(im_ptr, rnd_t::RNDN);
    ///     assert_eq!(im, 3.25);
    ///     // free object to prevent memory leak
    ///     mpc::clear(&mut m);
    /// }
    /// ```
    ///
    /// [`Complex`]: #
    /// [`mpc_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpc/struct.mpc_t.html
    #[inline]
    pub fn into_raw(self) -> mpc_t {
        let m = ManuallyDrop::new(self);
        m.inner
    }

    /// Returns a pointer to the inner [MPC complex number][`mpc_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::{
    ///     mpc,
    ///     mpfr::{self, rnd_t},
    /// };
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (-14.5, 3.25));
    /// let m_ptr = c.as_raw();
    /// unsafe {
    ///     let re_ptr = mpc::realref_const(m_ptr);
    ///     let re = mpfr::get_d(re_ptr, rnd_t::RNDN);
    ///     assert_eq!(re, -14.5);
    ///     let im_ptr = mpc::imagref_const(m_ptr);
    ///     let im = mpfr::get_d(im_ptr, rnd_t::RNDN);
    ///     assert_eq!(im, 3.25);
    /// }
    /// // c is still valid
    /// assert_eq!(c, (-14.5, 3.25));
    /// ```
    ///
    /// [`mpc_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpc/struct.mpc_t.html
    #[inline]
    pub fn as_raw(&self) -> *const mpc_t {
        &self.inner
    }

    /// Returns an unsafe mutable pointer to the inner
    /// [MPC complex number][`mpc_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::mpc;
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (-14.5, 3.25));
    /// let m_ptr = c.as_raw_mut();
    /// unsafe {
    ///     mpc::conj(m_ptr, m_ptr, mpc::RNDNN);
    /// }
    /// assert_eq!(c, (-14.5, -3.25));
    /// ```
    ///
    /// [`mpc_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/mpc/struct.mpc_t.html
    #[inline]
    pub fn as_raw_mut(&mut self) -> *mut mpc_t {
        &mut self.inner
    }

    /// Parses a decimal string slice (<code>&amp;[str]</code>) or
    /// byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into a
    /// [`Complex`] number.
    ///
    /// <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    /// is implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`.
    ///
    /// The string can contain either of the following three:
    ///
    ///  1. One floating-point number that can be parsed by
    ///     <code>[Float][`Float`]::[parse][`parse`]</code>. ASCII
    ///     whitespace is treated in the same way as well.
    ///  2. Two floating-point numbers inside round brackets separated
    ///     by one comma. ASCII whitespace is treated in the same way
    ///     as 1 above, and is also allowed around the brackets and
    ///     the comma.
    ///  3. Two floating-point numbers inside round brackets separated
    ///     by ASCII whitespace. Since the real and imaginary parts
    ///     are separated by whitespace, they themselves cannot
    ///     contain whitespace. ASCII whitespace is still allowed
    ///     around the brackets and between the two parts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Complex;
    ///
    /// let valid1 = Complex::parse("(12.5, -13.5)");
    /// let c1 = Complex::with_val(53, valid1.unwrap());
    /// assert_eq!(c1, (12.5, -13.5));
    /// let valid2 = Complex::parse("(inf 0.0)");
    /// let c2 = Complex::with_val(53, valid2.unwrap());
    /// assert_eq!(c2, (f64::INFINITY, 0.0));
    ///
    /// let invalid = Complex::parse("(1 2 3)");
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Complex`]: #
    /// [`Float`]: struct.Float.html
    /// [`parse`]: struct.Float.html#method.parse
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse<S: AsRef<[u8]>>(src: S) -> Result<ParseIncomplete, ParseComplexError> {
        parse(src.as_ref(), 10)
    }

    /// Parses a string slice (<code>&amp;[str]</code>) or byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into a
    /// [`Complex`] number.
    ///
    /// <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    /// is implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`.
    ///
    /// The string can contain either of the following three:
    ///
    ///  1. One floating-point number that can be parsed by
    ///     <code>[Float][`Float`]::[parse_radix][`parse_radix`]</code>.
    ///     ASCII whitespace is treated in the same way as well.
    ///  2. Two floating-point numbers inside round brackets separated
    ///     by one comma. ASCII whitespace is treated in the same way
    ///     as 1 above, and is also allowed around the brackets and
    ///     the comma.
    ///  3. Two floating-point numbers inside round brackets separated
    ///     by ASCII whitespace. Since the real and imaginary parts
    ///     are separated by whitespace, they themselves cannot
    ///     contain whitespace. ASCII whitespace is still allowed
    ///     around the brackets and between the two parts.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Complex;
    ///
    /// let valid1 = Complex::parse_radix("(12, 1a)", 16);
    /// let c1 = Complex::with_val(53, valid1.unwrap());
    /// assert_eq!(c1, (0x12, 0x1a));
    /// let valid2 = Complex::parse_radix("(@inf@ zz)", 36);
    /// let c2 = Complex::with_val(53, valid2.unwrap());
    /// assert_eq!(c2, (f64::INFINITY, 35 * 36 + 35));
    ///
    /// let invalid = Complex::parse_radix("(1 2 3)", 10);
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Complex`]: #
    /// [`Float`]: struct.Float.html
    /// [`parse_radix`]: struct.Float.html#method.parse_radix
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse_radix<S: AsRef<[u8]>>(
        src: S,
        radix: i32,
    ) -> Result<ParseIncomplete, ParseComplexError> {
        parse(src.as_ref(), radix)
    }

    /// Returns a string representation of the value for the specified
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
    /// use rug::Complex;
    /// let c1 = Complex::with_val(53, 0);
    /// assert_eq!(c1.to_string_radix(10, None), "(0 0)");
    /// let c2 = Complex::with_val(12, (15, 5));
    /// assert_eq!(c2.to_string_radix(16, None), "(f.000 5.000)");
    /// let c3 = Complex::with_val(53, (10, -4));
    /// assert_eq!(c3.to_string_radix(10, Some(3)), "(10.0 -4.00)");
    /// assert_eq!(c3.to_string_radix(5, Some(3)), "(20.0 -4.00)");
    /// // 2 raised to the power of 80 in hex is 1 followed by 20 zeros
    /// let c4 = Complex::with_val(53, (80f64.exp2(), 0.25));
    /// assert_eq!(c4.to_string_radix(10, Some(3)), "(1.21e24 2.50e-1)");
    /// assert_eq!(c4.to_string_radix(16, Some(3)), "(1.00@20 4.00@-1)");
    /// ```
    #[inline]
    pub fn to_string_radix(&self, radix: i32, num_digits: Option<usize>) -> String {
        self.to_string_radix_round(radix, num_digits, NEAREST2)
    }

    /// Returns a string representation of the value for the specified
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
    /// use rug::{float::Round, Complex};
    /// let c = Complex::with_val(10, 10.4);
    /// let down = (Round::Down, Round::Down);
    /// let nearest = (Round::Nearest, Round::Nearest);
    /// let up = (Round::Up, Round::Up);
    /// let nd = c.to_string_radix_round(10, None, down);
    /// assert_eq!(nd, "(10.406 0)");
    /// let nu = c.to_string_radix_round(10, None, up);
    /// assert_eq!(nu, "(10.407 0)");
    /// let sd = c.to_string_radix_round(10, Some(2), down);
    /// assert_eq!(sd, "(10 0)");
    /// let sn = c.to_string_radix_round(10, Some(2), nearest);
    /// assert_eq!(sn, "(10 0)");
    /// let su = c.to_string_radix_round(10, Some(2), up);
    /// assert_eq!(su, "(11 0)");
    /// ```
    pub fn to_string_radix_round(
        &self,
        radix: i32,
        num_digits: Option<usize>,
        round: Round2,
    ) -> String {
        let mut s = String::new();
        let format = Format {
            radix,
            precision: num_digits,
            round,
            to_upper: false,
            sign_plus: false,
            prefix: "",
            exp: ExpFormat::Point,
        };
        append_to_string(&mut s, self, format);
        s
    }

    /// Borrows the real part as a [`Float`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (12.5, -20.75));
    /// assert_eq!(*c.real(), 12.5)
    /// ```
    ///
    /// [`Float`]: struct.Float.html
    #[inline]
    pub fn real(&self) -> &Float {
        xmpc::realref_const(self)
    }

    /// Borrows the imaginary part as a [`Float`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (12.5, -20.75));
    /// assert_eq!(*c.imag(), -20.75)
    /// ```
    ///
    /// [`Float`]: struct.Float.html
    #[inline]
    pub fn imag(&self) -> &Float {
        xmpc::imagref_const(self)
    }

    /// Borrows the real part mutably.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (12.5, -20.75));
    /// assert_eq!(c, (12.5, -20.75));
    /// *c.mut_real() /= 2;
    /// assert_eq!(c, (6.25, -20.75));
    /// ```
    #[inline]
    pub fn mut_real(&mut self) -> &mut Float {
        xmpc::realref(self)
    }

    /// Borrows the imaginary part mutably.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (12.5, -20.75));
    /// assert_eq!(c, (12.5, -20.75));
    /// *c.mut_imag() *= 4;
    /// assert_eq!(c, (12.5, -83));
    /// ```
    #[inline]
    pub fn mut_imag(&mut self) -> &mut Float {
        xmpc::imagref(self)
    }

    /// Borrows the real and imaginary parts mutably.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    ///
    /// let mut c = Complex::with_val(53, (12.5, -20.75));
    /// {
    ///     let (real, imag) = c.as_mut_real_imag();
    ///     *real /= 2;
    ///     *imag *= 4;
    ///     // borrow ends here
    /// }
    /// assert_eq!(c, (6.25, -83));
    /// ```
    #[inline]
    pub fn as_mut_real_imag(&mut self) -> (&mut Float, &mut Float) {
        xmpc::realref_imagref(self)
    }

    /// Consumes and converts the value into real and imaginary
    /// [`Float`] values.
    ///
    /// This function reuses the allocated memory and does not
    /// allocate any new memory.
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (12.5, -20.75));
    /// let (real, imag) = c.into_real_imag();
    /// assert_eq!(real, 12.5);
    /// assert_eq!(imag, -20.75);
    /// ```
    ///
    /// [`Float`]: struct.Float.html
    #[inline]
    pub fn into_real_imag(self) -> (Float, Float) {
        xmpc::split(self)
    }

    /// Borrows a negated copy of the [`Complex`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Complex][`Complex`]&gt;</code>.
    ///
    /// This method performs a shallow copy and negates it, and
    /// negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (4.2, -2.3));
    /// let neg_c = c.as_neg();
    /// assert_eq!(*neg_c, (-4.2, 2.3));
    /// // methods taking &self can be used on the returned object
    /// let reneg_c = neg_c.as_neg();
    /// assert_eq!(*reneg_c, (4.2, -2.3));
    /// assert_eq!(*reneg_c, c);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Complex`]: #
    pub fn as_neg(&self) -> BorrowComplex<'_> {
        let mut raw = self.inner;
        raw.re.sign = -raw.re.sign;
        raw.im.sign = -raw.im.sign;
        if self.real().is_nan() || self.imag().is_nan() {
            xmpfr::set_nanflag();
        }
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowComplex::from_raw(raw) }
    }

    /// Borrows a conjugate copy of the [`Complex`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Complex][`Complex`]&gt;</code>.
    ///
    /// This method performs a shallow copy and negates its imaginary
    /// part, and negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (4.2, -2.3));
    /// let conj_c = c.as_conj();
    /// assert_eq!(*conj_c, (4.2, 2.3));
    /// // methods taking &self can be used on the returned object
    /// let reconj_c = conj_c.as_conj();
    /// assert_eq!(*reconj_c, (4.2, -2.3));
    /// assert_eq!(*reconj_c, c);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Complex`]: #
    pub fn as_conj(&self) -> BorrowComplex<'_> {
        let mut raw = self.inner;
        raw.im.sign = -raw.im.sign;
        if self.imag().is_nan() {
            xmpfr::set_nanflag();
        }
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowComplex::from_raw(raw) }
    }

    /// Borrows a rotated copy of the [`Complex`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Complex][`Complex`]&gt;</code>.
    ///
    /// This method operates by performing some shallow copying;
    /// unlike the [`mul_i`] method and friends, this method swaps the
    /// precision of the real and imaginary parts if they have unequal
    /// precisions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (4.2, -2.3));
    /// let mul_i_c = c.as_mul_i(false);
    /// assert_eq!(*mul_i_c, (2.3, 4.2));
    /// // methods taking &self can be used on the returned object
    /// let mul_ii_c = mul_i_c.as_mul_i(false);
    /// assert_eq!(*mul_ii_c, (-4.2, 2.3));
    /// let mul_1_c = mul_i_c.as_mul_i(true);
    /// assert_eq!(*mul_1_c, (4.2, -2.3));
    /// assert_eq!(*mul_1_c, c);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Complex`]: #
    /// [`mul_i`]: #method.mul_i
    pub fn as_mul_i(&self, negative: bool) -> BorrowComplex<'_> {
        let mut raw = mpc_t {
            re: self.inner.im,
            im: self.inner.re,
        };
        if negative {
            raw.im.sign = -raw.im.sign;
        } else {
            raw.re.sign = -raw.re.sign;
        }
        if self.real().is_nan() || self.imag().is_nan() {
            xmpfr::set_nanflag();
        }
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowComplex::from_raw(raw) }
    }

    /// Borrows the [`Complex`] number as an ordered complex number of
    /// type [`OrdComplex`].
    ///
    /// The same result can be obtained using the implementation of
    /// <code>[AsRef][`AsRef`]&lt;[OrdComplex][`OrdComplex`]&gt;</code>
    /// which is provided for [`Complex`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Special, Complex};
    ///
    /// let nan_c = Complex::with_val(53, (Special::Nan, Special::Nan));
    /// let nan = nan_c.as_ord();
    /// assert_eq!(nan.cmp(nan), Ordering::Equal);
    ///
    /// let one_neg0_c = Complex::with_val(53, (1, Special::NegZero));
    /// let one_neg0 = one_neg0_c.as_ord();
    /// let one_pos0_c = Complex::with_val(53, (1, Special::Zero));
    /// let one_pos0 = one_pos0_c.as_ord();
    /// assert_eq!(one_neg0.cmp(one_pos0), Ordering::Less);
    ///
    /// let zero_inf_s = (Special::Zero, Special::Infinity);
    /// let zero_inf_c = Complex::with_val(53, zero_inf_s);
    /// let zero_inf = zero_inf_c.as_ord();
    /// assert_eq!(one_pos0.cmp(zero_inf), Ordering::Greater);
    /// ```
    ///
    /// [`AsRef`]: https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html
    /// [`Complex`]: #
    /// [`OrdComplex`]: complex/struct.OrdComplex.html
    #[inline]
    pub fn as_ord(&self) -> &OrdComplex {
        // Safety: OrdComplex is repr(transparent) over Complex
        unsafe { &*cast_ptr!(self, OrdComplex) }
    }

    /// Returns the same result as
    /// <code>self.[eq][`eq`](&amp;0)</code>, but is faster.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{float::Special, Assign, Complex};
    /// let mut c = Complex::with_val(53, (Special::NegZero, Special::Zero));
    /// assert!(c.eq0());
    /// c += 5.2;
    /// assert!(!c.eq0());
    /// c.mut_real().assign(Special::Nan);
    /// assert!(!c.eq0());
    /// ```
    ///
    /// [`eq`]: https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq
    #[inline]
    pub fn eq0(&self) -> bool {
        self.real().cmp0() == Some(Ordering::Equal) && self.imag().cmp0() == Some(Ordering::Equal)
    }

    /// Compares the absolute values of `self` and `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::Complex;
    /// let five = Complex::with_val(53, (5, 0));
    /// let five_rotated = Complex::with_val(53, (3, -4));
    /// let greater_than_five = Complex::with_val(53, (-4, -4));
    /// let has_nan = Complex::with_val(53, (5, 0.0 / 0.0));
    /// assert_eq!(five.cmp_abs(&five_rotated), Some(Ordering::Equal));
    /// assert_eq!(five.cmp_abs(&greater_than_five), Some(Ordering::Less));
    /// assert_eq!(five.cmp_abs(&has_nan), None);
    /// ```
    #[inline]
    pub fn cmp_abs(&self, other: &Self) -> Option<Ordering> {
        if self.real().is_nan()
            || self.imag().is_nan()
            || other.real().is_nan()
            || other.imag().is_nan()
        {
            None
        } else {
            Some(xmpc::cmp_abs(self, other))
        }
    }

    /// Adds a list of [`Complex`] numbers with correct rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AddAssignRound][`AddAssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    ///
    /// // Give each value only 4 bits of precision for example purposes.
    /// let values = [
    ///     Complex::with_val(4, (5.0, 1024.0)),
    ///     Complex::with_val(4, (1024.0, 15.0)),
    ///     Complex::with_val(4, (-1024.0, -1024.0)),
    ///     Complex::with_val(4, (-4.5, -16.0)),
    /// ];
    ///
    /// // The result should still be exact if it fits.
    /// let r1 = Complex::sum(values.iter());
    /// let sum1 = Complex::with_val(4, r1);
    /// assert_eq!(sum1, (0.5, -1.0));
    ///
    /// let r2 = Complex::sum(values.iter());
    /// let sum2 = Complex::with_val(4, (1.0, -1.0)) + r2;
    /// assert_eq!(sum2, (1.5, -2.0));
    ///
    /// let r3 = Complex::sum(values.iter());
    /// let mut sum3 = Complex::with_val(4, (16, 16));
    /// sum3 += r3;
    /// // (16.5, 15) rounded to (16, 15)
    /// assert_eq!(sum3, (16, 15));
    /// ```
    ///
    /// [`AddAssignRound`]: ops/trait.AddAssignRound.html
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sum<'a, I>(values: I) -> SumIncomplete<'a, I>
    where
        I: Iterator<Item = &'a Self>,
    {
        SumIncomplete { values }
    }

    /// Finds the dot product of a list of [`Complex`] numbers pairs
    /// with correct rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AddAssignRound][`AddAssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// This method will produce a result with correct rounding,
    /// except for some cases where underflow and/or overflow occur in
    /// intermediate products.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    ///
    /// let a = [
    ///     Complex::with_val(53, (5.0, 10.25)),
    ///     Complex::with_val(53, (10.25, 5.0)),
    /// ];
    /// let b = [
    ///     Complex::with_val(53, (-2.75, -11.5)),
    ///     Complex::with_val(53, (-4.5, 16.0)),
    /// ];
    ///
    /// let r = Complex::dot(a.iter().zip(b.iter()));
    /// let dot = Complex::with_val(53, r);
    /// let expected = Complex::with_val(53, &a[0] * &b[0]) + &a[1] * &b[1];
    /// assert_eq!(dot, expected);
    ///
    /// let r = Complex::dot(a.iter().zip(b.iter()));
    /// let add_dot = Complex::with_val(53, (1.0, 2.0)) + r;
    /// let add_expected = Complex::with_val(53, (1.0, 2.0)) + &expected;
    /// assert_eq!(add_dot, add_expected);
    ///
    /// let r = Complex::dot(a.iter().zip(b.iter()));
    /// let mut add_dot2 = Complex::with_val(53, (1.0, 2.0));
    /// add_dot2 += r;
    /// assert_eq!(add_dot2, add_expected);
    /// ```
    ///
    /// [`AddAssignRound`]: ops/trait.AddAssignRound.html
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn dot<'a, I>(values: I) -> DotIncomplete<'a, I>
    where
        I: Iterator<Item = (&'a Self, &'a Self)>,
    {
        DotIncomplete { values }
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
    /// use rug::Complex;
    /// let a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) + (1000 + 1000i) = (1010 + 990i)
    /// let mul_add = a.mul_add(&b, &c);
    /// assert_eq!(mul_add, (1010, 990));
    /// ```
    #[inline]
    pub fn mul_add(mut self, mul: &Self, add: &Self) -> Self {
        self.mul_add_round(mul, add, NEAREST2);
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
    /// use rug::Complex;
    /// let mut a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) + (1000 + 1000i) = (1010 + 990i)
    /// a.mul_add_mut(&b, &c);
    /// assert_eq!(a, (1010, 990));
    /// ```
    #[inline]
    pub fn mul_add_mut(&mut self, mul: &Self, add: &Self) {
        self.mul_add_round(mul, add, NEAREST2);
    }

    /// Multiplies and adds in one fused operation, applying the
    /// specified rounding method with only one rounding error.
    ///
    /// `a.mul_add_round(&b, &c, round)` produces a result like
    /// `ans.assign_round(&a * &b + &c, round)`, but stores the result
    /// in `a` using its precision rather than in another [`Complex`]
    /// number like `ans`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let mut a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) + (1000 + 1000i) = (1010 + 990i)
    /// let dir = a.mul_add_round(&b, &c, (Round::Nearest, Round::Nearest));
    /// assert_eq!(a, (1010, 990));
    /// assert_eq!(dir, (Ordering::Equal, Ordering::Equal));
    /// ```
    ///
    /// [`Complex`]: #
    #[inline]
    pub fn mul_add_round(&mut self, mul: &Self, add: &Self, round: Round2) -> Ordering2 {
        xmpc::fma(self, (), mul, add, round)
    }

    /// Multiplies and adds in one fused operation.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// `a.mul_add_ref(&b, &c)` produces the exact same result as
    /// `&a * &b + &c`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) + (1000 + 1000i) = (1010 + 990i)
    /// let ans = Complex::with_val(53, a.mul_add_ref(&b, &c));
    /// assert_eq!(ans, (1010, 990));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
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
    /// use rug::Complex;
    /// let a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) − (1000 + 1000i) = (−990 − 1010i)
    /// let mul_sub = a.mul_sub(&b, &c);
    /// assert_eq!(mul_sub, (-990, -1010));
    /// ```
    #[inline]
    pub fn mul_sub(mut self, mul: &Self, sub: &Self) -> Self {
        self.mul_sub_round(mul, sub, NEAREST2);
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
    /// use rug::Complex;
    /// let mut a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) − (1000 + 1000i) = (−990 − 1010i)
    /// a.mul_sub_mut(&b, &c);
    /// assert_eq!(a, (-990, -1010));
    /// ```
    #[inline]
    pub fn mul_sub_mut(&mut self, mul: &Self, sub: &Self) {
        self.mul_sub_round(mul, sub, NEAREST2);
    }

    /// Multiplies and subtracts in one fused operation, applying the
    /// specified rounding method with only one rounding error.
    ///
    /// `a.mul_sub_round(&b, &c, round)` produces a result like
    /// `ans.assign_round(&a * &b - &c, round)`, but stores the result
    /// in `a` using its precision rather than in another [`Complex`]
    /// number like `ans`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let mut a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) − (1000 + 1000i) = (−990 − 1010i)
    /// let dir = a.mul_sub_round(&b, &c, (Round::Nearest, Round::Nearest));
    /// assert_eq!(a, (-990, -1010));
    /// assert_eq!(dir, (Ordering::Equal, Ordering::Equal));
    /// ```
    ///
    /// [`Complex`]: #
    #[inline]
    pub fn mul_sub_round(&mut self, mul: &Self, sub: &Self, round: Round2) -> Ordering2 {
        xmpc::fma(self, (), mul, &*sub.as_neg(), round)
    }

    /// Multiplies and subtracts in one fused operation.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// `a.mul_sub_ref(&b, &c)` produces the exact same result as
    /// `&a * &b - &c`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let a = Complex::with_val(53, (10, 0));
    /// let b = Complex::with_val(53, (1, -1));
    /// let c = Complex::with_val(53, (1000, 1000));
    /// // (10 + 0i) × (1 − i) − (1000 + 1000i) = (−990 − 1010i)
    /// let ans = Complex::with_val(53, a.mul_sub_ref(&b, &c));
    /// assert_eq!(ans, (-990, -1010));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn mul_sub_ref<'a>(&'a self, mul: &'a Self, sub: &'a Self) -> SubMulFromIncomplete<'a> {
        self * mul - sub
    }

    /// Computes a projection onto the Riemann sphere, rounding to
    /// the nearest.
    ///
    /// If no parts of the number are infinite, the result is
    /// unchanged. If any part is infinite, the real part of the
    /// result is set to +∞ and the imaginary part of the result
    /// is set to 0 with the same sign as the imaginary part of
    /// the input.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Complex;
    /// let c1 = Complex::with_val(53, (1.5, 2.5));
    /// let proj1 = c1.proj();
    /// assert_eq!(proj1, (1.5, 2.5));
    /// let c2 = Complex::with_val(53, (f64::NAN, f64::NEG_INFINITY));
    /// let proj2 = c2.proj();
    /// assert_eq!(proj2, (f64::INFINITY, 0.0));
    /// // imaginary was negative, so now it is minus zero
    /// assert!(proj2.imag().is_sign_negative());
    /// ```
    #[inline]
    pub fn proj(mut self) -> Self {
        self.proj_mut();
        self
    }

    /// Computes a projection onto the Riemann sphere, rounding to
    /// the nearest.
    ///
    /// If no parts of the number are infinite, the result is
    /// unchanged. If any part is infinite, the real part of the
    /// result is set to +∞ and the imaginary part of the result
    /// is set to 0 with the same sign as the imaginary part of
    /// the input.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Complex;
    /// let mut c1 = Complex::with_val(53, (1.5, 2.5));
    /// c1.proj_mut();
    /// assert_eq!(c1, (1.5, 2.5));
    /// let mut c2 = Complex::with_val(53, (f64::NAN, f64::NEG_INFINITY));
    /// c2.proj_mut();
    /// assert_eq!(c2, (f64::INFINITY, 0.0));
    /// // imaginary was negative, so now it is minus zero
    /// assert!(c2.imag().is_sign_negative());
    /// ```
    #[inline]
    pub fn proj_mut(&mut self) {
        xmpc::proj(self, (), NEAREST2);
    }

    /// Computes the projection onto the Riemann sphere.
    ///
    /// If no parts of the number are infinite, the result is
    /// unchanged. If any part is infinite, the real part of the
    /// result is set to +∞ and the imaginary part of the result
    /// is set to 0 with the same sign as the imaginary part of
    /// the input.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Complex;
    /// let c1 = Complex::with_val(53, (f64::INFINITY, 50));
    /// let proj1 = Complex::with_val(53, c1.proj_ref());
    /// assert_eq!(proj1, (f64::INFINITY, 0.0));
    /// let c2 = Complex::with_val(53, (f64::NAN, f64::NEG_INFINITY));
    /// let proj2 = Complex::with_val(53, c2.proj_ref());
    /// assert_eq!(proj2, (f64::INFINITY, 0.0));
    /// // imaginary was negative, so now it is minus zero
    /// assert!(proj2.imag().is_sign_negative());
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn proj_ref(&self) -> ProjIncomplete<'_> {
        ProjIncomplete { ref_self: self }
    }

    /// Computes the square, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, -2));
    /// // (1 − 2i) squared is (−3 − 4i)
    /// let square = c.square();
    /// assert_eq!(square, (-3, -4));
    /// ```
    #[inline]
    pub fn square(mut self) -> Self {
        self.square_round(NEAREST2);
        self
    }

    /// Computes the square, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, -2));
    /// // (1 − 2i) squared is (−3 − 4i)
    /// c.square_mut();
    /// assert_eq!(c, (-3, -4));
    /// ```
    #[inline]
    pub fn square_mut(&mut self) {
        self.square_round(NEAREST2);
    }

    /// Computes the square, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let mut c = Complex::with_val(4, (1.25, 1.25));
    /// // (1.25 + 1.25i) squared is (0 + 3.125i).
    /// // With 4 bits of precision, 3.125 is rounded down to 3.
    /// let dir = c.square_round((Round::Down, Round::Down));
    /// assert_eq!(c, (0, 3));
    /// assert_eq!(dir, (Ordering::Equal, Ordering::Less));
    /// ```
    #[inline]
    pub fn square_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::sqr(self, (), round)
    }

    /// Computes the square.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let c = Complex::with_val(53, (1.25, 1.25));
    /// // (1.25 + 1.25i) squared is (0 + 3.125i).
    /// let r = c.square_ref();
    /// // With 4 bits of precision, 3.125 is rounded down to 3.
    /// let round = (Round::Down, Round::Down);
    /// let (square, dir) = Complex::with_val_round(4, r, round);
    /// assert_eq!(square, (0, 3));
    /// assert_eq!(dir, (Ordering::Equal, Ordering::Less));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
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
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (-1, 0));
    /// // square root of (−1 + 0i) is (0 + i)
    /// let sqrt = c.sqrt();
    /// assert_eq!(sqrt, (0, 1));
    /// ```
    #[inline]
    pub fn sqrt(mut self) -> Self {
        self.sqrt_round(NEAREST2);
        self
    }

    /// Computes the square root, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (-1, 0));
    /// // square root of (−1 + 0i) is (0 + i)
    /// c.sqrt_mut();
    /// assert_eq!(c, (0, 1));
    /// ```
    #[inline]
    pub fn sqrt_mut(&mut self) {
        self.sqrt_round(NEAREST2);
    }

    /// Computes the square root, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let mut c = Complex::with_val(4, (2, 2.25));
    /// // Square root of (2 + 2.25i) is (1.5828 + 0.7108i).
    /// // Nearest with 4 bits of precision: (1.625 + 0.6875i)
    /// let dir = c.sqrt_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (1.625, 0.6875));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Less));
    /// ```
    #[inline]
    pub fn sqrt_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::sqrt(self, (), round)
    }

    /// Computes the square root.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let c = Complex::with_val(53, (2, 2.25));
    /// // Square root of (2 + 2.25i) is (1.5828 + 0.7108i).
    /// let r = c.sqrt_ref();
    /// // Nearest with 4 bits of precision: (1.625 + 0.6875i)
    /// let nearest = (Round::Nearest, Round::Nearest);
    /// let (sqrt, dir) = Complex::with_val_round(4, r, nearest);
    /// assert_eq!(sqrt, (1.625, 0.6875));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Less));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sqrt_ref(&self) -> SqrtIncomplete<'_> {
        SqrtIncomplete { ref_self: self }
    }

    /// Computes the complex conjugate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1.5, 2.5));
    /// let conj = c.conj();
    /// assert_eq!(conj, (1.5, -2.5));
    /// ```
    #[inline]
    pub fn conj(mut self) -> Self {
        self.conj_mut();
        self
    }

    /// Computes the complex conjugate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1.5, 2.5));
    /// c.conj_mut();
    /// assert_eq!(c, (1.5, -2.5));
    /// ```
    #[inline]
    pub fn conj_mut(&mut self) {
        xmpc::conj(self, (), NEAREST2);
    }

    /// Computes the complex conjugate.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1.5, 2.5));
    /// let conj = Complex::with_val(53, c.conj_ref());
    /// assert_eq!(conj, (1.5, -2.5));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn conj_ref(&self) -> ConjIncomplete<'_> {
        ConjIncomplete { ref_self: self }
    }

    /// Computes the absolute value, rounding to the nearest.
    ///
    /// The real part is set to the absolute value and the imaginary
    /// part is set to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (30, 40));
    /// let abs = c.abs();
    /// assert_eq!(abs, 50);
    /// ```
    #[inline]
    pub fn abs(mut self) -> Complex {
        self.abs_mut();
        self
    }

    /// Computes the absolute value, rounding to the nearest.
    ///
    /// The real part is set to the absolute value and the imaginary
    /// part is set to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (30, 40));
    /// c.abs_mut();
    /// assert_eq!(c, (50, 0));
    /// ```
    #[inline]
    pub fn abs_mut(&mut self) {
        self.abs_round(NEAREST2);
    }

    /// Computes the absolute value, applying the specified rounding
    /// method.
    ///
    /// The real part is set to the absolute value and the imaginary
    /// part is set to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (30, 40));
    /// // 50 rounded up using 4 bits is 52
    /// let dir = c.abs_round((Round::Up, Round::Up));
    /// assert_eq!(c, (52, 0));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Equal));
    /// ```
    #[inline]
    pub fn abs_round(&mut self, round: Round2) -> Ordering2 {
        // Use mpfr::hypot rather than mpc::abs because mpc::abs does not
        // document that the result can be stored in one of its parts.
        let (real, imag) = self.as_mut_real_imag();
        let dir_re = real.hypot_round(imag, round.0);
        let dir_im = imag.assign_round(Special::Zero, round.1);
        (dir_re, dir_im)
    }

    /// Computes the absolute value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Complex, Float};
    /// let c = Complex::with_val(53, (30, 40));
    /// let f = Float::with_val(53, c.abs_ref());
    /// assert_eq!(f, 50);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [`Float`]: struct.Float.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn abs_ref(&self) -> AbsIncomplete<'_> {
        AbsIncomplete { ref_self: self }
    }

    /// Computes the argument, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (4, 3));
    /// let f = c.arg();
    /// assert_eq!(f, 0.75_f64.atan());
    /// ```
    ///
    /// Special values are handled like atan2 in IEEE 754-2008.
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (40, 30));
    /// let arg = c.arg();
    /// assert_eq!(arg, (0.75_f64.atan(), 0));
    /// ```
    #[inline]
    pub fn arg(mut self) -> Complex {
        self.arg_round(NEAREST2);
        self
    }

    /// Computes the argument, rounding to the nearest.
    ///
    /// The real part is set to the argument and the imaginary part is
    /// set to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (40, 30));
    /// c.arg_mut();
    /// assert_eq!(c, (0.75_f64.atan(), 0));
    /// ```
    #[inline]
    pub fn arg_mut(&mut self) {
        self.arg_round(NEAREST2);
    }

    /// Computes the argument, applying the specified rounding method.
    ///
    /// The real part is set to the argument and the imaginary part is
    /// set to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // use only 4 bits of precision
    /// let mut c = Complex::with_val(4, (3, 4));
    /// // arg(3 + 4i) = 0.9316.
    /// // 0.9316 rounded to the nearest is 0.9375.
    /// let dir = c.arg_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.9375, 0));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Equal));
    /// ```
    #[inline]
    pub fn arg_round(&mut self, round: Round2) -> Ordering2 {
        let (re, im) = self.as_mut_real_imag();
        let dir_re = xmpfr::atan2(re, &*im, (), round.0);
        im.assign(Special::Zero);
        (dir_re, Ordering::Equal)
    }

    /// Computes the argument.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::{Assign, Complex, Float};
    /// // f has precision 53, just like f64, so PI constants match.
    /// let mut arg = Float::new(53);
    /// let c_pos = Complex::with_val(53, 1);
    /// arg.assign(c_pos.arg_ref());
    /// assert!(arg.is_zero());
    /// let c_neg = Complex::with_val(53, -1.3);
    /// arg.assign(c_neg.arg_ref());
    /// assert_eq!(arg, f64::consts::PI);
    /// let c_pi_4 = Complex::with_val(53, (1.333, 1.333));
    /// arg.assign(c_pi_4.arg_ref());
    /// assert_eq!(arg, f64::consts::FRAC_PI_4);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [`Float`]: struct.Float.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn arg_ref(&self) -> ArgIncomplete<'_> {
        ArgIncomplete { ref_self: self }
    }

    /// Multiplies the complex number by ±<i>i</i>, rounding to
    /// the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (13, 24));
    /// let rot1 = c.mul_i(false);
    /// assert_eq!(rot1, (-24, 13));
    /// let rot2 = rot1.mul_i(false);
    /// assert_eq!(rot2, (-13, -24));
    /// let rot2_less1 = rot2.mul_i(true);
    /// assert_eq!(rot2_less1, (-24, 13));
    /// ```
    #[inline]
    pub fn mul_i(mut self, negative: bool) -> Self {
        self.mul_i_round(negative, NEAREST2);
        self
    }

    /// Multiplies the complex number by ±<i>i</i>, rounding to
    /// the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (13, 24));
    /// c.mul_i_mut(false);
    /// assert_eq!(c, (-24, 13));
    /// c.mul_i_mut(false);
    /// assert_eq!(c, (-13, -24));
    /// c.mul_i_mut(true);
    /// assert_eq!(c, (-24, 13));
    /// ```
    #[inline]
    pub fn mul_i_mut(&mut self, negative: bool) {
        self.mul_i_round(negative, NEAREST2);
    }

    /// Multiplies the complex number by ±<i>i</i>, applying the
    /// specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // only 4 bits of precision for imaginary part
    /// let mut c = Complex::with_val((53, 4), (127, 15));
    /// assert_eq!(c, (127, 15));
    /// let dir = c.mul_i_round(false, (Round::Down, Round::Down));
    /// assert_eq!(c, (-15, 120));
    /// assert_eq!(dir, (Ordering::Equal, Ordering::Less));
    /// let dir = c.mul_i_round(true, (Round::Down, Round::Down));
    /// assert_eq!(c, (120, 15));
    /// assert_eq!(dir, (Ordering::Equal, Ordering::Equal));
    /// ```
    #[inline]
    pub fn mul_i_round(&mut self, negative: bool, round: Round2) -> Ordering2 {
        xmpc::mul_i(self, (), negative, round)
    }

    /// Multiplies the complex number by ±<i>i</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (13, 24));
    /// let rotated = Complex::with_val(53, c.mul_i_ref(false));
    /// assert_eq!(rotated, (-24, 13));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn mul_i_ref(&self, negative: bool) -> MulIIncomplete<'_> {
        MulIIncomplete {
            ref_self: self,
            negative,
        }
    }

    /// Computes the reciprocal, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// // 1/(1 + i) = (0.5 − 0.5i)
    /// let recip = c.recip();
    /// assert_eq!(recip, (0.5, -0.5));
    /// ```
    #[inline]
    pub fn recip(mut self) -> Self {
        self.recip_round(NEAREST2);
        self
    }

    /// Computes the reciprocal, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// // 1/(1 + i) = (0.5 − 0.5i)
    /// c.recip_mut();
    /// assert_eq!(c, (0.5, -0.5));
    /// ```
    #[inline]
    pub fn recip_mut(&mut self) {
        self.recip_round(NEAREST2);
    }

    /// Computes the reciprocal, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// let mut c = Complex::with_val(4, (1, 2));
    /// // 1/(1 + 2i) = (0.2 − 0.4i), binary (0.00110011..., −0.01100110...)
    /// // 4 bits of precision: (0.001101, −0.01101) = (13/64, −13/32)
    /// let dir = c.recip_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (13.0/64.0, -13.0/32.0));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Less));
    /// ```
    #[inline]
    pub fn recip_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::recip(self, (), round)
    }

    /// Computes the reciprocal.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// // 1/(1 + i) = (0.5 − 0.5i)
    /// let recip = Complex::with_val(53, c.recip_ref());
    /// assert_eq!(recip, (0.5, -0.5));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn recip_ref(&self) -> RecipIncomplete<'_> {
        RecipIncomplete { ref_self: self }
    }

    /// Computes the norm, that is the square of the absolute value,
    /// rounding it to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (3, 4));
    /// let norm = c.norm();
    /// assert_eq!(norm, 25);
    /// ```
    #[inline]
    pub fn norm(mut self) -> Complex {
        self.norm_round(NEAREST2);
        self
    }

    /// Computes the norm, that is the square of the absolute value,
    /// rounding to the nearest.
    ///
    /// The real part is set to the norm and the imaginary part is set
    /// to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (3, 4));
    /// c.norm_mut();
    /// assert_eq!(c, (25, 0));
    /// ```
    #[inline]
    pub fn norm_mut(&mut self) {
        self.norm_round(NEAREST2);
    }

    /// Computes the norm, that is the square of the absolute value,
    /// applying the specified rounding method.
    ///
    /// The real part is set to the norm and the imaginary part is set
    /// to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // use only 4 bits of precision
    /// let mut c = Complex::with_val(4, (3, 4));
    /// // 25 rounded up using 4 bits is 26
    /// let dir = c.norm_round((Round::Up, Round::Up));
    /// assert_eq!(c, (26, 0));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Equal));
    /// ```
    #[inline]
    pub fn norm_round(&mut self, round: Round2) -> Ordering2 {
        // Since mpc::norm mpc::norm does not document that the result
        // can be stored in one of its parts, we allocate a new Float.
        let (norm, dir_re) = Float::with_val_round(self.real().prec(), self.norm_ref(), round.0);
        let (real, imag) = self.as_mut_real_imag();
        *real = norm;
        let dir_im = imag.assign_round(Special::Zero, round.1);
        (dir_re, dir_im)
    }

    /// Computes the norm, that is the square of the absolute value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Float][`Float`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Complex, Float};
    /// let c = Complex::with_val(53, (3, 4));
    /// let f = Float::with_val(53, c.norm_ref());
    /// assert_eq!(f, 25);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [`Float`]: struct.Float.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn norm_ref(&self) -> NormIncomplete<'_> {
        NormIncomplete { ref_self: self }
    }

    /// Computes the natural logarithm, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1.5, -0.5));
    /// let ln = c.ln();
    /// let expected = Complex::with_val(53, (0.4581, -0.3218));
    /// assert!(*(ln - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn ln(mut self) -> Self {
        self.ln_round(NEAREST2);
        self
    }

    /// Computes the natural logarithm, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1.5, -0.5));
    /// c.ln_mut();
    /// let expected = Complex::with_val(53, (0.4581, -0.3218));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn ln_mut(&mut self) {
        self.ln_round(NEAREST2);
    }

    /// Computes the natural logarithm, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1.5, -0.5));
    /// // ln(1.5 − 0.5i) = (0.4581 − 0.3218i)
    /// // using 4 significant bits: (0.46875 − 0.3125i)
    /// let dir = c.ln_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.46875, -0.3125));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Greater));
    /// ```
    #[inline]
    pub fn ln_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::log(self, (), round)
    }

    /// Computes the natural logarithm;
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1.5, -0.5));
    /// let ln = Complex::with_val(53, c.ln_ref());
    /// let expected = Complex::with_val(53, (0.4581, -0.3218));
    /// assert!(*(ln - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn ln_ref(&self) -> LnIncomplete<'_> {
        LnIncomplete { ref_self: self }
    }

    /// Computes the logarithm to base 10, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1.5, -0.5));
    /// let log10 = c.log10();
    /// let expected = Complex::with_val(53, (0.1990, -0.1397));
    /// assert!(*(log10 - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn log10(mut self) -> Self {
        self.log10_round(NEAREST2);
        self
    }

    /// Computes the logarithm to base 10, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1.5, -0.5));
    /// c.log10_mut();
    /// let expected = Complex::with_val(53, (0.1990, -0.1397));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn log10_mut(&mut self) {
        self.log10_round(NEAREST2);
    }

    /// Computes the logarithm to base 10, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1.5, -0.5));
    /// // log10(1.5 − 0.5i) = (0.1990 − 0.1397i)
    /// // using 4 significant bits: (0.203125 − 0.140625i)
    /// let dir = c.log10_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.203125, -0.140625));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Less));
    /// ```
    #[inline]
    pub fn log10_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::log10(self, (), round)
    }

    /// Computes the logarithm to base 10.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1.5, -0.5));
    /// let log10 = Complex::with_val(53, c.log10_ref());
    /// let expected = Complex::with_val(53, (0.1990, -0.1397));
    /// assert!(*(log10 - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn log10_ref(&self) -> Log10Incomplete<'_> {
        Log10Incomplete { ref_self: self }
    }

    /// Generates a root of unity, rounding to the nearest.
    ///
    /// The generated number is the <i>n</i>th root of unity
    /// raised to the power <i>k</i>, that is its magnitude is 1
    /// and its argument is 2π<i>k</i>/<i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let r = Complex::root_of_unity(3, 2);
    /// let c = Complex::with_val(53, r);
    /// let expected = Complex::with_val(53, (-0.5, -0.8660));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn root_of_unity(n: u32, k: u32) -> RootOfUnityIncomplete {
        RootOfUnityIncomplete { n, k }
    }

    /// Computes the exponential, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (0.5, -0.75));
    /// let exp = c.exp();
    /// let expected = Complex::with_val(53, (1.2064, -1.1238));
    /// assert!(*(exp - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn exp(mut self) -> Self {
        self.exp_round(NEAREST2);
        self
    }

    /// Computes the exponential, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (0.5, -0.75));
    /// c.exp_mut();
    /// let expected = Complex::with_val(53, (1.2064, -1.1238));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn exp_mut(&mut self) {
        self.exp_round(NEAREST2);
    }

    /// Computes the exponential, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (0.5, -0.75));
    /// // exp(0.5 − 0.75i) = (1.2064 − 1.1238i)
    /// // using 4 significant bits: (1.25 − 1.125)
    /// let dir = c.exp_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (1.25, -1.125));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Less));
    /// ```
    #[inline]
    pub fn exp_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::exp(self, (), round)
    }

    /// Computes the exponential.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (0.5, -0.75));
    /// let exp = Complex::with_val(53, c.exp_ref());
    /// let expected = Complex::with_val(53, (1.2064, -1.1238));
    /// assert!(*(exp - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn exp_ref(&self) -> ExpIncomplete<'_> {
        ExpIncomplete { ref_self: self }
    }

    /// Computes the sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let sin = c.sin();
    /// let expected = Complex::with_val(53, (1.2985, 0.6350));
    /// assert!(*(sin - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn sin(mut self) -> Self {
        self.sin_round(NEAREST2);
        self
    }

    /// Computes the sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.sin_mut();
    /// let expected = Complex::with_val(53, (1.2985, 0.6350));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn sin_mut(&mut self) {
        self.sin_round(NEAREST2);
    }

    /// Computes the sine, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // sin(1 + i) = (1.2985 + 0.6350i)
    /// // using 4 significant bits: (1.25 + 0.625i)
    /// let dir = c.sin_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (1.25, 0.625));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Less));
    /// ```
    #[inline]
    pub fn sin_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::sin(self, (), round)
    }

    /// Computes the sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let sin = Complex::with_val(53, c.sin_ref());
    /// let expected = Complex::with_val(53, (1.2985, 0.6350));
    /// assert!(*(sin - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
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
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let cos = c.cos();
    /// let expected = Complex::with_val(53, (0.8337, -0.9889));
    /// assert!(*(cos - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn cos(mut self) -> Self {
        self.cos_round(NEAREST2);
        self
    }

    /// Computes the cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.cos_mut();
    /// let expected = Complex::with_val(53, (0.8337, -0.9889));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn cos_mut(&mut self) {
        self.cos_round(NEAREST2);
    }

    /// Computes the cosine, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // cos(1 + i) = (0.8337 − 0.9889i)
    /// // using 4 significant bits: (0.8125 − i)
    /// let dir = c.cos_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.8125, -1));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Less));
    /// ```
    #[inline]
    pub fn cos_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::cos(self, (), round)
    }

    /// Computes the cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let cos = Complex::with_val(53, c.cos_ref());
    /// let expected = Complex::with_val(53, (0.8337, -0.9889));
    /// assert!(*(cos - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn cos_ref(&self) -> CosIncomplete<'_> {
        CosIncomplete { ref_self: self }
    }

    /// Computes the sine and cosine of `self`, rounding to the
    /// nearest.
    ///
    /// The sine keeps the precision of `self` while the cosine
    /// keeps the precision of `cos`.
    ///
    /// The initial value of `cos` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let (sin, cos) = c.sin_cos(Complex::new(53));
    /// let expected_sin = Complex::with_val(53, (1.2985, 0.6350));
    /// let expected_cos = Complex::with_val(53, (0.8337, -0.9889));
    /// assert!(*(sin - expected_sin).abs().real() < 0.0001);
    /// assert!(*(cos - expected_cos).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn sin_cos(mut self, mut cos: Self) -> (Self, Self) {
        self.sin_cos_round(&mut cos, NEAREST2);
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
    /// use rug::Complex;
    /// let mut sin = Complex::with_val(53, (1, 1));
    /// let mut cos = Complex::new(53);
    /// sin.sin_cos_mut(&mut cos);
    /// let expected_sin = Complex::with_val(53, (1.2985, 0.6350));
    /// let expected_cos = Complex::with_val(53, (0.8337, -0.9889));
    /// assert!(*(sin - expected_sin).abs().real() < 0.0001);
    /// assert!(*(cos - expected_cos).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn sin_cos_mut(&mut self, cos: &mut Self) {
        self.sin_cos_round(cos, NEAREST2);
    }

    /// Computes the sine and cosine of `self`, applying the
    /// specified rounding methods.
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
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut sin = Complex::with_val(4, (1, 1));
    /// let mut cos = Complex::new(4);
    /// // sin(1 + i) = (1.2985 + 0.6350)
    /// // using 4 significant bits: (1.25 + 0.625i)
    /// // cos(1 + i) = (0.8337 − 0.9889i)
    /// // using 4 significant bits: (0.8125 − i)
    /// let (dir_sin, dir_cos) =
    ///     sin.sin_cos_round(&mut cos, (Round::Nearest, Round::Nearest));
    /// assert_eq!(sin, (1.25, 0.625));
    /// assert_eq!(dir_sin, (Ordering::Less, Ordering::Less));
    /// assert_eq!(cos, (0.8125, -1));
    /// assert_eq!(dir_cos, (Ordering::Less, Ordering::Less));
    /// ```
    #[inline]
    pub fn sin_cos_round(&mut self, cos: &mut Self, round: Round2) -> (Ordering2, Ordering2) {
        xmpc::sin_cos(self, cos, (), round)
    }

    /// Computes the sine and cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Complex][`Complex`],
    ///     [Complex][`Complex`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Complex][`Complex`],
    ///     &amp;mut [Complex][`Complex`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple][Complex][`Complex`],
    ///     [Complex][`Complex`][)][tuple]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Complex][`Complex`],
    ///     &amp;mut [Complex][`Complex`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, ops::AssignRound, Assign, Complex};
    /// let phase = Complex::with_val(53, (1, 1));
    ///
    /// let (mut sin, mut cos) = (Complex::new(53), Complex::new(53));
    /// let sin_cos = phase.sin_cos_ref();
    /// (&mut sin, &mut cos).assign(sin_cos);
    /// let expected_sin = Complex::with_val(53, (1.2985, 0.6350));
    /// let expected_cos = Complex::with_val(53, (0.8337, -0.9889));
    /// assert!(*(sin - expected_sin).abs().real() < 0.0001);
    /// assert!(*(cos - expected_cos).abs().real() < 0.0001);
    ///
    /// // using 4 significant bits: sin = (1.25 + 0.625i)
    /// // using 4 significant bits: cos = (0.8125 − i)
    /// let (mut sin_4, mut cos_4) = (Complex::new(4), Complex::new(4));
    /// let sin_cos = phase.sin_cos_ref();
    /// let (dir_sin, dir_cos) = (&mut sin_4, &mut cos_4)
    ///     .assign_round(sin_cos, (Round::Nearest, Round::Nearest));
    /// assert_eq!(sin_4, (1.25, 0.625));
    /// assert_eq!(dir_sin, (Ordering::Less, Ordering::Less));
    /// assert_eq!(cos_4, (0.8125, -1));
    /// assert_eq!(dir_cos, (Ordering::Less, Ordering::Less));
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn sin_cos_ref(&self) -> SinCosIncomplete<'_> {
        SinCosIncomplete { ref_self: self }
    }

    /// Computes the tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let tan = c.tan();
    /// let expected = Complex::with_val(53, (0.2718, 1.0839));
    /// assert!(*(tan - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn tan(mut self) -> Self {
        self.tan_round(NEAREST2);
        self
    }

    /// Computes the tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.tan_mut();
    /// let expected = Complex::with_val(53, (0.2718, 1.0839));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn tan_mut(&mut self) {
        self.tan_round(NEAREST2);
    }

    /// Computes the tangent, applying the specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // tan(1 + i) = (0.2718 + 1.0839)
    /// // using 4 significant bits: (0.28125 + 1.125i)
    /// let dir = c.tan_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.28125, 1.125));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Greater));
    /// ```
    #[inline]
    pub fn tan_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::tan(self, (), round)
    }

    /// Computes the tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let tan = Complex::with_val(53, c.tan_ref());
    /// let expected = Complex::with_val(53, (0.2718, 1.0839));
    /// assert!(*(tan - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn tan_ref(&self) -> TanIncomplete<'_> {
        TanIncomplete { ref_self: self }
    }

    /// Computes the hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let sinh = c.sinh();
    /// let expected = Complex::with_val(53, (0.6350, 1.2985));
    /// assert!(*(sinh - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn sinh(mut self) -> Self {
        self.sinh_round(NEAREST2);
        self
    }

    /// Computes the hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.sinh_mut();
    /// let expected = Complex::with_val(53, (0.6350, 1.2985));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn sinh_mut(&mut self) {
        self.sinh_round(NEAREST2);
    }

    /// Computes the hyperbolic sine, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // sinh(1 + i) = (0.6350 + 1.2985i)
    /// // using 4 significant bits: (0.625 + 1.25i)
    /// let dir = c.sinh_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.625, 1.25));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Less));
    /// ```
    #[inline]
    pub fn sinh_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::sinh(self, (), round)
    }

    /// Computes the hyperbolic sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let sinh = Complex::with_val(53, c.sinh_ref());
    /// let expected = Complex::with_val(53, (0.6350, 1.2985));
    /// assert!(*(sinh - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
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
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let cosh = c.cosh();
    /// let expected = Complex::with_val(53, (0.8337, 0.9889));
    /// assert!(*(cosh - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn cosh(mut self) -> Self {
        self.cosh_round(NEAREST2);
        self
    }

    /// Computes the hyperbolic cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.cosh_mut();
    /// let expected = Complex::with_val(53, (0.8337, 0.9889));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn cosh_mut(&mut self) {
        self.cosh_round(NEAREST2);
    }

    /// Computes the hyperbolic cosine, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // cosh(1 + i) = (0.8337 + 0.9889)
    /// // using 4 significant bits: (0.8125 + i)
    /// let dir = c.cosh_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.8125, 1));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Greater));
    /// ```
    #[inline]
    pub fn cosh_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::cosh(self, (), round)
    }

    /// Computes the hyperbolic cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let cosh = Complex::with_val(53, c.cosh_ref());
    /// let expected = Complex::with_val(53, (0.8337, 0.9889));
    /// assert!(*(cosh - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
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
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let tanh = c.tanh();
    /// let expected = Complex::with_val(53, (1.0839, 0.2718));
    /// assert!(*(tanh - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn tanh(mut self) -> Self {
        self.tanh_round(NEAREST2);
        self
    }

    /// Computes the hyperbolic tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.tanh_mut();
    /// let expected = Complex::with_val(53, (1.0839, 0.2718));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn tanh_mut(&mut self) {
        self.tanh_round(NEAREST2);
    }

    /// Computes the hyperbolic tangent, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // tanh(1 + i) = (1.0839 + 0.2718i)
    /// // using 4 significant bits: (1.125 + 0.28125i)
    /// let dir = c.tanh_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (1.125, 0.28125));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Greater));
    /// ```
    #[inline]
    pub fn tanh_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::tanh(self, (), round)
    }

    /// Computes the hyperbolic tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let tanh = Complex::with_val(53, c.tanh_ref());
    /// let expected = Complex::with_val(53, (1.0839, 0.2718));
    /// assert!(*(tanh - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn tanh_ref(&self) -> TanhIncomplete<'_> {
        TanhIncomplete { ref_self: self }
    }

    /// Computes the inverse sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let asin = c.asin();
    /// let expected = Complex::with_val(53, (0.6662, 1.0613));
    /// assert!(*(asin - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn asin(mut self) -> Self {
        self.asin_round(NEAREST2);
        self
    }

    /// Computes the inverse sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.asin_mut();
    /// let expected = Complex::with_val(53, (0.6662, 1.0613));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn asin_mut(&mut self) {
        self.asin_round(NEAREST2);
    }

    /// Computes the inverse sine, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // asin(1 + i) = (0.6662 + 1.0613i)
    /// // using 4 significant bits: (0.6875 + i)
    /// let dir = c.asin_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.6875, 1));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Less));
    /// ```
    #[inline]
    pub fn asin_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::asin(self, (), round)
    }

    /// Computes the inverse sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let asin = Complex::with_val(53, c.asin_ref());
    /// let expected = Complex::with_val(53, (0.6662, 1.0613));
    /// assert!(*(asin - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn asin_ref(&self) -> AsinIncomplete<'_> {
        AsinIncomplete { ref_self: self }
    }

    /// Computes the inverse cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let acos = c.acos();
    /// let expected = Complex::with_val(53, (0.9046, -1.0613));
    /// assert!(*(acos - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn acos(mut self) -> Self {
        self.acos_round(NEAREST2);
        self
    }

    /// Computes the inverse cosine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.acos_mut();
    /// let expected = Complex::with_val(53, (0.9046, -1.0613));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn acos_mut(&mut self) {
        self.acos_round(NEAREST2);
    }

    /// Computes the inverse cosine, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // acos(1 + i) = (0.9046 − 1.0613i)
    /// // using 4 significant bits: (0.875 − i)
    /// let dir = c.acos_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.875, -1));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Greater));
    /// ```
    #[inline]
    pub fn acos_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::acos(self, (), round)
    }

    /// Computes the inverse cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let acos = Complex::with_val(53, c.acos_ref());
    /// let expected = Complex::with_val(53, (0.9046, -1.0613));
    /// assert!(*(acos - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn acos_ref(&self) -> AcosIncomplete<'_> {
        AcosIncomplete { ref_self: self }
    }

    /// Computes the inverse tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let atan = c.atan();
    /// let expected = Complex::with_val(53, (1.0172, 0.4024));
    /// assert!(*(atan - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn atan(mut self) -> Self {
        self.atan_round(NEAREST2);
        self
    }

    /// Computes the inverse tangent, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.atan_mut();
    /// let expected = Complex::with_val(53, (1.0172, 0.4024));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn atan_mut(&mut self) {
        self.atan_round(NEAREST2);
    }

    /// Computes the inverse tangent, applying the specified rounding
    /// method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // atan(1 + i) = (1.0172 + 0.4024i)
    /// // using 4 significant bits: (1 + 0.40625i)
    /// let dir = c.atan_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (1, 0.40625));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Greater));
    /// ```
    #[inline]
    pub fn atan_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::atan(self, (), round)
    }

    /// Computes the inverse tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let atan = Complex::with_val(53, c.atan_ref());
    /// let expected = Complex::with_val(53, (1.0172, 0.4024));
    /// assert!(*(atan - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn atan_ref(&self) -> AtanIncomplete<'_> {
        AtanIncomplete { ref_self: self }
    }

    /// Computes the inverse hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let asinh = c.asinh();
    /// let expected = Complex::with_val(53, (1.0613, 0.6662));
    /// assert!(*(asinh - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn asinh(mut self) -> Self {
        self.asinh_round(NEAREST2);
        self
    }

    /// Computes the inverse hyperbolic sine, rounding to the nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.asinh_mut();
    /// let expected = Complex::with_val(53, (1.0613, 0.6662));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn asinh_mut(&mut self) {
        self.asinh_round(NEAREST2);
    }

    /// Computes the inverse hyperbolic sine, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // asinh(1 + i) = (1.0613 + 0.6662i)
    /// // using 4 significant bits: (1 + 0.6875i)
    /// let dir = c.asinh_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (1, 0.6875));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Greater));
    /// ```
    #[inline]
    pub fn asinh_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::asinh(self, (), round)
    }

    /// Computes the inverse hyperboic sine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let asinh = Complex::with_val(53, c.asinh_ref());
    /// let expected = Complex::with_val(53, (1.0613, 0.6662));
    /// assert!(*(asinh - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
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
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let acosh = c.acosh();
    /// let expected = Complex::with_val(53, (1.0613, 0.9046));
    /// assert!(*(acosh - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn acosh(mut self) -> Self {
        self.acosh_round(NEAREST2);
        self
    }

    /// Computes the inverse hyperbolic cosine, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.acosh_mut();
    /// let expected = Complex::with_val(53, (1.0613, 0.9046));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn acosh_mut(&mut self) {
        self.acosh_round(NEAREST2);
    }

    /// Computes the inverse hyperbolic cosine, applying the specified
    /// rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // acosh(1 + i) = (1.0613 + 0.9046i)
    /// // using 4 significant bits: (1 + 0.875i)
    /// let dir = c.acosh_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (1, 0.875));
    /// assert_eq!(dir, (Ordering::Less, Ordering::Less));
    /// ```
    #[inline]
    pub fn acosh_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::acosh(self, (), round)
    }

    /// Computes the inverse hyperbolic cosine.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let acosh = Complex::with_val(53, c.acosh_ref());
    /// let expected = Complex::with_val(53, (1.0613, 0.9046));
    /// assert!(*(acosh - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
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
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let atanh = c.atanh();
    /// let expected = Complex::with_val(53, (0.4024, 1.0172));
    /// assert!(*(atanh - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn atanh(mut self) -> Self {
        self.atanh_round(NEAREST2);
        self
    }

    /// Computes the inverse hyperbolic tangent, rounding to the
    /// nearest.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let mut c = Complex::with_val(53, (1, 1));
    /// c.atanh_mut();
    /// let expected = Complex::with_val(53, (0.4024, 1.0172));
    /// assert!(*(c - expected).abs().real() < 0.0001);
    /// ```
    #[inline]
    pub fn atanh_mut(&mut self) {
        self.atanh_round(NEAREST2);
    }

    /// Computes the inverse hyperbolic tangent, applying the
    /// specified rounding method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::{float::Round, Complex};
    /// // Use only 4 bits of precision to show rounding.
    /// let mut c = Complex::with_val(4, (1, 1));
    /// // atanh(1 + i) = (0.4024 + 1.0172i)
    /// // using 4 significant bits: (0.40625 + i)
    /// let dir = c.atanh_round((Round::Nearest, Round::Nearest));
    /// assert_eq!(c, (0.40625, 1));
    /// assert_eq!(dir, (Ordering::Greater, Ordering::Less));
    /// ```
    #[inline]
    pub fn atanh_round(&mut self, round: Round2) -> Ordering2 {
        xmpc::atanh(self, (), round)
    }

    /// Computes the inverse hyperbolic tangent.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Complex;
    /// let c = Complex::with_val(53, (1, 1));
    /// let atanh = Complex::with_val(53, c.atanh_ref());
    /// let expected = Complex::with_val(53, (0.4024, 1.0172));
    /// assert!(*(atanh - expected).abs().real() < 0.0001);
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn atanh_ref(&self) -> AtanhIncomplete<'_> {
        AtanhIncomplete { ref_self: self }
    }

    #[cfg(feature = "rand")]
    /// Generates a random complex number with both the real and
    /// imaginary parts in the range 0 ≤ <i>x</i> < 1.
    ///
    /// This is equivalent to generating a random integer in the range
    /// 0 ≤ <i>x</i> < 2<sup><i>p</i></sup> for each part, where
    /// 2<sup><i>p</i></sup> is two raised to the power of the
    /// precision, and then dividing the integer by
    /// 2<sup><i>p</i></sup>. The smallest non-zero result will thus
    /// be 2<sup>−<i>p</i></sup>, and will only have one bit set. In
    /// the smaller possible results, many bits will be zero, and not
    /// all the precision will be used.
    ///
    /// There is a corner case where the generated random number part
    /// is converted to NaN: if the precision is very large, the
    /// generated random number could have an exponent less than the
    /// allowed minimum exponent, and NaN is used to indicate this.
    /// For this to occur in practice, the minimum exponent has to be
    /// set to have a very small magnitude using the low-level MPFR
    /// interface, or the random number generator has to be designed
    /// specifically to trigger this case.
    ///
    /// <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    /// is implemented with the returned
    /// [incomplete-computation value][icv] as `Src`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Assign, Complex};
    /// let mut rand = RandState::new();
    /// let mut c = Complex::new(2);
    /// c.assign(Complex::random_bits(&mut rand));
    /// let (re, im) = c.into_real_imag();
    /// assert!(re == 0.0 || re == 0.25 || re == 0.5 || re == 0.75);
    /// assert!(im == 0.0 || im == 0.25 || im == 0.5 || im == 0.75);
    /// println!("0.0 ≤ {} < 1.0", re);
    /// println!("0.0 ≤ {} < 1.0", im);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_bits(rng: &mut dyn MutRandState) -> RandomBitsIncomplete {
        RandomBitsIncomplete { rng }
    }

    #[cfg(feature = "rand")]
    /// Generates a random complex number with both the real and
    /// imaginary parts in the continous range 0 ≤ <i>x</i> < 1, and
    /// rounds to the nearest.
    ///
    /// The result parts can be rounded up to be equal to one. Unlike
    /// the [`assign_random_bits`] method which generates a discrete
    /// random number at intervals depending on the precision, this
    /// method is equivalent to generating a continuous random number
    /// with infinite precision and then rounding the result. This
    /// means that even the smaller numbers will be using all the
    /// available precision bits, and rounding is performed in all
    /// cases, not in some corner case.
    ///
    /// Rounding directions for generated random numbers cannot be
    /// <code>[Ordering][`Ordering`]::[Equal][`Equal`]</code>,
    /// as the random numbers generated can be considered to have
    /// infinite precision before rounding.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///   * <code>[AssignRound][`AssignRound`]&lt;Src&gt; for [Complex][`Complex`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Complex};
    /// let mut rand = RandState::new();
    /// let c = Complex::with_val(2, Complex::random_cont(&mut rand));
    /// let (re, im) = c.into_real_imag();
    /// // The significand is either 0b10 or 0b11
    /// assert!(
    ///     re == 1.0
    ///         || re == 0.75
    ///         || re == 0.5
    ///         || re == 0.375
    ///         || re == 0.25
    ///         || re <= 0.1875
    /// );
    /// assert!(
    ///     im == 1.0
    ///         || im == 0.75
    ///         || im == 0.5
    ///         || im == 0.375
    ///         || im == 0.25
    ///         || im <= 0.1875
    /// );
    /// ```
    ///
    /// [`AssignRound`]: ops/trait.AssignRound.html
    /// [`Assign`]: trait.Assign.html
    /// [`Complex`]: #
    /// [`Equal`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html#variant.Equal
    /// [`Ordering`]: https://doc.rust-lang.org/nightly/core/cmp/enum.Ordering.html
    /// [`assign_random_bits`]: #method.assign_random_bits
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_cont(rng: &mut dyn MutRandState) -> RandomContIncomplete {
        RandomContIncomplete { rng }
    }
}

#[derive(Debug)]
pub struct SumIncomplete<'a, I>
where
    I: Iterator<Item = &'a Complex>,
{
    values: I,
}

impl<'a, I> AssignRound<SumIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = &'a Self>,
{
    type Round = Round2;
    type Ordering = Ordering2;
    #[inline]
    fn assign_round(&mut self, src: SumIncomplete<'a, I>, round: Round2) -> Ordering2 {
        xmpc::sum(self, src.values, round)
    }
}

impl<'a, I> Add<SumIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = &'a Self>,
{
    type Output = Self;
    #[inline]
    fn add(mut self, rhs: SumIncomplete<'a, I>) -> Self {
        self.add_assign_round(rhs, NEAREST2);
        self
    }
}

impl<'a, I> AddAssign<SumIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = &'a Self>,
{
    #[inline]
    fn add_assign(&mut self, rhs: SumIncomplete<'a, I>) {
        self.add_assign_round(rhs, NEAREST2);
    }
}

impl<'a, I> AddAssignRound<SumIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = &'a Self>,
{
    type Round = Round2;
    type Ordering = Ordering2;
    #[inline]
    fn add_assign_round(&mut self, src: SumIncomplete<'a, I>, round: Round2) -> Ordering2 {
        xmpc::sum_including_old(self, src.values, round)
    }
}

#[derive(Debug)]
pub struct DotIncomplete<'a, I>
where
    I: Iterator<Item = (&'a Complex, &'a Complex)>,
{
    values: I,
}

impl<'a, I> AssignRound<DotIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    type Round = Round2;
    type Ordering = Ordering2;
    fn assign_round(&mut self, src: DotIncomplete<'a, I>, round: Round2) -> Ordering2 {
        xmpc::dot(self, src.values, round)
    }
}

impl<'a, I> Add<DotIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    type Output = Self;
    #[inline]
    fn add(mut self, rhs: DotIncomplete<'a, I>) -> Self {
        self.add_assign_round(rhs, NEAREST2);
        self
    }
}

impl<'a, I> AddAssign<DotIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    #[inline]
    fn add_assign(&mut self, rhs: DotIncomplete<'a, I>) {
        self.add_assign_round(rhs, NEAREST2);
    }
}

impl<'a, I> AddAssignRound<DotIncomplete<'a, I>> for Complex
where
    I: Iterator<Item = (&'a Self, &'a Self)>,
{
    type Round = Round2;
    type Ordering = Ordering2;
    fn add_assign_round(&mut self, src: DotIncomplete<'a, I>, round: Round2) -> Ordering2 {
        xmpc::dot_including_old(self, src.values, round)
    }
}

ref_math_op1_complex! { xmpc::proj; struct ProjIncomplete {} }
ref_math_op1_complex! { xmpc::sqr; struct SquareIncomplete {} }
ref_math_op1_complex! { xmpc::sqrt; struct SqrtIncomplete {} }
ref_math_op1_complex! { xmpc::conj; struct ConjIncomplete {} }

#[derive(Debug)]
pub struct AbsIncomplete<'a> {
    ref_self: &'a Complex,
}

impl AssignRound<AbsIncomplete<'_>> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: AbsIncomplete<'_>, round: Round) -> Ordering {
        xmpc::abs(self, src.ref_self, round)
    }
}

#[derive(Debug)]
pub struct ArgIncomplete<'a> {
    ref_self: &'a Complex,
}

impl AssignRound<ArgIncomplete<'_>> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: ArgIncomplete<'_>, round: Round) -> Ordering {
        xmpc::arg(self, src.ref_self, round)
    }
}

ref_math_op1_complex! { xmpc::mul_i; struct MulIIncomplete { negative: bool } }
ref_math_op1_complex! { xmpc::recip; struct RecipIncomplete {} }

#[derive(Debug)]
pub struct NormIncomplete<'a> {
    ref_self: &'a Complex,
}

impl AssignRound<NormIncomplete<'_>> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: NormIncomplete<'_>, round: Round) -> Ordering {
        xmpc::norm(self, src.ref_self, round)
    }
}

ref_math_op1_complex! { xmpc::log; struct LnIncomplete {} }
ref_math_op1_complex! { xmpc::log10; struct Log10Incomplete {} }
ref_math_op0_complex! { xmpc::rootofunity; struct RootOfUnityIncomplete { n: u32, k: u32 } }
ref_math_op1_complex! { xmpc::exp; struct ExpIncomplete {} }
ref_math_op1_complex! { xmpc::sin; struct SinIncomplete {} }
ref_math_op1_complex! { xmpc::cos; struct CosIncomplete {} }
ref_math_op1_2_complex! { xmpc::sin_cos; struct SinCosIncomplete {} }
ref_math_op1_complex! { xmpc::tan; struct TanIncomplete {} }
ref_math_op1_complex! { xmpc::sinh; struct SinhIncomplete {} }
ref_math_op1_complex! { xmpc::cosh; struct CoshIncomplete {} }
ref_math_op1_complex! { xmpc::tanh; struct TanhIncomplete {} }
ref_math_op1_complex! { xmpc::asin; struct AsinIncomplete {} }
ref_math_op1_complex! { xmpc::acos; struct AcosIncomplete {} }
ref_math_op1_complex! { xmpc::atan; struct AtanIncomplete {} }
ref_math_op1_complex! { xmpc::asinh; struct AsinhIncomplete {} }
ref_math_op1_complex! { xmpc::acosh; struct AcoshIncomplete {} }
ref_math_op1_complex! { xmpc::atanh; struct AtanhIncomplete {} }

#[cfg(feature = "rand")]
pub struct RandomBitsIncomplete<'a> {
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl Assign<RandomBitsIncomplete<'_>> for Complex {
    #[inline]
    fn assign(&mut self, src: RandomBitsIncomplete) {
        self.mut_real().assign(Float::random_bits(src.rng));
        self.mut_imag().assign(Float::random_bits(src.rng));
    }
}

#[cfg(feature = "rand")]
pub struct RandomContIncomplete<'a> {
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl AssignRound<RandomContIncomplete<'_>> for Complex {
    type Round = Round2;
    type Ordering = Ordering2;
    #[inline]
    fn assign_round(&mut self, src: RandomContIncomplete, round: Round2) -> Ordering2 {
        let real_dir = self
            .mut_real()
            .assign_round(Float::random_cont(src.rng), round.0);
        let imag_dir = self
            .mut_imag()
            .assign_round(Float::random_cont(src.rng), round.1);
        (real_dir, imag_dir)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct BorrowComplex<'a> {
    inner: ManuallyDrop<Complex>,
    phantom: PhantomData<&'a Complex>,
}

impl BorrowComplex<'_> {
    // unsafe because the lifetime is obtained from return type
    pub(crate) unsafe fn from_raw<'a>(raw: mpc_t) -> BorrowComplex<'a> {
        BorrowComplex {
            inner: ManuallyDrop::new(Complex::from_raw(raw)),
            phantom: PhantomData,
        }
    }
}

impl Deref for BorrowComplex<'_> {
    type Target = Complex;
    #[inline]
    fn deref(&self) -> &Complex {
        &*self.inner
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Format {
    pub radix: i32,
    pub precision: Option<usize>,
    pub round: Round2,
    pub to_upper: bool,
    pub sign_plus: bool,
    pub prefix: &'static str,
    pub exp: ExpFormat,
}

impl Default for Format {
    #[inline]
    fn default() -> Format {
        Format {
            radix: 10,
            precision: None,
            round: Round2::default(),
            to_upper: false,
            sign_plus: false,
            prefix: "",
            exp: ExpFormat::Point,
        }
    }
}

pub(crate) fn append_to_string(s: &mut String, c: &Complex, f: Format) {
    let (re, im) = (c.real(), c.imag());
    let re_plus = f.sign_plus && re.is_sign_positive();
    let im_plus = f.sign_plus && im.is_sign_positive();
    let re_prefix = !f.prefix.is_empty() && re.is_finite();
    let im_prefix = !f.prefix.is_empty() && im.is_finite();
    let extra = 3
        + if re_plus { 1 } else { 0 }
        + if im_plus { 1 } else { 0 }
        + if re_prefix { f.prefix.len() } else { 0 }
        + if im_prefix { f.prefix.len() } else { 0 };
    let ff = FloatFormat {
        radix: f.radix,
        precision: f.precision,
        round: f.round.0,
        to_upper: f.to_upper,
        exp: f.exp,
    };
    let cap = big_float::req_chars(re, ff, extra);
    let cap = big_float::req_chars(im, ff, cap);
    s.reserve(cap);
    let reserved_ptr = s.as_ptr();
    s.push('(');
    if re_plus {
        s.push('+');
    }
    let prefix_start = s.len();
    if re_prefix {
        s.push_str(f.prefix);
    }
    let prefix_end = s.len();
    big_float::append_to_string(s, re, ff);
    if re_prefix && s.as_bytes()[prefix_end] == b'-' {
        unsafe {
            let bytes = slice::from_raw_parts_mut(s.as_mut_ptr(), s.len());
            bytes[prefix_start] = b'-';
            bytes[prefix_start + 1..=prefix_end].copy_from_slice(f.prefix.as_bytes());
        }
    }
    s.push(' ');
    if im_plus {
        s.push('+');
    }
    let prefix_start = s.len();
    if im_prefix {
        s.push_str(f.prefix);
    }
    let prefix_end = s.len();
    let ff = FloatFormat {
        round: f.round.1,
        ..ff
    };
    big_float::append_to_string(s, im, ff);
    if im_prefix && s.as_bytes()[prefix_end] == b'-' {
        unsafe {
            let bytes = slice::from_raw_parts_mut(s.as_mut_ptr(), s.len());
            bytes[prefix_start] = b'-';
            bytes[prefix_start + 1..=prefix_end].copy_from_slice(f.prefix.as_bytes());
        }
    }
    s.push(')');
    debug_assert_eq!(reserved_ptr, s.as_ptr());
    #[cfg(not(debug_assertions))]
    {
        let _ = reserved_ptr;
    }
}

#[derive(Debug)]
pub enum ParseIncomplete {
    Real(FloatParseIncomplete),
    Complex(FloatParseIncomplete, FloatParseIncomplete),
}

impl AssignRound<ParseIncomplete> for Complex {
    type Round = Round2;
    type Ordering = Ordering2;
    #[inline]
    fn assign_round(&mut self, src: ParseIncomplete, round: Round2) -> Ordering2 {
        match src {
            ParseIncomplete::Real(re) => {
                let real_ord = self.mut_real().assign_round(re, round.0);
                self.mut_imag().assign(Special::Zero);
                (real_ord, Ordering::Equal)
            }
            ParseIncomplete::Complex(re, im) => {
                let real_ord = self.mut_real().assign_round(re, round.0);
                let imag_ord = self.mut_imag().assign_round(im, round.1);
                (real_ord, imag_ord)
            }
        }
    }
}

macro_rules! parse_error {
    ($kind:expr) => {
        Err(ParseComplexError { kind: $kind })
    };
}

fn parse(mut bytes: &[u8], radix: i32) -> Result<ParseIncomplete, ParseComplexError> {
    bytes = misc::trim_start(bytes);
    bytes = misc::trim_end(bytes);
    if bytes.is_empty() {
        return parse_error!(ParseErrorKind::NoDigits);
    }
    if let Some((inside, remainder)) = misc::matched_brackets(bytes) {
        if !misc::trim_start(remainder).is_empty() {
            return parse_error!(ParseErrorKind::CloseNotLast);
        }
        bytes = misc::trim_start(inside);
        bytes = misc::trim_end(bytes);
    } else {
        return match Float::parse_radix(&bytes, radix) {
            Ok(re) => Ok(ParseIncomplete::Real(re)),
            Err(e) => parse_error!(ParseErrorKind::InvalidFloat(e)),
        };
    };
    let (real, imag) = if let Some(comma) = misc::find_outside_brackets(bytes, b',') {
        let real = misc::trim_end(&bytes[..comma]);
        if real.is_empty() {
            return parse_error!(ParseErrorKind::NoRealDigits);
        }
        let imag = misc::trim_start(&bytes[comma + 1..]);
        if imag.is_empty() {
            return parse_error!(ParseErrorKind::NoImagDigits);
        }
        if misc::find_outside_brackets(imag, b',').is_some() {
            return parse_error!(ParseErrorKind::MultipleSeparators);
        }
        (real, imag)
    } else if let Some(space) = misc::find_space_outside_brackets(bytes) {
        let real = &bytes[..space];
        assert!(!real.is_empty());
        let imag = misc::trim_start(&bytes[space + 1..]);
        assert!(!imag.is_empty());
        if misc::find_space_outside_brackets(imag).is_some() {
            return parse_error!(ParseErrorKind::MultipleSeparators);
        }
        (real, imag)
    } else {
        return parse_error!(ParseErrorKind::MissingSeparator);
    };
    let re = match Float::parse_radix(real, radix) {
        Ok(re) => re,
        Err(e) => return parse_error!(ParseErrorKind::InvalidRealFloat(e)),
    };
    let im = match Float::parse_radix(imag, radix) {
        Ok(im) => im,
        Err(e) => return parse_error!(ParseErrorKind::InvalidImagFloat(e)),
    };
    Ok(ParseIncomplete::Complex(re, im))
}

#[derive(Debug)]
/**
An error which can be returned when parsing a [`Complex`] number.

See the
<code>[Complex][`Complex`]::[parse_radix][`parse_radix`]</code>
method for details on what strings are accepted.

# Examples

```rust
use rug::{complex::ParseComplexError, Complex};
// This string is not a complex number.
let s = "something completely different (_!_!_)";
let error: ParseComplexError = match Complex::parse_radix(s, 4) {
    Ok(_) => unreachable!(),
    Err(error) => error,
};
println!("Parse error: {}", error);
```

[`Complex`]: ../struct.Complex.html
[`parse_radix`]: ../struct.Complex.html#method.parse_radix
*/
pub struct ParseComplexError {
    kind: ParseErrorKind,
}

#[derive(Debug)]
enum ParseErrorKind {
    NoDigits,
    NoRealDigits,
    NoImagDigits,
    InvalidFloat(ParseFloatError),
    InvalidRealFloat(ParseFloatError),
    InvalidImagFloat(ParseFloatError),
    MissingSeparator,
    MultipleSeparators,
    CloseNotLast,
}

impl Error for ParseComplexError {
    fn description(&self) -> &str {
        use self::ParseErrorKind::*;
        match self.kind {
            NoDigits => "string has no digits",
            NoRealDigits => "string has no real digits",
            NoImagDigits => "string has no imaginary digits",
            InvalidFloat(_) => "string is not a valid float",
            InvalidRealFloat(_) => "real part of string is not a valid float",
            InvalidImagFloat(_) => "imaginary part of string is not a valid float",
            MissingSeparator => "string has no separator inside brackets",
            MultipleSeparators => "string has more than one separator inside brackets",
            CloseNotLast => "string has more characters after closing bracket",
        }
    }
}

impl Display for ParseComplexError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        use self::ParseErrorKind::*;
        match &self.kind {
            NoDigits => Display::fmt("string has no digits", f),
            NoRealDigits => Display::fmt("string has no real digits", f),
            NoImagDigits => Display::fmt("string has no imaginary digits", f),
            InvalidFloat(e) => {
                Display::fmt("string is not a valid float: ", f)?;
                Display::fmt(e, f)
            }
            InvalidRealFloat(e) => {
                Display::fmt("real part of string is not a valid float: ", f)?;
                Display::fmt(e, f)
            }
            InvalidImagFloat(e) => {
                Display::fmt("imaginary part of string is not a valid float: ", f)?;
                Display::fmt(e, f)
            }
            MissingSeparator => Display::fmt("string has no separator inside brackets", f),
            MultipleSeparators => {
                Display::fmt("string has more than one separator inside brackets", f)
            }
            CloseNotLast => Display::fmt("string has more characters after closing bracket", f),
        }
    }
}
