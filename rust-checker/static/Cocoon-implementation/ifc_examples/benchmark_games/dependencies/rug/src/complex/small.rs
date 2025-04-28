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
    ext::xmpfr,
    float::{self, small::Mpfr, ToSmall},
    Assign, Complex,
};
use core::{
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
    ops::Deref,
    ptr::NonNull,
};
use gmp_mpfr_sys::{
    gmp::{self, limb_t},
    mpc::mpc_t,
    mpfr::{mpfr_t, prec_t},
};

const LIMBS_IN_SMALL: usize = (128 / gmp::LIMB_BITS) as usize;
type Limbs = [MaybeUninit<limb_t>; LIMBS_IN_SMALL];

/**
A small complex number that does not require any memory allocation.

This can be useful when you have real and imaginary numbers that are
primitive integers or floats and you need a reference to a
[`Complex`].

The `SmallComplex` will have a precision according to the types of the
primitives used to set its real and imaginary parts. Note that if
different types are used to set the parts, the parts can have
different precisions.

  * [`i8`], [`u8`]: the part will have eight bits of precision.
  * [`i16`], [`u16`]: the part will have 16 bits of precision.
  * [`i32`], [`u32`]: the part will have 32 bits of precision.
  * [`i64`], [`u64`]: the part will have 64 bits of precision.
  * [`i128`], [`u128`]: the part will have 128 bits of precision.
  * [`isize`], [`usize`]: the part will have 32 or 64 bits of
    precision, depending on the platform.
  * [`f32`]: the part will have 24 bits of precision.
  * [`f64`]: the part will have 53 bits of precision.
  * [`Special`]: the part will have the
    [minimum possible precision][`prec_min`].

The `SmallComplex` type can be coerced to a [`Complex`], as it
implements
<code>[Deref]&lt;[Target] = [Complex][`Complex`]&gt;</code>.

# Examples

```rust
use rug::{complex::SmallComplex, Complex};
// `a` requires a heap allocation
let mut a = Complex::with_val(53, (1, 2));
// `b` can reside on the stack
let b = SmallComplex::from((-10f64, -20.5f64));
a += &*b;
assert_eq!(*a.real(), -9);
assert_eq!(*a.imag(), -18.5);
```

[Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
[Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
[`Complex`]: ../struct.Complex.html
[`Special`]: ../float/enum.Special.html
[`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
[`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
[`i128`]: https://doc.rust-lang.org/nightly/std/primitive.i128.html
[`i16`]: https://doc.rust-lang.org/nightly/std/primitive.i16.html
[`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
[`i64`]: https://doc.rust-lang.org/nightly/std/primitive.i64.html
[`i8`]: https://doc.rust-lang.org/nightly/std/primitive.i8.html
[`isize`]: https://doc.rust-lang.org/nightly/std/primitive.isize.html
[`prec_min`]: ../float/fn.prec_min.html
[`u128`]: https://doc.rust-lang.org/nightly/std/primitive.u128.html
[`u16`]: https://doc.rust-lang.org/nightly/std/primitive.u16.html
[`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
[`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
[`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
[`usize`]: https://doc.rust-lang.org/nightly/std/primitive.usize.html
*/
#[derive(Clone)]
pub struct SmallComplex {
    inner: Mpc,
    // real part is first in limbs if inner.re.d <= inner.im.d
    first_limbs: Limbs,
    last_limbs: Limbs,
}

// Safety: SmallComplex cannot be Sync because it contains an
// UnsafeCell which is written to then read without further
// protection, so it could lead to data races. But SmallComplex can be
// Send because if it is owned, no other reference can be used to
// modify the UnsafeCell.
unsafe impl Send for SmallComplex {}

impl Default for SmallComplex {
    #[inline]
    fn default() -> Self {
        SmallComplex::new()
    }
}

// Safety: Mpfr has a repr equivalent to mpfr_t, so Mpc has a repr
// equivalent to mpc_t. The difference in the repr(C) types Mpfr and
// mpfr_t is that Mpfr uses UnsafeCell<NonNull<limb_t>> instead of
// *mut limb_t, but both UnsafeCell and NonNull are repr(transparent).
// The difference in the repr(C) types Mpc and mpc_t is that Mpc uses
// Mpfr instead of mpfr_t.
#[derive(Clone)]
#[repr(C)]
struct Mpc {
    re: Mpfr,
    im: Mpfr,
}

static_assert_same_layout!(Mpc, mpc_t);

impl SmallComplex {
    /// Creates a [`SmallComplex`] with value 0 and the
    /// [minimum possible precision][`prec_min`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::complex::SmallComplex;
    /// let c = SmallComplex::new();
    /// // Borrow c as if it were Complex.
    /// assert_eq!(*c, 0);
    /// ```
    ///
    /// [`SmallComplex`]: struct.SmallComplex.html
    /// [`prec_min`]: ../float/fn.prec_min.html
    #[inline]
    pub const fn new() -> Self {
        SmallComplex {
            inner: Mpc {
                re: Mpfr {
                    prec: float::prec_min() as prec_t,
                    sign: 1,
                    exp: xmpfr::EXP_ZERO,
                    d: UnsafeCell::new(NonNull::dangling()),
                },
                im: Mpfr {
                    prec: float::prec_min() as prec_t,
                    sign: 1,
                    exp: xmpfr::EXP_ZERO,
                    d: UnsafeCell::new(NonNull::dangling()),
                },
            },
            first_limbs: small_limbs![],
            last_limbs: small_limbs![],
        }
    }

    /// Returns a mutable reference to a [`Complex`] number for simple
    /// operations that do not need to change the precision of the
    /// real or imaginary part.
    ///
    /// # Safety
    ///
    /// It is undefined behaviour to modify the precision of the
    /// referenced [`Complex`] number or to swap it with another
    /// number.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::complex::SmallComplex;
    /// let mut c = SmallComplex::from((1.0f32, 3.0f32));
    /// // rotation does not change the precision
    /// unsafe {
    ///     c.as_nonreallocating_complex().mul_i_mut(false);
    /// }
    /// assert_eq!(*c, (-3.0, 1.0));
    /// ```
    ///
    /// [`Complex`]: ../struct.Complex.html
    #[inline]
    // Safety: after calling update_d(), self.inner.d points to the
    // limbs so it is in a consistent state.
    pub unsafe fn as_nonreallocating_complex(&mut self) -> &mut Complex {
        self.update_d();
        let ptr = cast_ptr_mut!(&mut self.inner, Complex);
        &mut *ptr
    }

    #[inline]
    // Safety: self is not Sync, so reading d does not cause a data race.
    fn re_is_first(&self) -> bool {
        unsafe { *self.inner.re.d.get() <= *self.inner.im.d.get() }
    }

    // To be used when offsetting re and im in case the struct has
    // been displaced in memory; if currently re.d <= im.d then re.d
    // points to first_limbs and im.d points to last_limbs, otherwise
    // re.d points to last_limbs and im.d points to first_limbs.
    #[inline]
    fn update_d(&self) {
        // Since this is borrowed, the limbs won't move around, and we
        // can set the d fields.
        let first = NonNull::<[MaybeUninit<limb_t>]>::from(&self.first_limbs[..]);
        let last = NonNull::<[MaybeUninit<limb_t>]>::from(&self.last_limbs[..]);
        let (re_d, im_d) = if self.re_is_first() {
            (first, last)
        } else {
            (last, first)
        };
        // Safety: self is not Sync, so we can write to d without causing a data race.
        unsafe {
            *self.inner.re.d.get() = re_d.cast();
            *self.inner.im.d.get() = im_d.cast();
        }
    }
}

impl Deref for SmallComplex {
    type Target = Complex;
    #[inline]
    fn deref(&self) -> &Complex {
        self.update_d();
        let ptr = cast_ptr!(&self.inner, Complex);
        // Safety: since we called update_d, the inner pointer is
        // pointing to the limbs and the complex number is in a
        // consistent state.
        unsafe { &*ptr }
    }
}

impl<Re: ToSmall> Assign<Re> for SmallComplex {
    fn assign(&mut self, src: Re) {
        unsafe {
            src.copy(&mut self.inner.re, &mut self.first_limbs);
            xmpfr::custom_zero(
                cast_ptr_mut!(&mut self.inner.im, mpfr_t),
                cast_ptr_mut!(self.last_limbs.as_mut_ptr(), limb_t),
                self.inner.re.prec,
            );
        }
    }
}

impl<Re: ToSmall> From<Re> for SmallComplex {
    fn from(src: Re) -> Self {
        let mut inner = Mpc {
            re: Mpfr {
                prec: 0,
                sign: 0,
                exp: 0,
                d: UnsafeCell::new(NonNull::dangling()),
            },
            im: Mpfr {
                prec: 0,
                sign: 0,
                exp: 0,
                d: UnsafeCell::new(NonNull::dangling()),
            },
        };
        let mut re_limbs = small_limbs![];
        let mut im_limbs = small_limbs![];
        unsafe {
            src.copy(&mut inner.re, &mut re_limbs);
            xmpfr::custom_zero(
                cast_ptr_mut!(&mut inner.im, mpfr_t),
                cast_ptr_mut!(im_limbs.as_mut_ptr(), limb_t),
                inner.re.prec,
            );
        }
        // order of limbs is important as inner.num.d != inner.den.d
        if re_limbs.as_ptr() <= im_limbs.as_ptr() {
            SmallComplex {
                inner,
                first_limbs: re_limbs,
                last_limbs: im_limbs,
            }
        } else {
            SmallComplex {
                inner,
                first_limbs: im_limbs,
                last_limbs: re_limbs,
            }
        }
    }
}

impl<Re: ToSmall, Im: ToSmall> Assign<(Re, Im)> for SmallComplex {
    fn assign(&mut self, src: (Re, Im)) {
        unsafe {
            src.0.copy(&mut self.inner.re, &mut self.first_limbs);
            src.1.copy(&mut self.inner.im, &mut self.last_limbs);
        }
    }
}

impl<Re: ToSmall, Im: ToSmall> From<(Re, Im)> for SmallComplex {
    fn from(src: (Re, Im)) -> Self {
        let mut inner = Mpc {
            re: Mpfr {
                prec: 0,
                sign: 0,
                exp: 0,
                d: UnsafeCell::new(NonNull::dangling()),
            },
            im: Mpfr {
                prec: 0,
                sign: 0,
                exp: 0,
                d: UnsafeCell::new(NonNull::dangling()),
            },
        };
        let mut re_limbs = small_limbs![];
        let mut im_limbs = small_limbs![];
        unsafe {
            src.0.copy(&mut inner.re, &mut re_limbs);
            src.1.copy(&mut inner.im, &mut im_limbs);
        }
        // order of limbs is important as inner.num.d != inner.den.d
        if re_limbs.as_ptr() <= im_limbs.as_ptr() {
            SmallComplex {
                inner,
                first_limbs: re_limbs,
                last_limbs: im_limbs,
            }
        } else {
            SmallComplex {
                inner,
                first_limbs: im_limbs,
                last_limbs: re_limbs,
            }
        }
    }
}

impl Assign<&Self> for SmallComplex {
    #[inline]
    fn assign(&mut self, other: &Self) {
        self.clone_from(other);
    }
}

impl Assign for SmallComplex {
    #[inline]
    fn assign(&mut self, other: Self) {
        drop(mem::replace(self, other));
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        complex::SmallComplex,
        float::{self, FreeCache},
        Assign,
    };

    #[test]
    fn check_assign() {
        let mut c = SmallComplex::from((1.0, 2.0));
        assert_eq!(*c, (1.0, 2.0));
        c.assign(3.0);
        assert_eq!(*c, (3.0, 0.0));
        let other = SmallComplex::from((4.0, 5.0));
        c.assign(&other);
        assert_eq!(*c, (4.0, 5.0));
        c.assign((6.0, 7.0));
        assert_eq!(*c, (6.0, 7.0));
        c.assign(other);
        assert_eq!(*c, (4.0, 5.0));

        float::free_cache(FreeCache::All);
    }

    fn swapped_parts(small: &SmallComplex) -> bool {
        unsafe {
            let re = (*small.real().as_raw()).d;
            let im = (*small.imag().as_raw()).d;
            re > im
        }
    }

    #[test]
    fn check_swapped_parts() {
        let mut c = SmallComplex::from((1, 2));
        assert_eq!(*c, (1, 2));
        assert_eq!(*c.clone(), *c);
        let mut orig_swapped_parts = swapped_parts(&c);
        unsafe {
            c.as_nonreallocating_complex().mul_i_mut(false);
        }
        assert_eq!(*c, (-2, 1));
        assert_eq!(*c.clone(), *c);
        assert!(swapped_parts(&c) != orig_swapped_parts);

        c.assign(12);
        assert_eq!(*c, 12);
        assert_eq!(*c.clone(), *c);
        orig_swapped_parts = swapped_parts(&c);
        unsafe {
            c.as_nonreallocating_complex().mul_i_mut(false);
        }
        assert_eq!(*c, (0, 12));
        assert_eq!(*c.clone(), *c);
        assert!(swapped_parts(&c) != orig_swapped_parts);

        c.assign((4, 5));
        assert_eq!(*c, (4, 5));
        assert_eq!(*c.clone(), *c);
        orig_swapped_parts = swapped_parts(&c);
        unsafe {
            c.as_nonreallocating_complex().mul_i_mut(false);
        }
        assert_eq!(*c, (-5, 4));
        assert_eq!(*c.clone(), *c);
        assert!(swapped_parts(&c) != orig_swapped_parts);
    }
}
