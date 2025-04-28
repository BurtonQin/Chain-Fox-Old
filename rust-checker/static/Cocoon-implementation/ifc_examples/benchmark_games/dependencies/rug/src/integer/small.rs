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

use crate::{misc::NegAbs, Assign, Integer};
use az::{Az, Cast, WrappingCast};
use core::{
    cell::UnsafeCell,
    mem::{self, MaybeUninit},
    ops::Deref,
    ptr::NonNull,
};
use gmp_mpfr_sys::gmp::{self, limb_t, mpz_t};
use libc::c_int;

pub const LIMBS_IN_SMALL: usize = (128 / gmp::LIMB_BITS) as usize;
pub type Limbs = [MaybeUninit<limb_t>; LIMBS_IN_SMALL];

/**
A small integer that does not require any memory allocation.

This can be useful when you have a primitive integer type such as
[`u64`] or [`i8`], but need a reference to an [`Integer`].

If there are functions that take a [`u32`] or [`i32`] directly instead
of an [`Integer`] reference, using them can still be faster than using
a `SmallInteger`; the functions would still need to check for the size
of an [`Integer`] obtained using `SmallInteger`.

The `SmallInteger` type can be coerced to an [`Integer`], as it
implements
<code>[Deref]&lt;[Target] = [Integer][`Integer`]&gt;</code>.

# Examples

```rust
use rug::{integer::SmallInteger, Integer};
// `a` requires a heap allocation
let mut a = Integer::from(250);
// `b` can reside on the stack
let b = SmallInteger::from(-100);
a.lcm_mut(&b);
assert_eq!(a, 500);
// another computation:
a.lcm_mut(&SmallInteger::from(30));
assert_eq!(a, 1500);
```

[Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
[Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
[`Integer`]: ../struct.Integer.html
[`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
[`i8`]: https://doc.rust-lang.org/nightly/std/primitive.i8.html
[`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
[`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
*/
#[derive(Clone)]
pub struct SmallInteger {
    inner: Mpz,
    limbs: Limbs,
}

// Safety: Mpz has a repr equivalent to mpz_t. The difference in the
// repr(C) types Mpz and mpz_t is that Mpz uses
// UnsafeCell<NonNull<limb_t>> instead of *mut limb_t, but both
// UnsafeCell and NonNull are repr(transparent).
#[repr(C)]
pub struct Mpz {
    pub alloc: c_int,
    pub size: c_int,
    pub d: UnsafeCell<NonNull<limb_t>>,
}

impl Clone for Mpz {
    fn clone(&self) -> Mpz {
        Mpz {
            alloc: self.alloc,
            size: self.size,
            d: UnsafeCell::new(unsafe { *self.d.get() }),
        }
    }
}

static_assert!(mem::size_of::<Limbs>() == 16);
static_assert_same_layout!(Mpz, mpz_t);

// Safety: SmallInteger cannot be Sync because it contains an
// UnsafeCell which is written to then read without further
// protection, so it could lead to data races. But SmallInteger can be
// Send because if it is owned, no other reference can be used to
// modify the UnsafeCell.
unsafe impl Send for SmallInteger {}

impl Default for SmallInteger {
    #[inline]
    fn default() -> Self {
        SmallInteger::new()
    }
}

impl SmallInteger {
    /// Creates a [`SmallInteger`] with value 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::integer::SmallInteger;
    /// let i = SmallInteger::new();
    /// // Borrow i as if it were Integer.
    /// assert_eq!(*i, 0);
    /// ```
    ///
    /// [`SmallInteger`]: struct.SmallInteger.html
    #[inline]
    pub const fn new() -> Self {
        SmallInteger {
            inner: Mpz {
                alloc: LIMBS_IN_SMALL as c_int,
                size: 0,
                d: UnsafeCell::new(NonNull::dangling()),
            },
            limbs: small_limbs![0],
        }
    }

    /// Returns a mutable reference to an [`Integer`] for simple
    /// operations that do not need to allocate more space for the
    /// number.
    ///
    /// # Safety
    ///
    /// It is undefined behaviour to perform operations that
    /// reallocate the internal data of the referenced [`Integer`] or
    /// to swap it with another number.
    ///
    /// Some GMP functions swap the allocations of their target
    /// operands; calling such functions with the mutable reference
    /// returned by this method can lead to undefined behaviour.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::SmallInteger, Assign};
    /// let mut i = SmallInteger::from(1u64);
    /// let capacity = i.capacity();
    /// // another u64 will not require a reallocation
    /// unsafe {
    ///     i.as_nonreallocating_integer().assign(2u64);
    /// }
    /// assert_eq!(*i, 2);
    /// assert_eq!(i.capacity(), capacity);
    /// ```
    ///
    /// [`Integer`]: ../struct.Integer.html
    #[inline]
    // Safety: after calling update_d(), self.inner.d points to the
    // limbs so it is in a consistent state.
    pub unsafe fn as_nonreallocating_integer(&mut self) -> &mut Integer {
        self.update_d();
        let ptr = cast_ptr_mut!(&mut self.inner, Integer);
        &mut *ptr
    }

    #[inline]
    fn update_d(&self) {
        // Since this is borrowed, the limbs won't move around, and we
        // can set the d field.
        let d = NonNull::<[MaybeUninit<limb_t>]>::from(&self.limbs[..]);
        unsafe {
            *self.inner.d.get() = d.cast();
        }
    }
}

impl Deref for SmallInteger {
    type Target = Integer;
    #[inline]
    fn deref(&self) -> &Integer {
        self.update_d();
        let ptr = cast_ptr!(&self.inner, Integer);
        // Safety: since we called update_d, the inner pointer is pointing
        // to the limbs and the number is in a consistent  state.
        unsafe { &*ptr }
    }
}

/// Types implementing this trait can be converted to [`SmallInteger`].
///
/// The following are implemented when `T` implements `ToSmall`:
///   * <code>[Assign][`Assign`]&lt;T&gt; for [SmallInteger][`SmallInteger`]</code>
///   * <code>[From][`From`]&lt;T&gt; for [SmallInteger][`SmallInteger`]</code>
///
/// This trait is sealed and cannot be implemented for more types; it
/// is implemented for [`bool`] and the unsigned integer types [`u8`],
/// [`u16`], [`u32`], [`u64`], [`u128`] and [`usize`].
///
/// [`Assign`]: ../trait.Assign.html
/// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
/// [`SmallInteger`]: struct.SmallInteger.html
/// [`bool`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
/// [`u128`]: https://doc.rust-lang.org/nightly/std/primitive.u128.html
/// [`u16`]: https://doc.rust-lang.org/nightly/std/primitive.u16.html
/// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
/// [`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
/// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
/// [`usize`]: https://doc.rust-lang.org/nightly/std/primitive.usize.html
pub trait ToSmall: SealedToSmall {}

pub trait SealedToSmall: Sized {
    fn copy(self, size: &mut c_int, limbs: &mut Limbs);
    fn is_zero(&self) -> bool;
}

macro_rules! is_zero {
    () => {
        #[inline]
        fn is_zero(&self) -> bool {
            *self == 0
        }
    };
}

macro_rules! signed {
    ($($I:ty)*) => { $(
        impl ToSmall for $I {}
        impl SealedToSmall for $I {
            #[inline]
            fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
                let (neg, abs) = self.neg_abs();
                abs.copy(size, limbs);
                if neg {
                    *size = -*size;
                }
            }

            is_zero! {}
        }
    )* };
}

macro_rules! one_limb {
    ($($U:ty)*) => { $(
        impl ToSmall for $U {}
        impl SealedToSmall for $U {
            #[inline]
            fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
                if self == 0 {
                    *size = 0;
                } else {
                    *size = 1;
                    limbs[0] = MaybeUninit::new(self.into());
                }
            }

            is_zero! {}
        }
    )* };
}

signed! { i8 i16 i32 i64 i128 isize }

impl ToSmall for bool {}

impl SealedToSmall for bool {
    #[inline]
    fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
        if !self {
            *size = 0;
        } else {
            *size = 1;
            limbs[0] = MaybeUninit::new(1);
        }
    }

    #[inline]
    fn is_zero(&self) -> bool {
        !*self
    }
}

one_limb! { u8 u16 u32 }

#[cfg(gmp_limb_bits_64)]
one_limb! { u64 }

#[cfg(gmp_limb_bits_32)]
impl ToSmall for u64 {}
#[cfg(gmp_limb_bits_32)]
impl SealedToSmall for u64 {
    #[inline]
    fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
        if self == 0 {
            *size = 0;
        } else if self <= 0xffff_ffff {
            *size = 1;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
        } else {
            *size = 2;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
            limbs[1] = MaybeUninit::new((self >> 32).wrapping_cast());
        }
    }

    is_zero! {}
}

impl ToSmall for u128 {}

impl SealedToSmall for u128 {
    #[cfg(gmp_limb_bits_64)]
    #[inline]
    fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
        if self == 0 {
            *size = 0;
        } else if self <= 0xffff_ffff_ffff_ffff {
            *size = 1;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
        } else {
            *size = 2;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
            limbs[1] = MaybeUninit::new((self >> 64).wrapping_cast());
        }
    }

    #[cfg(gmp_limb_bits_32)]
    #[inline]
    fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
        if self == 0 {
            *size = 0;
        } else if self <= 0xffff_ffff {
            *size = 1;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
        } else if self <= 0xffff_ffff_ffff_ffff {
            *size = 2;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
            limbs[1] = MaybeUninit::new((self >> 32).wrapping_cast());
        } else if self <= 0xffff_ffff_ffff_ffff_ffff_ffff {
            *size = 3;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
            limbs[1] = MaybeUninit::new((self >> 32).wrapping_cast());
            limbs[2] = MaybeUninit::new((self >> 64).wrapping_cast());
        } else {
            *size = 4;
            limbs[0] = MaybeUninit::new(self.wrapping_cast());
            limbs[1] = MaybeUninit::new((self >> 32).wrapping_cast());
            limbs[2] = MaybeUninit::new((self >> 64).wrapping_cast());
            limbs[3] = MaybeUninit::new((self >> 96).wrapping_cast());
        }
    }

    is_zero! {}
}

impl ToSmall for usize {}
impl SealedToSmall for usize {
    #[cfg(target_pointer_width = "32")]
    #[inline]
    fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
        self.az::<u32>().copy(size, limbs);
    }

    #[cfg(target_pointer_width = "64")]
    #[inline]
    fn copy(self, size: &mut c_int, limbs: &mut Limbs) {
        self.az::<u64>().copy(size, limbs);
    }

    is_zero! {}
}

impl<T: ToSmall> Assign<T> for SmallInteger {
    #[inline]
    fn assign(&mut self, src: T) {
        src.copy(&mut self.inner.size, &mut self.limbs);
    }
}

impl<T: ToSmall> From<T> for SmallInteger {
    #[inline]
    fn from(src: T) -> Self {
        let mut size = 0;
        let mut limbs = small_limbs![0];
        src.copy(&mut size, &mut limbs);
        SmallInteger {
            inner: Mpz {
                alloc: LIMBS_IN_SMALL.cast(),
                size,
                d: UnsafeCell::new(NonNull::dangling()),
            },
            limbs,
        }
    }
}

impl Assign<&Self> for SmallInteger {
    #[inline]
    fn assign(&mut self, other: &Self) {
        self.clone_from(other);
    }
}

impl Assign for SmallInteger {
    #[inline]
    fn assign(&mut self, other: Self) {
        drop(mem::replace(self, other));
    }
}

#[cfg(test)]
mod tests {
    use crate::{integer::SmallInteger, Assign};

    #[test]
    fn check_assign() {
        let mut i = SmallInteger::from(-1i32);
        assert_eq!(*i, -1);
        let other = SmallInteger::from(2i32);
        i.assign(&other);
        assert_eq!(*i, 2);
        i.assign(6u8);
        assert_eq!(*i, 6);
        i.assign(-6i8);
        assert_eq!(*i, -6);
        i.assign(other);
        assert_eq!(*i, 2);
        i.assign(6u16);
        assert_eq!(*i, 6);
        i.assign(-6i16);
        assert_eq!(*i, -6);
        i.assign(6u32);
        assert_eq!(*i, 6);
        i.assign(-6i32);
        assert_eq!(*i, -6);
        i.assign(0xf_0000_0006u64);
        assert_eq!(*i, 0xf_0000_0006u64);
        i.assign(-0xf_0000_0006i64);
        assert_eq!(*i, -0xf_0000_0006i64);
        i.assign(6u128 << 64 | 7u128);
        assert_eq!(*i, 6u128 << 64 | 7u128);
        i.assign(-6i128 << 64 | 7i128);
        assert_eq!(*i, -6i128 << 64 | 7i128);
        i.assign(6usize);
        assert_eq!(*i, 6);
        i.assign(-6isize);
        assert_eq!(*i, -6);
        i.assign(0u32);
        assert_eq!(*i, 0);
    }
}
