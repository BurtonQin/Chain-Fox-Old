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
use crate::{ext::xmpz, integer::Order, misc, ops::DivRounding, Assign};
use az::{Az, Cast, CheckedCast, UnwrappedAs, UnwrappedCast, WrappingCast};
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    mem::{self, ManuallyDrop, MaybeUninit},
    ops::{Add, AddAssign, Deref, Mul, MulAssign},
    slice,
};
use gmp_mpfr_sys::gmp::{self, limb_t, mpz_t};
use libc::{c_char, c_void};
use std::error::Error;
#[cfg(feature = "rational")]
use {crate::rational::big::BorrowRational, core::ptr::NonNull, gmp_mpfr_sys::gmp::mpq_t};

/**
An arbitrary-precision integer.

Standard arithmetic operations, bitwise operations and comparisons are
supported. In standard arithmetic operations such as addition, you can
mix `Integer` and primitive integer types; the result will be an
`Integer`.

Internally the integer is not stored using a two’s-complement
representation, however, for bitwise operations and shifts, the
functionality is the same as if the representation was using two’s
complement.

# Examples

```rust
use rug::{Assign, Integer};
// Create an integer initialized as zero.
let mut int = Integer::new();
assert_eq!(int, 0);
assert_eq!(int.to_u32(), Some(0));
int.assign(-14);
assert_eq!(int, -14);
assert_eq!(int.to_u32(), None);
assert_eq!(int.to_i32(), Some(-14));
```

Arithmetic operations with mixed arbitrary and primitive types are
allowed. Note that in the following example, there is only one
allocation. The `Integer` instance is moved into the shift operation
so that the result can be stored in the same instance, then that
result is similarly consumed by the addition operation.

```rust
use rug::Integer;
let mut a = Integer::from(0xc);
a = (a << 80) + 0xffee;
assert_eq!(a.to_string_radix(16), "c0000000000000000ffee");
//                                 ↑   ↑   ↑   ↑   ↑   ↑
//                                80  64  48  32  16   0
```

Bitwise operations on `Integer` values behave as if the value uses a
two’s-complement representation.

```rust
use rug::Integer;

let mut i = Integer::from(1);
i = i << 1000;
// i is now 1000000... (1000 zeros)
assert_eq!(i.significant_bits(), 1001);
assert_eq!(i.find_one(0), Some(1000));
i -= 1;
// i is now 111111... (1000 ones)
assert_eq!(i.count_ones(), Some(1000));

let a = Integer::from(0xf00d);
// −1 is all ones in two’s complement
let all_ones_xor_a = Integer::from(-1 ^ &a);
// a is unchanged as we borrowed it
let complement_a = !a;
// now a has been moved, so this would cause an error:
// assert!(a > 0);
assert_eq!(all_ones_xor_a, complement_a);
assert_eq!(complement_a, -0xf00e);
assert_eq!(format!("{:x}", complement_a), "-f00e");
```

To initialize a large `Integer` that does not fit in a primitive type,
you can parse a string.

```rust
use rug::Integer;
let s1 = "123456789012345678901234567890";
let i1 = s1.parse::<Integer>().unwrap();
assert_eq!(i1.significant_bits(), 97);
let s2 = "ffff0000ffff0000ffff0000ffff0000ffff0000";
let i2 = Integer::from_str_radix(s2, 16).unwrap();
assert_eq!(i2.significant_bits(), 160);
assert_eq!(i2.count_ones(), Some(80));
```

Operations on two borrowed `Integer` values result in an
[incomplete-computation value][icv] that has to be assigned to a new
`Integer` value.

```rust
use rug::Integer;
let a = Integer::from(10);
let b = Integer::from(3);
let a_b_ref = &a + &b;
let a_b = Integer::from(a_b_ref);
assert_eq!(a_b, 13);
```

As a special case, when an [incomplete-computation value][icv] is
obtained from multiplying two `Integer` references, it can be added to
or subtracted from another `Integer` (or reference). This can be
useful for multiply-accumulate operations.

```rust
use rug::Integer;
let mut acc = Integer::from(100);
let m1 = Integer::from(3);
let m2 = Integer::from(7);
// 100 + 3 × 7 = 121
acc += &m1 * &m2;
assert_eq!(acc, 121);
let other = Integer::from(2000);
// Do not consume any values here:
// 2000 − 3 × 7 = 1979
let sub = Integer::from(&other - &m1 * &m2);
assert_eq!(sub, 1979);
```

The `Integer` type supports various functions. Most methods have three
versions:

 1. The first method consumes the operand.
 2. The second method has a “`_mut`” suffix and mutates the operand.
 3. The third method has a “`_ref`” suffix and borrows the operand.
    The returned item is an [incomplete-computation value][icv] that
    can be assigned to an `Integer`.

```rust
use rug::Integer;

// 1. consume the operand
let a = Integer::from(-15);
let abs_a = a.abs();
assert_eq!(abs_a, 15);

// 2. mutate the operand
let mut b = Integer::from(-16);
b.abs_mut();
assert_eq!(b, 16);

// 3. borrow the operand
let c = Integer::from(-17);
let r = c.abs_ref();
let abs_c = Integer::from(r);
assert_eq!(abs_c, 17);
// c was not consumed
assert_eq!(c, -17);
```

[icv]: index.html#incomplete-computation-values
*/
#[repr(transparent)]
pub struct Integer {
    inner: mpz_t,
}

impl Integer {
    #[inline]
    pub(crate) fn inner(&self) -> &mpz_t {
        &self.inner
    }
    #[inline]
    pub(crate) unsafe fn inner_mut(&mut self) -> &mut mpz_t {
        &mut self.inner
    }
    #[inline]
    pub(crate) fn inner_data(&self) -> &[limb_t] {
        let limbs = self
            .inner
            .size
            .checked_abs()
            .expect("overflow")
            .unwrapped_as::<usize>();
        unsafe { slice::from_raw_parts(self.inner.d.as_ptr(), limbs) }
    }
}

static_assert_same_layout!(Integer, mpz_t);
static_assert_same_layout!(BorrowInteger<'_>, mpz_t);

static_assert_same_size!(Integer, Option<Integer>);

impl Integer {
    /// Constructs a new arbitrary-precision [`Integer`] with value 0.
    ///
    /// The created [`Integer`] will have no allocated memory yet.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::new();
    /// assert_eq!(i, 0);
    /// ```
    ///
    /// [`Integer`]: #
    #[inline]
    pub const fn new() -> Self {
        Integer {
            inner: xmpz::owned_init(),
        }
    }

    /// Constructs a new arbitrary-precision [`Integer`] with at least
    /// the specified capacity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::with_capacity(137);
    /// assert!(i.capacity() >= 137);
    /// ```
    ///
    /// [`Integer`]: #
    #[inline]
    pub fn with_capacity(bits: usize) -> Self {
        unsafe {
            let mut dst = MaybeUninit::uninit();
            xmpz::init2(dst.as_mut_ptr(), bits);
            dst.assume_init()
        }
    }

    /// Returns the capacity in bits that can be stored without
    /// reallocating.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::with_capacity(137);
    /// assert!(i.capacity() >= 137);
    /// ```
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner
            .alloc
            .unwrapped_as::<usize>()
            .checked_mul(gmp::LIMB_BITS.az::<usize>())
            .expect("overflow")
    }

    /// Reserves capacity for at least `additional` more bits in the
    /// [`Integer`].
    ///
    /// If the integer already has enough excess capacity, this
    /// function does nothing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 0x2000_0000 needs 30 bits.
    /// let mut i = Integer::from(0x2000_0000);
    /// assert_eq!(i.significant_bits(), 30);
    /// i.reserve(290);
    /// let capacity = i.capacity();
    /// assert!(capacity >= 320);
    /// i.reserve(0);
    /// assert_eq!(i.capacity(), capacity);
    /// i.reserve(291);
    /// assert!(i.capacity() >= 321);
    /// ```
    ///
    /// [`Integer`]: #
    pub fn reserve(&mut self, additional: usize) {
        let used_bits = xmpz::significant_bits(self);
        let req_bits = used_bits.checked_add(additional).expect("overflow");
        let alloc_bits = (self.inner.alloc.az::<usize>())
            .checked_mul(gmp::LIMB_BITS.az::<usize>())
            .expect("overflow");
        if alloc_bits < req_bits {
            unsafe {
                gmp::mpz_realloc2(self.as_raw_mut(), req_bits.unwrapped_cast());
            }
        }
    }

    /// Shrinks the capacity of the [`Integer`] as much as possible.
    ///
    /// The capacity can still be larger than the number of
    /// significant bits.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // let i be 100 bits wide
    /// let mut i = Integer::from_str_radix("fffff12345678901234567890", 16)
    ///     .unwrap();
    /// assert_eq!(i.significant_bits(), 100);
    /// assert!(i.capacity() >= 100);
    /// i >>= 80;
    /// i.shrink_to_fit();
    /// assert!(i.capacity() >= 20);
    /// # assert!(i.capacity() < 100);
    /// ```
    ///
    /// [`Integer`]: #
    pub fn shrink_to_fit(&mut self) {
        let used_limbs = self.inner.size.checked_abs().expect("overflow");
        let req_limbs = if used_limbs == 0 { 1 } else { used_limbs };
        if self.inner.alloc > req_limbs {
            unsafe {
                gmp::_mpz_realloc(self.as_raw_mut(), req_limbs.unwrapped_cast());
            }
        }
    }

    /// Creates an [`Integer`] from an initialized
    /// [GMP integer][`mpz_t`].
    ///
    /// # Safety
    ///
    ///   * The function must *not* be used to create a constant
    ///     [`Integer`], though it can be used to create a static
    ///     [`Integer`]. This is because constant values are *copied*
    ///     on use, leading to undefined behaviour when they are
    ///     dropped.
    ///   * The value must be initialized.
    ///   * The [`mpz_t`] type can be considered as a kind of pointer,
    ///     so there can be multiple copies of it. Since this function
    ///     takes over ownership, no other copies of the passed value
    ///     should exist.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::mem::MaybeUninit;
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Integer;
    /// let i = unsafe {
    ///     let mut z = MaybeUninit::uninit();
    ///     gmp::mpz_init_set_ui(z.as_mut_ptr(), 15);
    ///     let z = z.assume_init();
    ///     // z is initialized and unique
    ///     Integer::from_raw(z)
    /// };
    /// assert_eq!(i, 15);
    /// // since i is an Integer now, deallocation is automatic
    /// ```
    ///
    /// This can be used to create a static [`Integer`] using
    /// [`MPZ_ROINIT_N`] to initialize the raw value. See the
    /// [GMP documentation][gmp roinit] for details.
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp::{self, limb_t, mpz_t};
    /// use rug::Integer;
    /// const LIMBS: [limb_t; 2] = [123, 456];
    /// const MPZ: mpz_t =
    ///     unsafe { gmp::MPZ_ROINIT_N(LIMBS.as_ptr() as *mut limb_t, -2) };
    /// // Must *not* be const, otherwise it would lead to undefined
    /// // behavior on use, as it would create a copy that is dropped.
    /// static I: Integer = unsafe { Integer::from_raw(MPZ) };
    /// let check = -((Integer::from(LIMBS[1]) << gmp::NUMB_BITS) + LIMBS[0]);
    /// assert_eq!(I, check);
    /// ```
    ///
    /// [`Integer`]: #
    /// [`MPZ_ROINIT_N`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/fn.MPZ_ROINIT_N.html
    /// [`mpz_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpz_t.html
    /// [gmp roinit]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/C/GMP/constant.Integer_Functions.html#index-MPZ_005fROINIT_005fN
    #[inline]
    pub const unsafe fn from_raw(raw: mpz_t) -> Self {
        Integer { inner: raw }
    }

    /// Converts an [`Integer`] into a [GMP integer][`mpz_t`].
    ///
    /// The returned object should be freed to avoid memory leaks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Integer;
    /// let i = Integer::from(15);
    /// let mut z = i.into_raw();
    /// unsafe {
    ///     let u = gmp::mpz_get_ui(&z);
    ///     assert_eq!(u, 15);
    ///     // free object to prevent memory leak
    ///     gmp::mpz_clear(&mut z);
    /// }
    /// ```
    ///
    /// [`Integer`]: #
    /// [`mpz_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpz_t.html
    #[inline]
    pub const fn into_raw(self) -> mpz_t {
        let ret = self.inner;
        let _ = ManuallyDrop::new(self);
        ret
    }

    /// Returns a pointer to the inner [GMP integer][`mpz_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Integer;
    /// let i = Integer::from(15);
    /// let z_ptr = i.as_raw();
    /// unsafe {
    ///     let u = gmp::mpz_get_ui(z_ptr);
    ///     assert_eq!(u, 15);
    /// }
    /// // i is still valid
    /// assert_eq!(i, 15);
    /// ```
    ///
    /// [`mpz_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpz_t.html
    #[inline]
    pub const fn as_raw(&self) -> *const mpz_t {
        &self.inner
    }

    /// Returns an unsafe mutable pointer to the inner
    /// [GMP integer][`mpz_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::Integer;
    /// let mut i = Integer::from(15);
    /// let z_ptr = i.as_raw_mut();
    /// unsafe {
    ///     gmp::mpz_add_ui(z_ptr, z_ptr, 20);
    /// }
    /// assert_eq!(i, 35);
    /// ```
    ///
    /// [`mpz_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.mpz_t.html
    #[inline]
    pub fn as_raw_mut(&mut self) -> *mut mpz_t {
        &mut self.inner
    }

    /// Creates an [`Integer`] from a [slice] of digits of type `T`,
    /// where `T` can be any [unsigned integer primitive type][upt].
    ///
    /// The resulting value cannot be negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::Order, Integer};
    /// let digits = [0x5678u16, 0x1234u16];
    /// let i = Integer::from_digits(&digits, Order::Lsf);
    /// assert_eq!(i, 0x1234_5678);
    /// ```
    ///
    /// [`Integer`]: #
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [upt]: integer/trait.UnsignedPrimitive.html
    pub fn from_digits<T: UnsignedPrimitive>(digits: &[T], order: Order) -> Self {
        let capacity = digits.len().checked_mul(T::PRIVATE.bits).expect("overflow");
        let mut i = Integer::with_capacity(capacity);
        i.assign_digits(digits, order);
        i
    }

    /// Assigns from a [slice] of digits of type `T`, where `T` can be
    /// any [unsigned integer primitive type][upt].
    ///
    /// The resulting value cannot be negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::Order, Integer};
    /// let digits = [0x5678u16, 0x1234u16];
    /// let mut i = Integer::new();
    /// i.assign_digits(&digits, Order::Lsf);
    /// assert_eq!(i, 0x1234_5678);
    /// ```
    ///
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [upt]: integer/trait.UnsignedPrimitive.html
    pub fn assign_digits<T: UnsignedPrimitive>(&mut self, digits: &[T], order: Order) {
        // Safety: it is valid to read digits.len() digits from digits.as_mut_ptr().
        unsafe {
            self.assign_digits_unaligned(digits.as_ptr(), digits.len(), order);
        }
    }

    /// Assigns from digits of type `T` in a memory area, where `T`
    /// can be any [unsigned integer primitive type][upt].
    ///
    /// The memory area is addressed using a pointer and a length. The
    /// `len` parameter is the number of digits, *not* the number of
    /// bytes.
    ///
    /// There are no data alignment restrictions on `src`, any address
    /// is allowed.
    ///
    /// The resulting value cannot be negative.
    ///
    /// # Safety
    ///
    /// To avoid undefined behavior, `src` must be [valid] for reading
    /// `len` digits, that is `len` × `size_of::<T>()` bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::Order, Integer};
    /// // hex bytes: [ fe dc ba 98 87 87 87 87 76 54 32 10 ]
    /// let digits = [
    ///     0xfedc_ba98u32.to_be(),
    ///     0x8787_8787u32.to_be(),
    ///     0x7654_3210u32.to_be(),
    /// ];
    /// let ptr = digits.as_ptr();
    /// let mut i = Integer::new();
    /// unsafe {
    ///     let unaligned = (ptr as *const u8).offset(2) as *const u32;
    ///     i.assign_digits_unaligned(unaligned, 2, Order::MsfBe);
    /// }
    /// assert_eq!(i, 0xba98_8787_8787_7654u64);
    /// ```
    ///
    /// [upt]: integer/trait.UnsignedPrimitive.html
    /// [valid]: https://doc.rust-lang.org/nightly/core/ptr/index.html#safety
    pub unsafe fn assign_digits_unaligned<T: UnsignedPrimitive>(
        &mut self,
        src: *const T,
        len: usize,
        order: Order,
    ) {
        let bytes = mem::size_of::<T>();
        let nails = 8 * bytes - T::PRIVATE.bits;
        gmp::mpz_import(
            self.as_raw_mut(),
            len,
            order.order(),
            bytes,
            order.endian(),
            nails,
            src as *const c_void,
        );
    }

    /// Returns the number of digits of type `T` required to represent
    /// the absolute value.
    ///
    /// `T` can be any [unsigned integer primitive type][upt].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// let i: Integer = Integer::from(1) << 256;
    /// assert_eq!(i.significant_digits::<bool>(), 257);
    /// assert_eq!(i.significant_digits::<u8>(), 33);
    /// assert_eq!(i.significant_digits::<u16>(), 17);
    /// assert_eq!(i.significant_digits::<u32>(), 9);
    /// assert_eq!(i.significant_digits::<u64>(), 5);
    /// ```
    ///
    /// [upt]: integer/trait.UnsignedPrimitive.html
    #[inline]
    pub fn significant_digits<T: UnsignedPrimitive>(&self) -> usize {
        xmpz::significant_bits(self).div_ceil(T::PRIVATE.bits)
    }

    /// Converts the absolute value to a [`Vec`] of digits of type
    /// `T`, where `T` can be any
    /// [unsigned integer primitive type][upt].
    ///
    /// The [`Integer`] type also has the [`as_limbs`] method, which
    /// can be used to borrow the digits without copying them. This
    /// does come with some more constraints compared to `to_digits`:
    ///
    ///  1. The digit width is not optional and depends on the
    ///     implementation: [`limb_t`] is typically [`u64`] on 64-bit
    ///     systems and [`u32`] on 32-bit systems.
    ///  2. The order is not optional and is least significant digit
    ///     first, with each digit in the target’s endianness,
    ///     equivalent to <code>[Order][`Order`]::[Lsf][`Lsf`]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::Order, Integer};
    /// let i = Integer::from(0x1234_5678_9abc_def0u64);
    /// let digits = i.to_digits::<u32>(Order::MsfBe);
    /// assert_eq!(digits, [0x1234_5678u32.to_be(), 0x9abc_def0u32.to_be()]);
    ///
    /// let zero = Integer::new();
    /// let digits_zero = zero.to_digits::<u32>(Order::MsfBe);
    /// assert!(digits_zero.is_empty());
    /// ```
    ///
    /// [`Integer`]: #
    /// [`Lsf`]: integer/enum.Order.html#variant.Lsf
    /// [`Order`]: integer/enum.Order.html
    /// [`Vec`]: https://doc.rust-lang.org/nightly/std/vec/struct.Vec.html
    /// [`as_limbs`]: #method.as_limbs
    /// [`limb_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/type.limb_t.html
    /// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
    /// [`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
    /// [upt]: integer/trait.UnsignedPrimitive.html
    pub fn to_digits<T: UnsignedPrimitive>(&self, order: Order) -> Vec<T> {
        let digit_count = self.significant_digits::<T>();
        let mut v = Vec::with_capacity(digit_count);
        unsafe {
            let digits_ptr = v.as_mut_ptr();
            let mut count = MaybeUninit::uninit();
            gmp::mpz_export(
                digits_ptr as *mut c_void,
                count.as_mut_ptr(),
                order.order(),
                T::PRIVATE.bytes,
                order.endian(),
                T::PRIVATE.nails,
                self.as_raw(),
            );
            assert_eq!(count.assume_init(), digit_count);
            v.set_len(digit_count);
        }
        v
    }

    /// Writes the absolute value into a [slice] of digits of type
    /// `T`, where `T` can be any
    /// [unsigned integer primitive type][upt].
    ///
    /// The slice must be large enough to hold the digits; the minimum
    /// size can be obtained using the [`significant_digits`] method.
    ///
    /// # Panics
    ///
    /// Panics if the slice does not have sufficient capacity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::Order, Integer};
    /// let i = Integer::from(0x1234_5678_9abc_def0u64);
    /// let mut digits = [0xffff_ffffu32; 4];
    /// i.write_digits(&mut digits, Order::MsfBe);
    /// let word0 = 0x9abc_def0u32;
    /// let word1 = 0x1234_5678u32;
    /// assert_eq!(digits, [0, 0, word1.to_be(), word0.to_be()]);
    /// ```
    ///
    /// [`significant_digits`]: #method.significant_digits
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [upt]: integer/trait.UnsignedPrimitive.html
    pub fn write_digits<T: UnsignedPrimitive>(&self, digits: &mut [T], order: Order) {
        // Safety: it is valid to write digits.len() digits into digits.as_mut_ptr().
        unsafe {
            self.write_digits_unaligned(digits.as_mut_ptr(), digits.len(), order);
        }
    }

    /// Writes the absolute value into a memory area of digits of type
    /// `T`, where `T` can be any
    /// [unsigned integer primitive type][upt].
    ///
    /// The memory area is addressed using a pointer and a length. The
    /// `len` parameter is the number of digits, *not* the number of
    /// bytes.
    ///
    /// The length must be large enough to hold the digits; the
    /// minimum length can be obtained using the
    /// [`significant_digits`] method.
    ///
    /// There are no data alignment restrictions on `dst`, any address
    /// is allowed.
    ///
    /// The memory locations can be uninitialized before this method
    /// is called; this method sets all `len` elements, padding with
    /// zeros if the length is larger than required.
    ///
    /// # Safety
    ///
    /// To avoid undefined behavior, `dst` must be [valid] for writing
    /// `len` digits, that is `len` × `size_of::<T>()` bytes.
    ///
    /// # Panics
    ///
    /// Panics if the length is less than the number of digits.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::Order, Integer};
    /// let i = Integer::from(0xfedc_ba98_7654_3210u64);
    /// let mut digits = [0xffff_ffffu32; 4];
    /// let ptr = digits.as_mut_ptr();
    /// unsafe {
    ///     let unaligned = (ptr as *mut u8).offset(2) as *mut u32;
    ///     i.write_digits_unaligned(unaligned, 3, Order::MsfBe);
    /// }
    /// assert_eq!(
    ///     digits,
    ///     [
    ///         0xffff_0000u32.to_be(),
    ///         0x0000_fedcu32.to_be(),
    ///         0xba98_7654u32.to_be(),
    ///         0x3210_ffffu32.to_be(),
    ///     ]
    /// );
    /// ```
    ///
    /// The following example shows how to write into uninitialized
    /// memory. In practice, the following code could be replaced by a
    /// call to the safe method [`to_digits`].
    ///
    /// ```rust
    /// use rug::{integer::Order, Integer};
    /// let i = Integer::from(0x1234_5678_9abc_def0u64);
    /// let len = i.significant_digits::<u32>();
    /// assert_eq!(len, 2);
    ///
    /// // The following code is equivalent to:
    /// //     let digits = i.to_digits::<u32>(Order::MsfBe);
    /// let mut digits = Vec::<u32>::with_capacity(len);
    /// let ptr = digits.as_mut_ptr();
    /// unsafe {
    ///     i.write_digits_unaligned(ptr, len, Order::MsfBe);
    ///     digits.set_len(len);
    /// }
    ///
    /// assert_eq!(digits, [0x1234_5678u32.to_be(), 0x9abc_def0u32.to_be()]);
    /// ```
    ///
    /// [`significant_digits`]: #method.significant_digits
    /// [`to_digits`]: #method.to_digits
    /// [upt]: integer/trait.UnsignedPrimitive.html
    /// [valid]: https://doc.rust-lang.org/nightly/core/ptr/index.html#safety
    pub unsafe fn write_digits_unaligned<T: UnsignedPrimitive>(
        &self,
        dst: *mut T,
        len: usize,
        order: Order,
    ) {
        let digit_count = self.significant_digits::<T>();
        let zero_count = len.checked_sub(digit_count).expect("not enough capacity");
        let (zeros, digits) = if order.order() < 0 {
            (dst.offset(digit_count.unwrapped_cast()), dst)
        } else {
            (dst, dst.offset(zero_count.unwrapped_cast()))
        };
        // use *mut u8 to allow for unaligned pointers
        (zeros as *mut u8).write_bytes(0, zero_count * T::PRIVATE.bytes);
        let mut count = MaybeUninit::uninit();
        gmp::mpz_export(
            digits as *mut c_void,
            count.as_mut_ptr(),
            order.order(),
            T::PRIVATE.bytes,
            order.endian(),
            T::PRIVATE.nails,
            self.as_raw(),
        );
        assert_eq!(count.assume_init(), digit_count);
    }

    /// Extracts a [slice] of [limbs][`limb_t`] used to store the value.
    ///
    /// The [slice] contains the absolute value of `self`, with the
    /// least significant limb first.
    ///
    /// The [`Integer`] type also implements
    /// <code>[AsRef][`AsRef`]&lt;[\[][slice][limb_t][`limb_t`][\]][slice]&gt;</code>,
    /// which is equivalent to this method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// assert!(Integer::new().as_limbs().is_empty());
    /// assert_eq!(Integer::from(13).as_limbs(), &[13]);
    /// assert_eq!(Integer::from(-23).as_limbs(), &[23]);
    /// ```
    ///
    /// `int.as_limbs()` is like a borrowing non-copy version of
    /// <code>int.[to_digits][`to_digits`]::&lt;[limb_t][`limb_t`]&gt;([Order][`Order`]::[Lsf][`Lsf`])</code>.
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp::limb_t;
    /// use rug::{integer::Order, Integer};
    /// let int = Integer::from(0x1234_5678_9abc_def0u64);
    /// // no copying for int_slice, which is borrowing int
    /// let int_slice = int.as_limbs();
    /// // digits is a copy and does not borrow int
    /// let digits = int.to_digits::<limb_t>(Order::Lsf);
    /// // no copying for digits_slice, which is borrowing digits
    /// let digits_slice = &digits[..];
    /// assert_eq!(int_slice, digits_slice);
    /// ```
    ///
    /// [`AsRef`]: https://doc.rust-lang.org/nightly/core/convert/trait.AsRef.html
    /// [`Lsf`]: integer/enum.Order.html#variant.Lsf
    /// [`Order`]: integer/enum.Order.html
    /// [`limb_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/type.limb_t.html
    /// [`to_digits`]: #method.to_digits
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    pub fn as_limbs(&self) -> &[limb_t] {
        self.inner_data()
    }

    /// Creates an [`Integer`] from an [`f32`] if it is
    /// [finite][`is_finite`], rounding towards zero.
    ///
    /// This conversion can also be performed using
    /// <code>value.[checked\_as][`checked_as`]::&lt;[Integer][`Integer`]&gt;()</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::Integer;
    /// let i = Integer::from_f32(-5.6).unwrap();
    /// assert_eq!(i, -5);
    /// let neg_inf = Integer::from_f32(f32::NEG_INFINITY);
    /// assert!(neg_inf.is_none());
    /// ```
    ///
    /// [`Integer`]: #
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html#method.is_finite
    #[inline]
    pub fn from_f32(value: f32) -> Option<Self> {
        value.checked_cast()
    }

    /// Creates an [`Integer`] from an [`f64`] if it is
    /// [finite][`is_finite`], rounding towards zero.
    ///
    /// This conversion can also be performed using
    /// <code>value.[checked\_as][`checked_as`]::&lt;[Integer][`Integer`]&gt;()</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Integer;
    /// let i = Integer::from_f64(1e20).unwrap();
    /// assert_eq!(i, "100000000000000000000".parse::<Integer>().unwrap());
    /// let inf = Integer::from_f64(f64::INFINITY);
    /// assert!(inf.is_none());
    /// ```
    ///
    /// [`Integer`]: #
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html#method.is_finite
    #[inline]
    pub fn from_f64(value: f64) -> Option<Self> {
        value.checked_cast()
    }

    /// Parses an [`Integer`] using the given radix.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from_str_radix("-ff", 16).unwrap();
    /// assert_eq!(i, -0xff);
    /// ```
    ///
    /// [`Integer`]: #
    #[inline]
    pub fn from_str_radix(src: &str, radix: i32) -> Result<Self, ParseIntegerError> {
        Ok(Integer::from(Integer::parse_radix(src, radix)?))
    }

    /// Parses a decimal string slice (<code>&amp;[str]</code>) or
    /// byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into an
    /// [`Integer`].
    ///
    /// The following are implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// The string can start with an optional minus or plus sign.
    /// ASCII whitespace is ignored everywhere in the string.
    /// Underscores anywhere except before the first digit are ignored
    /// as well.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// let valid1 = Integer::parse("1223");
    /// let i1 = Integer::from(valid1.unwrap());
    /// assert_eq!(i1, 1223);
    /// let valid2 = Integer::parse("123 456 789");
    /// let i2 = Integer::from(valid2.unwrap());
    /// assert_eq!(i2, 123_456_789);
    ///
    /// let invalid = Integer::parse("789a");
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse<S: AsRef<[u8]>>(src: S) -> Result<ParseIncomplete, ParseIntegerError> {
        parse(src.as_ref(), 10)
    }

    /// Parses a string slice (<code>&amp;[str]</code>) or byte slice
    /// (<code>[&amp;\[][slice][u8][`u8`][\]][slice]</code>) into an
    /// [`Integer`].
    ///
    /// The following are implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// The string can start with an optional minus or plus sign.
    /// ASCII whitespace is ignored everywhere in the string.
    /// Underscores anywhere except before the first digit are ignored
    /// as well.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// let valid1 = Integer::parse_radix("1223", 4);
    /// let i1 = Integer::from(valid1.unwrap());
    /// assert_eq!(i1, 3 + 4 * (2 + 4 * (2 + 4 * 1)));
    /// let valid2 = Integer::parse_radix("1234 abcd", 16);
    /// let i2 = Integer::from(valid2.unwrap());
    /// assert_eq!(i2, 0x1234_abcd);
    ///
    /// let invalid = Integer::parse_radix("123", 3);
    /// assert!(invalid.is_err());
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [icv]: index.html#incomplete-computation-values
    /// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
    /// [str]: https://doc.rust-lang.org/nightly/std/primitive.str.html
    #[inline]
    pub fn parse_radix<S: AsRef<[u8]>>(
        src: S,
        radix: i32,
    ) -> Result<ParseIncomplete, ParseIntegerError> {
        parse(src.as_ref(), radix)
    }

    /// Converts to an [`i8`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[i8][`i8`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[i8][`i8`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[i8][`i8`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[i8][`i8`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(-100);
    /// assert_eq!(fits.to_i8(), Some(-100));
    /// let small = Integer::from(-200);
    /// assert_eq!(small.to_i8(), None);
    /// let large = Integer::from(200);
    /// assert_eq!(large.to_i8(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`i8`]: https://doc.rust-lang.org/nightly/std/primitive.i8.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_i8(&self) -> Option<i8> {
        self.checked_cast()
    }

    /// Converts to an [`i16`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[i16][`i16`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[i16][`i16`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[i16][`i16`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[i16][`i16`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(-30_000);
    /// assert_eq!(fits.to_i16(), Some(-30_000));
    /// let small = Integer::from(-40_000);
    /// assert_eq!(small.to_i16(), None);
    /// let large = Integer::from(40_000);
    /// assert_eq!(large.to_i16(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`i16`]: https://doc.rust-lang.org/nightly/std/primitive.i16.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_i16(&self) -> Option<i16> {
        self.checked_cast()
    }

    /// Converts to an [`i32`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[i32][`i32`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[i32][`i32`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[i32][`i32`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[i32][`i32`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(-50);
    /// assert_eq!(fits.to_i32(), Some(-50));
    /// let small = Integer::from(-123456789012345_i64);
    /// assert_eq!(small.to_i32(), None);
    /// let large = Integer::from(123456789012345_i64);
    /// assert_eq!(large.to_i32(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_i32(&self) -> Option<i32> {
        self.checked_cast()
    }

    /// Converts to an [`i64`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[i64][`i64`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[i64][`i64`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[i64][`i64`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[i64][`i64`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(-50);
    /// assert_eq!(fits.to_i64(), Some(-50));
    /// let small = Integer::from_str_radix("-fedcba9876543210", 16).unwrap();
    /// assert_eq!(small.to_i64(), None);
    /// let large = Integer::from_str_radix("fedcba9876543210", 16).unwrap();
    /// assert_eq!(large.to_i64(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`i64`]: https://doc.rust-lang.org/nightly/std/primitive.i64.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_i64(&self) -> Option<i64> {
        self.checked_cast()
    }

    /// Converts to an [`i128`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[i128][`i128`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[i128][`i128`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[i128][`i128`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[i128][`i128`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(-50);
    /// assert_eq!(fits.to_i128(), Some(-50));
    /// let small: Integer = Integer::from(-1) << 130;
    /// assert_eq!(small.to_i128(), None);
    /// let large: Integer = Integer::from(1) << 130;
    /// assert_eq!(large.to_i128(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`i128`]: https://doc.rust-lang.org/nightly/std/primitive.i128.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_i128(&self) -> Option<i128> {
        self.checked_cast()
    }

    /// Converts to an [`isize`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[isize][`isize`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[isize][`isize`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[isize][`isize`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[isize][`isize`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(0x1000);
    /// assert_eq!(fits.to_isize(), Some(0x1000));
    /// let large: Integer = Integer::from(0x1000) << 128;
    /// assert_eq!(large.to_isize(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`isize`]: https://doc.rust-lang.org/nightly/std/primitive.isize.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_isize(&self) -> Option<isize> {
        self.checked_cast()
    }

    /// Converts to a [`u8`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[u8][`u8`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[u8][`u8`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[u8][`u8`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[u8][`u8`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(200);
    /// assert_eq!(fits.to_u8(), Some(200));
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u8(), None);
    /// let large = Integer::from(300);
    /// assert_eq!(large.to_u8(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_u8(&self) -> Option<u8> {
        self.checked_cast()
    }

    /// Converts to a [`u16`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[u16][`u16`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[u16][`u16`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[u16][`u16`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[u16][`u16`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(60_000);
    /// assert_eq!(fits.to_u16(), Some(60_000));
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u16(), None);
    /// let large = Integer::from(70_000);
    /// assert_eq!(large.to_u16(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`u16`]: https://doc.rust-lang.org/nightly/std/primitive.u16.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_u16(&self) -> Option<u16> {
        self.checked_cast()
    }

    /// Converts to a [`u32`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[u32][`u32`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[u32][`u32`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[u32][`u32`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[u32][`u32`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(1234567890);
    /// assert_eq!(fits.to_u32(), Some(1234567890));
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u32(), None);
    /// let large = Integer::from(123456789012345_u64);
    /// assert_eq!(large.to_u32(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_u32(&self) -> Option<u32> {
        self.checked_cast()
    }

    /// Converts to a [`u64`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[u64][`u64`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[u64][`u64`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[u64][`u64`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[u64][`u64`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(123456789012345_u64);
    /// assert_eq!(fits.to_u64(), Some(123456789012345));
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u64(), None);
    /// let large = "1234567890123456789012345".parse::<Integer>().unwrap();
    /// assert_eq!(large.to_u64(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.tryfrom
    #[inline]
    pub fn to_u64(&self) -> Option<u64> {
        self.checked_cast()
    }

    /// Converts to a [`u128`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[u128][`u128`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[u128][`u128`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[u128][`u128`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[u128][`u128`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(12345678901234567890_u128);
    /// assert_eq!(fits.to_u128(), Some(12345678901234567890));
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u128(), None);
    /// let large = "1234567890123456789012345678901234567890"
    ///     .parse::<Integer>()
    ///     .unwrap();
    /// assert_eq!(large.to_u128(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`u128`]: https://doc.rust-lang.org/nightly/std/primitive.u128.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.tryfrom
    #[inline]
    pub fn to_u128(&self) -> Option<u128> {
        self.checked_cast()
    }

    /// Converts to a [`usize`] if the value fits.
    ///
    /// This conversion can also be performed using
    ///   * <code>[usize][`usize`]::[try_from][`try_from`](&amp;integer)</code>
    ///   * <code>[usize][`usize`]::[try_from][`try_from`](integer)</code>
    ///   * <code>(&amp;integer).[checked\_as][`checked_as`]::&lt;[usize][`usize`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[checked\_as][`checked_as`]::&lt;[usize][`usize`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let fits = Integer::from(0x1000);
    /// assert_eq!(fits.to_usize(), Some(0x1000));
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_usize(), None);
    /// let large: Integer = Integer::from(0x1000) << 128;
    /// assert_eq!(large.to_usize(), None);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`checked_as`]: https://docs.rs/az/1/az/trait.CheckedAs.html#tymethod.checked_as
    /// [`usize`]: https://doc.rust-lang.org/nightly/std/primitive.usize.html
    /// [`try_from`]: https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from
    #[inline]
    pub fn to_usize(&self) -> Option<usize> {
        self.checked_cast()
    }

    /// Converts to an [`i8`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[i8][`i8`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[i8][`i8`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let large = Integer::from(0x1234);
    /// assert_eq!(large.to_i8_wrapping(), 0x34);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    /// [`i8`]: https://doc.rust-lang.org/nightly/std/primitive.i8.html
    #[inline]
    pub fn to_i8_wrapping(&self) -> i8 {
        self.wrapping_cast()
    }

    /// Converts to an [`i16`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[i16][`i16`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[i16][`i16`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let large = Integer::from(0x1234_5678);
    /// assert_eq!(large.to_i16_wrapping(), 0x5678);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`i16`]: https://doc.rust-lang.org/nightly/std/primitive.i16.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_i16_wrapping(&self) -> i16 {
        self.wrapping_cast()
    }

    /// Converts to an [`i32`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[i32][`i32`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[i32][`i32`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let large = Integer::from(0x1234_5678_9abc_def0_u64);
    /// assert_eq!(large.to_i32_wrapping(), 0x9abc_def0_u32 as i32);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`i32`]: https://doc.rust-lang.org/nightly/std/primitive.i32.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_i32_wrapping(&self) -> i32 {
        self.wrapping_cast()
    }

    /// Converts to an [`i64`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[i64][`i64`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[i64][`i64`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let large = Integer::from_str_radix("f123456789abcdef0", 16).unwrap();
    /// assert_eq!(large.to_i64_wrapping(), 0x1234_5678_9abc_def0);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`i64`]: https://doc.rust-lang.org/nightly/std/primitive.i64.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_i64_wrapping(&self) -> i64 {
        self.wrapping_cast()
    }

    /// Converts to an [`i128`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[i128][`i128`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[i128][`i128`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let s = "f123456789abcdef0123456789abcdef0";
    /// let large = Integer::from_str_radix(s, 16).unwrap();
    /// assert_eq!(
    ///     large.to_i128_wrapping(),
    ///     0x1234_5678_9abc_def0_1234_5678_9abc_def0
    /// );
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`i128`]: https://doc.rust-lang.org/nightly/std/primitive.i128.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_i128_wrapping(&self) -> i128 {
        self.wrapping_cast()
    }

    /// Converts to an [`isize`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[isize][`isize`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[isize][`isize`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let large: Integer = (Integer::from(0x1000) << 128) | 0x1234;
    /// assert_eq!(large.to_isize_wrapping(), 0x1234);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`isize`]: https://doc.rust-lang.org/nightly/std/primitive.isize.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_isize_wrapping(&self) -> isize {
        self.wrapping_cast()
    }

    /// Converts to a [`u8`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[u8][`u8`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[u8][`u8`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u8_wrapping(), 0xff);
    /// let large = Integer::from(0x1234);
    /// assert_eq!(large.to_u8_wrapping(), 0x34);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_u8_wrapping(&self) -> u8 {
        self.wrapping_cast()
    }

    /// Converts to a [`u16`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[u16][`u16`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[u16][`u16`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u16_wrapping(), 0xffff);
    /// let large = Integer::from(0x1234_5678);
    /// assert_eq!(large.to_u16_wrapping(), 0x5678);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`u16`]: https://doc.rust-lang.org/nightly/std/primitive.u16.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_u16_wrapping(&self) -> u16 {
        self.wrapping_cast()
    }

    /// Converts to a [`u32`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[u32][`u32`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[u32][`u32`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u32_wrapping(), 0xffff_ffff);
    /// let large = Integer::from(0x1234_5678_9abc_def0_u64);
    /// assert_eq!(large.to_u32_wrapping(), 0x9abc_def0);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_u32_wrapping(&self) -> u32 {
        self.wrapping_cast()
    }

    /// Converts to a [`u64`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[u64][`u64`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[u64][`u64`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let neg = Integer::from(-1);
    /// assert_eq!(neg.to_u64_wrapping(), 0xffff_ffff_ffff_ffff);
    /// let large = Integer::from_str_radix("f123456789abcdef0", 16).unwrap();
    /// assert_eq!(large.to_u64_wrapping(), 0x1234_5678_9abc_def0);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_u64_wrapping(&self) -> u64 {
        self.wrapping_cast()
    }

    /// Converts to a [`u128`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[u128][`u128`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[u128][`u128`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let neg = Integer::from(-1);
    /// assert_eq!(
    ///     neg.to_u128_wrapping(),
    ///     0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff
    /// );
    /// let s = "f123456789abcdef0123456789abcdef0";
    /// let large = Integer::from_str_radix(s, 16).unwrap();
    /// assert_eq!(
    ///     large.to_u128_wrapping(),
    ///     0x1234_5678_9abc_def0_1234_5678_9abc_def0
    /// );
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`u128`]: https://doc.rust-lang.org/nightly/std/primitive.u128.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_u128_wrapping(&self) -> u128 {
        self.wrapping_cast()
    }

    /// Converts to a [`usize`], wrapping if the value does not fit.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[wrapping\_as][`wrapping_as`]::&lt;[usize][`usize`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[wrapping\_as][`wrapping_as`]::&lt;[usize][`usize`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let large: Integer = (Integer::from(0x1000) << 128) | 0x1234;
    /// assert_eq!(large.to_usize_wrapping(), 0x1234);
    /// ```
    ///
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`usize`]: https://doc.rust-lang.org/nightly/std/primitive.usize.html
    /// [`wrapping_as`]: https://docs.rs/az/1/az/trait.WrappingAs.html#tymethod.wrapping_as
    #[inline]
    pub fn to_usize_wrapping(&self) -> usize {
        self.wrapping_cast()
    }

    /// Converts to an [`f32`], rounding towards zero.
    ///
    /// This conversion can also be performed using
    ///   * <code>(&amp;integer).[az][`az`]::&lt;[f32][`f32`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[az][`az`]::&lt;[f32][`f32`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::Integer;
    /// let min = Integer::from_f32(f32::MIN).unwrap();
    /// let min_minus_one = min - 1u32;
    /// // min_minus_one is truncated to f32::MIN
    /// assert_eq!(min_minus_one.to_f32(), f32::MIN);
    /// let times_two = min_minus_one * 2u32;
    /// // times_two is too small
    /// assert_eq!(times_two.to_f32(), f32::NEG_INFINITY);
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
    ///   * <code>(&amp;integer).[az][`az`]::&lt;[f64][`f64`]&gt;()</code>
    ///   * <code>integer.[borrow][`borrow`]().[az][`az`]::&lt;[f64][`f64`]&gt;()</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f64;
    /// use rug::Integer;
    ///
    /// // An `f64` has 53 bits of precision.
    /// let exact = 0x1f_ffff_ffff_ffff_u64;
    /// let i = Integer::from(exact);
    /// assert_eq!(i.to_f64(), exact as f64);
    ///
    /// // large has 56 ones
    /// let large = 0xff_ffff_ffff_ffff_u64;
    /// // trunc has 53 ones followed by 3 zeros
    /// let trunc = 0xff_ffff_ffff_fff8_u64;
    /// let j = Integer::from(large);
    /// assert_eq!(j.to_f64() as u64, trunc);
    ///
    /// let max = Integer::from_f64(f64::MAX).unwrap();
    /// let max_plus_one = max + 1u32;
    /// // max_plus_one is truncated to f64::MAX
    /// assert_eq!(max_plus_one.to_f64(), f64::MAX);
    /// let times_two = max_plus_one * 2u32;
    /// // times_two is too large
    /// assert_eq!(times_two.to_f64(), f64::INFINITY);
    /// ```
    ///
    /// [`az`]: https://docs.rs/az/1/az/trait.Az.html#tymethod.az
    /// [`borrow`]: https://doc.rust-lang.org/nightly/core/borrow/trait.Borrow.html#tymethod.borrow
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    #[inline]
    pub fn to_f64(&self) -> f64 {
        self.cast()
    }

    /// Converts to an [`f32`] and an exponent, rounding towards zero.
    ///
    /// The returned [`f32`] is in the range 0.5 ≤ <i>x</i> < 1. If
    /// the value is zero, `(0.0, 0)` is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let zero = Integer::new();
    /// let (d0, exp0) = zero.to_f32_exp();
    /// assert_eq!((d0, exp0), (0.0, 0));
    /// let fifteen = Integer::from(15);
    /// let (d15, exp15) = fifteen.to_f32_exp();
    /// assert_eq!((d15, exp15), (15.0 / 16.0, 4));
    /// ```
    ///
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    #[inline]
    pub fn to_f32_exp(&self) -> (f32, u32) {
        let (f, exp) = self.to_f64_exp();
        let trunc_f = misc::trunc_f64_to_f32(f);
        (trunc_f, exp)
    }

    /// Converts to an [`f64`] and an exponent, rounding towards zero.
    ///
    /// The returned [`f64`] is in the range 0.5 ≤ <i>x</i> < 1. If
    /// the value is zero, `(0.0, 0)` is returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let zero = Integer::new();
    /// let (d0, exp0) = zero.to_f64_exp();
    /// assert_eq!((d0, exp0), (0.0, 0));
    /// let fifteen = Integer::from(15);
    /// let (d15, exp15) = fifteen.to_f64_exp();
    /// assert_eq!((d15, exp15), (15.0 / 16.0, 4));
    /// ```
    ///
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    #[inline]
    pub fn to_f64_exp(&self) -> (f64, u32) {
        let (f, exp) = xmpz::get_f64_2exp(self);
        (f, exp.unwrapped_cast())
    }

    /// Returns a string representation of the number for the
    /// specified `radix`.
    ///
    /// # Panics
    ///
    /// Panics if `radix` is less than 2 or greater than 36.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let mut i = Integer::new();
    /// assert_eq!(i.to_string_radix(10), "0");
    /// i.assign(-10);
    /// assert_eq!(i.to_string_radix(16), "-a");
    /// i.assign(0x1234cdef);
    /// assert_eq!(i.to_string_radix(4), "102031030313233");
    /// i.assign(Integer::parse_radix("123456789aAbBcCdDeEfF", 16).unwrap());
    /// assert_eq!(i.to_string_radix(16), "123456789aabbccddeeff");
    /// ```
    #[inline]
    pub fn to_string_radix(&self, radix: i32) -> String {
        let mut s = String::new();
        append_to_string(&mut s, self, radix, false);
        s
    }

    /// Assigns from an [`f32`] if it is [finite][`is_finite`],
    /// rounding towards zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::f32;
    /// use rug::Integer;
    /// let mut i = Integer::new();
    /// let ret = i.assign_f64(-12.7);
    /// assert!(ret.is_ok());
    /// assert_eq!(i, -12);
    /// let ret = i.assign_f32(f32::NAN);
    /// assert!(ret.is_err());
    /// assert_eq!(i, -12);
    /// ```
    ///
    /// [`f32`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f32.html#method.is_finite
    #[inline]
    #[allow(clippy::result_unit_err)]
    pub fn assign_f32(&mut self, val: f32) -> Result<(), ()> {
        self.assign_f64(val.into())
    }

    /// Assigns from an [`f64`] if it is [finite][`is_finite`],
    /// rounding towards zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::new();
    /// let ret = i.assign_f64(12.7);
    /// assert!(ret.is_ok());
    /// assert_eq!(i, 12);
    /// let ret = i.assign_f64(1.0 / 0.0);
    /// assert!(ret.is_err());
    /// assert_eq!(i, 12);
    /// ```
    ///
    /// [`f64`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html
    /// [`is_finite`]: https://doc.rust-lang.org/nightly/std/primitive.f64.html#method.is_finite
    #[inline]
    #[allow(clippy::result_unit_err)]
    pub fn assign_f64(&mut self, val: f64) -> Result<(), ()> {
        xmpz::set_f64(self, val)
    }

    /// Borrows a negated copy of the [`Integer`].
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Integer][`Integer`]&gt;</code>.
    ///
    /// This method performs a shallow copy and negates it, and
    /// negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(42);
    /// let neg_i = i.as_neg();
    /// assert_eq!(*neg_i, -42);
    /// // methods taking &self can be used on the returned object
    /// let reneg_i = neg_i.as_neg();
    /// assert_eq!(*reneg_i, 42);
    /// assert_eq!(*reneg_i, i);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Integer`]: #
    pub fn as_neg(&self) -> BorrowInteger<'_> {
        let mut raw = self.inner;
        raw.size = raw.size.checked_neg().expect("overflow");
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowInteger::from_raw(raw) }
    }

    /// Borrows an absolute copy of the [`Integer`].
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Integer][`Integer`]&gt;</code>.
    ///
    /// This method performs a shallow copy and possibly negates it,
    /// and negation does not change the allocated data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-42);
    /// let abs_i = i.as_abs();
    /// assert_eq!(*abs_i, 42);
    /// // methods taking &self can be used on the returned object
    /// let reabs_i = abs_i.as_abs();
    /// assert_eq!(*reabs_i, 42);
    /// assert_eq!(*reabs_i, *abs_i);
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Integer`]: #
    pub fn as_abs(&self) -> BorrowInteger<'_> {
        let mut raw = self.inner;
        raw.size = raw.size.checked_abs().expect("overflow");
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        unsafe { BorrowInteger::from_raw(raw) }
    }

    #[cfg(feature = "rational")]
    /// Borrows a copy of the [`Integer`] as a [`Rational`] number.
    ///
    /// The returned object implements
    /// <code>[Deref]&lt;[Target] = [Rational][`Rational`]&gt;</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(42);
    /// let r = i.as_rational();
    /// assert_eq!(*r, (42, 1));
    /// // methods taking &self can be used on the returned object
    /// let recip_r = r.as_recip();
    /// assert_eq!(*recip_r, (1, 42));
    /// ```
    ///
    /// [Deref]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html
    /// [Target]: https://doc.rust-lang.org/nightly/core/ops/trait.Deref.html#associatedtype.Target
    /// [`Integer`]: #
    /// [`Rational`]: struct.Rational.html
    pub const fn as_rational(&self) -> BorrowRational<'_> {
        const ONE: limb_t = 1;
        // use NonNull::new_unchecked because NonNull::from is not usable in const
        let raw_rational = mpq_t {
            num: self.inner,
            den: mpz_t {
                alloc: 1,
                size: 1,
                d: unsafe { NonNull::new_unchecked(&ONE as *const limb_t as *mut limb_t) },
            },
        };
        // Safety: the lifetime of the return type is equal to the lifetime of self.
        // Safety: the number is in canonical form as the denominator is 1.
        unsafe { BorrowRational::from_raw(raw_rational) }
    }

    /// Returns [`true`] if the number is even.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// assert!(!(Integer::from(13).is_even()));
    /// assert!(Integer::from(-14).is_even());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_even(&self) -> bool {
        xmpz::even_p(self)
    }

    /// Returns [`true`] if the number is odd.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// assert!(Integer::from(13).is_odd());
    /// assert!(!Integer::from(-14).is_odd());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_odd(&self) -> bool {
        xmpz::odd_p(self)
    }

    /// Returns [`true`] if the number is divisible by `divisor`. Unlike
    /// other division functions, `divisor` can be zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(230);
    /// assert!(i.is_divisible(&Integer::from(10)));
    /// assert!(!i.is_divisible(&Integer::from(100)));
    /// assert!(!i.is_divisible(&Integer::new()));
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_divisible(&self, divisor: &Self) -> bool {
        xmpz::divisible_p(self, divisor)
    }

    /// Returns [`true`] if the number is divisible by `divisor`. Unlike
    /// other division functions, `divisor` can be zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(230);
    /// assert!(i.is_divisible_u(23));
    /// assert!(!i.is_divisible_u(100));
    /// assert!(!i.is_divisible_u(0));
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_divisible_u(&self, divisor: u32) -> bool {
        xmpz::divisible_ui_p(self, divisor.into())
    }

    /// Returns [`true`] if the number is divisible by 2<sup><i>b</i></sup>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(15 << 17);
    /// assert!(i.is_divisible_2pow(16));
    /// assert!(i.is_divisible_2pow(17));
    /// assert!(!i.is_divisible_2pow(18));
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_divisible_2pow(&self, b: u32) -> bool {
        xmpz::divisible_2exp_p(self, b.into())
    }

    /// Returns [`true`] if the number is congruent to <i>c</i> mod
    /// <i>divisor</i>, that is, if there exists a <i>q</i> such that
    /// `self` = <i>c</i> + <i>q</i> × <i>divisor</i>. Unlike other
    /// division functions, `divisor` can be zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let n = Integer::from(105);
    /// let divisor = Integer::from(10);
    /// assert!(n.is_congruent(&Integer::from(5), &divisor));
    /// assert!(n.is_congruent(&Integer::from(25), &divisor));
    /// assert!(!n.is_congruent(&Integer::from(7), &divisor));
    /// // n is congruent to itself if divisor is 0
    /// assert!(n.is_congruent(&n, &Integer::from(0)));
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_congruent(&self, c: &Self, divisor: &Self) -> bool {
        xmpz::congruent_p(self, c, divisor)
    }

    /// Returns [`true`] if the number is congruent to <i>c</i> mod
    /// <i>divisor</i>, that is, if there exists a <i>q</i> such that
    /// `self` = <i>c</i> + <i>q</i> × <i>divisor</i>. Unlike other
    /// division functions, `divisor` can be zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let n = Integer::from(105);
    /// assert!(n.is_congruent_u(3335, 10));
    /// assert!(!n.is_congruent_u(107, 10));
    /// // n is congruent to itself if divisor is 0
    /// assert!(n.is_congruent_u(105, 0));
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_congruent_u(&self, c: u32, divisor: u32) -> bool {
        xmpz::congruent_ui_p(self, c.into(), divisor.into())
    }

    /// Returns [`true`] if the number is congruent to <i>c</i> mod
    /// 2<sup><i>b</i></sup>, that is, if there exists a <i>q</i> such
    /// that `self` = <i>c</i> + <i>q</i> × 2<sup><i>b</i></sup>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let n = Integer::from(13 << 17 | 21);
    /// assert!(n.is_congruent_2pow(&Integer::from(7 << 17 | 21), 17));
    /// assert!(!n.is_congruent_2pow(&Integer::from(13 << 17 | 22), 17));
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_congruent_2pow(&self, c: &Self, b: u32) -> bool {
        xmpz::congruent_2exp_p(self, c, b.into())
    }

    /// Returns [`true`] if the number is a perfect power.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 0 is 0 to the power of anything
    /// assert!(Integer::from(0).is_perfect_power());
    /// // 25 is 5 to the power of 2
    /// assert!(Integer::from(25).is_perfect_power());
    /// // −243 is −3 to the power of 5
    /// assert!(Integer::from(243).is_perfect_power());
    ///
    /// assert!(!Integer::from(24).is_perfect_power());
    /// assert!(!Integer::from(-100).is_perfect_power());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_perfect_power(&self) -> bool {
        xmpz::perfect_power_p(self)
    }

    /// Returns [`true`] if the number is a perfect square.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// assert!(Integer::from(0).is_perfect_square());
    /// assert!(Integer::from(1).is_perfect_square());
    /// assert!(Integer::from(4).is_perfect_square());
    /// assert!(Integer::from(9).is_perfect_square());
    ///
    /// assert!(!Integer::from(15).is_perfect_square());
    /// assert!(!Integer::from(-9).is_perfect_square());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_perfect_square(&self) -> bool {
        xmpz::perfect_square_p(self)
    }

    /// Returns [`true`] if the number is a power of two.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// assert!(Integer::from(1).is_power_of_two());
    /// assert!(Integer::from(4).is_power_of_two());
    /// assert!(Integer::from(1 << 30).is_power_of_two());
    ///
    /// assert!(!Integer::from(7).is_power_of_two());
    /// assert!(!Integer::from(0).is_power_of_two());
    /// assert!(!Integer::from(-1).is_power_of_two());
    /// ```
    ///
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn is_power_of_two(&self) -> bool {
        xmpz::power_of_two_p(self)
    }

    /// Returns the same result as
    /// <code>self.[cmp][`cmp`](&amp;0.[into][`into`]())</code>, but is faster.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::Integer;
    /// assert_eq!(Integer::from(-5).cmp0(), Ordering::Less);
    /// assert_eq!(Integer::from(0).cmp0(), Ordering::Equal);
    /// assert_eq!(Integer::from(5).cmp0(), Ordering::Greater);
    /// ```
    ///
    /// [`cmp`]: https://doc.rust-lang.org/nightly/core/cmp/trait.Ord.html#tymethod.cmp
    /// [`into`]: https://doc.rust-lang.org/nightly/core/convert/trait.Into.html#tymethod.into
    #[inline]
    pub fn cmp0(&self) -> Ordering {
        xmpz::sgn(self)
    }

    /// Compares the absolute values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::cmp::Ordering;
    /// use rug::Integer;
    /// let a = Integer::from(-10);
    /// let b = Integer::from(4);
    /// assert_eq!(a.cmp(&b), Ordering::Less);
    /// assert_eq!(a.cmp_abs(&b), Ordering::Greater);
    /// ```
    #[inline]
    pub fn cmp_abs(&self, other: &Self) -> Ordering {
        xmpz::cmpabs(self, other)
    }

    /// Returns the number of bits required to represent the absolute
    /// value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// assert_eq!(Integer::from(0).significant_bits(), 0);  //    “”
    /// assert_eq!(Integer::from(1).significant_bits(), 1);  //   “1”
    /// assert_eq!(Integer::from(4).significant_bits(), 3);  // “100”
    /// assert_eq!(Integer::from(7).significant_bits(), 3);  // “111”
    /// assert_eq!(Integer::from(-1).significant_bits(), 1); //   “1”
    /// assert_eq!(Integer::from(-4).significant_bits(), 3); // “100”
    /// assert_eq!(Integer::from(-7).significant_bits(), 3); // “111”
    /// ```
    #[inline]
    pub fn significant_bits(&self) -> u32 {
        xmpz::significant_bits(self).unwrapped_cast()
    }

    /// Returns the number of bits required to represent the value
    /// using a two’s-complement representation.
    ///
    /// For non-negative numbers, this method returns one more than
    /// the [`significant_bits`] method, since an extra zero is needed
    /// before the most significant bit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// assert_eq!(Integer::from(-5).signed_bits(), 4); // “1011”
    /// assert_eq!(Integer::from(-4).signed_bits(), 3); //  “100”
    /// assert_eq!(Integer::from(-3).signed_bits(), 3); //  “101”
    /// assert_eq!(Integer::from(-2).signed_bits(), 2); //   “10”
    /// assert_eq!(Integer::from(-1).signed_bits(), 1); //    “1”
    /// assert_eq!(Integer::from(0).signed_bits(), 1);  //    “0”
    /// assert_eq!(Integer::from(1).signed_bits(), 2);  //   “01”
    /// assert_eq!(Integer::from(2).signed_bits(), 3);  //  “010”
    /// assert_eq!(Integer::from(3).signed_bits(), 3);  //  “011”
    /// assert_eq!(Integer::from(4).signed_bits(), 4);  // “0100”
    /// ```
    ///
    /// [`significant_bits`]: #method.significant_bits
    #[inline]
    pub fn signed_bits(&self) -> u32 {
        xmpz::signed_bits(self)
    }

    /// Returns the number of one bits if the value ≥ 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// assert_eq!(Integer::from(0).count_ones(), Some(0));
    /// assert_eq!(Integer::from(15).count_ones(), Some(4));
    /// assert_eq!(Integer::from(-1).count_ones(), None);
    /// ```
    #[inline]
    pub fn count_ones(&self) -> Option<u32> {
        xmpz::popcount(self)
    }

    /// Returns the number of zero bits if the value < 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// assert_eq!(Integer::from(0).count_zeros(), None);
    /// assert_eq!(Integer::from(1).count_zeros(), None);
    /// assert_eq!(Integer::from(-1).count_zeros(), Some(0));
    /// assert_eq!(Integer::from(-2).count_zeros(), Some(1));
    /// assert_eq!(Integer::from(-7).count_zeros(), Some(2));
    /// assert_eq!(Integer::from(-8).count_zeros(), Some(3));
    /// ```
    #[inline]
    pub fn count_zeros(&self) -> Option<u32> {
        xmpz::zerocount(self)
    }

    /// Returns the location of the first zero, starting at `start`.
    /// If the bit at location `start` is zero, returns `start`.
    ///
    /// ```rust
    /// use rug::Integer;
    /// // −2 is ...11111110
    /// assert_eq!(Integer::from(-2).find_zero(0), Some(0));
    /// assert_eq!(Integer::from(-2).find_zero(1), None);
    /// // 15 is ...00001111
    /// assert_eq!(Integer::from(15).find_zero(0), Some(4));
    /// assert_eq!(Integer::from(15).find_zero(20), Some(20));
    /// ```
    #[inline]
    pub fn find_zero(&self, start: u32) -> Option<u32> {
        xmpz::scan0(self, start)
    }

    /// Returns the location of the first one, starting at `start`.
    /// If the bit at location `start` is one, returns `start`.
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 1 is ...00000001
    /// assert_eq!(Integer::from(1).find_one(0), Some(0));
    /// assert_eq!(Integer::from(1).find_one(1), None);
    /// // −16 is ...11110000
    /// assert_eq!(Integer::from(-16).find_one(0), Some(4));
    /// assert_eq!(Integer::from(-16).find_one(20), Some(20));
    /// ```
    #[inline]
    pub fn find_one(&self, start: u32) -> Option<u32> {
        xmpz::scan1(self, start)
    }

    /// Sets the bit at location `index` to 1 if `val` is [`true`] or
    /// 0 if `val` is [`false`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let mut i = Integer::from(-1);
    /// assert_eq!(*i.set_bit(0, false), -2);
    /// i.assign(0xff);
    /// assert_eq!(*i.set_bit(11, true), 0x8ff);
    /// ```
    ///
    /// [`false`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn set_bit(&mut self, index: u32, val: bool) -> &mut Self {
        if val {
            xmpz::setbit(self, index.into());
        } else {
            xmpz::clrbit(self, index.into());
        }
        self
    }

    /// Returns [`true`] if the bit at location `index` is 1 or
    /// [`false`] if the bit is 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(0b100101);
    /// assert!(i.get_bit(0));
    /// assert!(!i.get_bit(1));
    /// assert!(i.get_bit(5));
    /// let neg = Integer::from(-1);
    /// assert!(neg.get_bit(1000));
    /// ```
    ///
    /// [`false`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    /// [`true`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
    #[inline]
    pub fn get_bit(&self, index: u32) -> bool {
        xmpz::tstbit(self, index.into())
    }

    /// Toggles the bit at location `index`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(0b100101);
    /// i.toggle_bit(5);
    /// assert_eq!(i, 0b101);
    /// ```
    #[inline]
    pub fn toggle_bit(&mut self, index: u32) -> &mut Self {
        xmpz::combit(self, index.into());
        self
    }

    /// Retuns the Hamming distance if the two numbers have the same
    /// sign.
    ///
    /// The Hamming distance is the number of different bits.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-1);
    /// assert_eq!(Integer::from(0).hamming_dist(&i), None);
    /// assert_eq!(Integer::from(-1).hamming_dist(&i), Some(0));
    /// // −1 is ...11111111 and −13 is ...11110011
    /// assert_eq!(Integer::from(-13).hamming_dist(&i), Some(2));
    /// ```
    #[inline]
    pub fn hamming_dist(&self, other: &Self) -> Option<u32> {
        xmpz::hamdist(self, other)
    }

    /// Adds a list of [`Integer`] values.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// let values = [
    ///     Integer::from(5),
    ///     Integer::from(1024),
    ///     Integer::from(-100_000),
    ///     Integer::from(-4),
    /// ];
    ///
    /// let r = Integer::sum(values.iter());
    /// let sum = Integer::from(r);
    /// let expected = 5 + 1024 - 100_000 - 4;
    /// assert_eq!(sum, expected);
    /// ```
    ///
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sum<'a, I>(values: I) -> SumIncomplete<'a, I>
    where
        I: Iterator<Item = &'a Self>,
    {
        SumIncomplete { values }
    }

    /// Finds the dot product of a list of [`Integer`] value pairs.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[AddAssign][`AddAssign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Add][`Add`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// let a = [Integer::from(270), Integer::from(-11)];
    /// let b = [Integer::from(100), Integer::from(5)];
    ///
    /// let r = Integer::dot(a.iter().zip(b.iter()));
    /// let dot = Integer::from(r);
    /// let expected = 270 * 100 - 11 * 5;
    /// assert_eq!(dot, expected);
    /// ```
    ///
    /// [`AddAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.AddAssign.html
    /// [`Add`]: https://doc.rust-lang.org/nightly/core/ops/trait.Add.html
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn dot<'a, I>(values: I) -> DotIncomplete<'a, I>
    where
        I: Iterator<Item = (&'a Self, &'a Self)>,
    {
        DotIncomplete { values }
    }

    /// Multiplies a list of [`Integer`] values.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[MulAssign][`MulAssign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[Mul][`Mul`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    ///
    /// let values = [
    ///     Integer::from(5),
    ///     Integer::from(1024),
    ///     Integer::from(-100_000),
    ///     Integer::from(-4),
    /// ];
    ///
    /// let r = Integer::product(values.iter());
    /// let product = Integer::from(r);
    /// let expected = 5 * 1024 * -100_000 * -4;
    /// assert_eq!(product, expected);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [`MulAssign`]: https://doc.rust-lang.org/nightly/core/ops/trait.MulAssign.html
    /// [`Mul`]: https://doc.rust-lang.org/nightly/core/ops/trait.Mul.html
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
    /// use rug::Integer;
    /// let i = Integer::from(-100);
    /// let abs = i.abs();
    /// assert_eq!(abs, 100);
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
    /// use rug::Integer;
    /// let mut i = Integer::from(-100);
    /// i.abs_mut();
    /// assert_eq!(i, 100);
    /// ```
    #[inline]
    pub fn abs_mut(&mut self) {
        xmpz::abs(self, ());
    }

    /// Computes the absolute value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-100);
    /// let r = i.abs_ref();
    /// let abs = Integer::from(r);
    /// assert_eq!(abs, 100);
    /// assert_eq!(i, -100);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn abs_ref(&self) -> AbsIncomplete {
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
    /// use rug::Integer;
    /// assert_eq!(Integer::from(-100).signum(), -1);
    /// assert_eq!(Integer::from(0).signum(), 0);
    /// assert_eq!(Integer::from(100).signum(), 1);
    /// ```
    #[inline]
    pub fn signum(mut self) -> Self {
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
    /// use rug::Integer;
    /// let mut i = Integer::from(-100);
    /// i.signum_mut();
    /// assert_eq!(i, -1);
    /// ```
    #[inline]
    pub fn signum_mut(&mut self) {
        xmpz::signum(self, ())
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
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-100);
    /// let r = i.signum_ref();
    /// let signum = Integer::from(r);
    /// assert_eq!(signum, -1);
    /// assert_eq!(i, -100);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn signum_ref(&self) -> SignumIncomplete {
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
    /// use rug::Integer;
    /// let min = -10;
    /// let max = 10;
    /// let too_small = Integer::from(-100);
    /// let clamped1 = too_small.clamp(&min, &max);
    /// assert_eq!(clamped1, -10);
    /// let in_range = Integer::from(3);
    /// let clamped2 = in_range.clamp(&min, &max);
    /// assert_eq!(clamped2, 3);
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
    /// use rug::Integer;
    /// let min = -10;
    /// let max = 10;
    /// let mut too_small = Integer::from(-100);
    /// too_small.clamp_mut(&min, &max);
    /// assert_eq!(too_small, -10);
    /// let mut in_range = Integer::from(3);
    /// in_range.clamp_mut(&min, &max);
    /// assert_eq!(in_range, 3);
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
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Panics
    ///
    /// Panics if the maximum value is less than the minimum value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let min = -10;
    /// let max = 10;
    /// let too_small = Integer::from(-100);
    /// let r1 = too_small.clamp_ref(&min, &max);
    /// let clamped1 = Integer::from(r1);
    /// assert_eq!(clamped1, -10);
    /// let in_range = Integer::from(3);
    /// let r2 = in_range.clamp_ref(&min, &max);
    /// let clamped2 = Integer::from(r2);
    /// assert_eq!(clamped2, 3);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
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

    /// Keeps the <i>n</i> least significant bits only, producing
    /// a result that is greater or equal to 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-1);
    /// let keep_8 = i.keep_bits(8);
    /// assert_eq!(keep_8, 0xff);
    /// ```
    #[inline]
    pub fn keep_bits(mut self, n: u32) -> Self {
        self.keep_bits_mut(n);
        self
    }

    /// Keeps the <i>n</i> least significant bits only, producing
    /// a result that is greater or equal to 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(-1);
    /// i.keep_bits_mut(8);
    /// assert_eq!(i, 0xff);
    /// ```
    #[inline]
    pub fn keep_bits_mut(&mut self, n: u32) {
        xmpz::fdiv_r_2exp(self, (), n)
    }

    /// Keeps the <i>n</i> least significant bits only, producing
    /// a result that is greater or equal to 0.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-1);
    /// let r = i.keep_bits_ref(8);
    /// let eight_bits = Integer::from(r);
    /// assert_eq!(eight_bits, 0xff);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    pub fn keep_bits_ref(&self, n: u32) -> KeepBitsIncomplete {
        KeepBitsIncomplete { ref_self: self, n }
    }

    /// Keeps the <i>n</i> least significant bits only, producing
    /// a negative result if the <i>n</i>th least significant bit
    /// is one.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-1);
    /// let i_keep_8 = i.keep_signed_bits(8);
    /// assert_eq!(i_keep_8, -1);
    /// let j = Integer::from(15 << 8 | 15);
    /// let j_keep_8 = j.keep_signed_bits(8);
    /// assert_eq!(j_keep_8, 15);
    /// ```
    #[inline]
    pub fn keep_signed_bits(mut self, n: u32) -> Self {
        self.keep_signed_bits_mut(n);
        self
    }

    /// Keeps the <i>n</i> least significant bits only, producing
    /// a negative result if the <i>n</i>th least significant bit
    /// is one.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(-1);
    /// i.keep_signed_bits_mut(8);
    /// assert_eq!(i, -1);
    /// let mut j = Integer::from(15 << 8 | 15);
    /// j.keep_signed_bits_mut(8);
    /// assert_eq!(j, 15);
    /// ```
    #[inline]
    pub fn keep_signed_bits_mut(&mut self, n: u32) {
        xmpz::keep_signed_bits(self, (), n);
    }

    /// Keeps the <i>n</i> least significant bits only, producing
    /// a negative result if the <i>n</i>th least significant bit
    /// is one.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-1);
    /// let r = i.keep_signed_bits_ref(8);
    /// let eight_bits = Integer::from(r);
    /// assert_eq!(eight_bits, -1);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn keep_signed_bits_ref(&self, n: u32) -> KeepSignedBitsIncomplete<'_> {
        KeepSignedBitsIncomplete { ref_self: self, n }
    }

    /// Finds the next power of two, or 1 if the number ≤ 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(-3).next_power_of_two();
    /// assert_eq!(i, 1);
    /// let i = Integer::from(4).next_power_of_two();
    /// assert_eq!(i, 4);
    /// let i = Integer::from(7).next_power_of_two();
    /// assert_eq!(i, 8);
    /// ```
    #[inline]
    pub fn next_power_of_two(mut self) -> Self {
        self.next_power_of_two_mut();
        self
    }

    /// Finds the next power of two, or 1 if the number ≤ 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(53);
    /// i.next_power_of_two_mut();
    /// assert_eq!(i, 64);
    /// ```
    #[inline]
    pub fn next_power_of_two_mut(&mut self) {
        xmpz::next_pow_of_two(self, ());
    }

    /// Finds the next power of two, or 1 if the number ≤ 0.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(53);
    /// let r = i.next_power_of_two_ref();
    /// let next = Integer::from(r);
    /// assert_eq!(next, 64);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn next_power_of_two_ref(&self) -> NextPowerOfTwoIncomplete<'_> {
        NextPowerOfTwoIncomplete { ref_self: self }
    }

    /// Performs a division producing both the quotient and
    /// remainder.
    ///
    /// The remainder has the same sign as the dividend.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(23);
    /// let divisor = Integer::from(-10);
    /// let (quotient, rem) = dividend.div_rem(divisor);
    /// assert_eq!(quotient, -2);
    /// assert_eq!(rem, 3);
    /// ```
    #[inline]
    pub fn div_rem(mut self, mut divisor: Self) -> (Self, Self) {
        self.div_rem_mut(&mut divisor);
        (self, divisor)
    }

    /// Performs a division producing both the quotient and
    /// remainder.
    ///
    /// The remainder has the same sign as the dividend.
    ///
    /// The quotient is stored in `self` and the remainder is
    /// stored in `divisor`.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut dividend_quotient = Integer::from(-23);
    /// let mut divisor_rem = Integer::from(10);
    /// dividend_quotient.div_rem_mut(&mut divisor_rem);
    /// assert_eq!(dividend_quotient, -2);
    /// assert_eq!(divisor_rem, -3);
    /// ```
    #[inline]
    pub fn div_rem_mut(&mut self, divisor: &mut Self) {
        xmpz::tdiv_qr(self, divisor, (), ());
    }

    /// Performs a division producing both the quotient and
    /// remainder.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// The remainder has the same sign as the dividend.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(-23);
    /// let divisor = Integer::from(-10);
    /// let r = dividend.div_rem_ref(&divisor);
    /// let (quotient, rem) = <(Integer, Integer)>::from(r);
    /// assert_eq!(quotient, 2);
    /// assert_eq!(rem, -3);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn div_rem_ref<'a>(&'a self, divisor: &'a Self) -> DivRemIncomplete<'_> {
        DivRemIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded up.
    ///
    /// The sign of the remainder is the opposite of the divisor’s
    /// sign.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(23);
    /// let divisor = Integer::from(-10);
    /// let (quotient, rem) = dividend.div_rem_ceil(divisor);
    /// assert_eq!(quotient, -2);
    /// assert_eq!(rem, 3);
    /// ```
    #[inline]
    pub fn div_rem_ceil(mut self, mut divisor: Self) -> (Self, Self) {
        self.div_rem_ceil_mut(&mut divisor);
        (self, divisor)
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded up.
    ///
    /// The sign of the remainder is the opposite of the divisor’s
    /// sign.
    ///
    /// The quotient is stored in `self` and the remainder is
    /// stored in `divisor`.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut dividend_quotient = Integer::from(-23);
    /// let mut divisor_rem = Integer::from(10);
    /// dividend_quotient.div_rem_ceil_mut(&mut divisor_rem);
    /// assert_eq!(dividend_quotient, -2);
    /// assert_eq!(divisor_rem, -3);
    /// ```
    #[inline]
    pub fn div_rem_ceil_mut(&mut self, divisor: &mut Self) {
        xmpz::cdiv_qr(self, divisor, (), ());
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded up.
    ///
    /// The sign of the remainder is the opposite of the divisor’s
    /// sign.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(-23);
    /// let divisor = Integer::from(-10);
    /// let r = dividend.div_rem_ceil_ref(&divisor);
    /// let (quotient, rem) = <(Integer, Integer)>::from(r);
    /// assert_eq!(quotient, 3);
    /// assert_eq!(rem, 7);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn div_rem_ceil_ref<'a>(&'a self, divisor: &'a Self) -> DivRemCeilIncomplete<'_> {
        DivRemCeilIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded down.
    ///
    /// The remainder has the same sign as the divisor.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(23);
    /// let divisor = Integer::from(-10);
    /// let (quotient, rem) = dividend.div_rem_floor(divisor);
    /// assert_eq!(quotient, -3);
    /// assert_eq!(rem, -7);
    /// ```
    #[inline]
    pub fn div_rem_floor(mut self, mut divisor: Self) -> (Self, Self) {
        self.div_rem_floor_mut(&mut divisor);
        (self, divisor)
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded down.
    ///
    /// The remainder has the same sign as the divisor.
    ///
    /// The quotient is stored in `self` and the remainder is
    /// stored in `divisor`.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut dividend_quotient = Integer::from(-23);
    /// let mut divisor_rem = Integer::from(10);
    /// dividend_quotient.div_rem_floor_mut(&mut divisor_rem);
    /// assert_eq!(dividend_quotient, -3);
    /// assert_eq!(divisor_rem, 7);
    /// ```
    #[inline]
    pub fn div_rem_floor_mut(&mut self, divisor: &mut Self) {
        xmpz::fdiv_qr(self, divisor, (), ());
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded down.
    ///
    /// The remainder has the same sign as the divisor.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(-23);
    /// let divisor = Integer::from(-10);
    /// let r = dividend.div_rem_floor_ref(&divisor);
    /// let (quotient, rem) = <(Integer, Integer)>::from(r);
    /// assert_eq!(quotient, 2);
    /// assert_eq!(rem, -3);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn div_rem_floor_ref<'a>(&'a self, divisor: &'a Self) -> DivRemFloorIncomplete<'_> {
        DivRemFloorIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded to the nearest
    /// integer.
    ///
    /// When the quotient before rounding lies exactly between two
    /// integers, it is rounded away from zero.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 23 / −10 → −2 rem 3
    /// let (q, rem) = Integer::from(23).div_rem_round((-10).into());
    /// assert!(q == -2 && rem == 3);
    /// // 25 / 10 → 3 rem −5
    /// let (q, rem) = Integer::from(25).div_rem_round(10.into());
    /// assert!(q == 3 && rem == -5);
    /// // −27 / 10 → −3 rem 3
    /// let (q, rem) = Integer::from(-27).div_rem_round(10.into());
    /// assert!(q == -3 && rem == 3);
    /// ```
    #[inline]
    pub fn div_rem_round(mut self, mut divisor: Self) -> (Self, Self) {
        self.div_rem_round_mut(&mut divisor);
        (self, divisor)
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded to the nearest
    /// integer.
    ///
    /// When the quotient before rounding lies exactly between two
    /// integers, it is rounded away from zero.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // −25 / −10 → 3 rem 5
    /// let mut dividend_quotient = Integer::from(-25);
    /// let mut divisor_rem = Integer::from(-10);
    /// dividend_quotient.div_rem_round_mut(&mut divisor_rem);
    /// assert_eq!(dividend_quotient, 3);
    /// assert_eq!(divisor_rem, 5);
    /// ```
    #[inline]
    pub fn div_rem_round_mut(&mut self, divisor: &mut Self) {
        xmpz::rdiv_qr(self, divisor, (), ());
    }

    /// Performs a division producing both the quotient and
    /// remainder, with the quotient rounded to the nearest
    /// integer.
    ///
    /// When the quotient before rounding lies exactly between two
    /// integers, it is rounded away from zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // −28 / −10 → 3 rem 2
    /// let dividend = Integer::from(-28);
    /// let divisor = Integer::from(-10);
    /// let r = dividend.div_rem_round_ref(&divisor);
    /// let (quotient, rem) = <(Integer, Integer)>::from(r);
    /// assert_eq!(quotient, 3);
    /// assert_eq!(rem, 2);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn div_rem_round_ref<'a>(&'a self, divisor: &'a Self) -> DivRemRoundIncomplete<'_> {
        DivRemRoundIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Performs Euclidean division producing both the quotient
    /// and remainder, with a positive remainder.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(23);
    /// let divisor = Integer::from(-10);
    /// let (quotient, rem) = dividend.div_rem_euc(divisor);
    /// assert_eq!(quotient, -2);
    /// assert_eq!(rem, 3);
    /// ```
    #[inline]
    pub fn div_rem_euc(mut self, mut divisor: Self) -> (Self, Self) {
        self.div_rem_euc_mut(&mut divisor);
        (self, divisor)
    }

    /// Performs Euclidean division producing both the quotient
    /// and remainder, with a positive remainder.
    ///
    /// The quotient is stored in `self` and the remainder is
    /// stored in `divisor`.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut dividend_quotient = Integer::from(-23);
    /// let mut divisor_rem = Integer::from(10);
    /// dividend_quotient.div_rem_euc_mut(&mut divisor_rem);
    /// assert_eq!(dividend_quotient, -3);
    /// assert_eq!(divisor_rem, 7);
    /// ```
    #[inline]
    pub fn div_rem_euc_mut(&mut self, divisor: &mut Self) {
        xmpz::ediv_qr(self, divisor, (), ());
    }

    /// Performs Euclidan division producing both the quotient and
    /// remainder, with a positive remainder.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let dividend = Integer::from(-23);
    /// let divisor = Integer::from(-10);
    /// let r = dividend.div_rem_euc_ref(&divisor);
    /// let (quotient, rem) = <(Integer, Integer)>::from(r);
    /// assert_eq!(quotient, 3);
    /// assert_eq!(rem, 7);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn div_rem_euc_ref<'a>(&'a self, divisor: &'a Self) -> DivRemEucIncomplete<'_> {
        DivRemEucIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Returns the modulo, or the remainder of Euclidean division by
    /// a [`u32`].
    ///
    /// The result is always zero or positive.
    ///
    /// # Panics
    ///
    /// Panics if `modulo` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let pos = Integer::from(23);
    /// assert_eq!(pos.mod_u(1), 0);
    /// assert_eq!(pos.mod_u(10), 3);
    /// assert_eq!(pos.mod_u(100), 23);
    /// let neg = Integer::from(-23);
    /// assert_eq!(neg.mod_u(1), 0);
    /// assert_eq!(neg.mod_u(10), 7);
    /// assert_eq!(neg.mod_u(100), 77);
    /// ```
    ///
    /// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
    #[inline]
    pub fn mod_u(&self, modulo: u32) -> u32 {
        xmpz::fdiv_u32(self, modulo)
    }

    /// Performs an exact division.
    ///
    /// This is much faster than normal division, but produces
    /// correct results only when the division is exact.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(12345 * 54321);
    /// let quotient = i.div_exact(&Integer::from(12345));
    /// assert_eq!(quotient, 54321);
    /// ```
    #[inline]
    pub fn div_exact(mut self, divisor: &Self) -> Self {
        self.div_exact_mut(divisor);
        self
    }

    /// Performs an exact division.
    ///
    /// This is much faster than normal division, but produces
    /// correct results only when the division is exact.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(12345 * 54321);
    /// i.div_exact_mut(&Integer::from(12345));
    /// assert_eq!(i, 54321);
    /// ```
    #[inline]
    pub fn div_exact_mut(&mut self, divisor: &Self) {
        xmpz::divexact(self, (), divisor);
    }

    /// Performs an exact division `dividend` / `self`.
    ///
    /// This is much faster than normal division, but produces
    /// correct results only when the division is exact.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(12345);
    /// i.div_exact_from(&Integer::from(12345 * 54321));
    /// assert_eq!(i, 54321);
    /// ```
    pub fn div_exact_from(&mut self, dividend: &Integer) {
        xmpz::divexact(self, dividend, ());
    }

    /// Performs an exact division.
    ///
    /// This is much faster than normal division, but produces
    /// correct results only when the division is exact.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(12345 * 54321);
    /// let divisor = Integer::from(12345);
    /// let r = i.div_exact_ref(&divisor);
    /// let quotient = Integer::from(r);
    /// assert_eq!(quotient, 54321);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn div_exact_ref<'a>(&'a self, divisor: &'a Self) -> DivExactIncomplete<'_> {
        DivExactIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Performs an exact division.
    ///
    /// This is much faster than normal division, but produces
    /// correct results only when the division is exact.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(12345 * 54321);
    /// let q = i.div_exact_u(12345);
    /// assert_eq!(q, 54321);
    /// ```
    #[inline]
    pub fn div_exact_u(mut self, divisor: u32) -> Self {
        self.div_exact_u_mut(divisor);
        self
    }

    /// Performs an exact division.
    ///
    /// This is much faster than normal division, but produces
    /// correct results only when the division is exact.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(12345 * 54321);
    /// i.div_exact_u_mut(12345);
    /// assert_eq!(i, 54321);
    /// ```
    #[inline]
    pub fn div_exact_u_mut(&mut self, divisor: u32) {
        xmpz::divexact_u32(self, (), divisor);
    }

    /// Performs an exact division.
    ///
    /// This is much faster than normal division, but produces
    /// correct results only when the division is exact.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(12345 * 54321);
    /// let r = i.div_exact_u_ref(12345);
    /// assert_eq!(Integer::from(r), 54321);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn div_exact_u_ref(&self, divisor: u32) -> DivExactUIncomplete<'_> {
        DivExactUIncomplete {
            ref_self: self,
            divisor,
        }
    }

    /// Finds the inverse modulo `modulo` and returns
    /// [`Ok(inverse)`][`Ok`] if it exists, or
    /// [`Err(unchanged)`][`Err`] if the inverse does not exist.
    ///
    /// The inverse exists if the modulo is not zero, and `self` and
    /// the modulo are co-prime, that is their GCD is 1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let n = Integer::from(2);
    /// // Modulo 4, 2 has no inverse: there is no i such that 2 × i = 1.
    /// let inv_mod_4 = match n.invert(&Integer::from(4)) {
    ///     Ok(_) => unreachable!(),
    ///     Err(unchanged) => unchanged,
    /// };
    /// // no inverse exists, so value is unchanged
    /// assert_eq!(inv_mod_4, 2);
    /// let n = inv_mod_4;
    /// // Modulo 5, the inverse of 2 is 3, as 2 × 3 = 1.
    /// let inv_mod_5 = match n.invert(&Integer::from(5)) {
    ///     Ok(inverse) => inverse,
    ///     Err(_) => unreachable!(),
    /// };
    /// assert_eq!(inv_mod_5, 3);
    /// ```
    ///
    /// [`Err`]: https://doc.rust-lang.org/nightly/core/result/enum.Result.html#variant.Err
    /// [`Ok`]: https://doc.rust-lang.org/nightly/core/result/enum.Result.html#variant.Ok
    #[inline]
    pub fn invert(mut self, modulo: &Self) -> Result<Self, Self> {
        match self.invert_mut(modulo) {
            Ok(()) => Ok(self),
            Err(()) => Err(self),
        }
    }

    /// Finds the inverse modulo `modulo` if an inverse exists.
    ///
    /// The inverse exists if the modulo is not zero, and `self` and
    /// the modulo are co-prime, that is their GCD is 1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut n = Integer::from(2);
    /// // Modulo 4, 2 has no inverse: there is no i such that 2 × i = 1.
    /// match n.invert_mut(&Integer::from(4)) {
    ///     Ok(()) => unreachable!(),
    ///     Err(()) => assert_eq!(n, 2),
    /// }
    /// // Modulo 5, the inverse of 2 is 3, as 2 × 3 = 1.
    /// match n.invert_mut(&Integer::from(5)) {
    ///     Ok(()) => assert_eq!(n, 3),
    ///     Err(()) => unreachable!(),
    /// }
    /// ```
    #[inline]
    #[allow(clippy::result_unit_err)]
    pub fn invert_mut(&mut self, modulo: &Self) -> Result<(), ()> {
        match self.invert_ref(modulo) {
            Some(InvertIncomplete { sinverse, .. }) => {
                xmpz::finish_invert(self, &sinverse, modulo);
                Ok(())
            }
            None => Err(()),
        }
    }

    /// Finds the inverse modulo `modulo` if an inverse exists.
    ///
    /// The inverse exists if the modulo is not zero, and `self` and
    /// the modulo are co-prime, that is their GCD is 1.
    ///
    /// The following are implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let two = Integer::from(2);
    /// let four = Integer::from(4);
    /// let five = Integer::from(5);
    ///
    /// // Modulo 4, 2 has no inverse, there is no i such that 2 × i = 1.
    /// // For this conversion, if no inverse exists, the Integer
    /// // created is left unchanged as 0.
    /// assert!(two.invert_ref(&four).is_none());
    ///
    /// // Modulo 5, the inverse of 2 is 3, as 2 × 3 = 1.
    /// let r = two.invert_ref(&five).unwrap();
    /// let inverse = Integer::from(r);
    /// assert_eq!(inverse, 3);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    pub fn invert_ref<'a>(&'a self, modulo: &'a Self) -> Option<InvertIncomplete<'a>> {
        xmpz::start_invert(self, modulo).map(|sinverse| InvertIncomplete { sinverse, modulo })
    }

    /// Raises a number to the power of `exponent` modulo `modulo` and
    /// returns [`Ok(power)`][`Ok`] if an answer exists, or
    /// [`Err(unchanged)`][`Err`] if it does not.
    ///
    /// If the exponent is negative, then the number must have an
    /// inverse for an answer to exist.
    ///
    /// When the exponent is positive and the modulo is not zero, an
    /// answer always exists.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 ^ 5 = 16807
    /// let n = Integer::from(7);
    /// let e = Integer::from(5);
    /// let m = Integer::from(1000);
    /// let power = match n.pow_mod(&e, &m) {
    ///     Ok(power) => power,
    ///     Err(_) => unreachable!(),
    /// };
    /// assert_eq!(power, 807);
    /// ```
    ///
    /// When the exponent is negative, an answer exists if an inverse
    /// exists.
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 × 143 modulo 1000 = 1, so 7 has an inverse 143.
    /// // 7 ^ −5 modulo 1000 = 143 ^ 5 modulo 1000 = 943.
    /// let n = Integer::from(7);
    /// let e = Integer::from(-5);
    /// let m = Integer::from(1000);
    /// let power = match n.pow_mod(&e, &m) {
    ///     Ok(power) => power,
    ///     Err(_) => unreachable!(),
    /// };
    /// assert_eq!(power, 943);
    /// ```
    ///
    /// [`Err`]: https://doc.rust-lang.org/nightly/core/result/enum.Result.html#variant.Err
    /// [`Ok`]: https://doc.rust-lang.org/nightly/core/result/enum.Result.html#variant.Ok
    #[inline]
    pub fn pow_mod(mut self, exponent: &Self, modulo: &Self) -> Result<Self, Self> {
        match self.pow_mod_mut(exponent, modulo) {
            Ok(()) => Ok(self),
            Err(()) => Err(self),
        }
    }

    /// Raises a number to the power of `exponent` modulo `modulo` if
    /// an answer exists.
    ///
    /// If the exponent is negative, then the number must have an
    /// inverse for an answer to exist.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// // Modulo 1000, 2 has no inverse: there is no i such that 2 × i = 1.
    /// let mut n = Integer::from(2);
    /// let e = Integer::from(-5);
    /// let m = Integer::from(1000);
    /// match n.pow_mod_mut(&e, &m) {
    ///     Ok(()) => unreachable!(),
    ///     Err(()) => assert_eq!(n, 2),
    /// }
    /// // 7 × 143 modulo 1000 = 1, so 7 has an inverse 143.
    /// // 7 ^ −5 modulo 1000 = 143 ^ 5 modulo 1000 = 943.
    /// n.assign(7);
    /// match n.pow_mod_mut(&e, &m) {
    ///     Ok(()) => assert_eq!(n, 943),
    ///     Err(()) => unreachable!(),
    /// }
    /// ```
    #[inline]
    #[allow(clippy::result_unit_err)]
    pub fn pow_mod_mut(&mut self, exponent: &Self, modulo: &Self) -> Result<(), ()> {
        let sinverse = match self.pow_mod_ref(exponent, modulo) {
            Some(PowModIncomplete { sinverse, .. }) => sinverse,
            None => return Err(()),
        };
        if let Some(sinverse) = &sinverse {
            xmpz::pow_mod(self, sinverse, exponent, modulo);
        } else {
            xmpz::pow_mod(self, (), exponent, modulo);
        }
        Ok(())
    }

    /// Raises a number to the power of `exponent` modulo `modulo` if
    /// an answer exists.
    ///
    /// If the exponent is negative, then the number must have an
    /// inverse for an answer to exist.
    ///
    /// The following are implemented with the unwrapped returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let two = Integer::from(2);
    /// let thousand = Integer::from(1000);
    /// let minus_five = Integer::from(-5);
    /// let seven = Integer::from(7);
    ///
    /// // Modulo 1000, 2 has no inverse: there is no i such that 2 × i = 1.
    /// assert!(two.pow_mod_ref(&minus_five, &thousand).is_none());
    ///
    /// // 7 × 143 modulo 1000 = 1, so 7 has an inverse 143.
    /// // 7 ^ −5 modulo 1000 = 143 ^ 5 modulo 1000 = 943.
    /// let r = seven.pow_mod_ref(&minus_five, &thousand).unwrap();
    /// let power = Integer::from(r);
    /// assert_eq!(power, 943);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    pub fn pow_mod_ref<'a>(
        &'a self,
        exponent: &'a Self,
        modulo: &'a Self,
    ) -> Option<PowModIncomplete<'a>> {
        if exponent.cmp0() == Ordering::Less {
            let sinverse = match self.invert_ref(modulo) {
                Some(InvertIncomplete { sinverse, .. }) => sinverse,
                None => return None,
            };
            Some(PowModIncomplete {
                ref_self: None,
                sinverse: Some(sinverse),
                exponent,
                modulo,
            })
        } else if modulo.cmp0() != Ordering::Equal {
            Some(PowModIncomplete {
                ref_self: Some(self),
                sinverse: None,
                exponent,
                modulo,
            })
        } else {
            None
        }
    }

    /// Raises a number to the power of `exponent` modulo `modulo`,
    /// with resilience to side-channel attacks.
    ///
    /// The exponent must be greater than zero, and the modulo must be
    /// odd.
    ///
    /// This method is intended for cryptographic purposes where
    /// resilience to side-channel attacks is desired. The function is
    /// designed to take the same time and use the same cache access
    /// patterns for same-sized arguments, assuming that the arguments
    /// are placed at the same position and the machine state is
    /// identical when starting.
    ///
    /// # Panics
    ///
    /// Panics if `exponent` ≤ 0 or if `modulo` is even.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 ^ 4 mod 13 = 9
    /// let n = Integer::from(7);
    /// let e = Integer::from(4);
    /// let m = Integer::from(13);
    /// let power = n.secure_pow_mod(&e, &m);
    /// assert_eq!(power, 9);
    /// ```
    #[inline]
    pub fn secure_pow_mod(mut self, exponent: &Self, modulo: &Self) -> Self {
        self.secure_pow_mod_mut(exponent, modulo);
        self
    }

    /// Raises a number to the power of `exponent` modulo `modulo`,
    /// with resilience to side-channel attacks.
    ///
    /// The exponent must be greater than zero, and the modulo must be
    /// odd.
    ///
    /// This method is intended for cryptographic purposes where
    /// resilience to side-channel attacks is desired. The function is
    /// designed to take the same time and use the same cache access
    /// patterns for same-sized arguments, assuming that the arguments
    /// are placed at the same position and the machine state is
    /// identical when starting.
    ///
    /// # Panics
    ///
    /// Panics if `exponent` ≤ 0 or if `modulo` is even.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 ^ 4 mod 13 = 9
    /// let mut n = Integer::from(7);
    /// let e = Integer::from(4);
    /// let m = Integer::from(13);
    /// n.secure_pow_mod_mut(&e, &m);
    /// assert_eq!(n, 9);
    /// ```
    #[inline]
    pub fn secure_pow_mod_mut(&mut self, exponent: &Self, modulo: &Self) {
        xmpz::powm_sec(self, (), exponent, modulo);
    }

    /// Raises a number to the power of `exponent` modulo `modulo`,
    /// with resilience to side-channel attacks.
    ///
    /// The exponent must be greater than zero, and the modulo must be
    /// odd.
    ///
    /// This method is intended for cryptographic purposes where
    /// resilience to side-channel attacks is desired. The function is
    /// designed to take the same time and use the same cache access
    /// patterns for same-sized arguments, assuming that the arguments
    /// are placed at the same position and the machine state is
    /// identical when starting.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Panics
    ///
    /// Panics if `exponent` ≤ 0 or if `modulo` is even.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 ^ 4 mod 13 = 9
    /// let n = Integer::from(7);
    /// let e = Integer::from(4);
    /// let m = Integer::from(13);
    /// let power = Integer::from(n.secure_pow_mod_ref(&e, &m));
    /// assert_eq!(power, 9);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn secure_pow_mod_ref<'a>(
        &'a self,
        exponent: &'a Self,
        modulo: &'a Self,
    ) -> SecurePowModIncomplete<'a> {
        SecurePowModIncomplete {
            ref_self: self,
            exponent,
            modulo,
        }
    }

    /// Raises `base` to the power of `exponent`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let p = Integer::u_pow_u(13, 12);
    /// let i = Integer::from(p);
    /// assert_eq!(i, 13_u64.pow(12));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn u_pow_u(base: u32, exponent: u32) -> UPowUIncomplete {
        UPowUIncomplete { base, exponent }
    }

    /// Raises `base` to the power of `exponent`.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let p1 = Integer::i_pow_u(-13, 13);
    /// let i1 = Integer::from(p1);
    /// assert_eq!(i1, (-13_i64).pow(13));
    /// let p2 = Integer::i_pow_u(13, 13);
    /// let i2 = Integer::from(p2);
    /// assert_eq!(i2, (13_i64).pow(13));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn i_pow_u(base: i32, exponent: u32) -> IPowUIncomplete {
        IPowUIncomplete { base, exponent }
    }

    /// Computes the <i>n</i>th root and truncates the result.
    ///
    /// # Panics
    ///
    /// Panics if <i>n</i> is zero or if <i>n</i> is even and the
    /// value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(1004);
    /// let root = i.root(3);
    /// assert_eq!(root, 10);
    /// ```
    #[inline]
    pub fn root(mut self, n: u32) -> Self {
        self.root_mut(n);
        self
    }

    /// Computes the <i>n</i>th root and truncates the result.
    ///
    /// # Panics
    ///
    /// Panics if <i>n</i> is zero or if <i>n</i> is even and the
    /// value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(1004);
    /// i.root_mut(3);
    /// assert_eq!(i, 10);
    /// ```
    #[inline]
    pub fn root_mut(&mut self, n: u32) {
        xmpz::root(self, (), n);
    }

    /// Computes the <i>n</i>th root and truncates the result.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(1004);
    /// assert_eq!(Integer::from(i.root_ref(3)), 10);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn root_ref(&self, n: u32) -> RootIncomplete<'_> {
        RootIncomplete { ref_self: self, n }
    }

    /// Computes the <i>n</i>th root and returns the truncated
    /// root and the remainder.
    ///
    /// The remainder is the original number minus the truncated
    /// root raised to the power of <i>n</i>.
    ///
    /// The initial value of `remainder` is ignored.
    ///
    /// # Panics
    ///
    /// Panics if <i>n</i> is zero or if <i>n</i> is even and the
    /// value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(1004);
    /// let (root, rem) = i.root_rem(Integer::new(), 3);
    /// assert_eq!(root, 10);
    /// assert_eq!(rem, 4);
    /// ```
    #[inline]
    pub fn root_rem(mut self, mut remainder: Self, n: u32) -> (Self, Self) {
        self.root_rem_mut(&mut remainder, n);
        (self, remainder)
    }

    /// Computes the <i>n</i>th root and returns the truncated
    /// root and the remainder.
    ///
    /// The remainder is the original number minus the truncated
    /// root raised to the power of <i>n</i>.
    ///
    /// The initial value of `remainder` is ignored.
    ///
    /// # Panics
    ///
    /// Panics if <i>n</i> is zero or if <i>n</i> is even and the
    /// value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(1004);
    /// let mut rem = Integer::new();
    /// i.root_rem_mut(&mut rem, 3);
    /// assert_eq!(i, 10);
    /// assert_eq!(rem, 4);
    /// ```
    #[inline]
    pub fn root_rem_mut(&mut self, remainder: &mut Self, n: u32) {
        xmpz::rootrem(self, remainder, (), n);
    }

    /// Computes the <i>n</i>th root and returns the truncated
    /// root and the remainder.
    ///
    /// The remainder is the original number minus the truncated
    /// root raised to the power of <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let i = Integer::from(1004);
    /// let mut root = Integer::new();
    /// let mut rem = Integer::new();
    /// let r = i.root_rem_ref(3);
    /// (&mut root, &mut rem).assign(r);
    /// assert_eq!(root, 10);
    /// assert_eq!(rem, 4);
    /// let r = i.root_rem_ref(3);
    /// let (other_root, other_rem) = <(Integer, Integer)>::from(r);
    /// assert_eq!(other_root, 10);
    /// assert_eq!(other_rem, 4);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn root_rem_ref(&self, n: u32) -> RootRemIncomplete<'_> {
        RootRemIncomplete { ref_self: self, n }
    }

    /// Computes the square.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(13);
    /// let square = i.square();
    /// assert_eq!(square, 169);
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
    /// use rug::Integer;
    /// let mut i = Integer::from(13);
    /// i.square_mut();
    /// assert_eq!(i, 169);
    /// ```
    #[inline]
    pub fn square_mut(&mut self) {
        xmpz::square(self, ());
    }

    /// Computes the square.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(13);
    /// assert_eq!(Integer::from(i.square_ref()), 169);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn square_ref(&self) -> SquareIncomplete<'_> {
        SquareIncomplete { ref_self: self }
    }

    /// Computes the square root and truncates the result.
    ///
    /// # Panics
    ///
    /// Panics if the value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(104);
    /// let sqrt = i.sqrt();
    /// assert_eq!(sqrt, 10);
    /// ```
    #[inline]
    pub fn sqrt(mut self) -> Self {
        self.sqrt_mut();
        self
    }

    /// Computes the square root and truncates the result.
    ///
    /// # Panics
    ///
    /// Panics if the value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(104);
    /// i.sqrt_mut();
    /// assert_eq!(i, 10);
    /// ```
    #[inline]
    pub fn sqrt_mut(&mut self) {
        xmpz::sqrt(self, ());
    }

    /// Computes the square root and truncates the result.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(104);
    /// assert_eq!(Integer::from(i.sqrt_ref()), 10);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn sqrt_ref(&self) -> SqrtIncomplete<'_> {
        SqrtIncomplete { ref_self: self }
    }

    /// Computes the square root and the remainder.
    ///
    /// The remainder is the original number minus the truncated
    /// root squared.
    ///
    /// The initial value of `remainder` is ignored.
    ///
    /// # Panics
    ///
    /// Panics if the value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(104);
    /// let (sqrt, rem) = i.sqrt_rem(Integer::new());
    /// assert_eq!(sqrt, 10);
    /// assert_eq!(rem, 4);
    /// ```
    #[inline]
    pub fn sqrt_rem(mut self, mut remainder: Self) -> (Self, Self) {
        self.sqrt_rem_mut(&mut remainder);
        (self, remainder)
    }

    /// Computes the square root and the remainder.
    ///
    /// The remainder is the original number minus the truncated
    /// root squared.
    ///
    /// The initial value of `remainder` is ignored.
    ///
    /// # Panics
    ///
    /// Panics if the value is negative.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(104);
    /// let mut rem = Integer::new();
    /// i.sqrt_rem_mut(&mut rem);
    /// assert_eq!(i, 10);
    /// assert_eq!(rem, 4);
    /// ```
    #[inline]
    pub fn sqrt_rem_mut(&mut self, remainder: &mut Self) {
        xmpz::sqrtrem(self, remainder, ());
    }

    /// Computes the square root and the remainder.
    ///
    /// The remainder is the original number minus the truncated
    /// root squared.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let i = Integer::from(104);
    /// let mut sqrt = Integer::new();
    /// let mut rem = Integer::new();
    /// let r = i.sqrt_rem_ref();
    /// (&mut sqrt, &mut rem).assign(r);
    /// assert_eq!(sqrt, 10);
    /// assert_eq!(rem, 4);
    /// let r = i.sqrt_rem_ref();
    /// let (other_sqrt, other_rem) = <(Integer, Integer)>::from(r);
    /// assert_eq!(other_sqrt, 10);
    /// assert_eq!(other_rem, 4);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn sqrt_rem_ref(&self) -> SqrtRemIncomplete<'_> {
        SqrtRemIncomplete { ref_self: self }
    }

    /// Determines wheter a number is prime.
    ///
    /// This function uses some trial divisions, a Baille-PSW probable
    /// prime test, then `reps` − 24 Miller-Rabin probabilistic
    /// primality tests.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{integer::IsPrime, Integer};
    /// let no = Integer::from(163 * 4003);
    /// assert_eq!(no.is_probably_prime(30), IsPrime::No);
    /// let yes = Integer::from(817_504_243);
    /// assert_eq!(yes.is_probably_prime(30), IsPrime::Yes);
    /// // 16_412_292_043_871_650_369 is actually a prime.
    /// let probably = Integer::from(16_412_292_043_871_650_369_u64);
    /// assert_eq!(probably.is_probably_prime(30), IsPrime::Probably);
    /// ```
    #[inline]
    pub fn is_probably_prime(&self, reps: u32) -> IsPrime {
        match xmpz::probab_prime_p(self, reps.unwrapped_cast()) {
            0 => IsPrime::No,
            1 => IsPrime::Probably,
            2 => IsPrime::Yes,
            _ => unreachable!(),
        }
    }

    /// Identifies primes using a probabilistic algorithm; the
    /// chance of a composite passing will be extremely small.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(800_000_000);
    /// let prime = i.next_prime();
    /// assert_eq!(prime, 800_000_011);
    /// ```
    #[inline]
    pub fn next_prime(mut self) -> Self {
        self.next_prime_mut();
        self
    }

    /// Identifies primes using a probabilistic algorithm; the
    /// chance of a composite passing will be extremely small.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(800_000_000);
    /// i.next_prime_mut();
    /// assert_eq!(i, 800_000_011);
    /// ```
    #[inline]
    pub fn next_prime_mut(&mut self) {
        xmpz::nextprime(self, ());
    }

    /// Identifies primes using a probabilistic algorithm; the
    /// chance of a composite passing will be extremely small.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(800_000_000);
    /// let r = i.next_prime_ref();
    /// let prime = Integer::from(r);
    /// assert_eq!(prime, 800_000_011);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn next_prime_ref(&self) -> NextPrimeIncomplete<'_> {
        NextPrimeIncomplete { ref_self: self }
    }

    /// Finds the greatest common divisor.
    ///
    /// The result is always positive except when both inputs are
    /// zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let a = Integer::new();
    /// let mut b = Integer::new();
    /// // gcd of 0, 0 is 0
    /// let gcd1 = a.gcd(&b);
    /// assert_eq!(gcd1, 0);
    /// b.assign(10);
    /// // gcd of 0, 10 is 10
    /// let gcd2 = gcd1.gcd(&b);
    /// assert_eq!(gcd2, 10);
    /// b.assign(25);
    /// // gcd of 10, 25 is 5
    /// let gcd3 = gcd2.gcd(&b);
    /// assert_eq!(gcd3, 5);
    /// ```
    #[inline]
    pub fn gcd(mut self, other: &Self) -> Self {
        self.gcd_mut(other);
        self
    }

    /// Finds the greatest common divisor.
    ///
    /// The result is always positive except when both inputs are
    /// zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let mut a = Integer::new();
    /// let mut b = Integer::new();
    /// // gcd of 0, 0 is 0
    /// a.gcd_mut(&b);
    /// assert_eq!(a, 0);
    /// b.assign(10);
    /// // gcd of 0, 10 is 10
    /// a.gcd_mut(&b);
    /// assert_eq!(a, 10);
    /// b.assign(25);
    /// // gcd of 10, 25 is 5
    /// a.gcd_mut(&b);
    /// assert_eq!(a, 5);
    /// ```
    #[inline]
    pub fn gcd_mut(&mut self, other: &Self) {
        xmpz::gcd(self, (), other);
    }

    /// Finds the greatest common divisor.
    ///
    /// The result is always positive except when both inputs are
    /// zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let a = Integer::from(100);
    /// let b = Integer::from(125);
    /// let r = a.gcd_ref(&b);
    /// // gcd of 100, 125 is 25
    /// assert_eq!(Integer::from(r), 25);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn gcd_ref<'a>(&'a self, other: &'a Self) -> GcdIncomplete<'_> {
        GcdIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Finds the greatest common divisor.
    ///
    /// The result is always positive except when both inputs are
    /// zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::new();
    /// // gcd of 0, 0 is 0
    /// let gcd1 = i.gcd_u(0);
    /// assert_eq!(gcd1, 0);
    /// // gcd of 0, 10 is 10
    /// let gcd2 = gcd1.gcd_u(10);
    /// assert_eq!(gcd2, 10);
    /// // gcd of 10, 25 is 5
    /// let gcd3 = gcd2.gcd_u(25);
    /// assert_eq!(gcd3, 5);
    /// ```
    #[inline]
    pub fn gcd_u(mut self, other: u32) -> Self {
        self.gcd_u_mut(other);
        self
    }

    /// Finds the greatest common divisor.
    ///
    /// The result is always positive except when both inputs are
    /// zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::new();
    /// // gcd of 0, 0 is 0
    /// i.gcd_u_mut(0);
    /// assert_eq!(i, 0);
    /// // gcd of 0, 10 is 10
    /// i.gcd_u_mut(10);
    /// assert_eq!(i, 10);
    /// // gcd of 10, 25 is 5
    /// i.gcd_u_mut(25);
    /// assert_eq!(i, 5);
    /// ```
    #[inline]
    pub fn gcd_u_mut(&mut self, other: u32) {
        xmpz::gcd_u32(self, (), other);
    }

    /// Finds the greatest common divisor.
    ///
    /// The result is always positive except when both inputs are
    /// zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Option][`Option`]&lt;[u32][`u32`]&gt;</code>
    ///
    /// The last item above is useful to obtain the result as a
    /// [`u32`] if it fits. If `other` > 0 , the result always
    /// fits. If the result does not fit, it is equal to the
    /// absolute value of `self`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(100);
    /// let r = i.gcd_u_ref(125);
    /// // gcd of 100, 125 is 25
    /// assert_eq!(Integer::from(r), 25);
    /// let r = i.gcd_u_ref(125);
    /// assert_eq!(Option::<u32>::from(r), Some(25));
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [`Option`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html
    /// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn gcd_u_ref(&self, other: u32) -> GcdUIncomplete<'_> {
        GcdUIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Finds the greatest common divisor (GCD) of the two inputs
    /// (`self` and `other`), and two cofactors to obtain the GCD
    /// from the two inputs.
    ///
    /// The GCD is always positive except when both inputs are
    /// zero. If the inputs are <i>a</i> and <i>b</i>, then the
    /// GCD is <i>g</i> and the cofactors are <i>s</i> and
    /// <i>t</i> such that
    ///
    /// <i>a</i> × <i>s</i> + <i>b</i> × <i>t</i> = <i>g</i>
    ///
    /// The values <i>s</i> and <i>t</i> are chosen such that
    /// normally, |<i>s</i>| < |<i>b</i>| / (2<i>g</i>) and
    /// |<i>t</i>| < |<i>a</i>| / (2<i>g</i>), and these relations
    /// define <i>s</i> and <i>t</i> uniquely. There are a few
    /// exceptional cases:
    ///
    ///   * If |<i>a</i>| = |<i>b</i>|, then <i>s</i> = 0,
    ///     <i>t</i> = sgn(<i>b</i>).
    ///   * Otherwise, if <i>b</i> = 0 or |<i>b</i>| = 2<i>g</i>,
    ///     then <i>s</i> = sgn(<i>a</i>), and if <i>a</i> = 0 or
    ///     |<i>a</i>| = 2<i>g</i>, then <i>t</i> = sgn(<i>b</i>).
    ///
    /// The initial value of `rop` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let a = Integer::from(4);
    /// let b = Integer::from(6);
    /// let (g, s, t) = a.gcd_cofactors(b, Integer::new());
    /// assert_eq!(g, 2);
    /// assert_eq!(s, -1);
    /// assert_eq!(t, 1);
    /// ```
    #[inline]
    pub fn gcd_cofactors(mut self, mut other: Self, mut rop: Self) -> (Self, Self, Self) {
        self.gcd_cofactors_mut(&mut other, &mut rop);
        (self, other, rop)
    }

    /// Finds the greatest common divisor (GCD) of the two inputs
    /// (`self` and `other`), and two cofactors to obtain the GCD
    /// from the two inputs.
    ///
    /// The GCD is stored in `self`, and the two cofactors are
    /// stored in `other` and `rop`.
    ///
    /// The GCD is always positive except when both inputs are
    /// zero. If the inputs are <i>a</i> and <i>b</i>, then the
    /// GCD is <i>g</i> and the cofactors are <i>s</i> and
    /// <i>t</i> such that
    ///
    /// <i>a</i> × <i>s</i> + <i>b</i> × <i>t</i> = <i>g</i>
    ///
    /// The values <i>s</i> and <i>t</i> are chosen such that
    /// normally, |<i>s</i>| < |<i>b</i>| / (2<i>g</i>) and
    /// |<i>t</i>| < |<i>a</i>| / (2<i>g</i>), and these relations
    /// define <i>s</i> and <i>t</i> uniquely. There are a few
    /// exceptional cases:
    ///
    ///   * If |<i>a</i>| = |<i>b</i>|, then <i>s</i> = 0,
    ///     <i>t</i> = sgn(<i>b</i>).
    ///   * Otherwise, if <i>b</i> = 0 or |<i>b</i>| = 2<i>g</i>,
    ///     then <i>s</i> = sgn(<i>a</i>), and if <i>a</i> = 0 or
    ///     |<i>a</i>| = 2<i>g</i>, then <i>t</i> = sgn(<i>b</i>).
    ///
    /// The initial value of `rop` is ignored.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut a_g = Integer::from(4);
    /// let mut b_s = Integer::from(6);
    /// let mut t = Integer::new();
    /// a_g.gcd_cofactors_mut(&mut b_s, &mut t);
    /// assert_eq!(a_g, 2);
    /// assert_eq!(b_s, -1);
    /// assert_eq!(t, 1);
    /// ```
    #[inline]
    pub fn gcd_cofactors_mut(&mut self, other: &mut Self, rop: &mut Self) {
        xmpz::gcdext(self, other, Some(rop), (), ());
    }

    /// Finds the greatest common divisor (GCD) of the two inputs
    /// (`self` and `other`), and two cofactors to obtain the GCD
    /// from the two inputs.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// In the case that only one of the two cofactors is
    /// required, the following are also implemented:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// The GCD is always positive except when both inputs are
    /// zero. If the inputs are <i>a</i> and <i>b</i>, then the
    /// GCD is <i>g</i> and the cofactors are <i>s</i> and
    /// <i>t</i> such that
    ///
    /// <i>a</i> × <i>s</i> + <i>b</i> × <i>t</i> = <i>g</i>
    ///
    /// The values <i>s</i> and <i>t</i> are chosen such that
    /// normally, |<i>s</i>| < |<i>b</i>| / (2<i>g</i>) and
    /// |<i>t</i>| < |<i>a</i>| / (2<i>g</i>), and these relations
    /// define <i>s</i> and <i>t</i> uniquely. There are a few
    /// exceptional cases:
    ///
    ///   * If |<i>a</i>| = |<i>b</i>|, then <i>s</i> = 0,
    ///     <i>t</i> = sgn(<i>b</i>).
    ///   * Otherwise, if <i>b</i> = 0 or |<i>b</i>| = 2<i>g</i>,
    ///     then <i>s</i> = sgn(<i>a</i>), and if <i>a</i> = 0 or
    ///     |<i>a</i>| = 2<i>g</i>, then <i>t</i> = sgn(<i>b</i>).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let a = Integer::from(4);
    /// let b = Integer::from(6);
    /// let r = a.gcd_cofactors_ref(&b);
    /// let mut g = Integer::new();
    /// let mut s = Integer::new();
    /// let mut t = Integer::new();
    /// (&mut g, &mut s, &mut t).assign(r);
    /// assert_eq!(a, 4);
    /// assert_eq!(b, 6);
    /// assert_eq!(g, 2);
    /// assert_eq!(s, -1);
    /// assert_eq!(t, 1);
    /// ```
    ///
    /// In the case that only one of the two cofactors is
    /// required, this can be achieved as follows:
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let a = Integer::from(4);
    /// let b = Integer::from(6);
    ///
    /// // no t required
    /// let (mut g1, mut s1) = (Integer::new(), Integer::new());
    /// (&mut g1, &mut s1).assign(a.gcd_cofactors_ref(&b));
    /// assert_eq!(g1, 2);
    /// assert_eq!(s1, -1);
    ///
    /// // no s required
    /// let (mut g2, mut t2) = (Integer::new(), Integer::new());
    /// (&mut g2, &mut t2).assign(b.gcd_cofactors_ref(&a));
    /// assert_eq!(g2, 2);
    /// assert_eq!(t2, 1);
    /// ```
    ///
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Assign`]: trait.Assign.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn gcd_cofactors_ref<'a>(&'a self, other: &'a Self) -> GcdIncomplete<'_> {
        GcdIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Finds the least common multiple.
    ///
    /// The result is always positive except when one or both
    /// inputs are zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let a = Integer::from(10);
    /// let mut b = Integer::from(25);
    /// // lcm of 10, 25 is 50
    /// let lcm1 = a.lcm(&b);
    /// assert_eq!(lcm1, 50);
    /// b.assign(0);
    /// // lcm of 50, 0 is 0
    /// let lcm2 = lcm1.lcm(&b);
    /// assert_eq!(lcm2, 0);
    /// ```
    #[inline]
    pub fn lcm(mut self, other: &Self) -> Self {
        self.lcm_mut(other);
        self
    }

    /// Finds the least common multiple.
    ///
    /// The result is always positive except when one or both
    /// inputs are zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let mut a = Integer::from(10);
    /// let mut b = Integer::from(25);
    /// // lcm of 10, 25 is 50
    /// a.lcm_mut(&b);
    /// assert_eq!(a, 50);
    /// b.assign(0);
    /// // lcm of 50, 0 is 0
    /// a.lcm_mut(&b);
    /// assert_eq!(a, 0);
    /// ```
    #[inline]
    pub fn lcm_mut(&mut self, other: &Self) {
        xmpz::lcm(self, (), other);
    }

    /// Finds the least common multiple.
    ///
    /// The result is always positive except when one or both
    /// inputs are zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let a = Integer::from(100);
    /// let b = Integer::from(125);
    /// let r = a.lcm_ref(&b);
    /// // lcm of 100, 125 is 500
    /// assert_eq!(Integer::from(r), 500);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn lcm_ref<'a>(&'a self, other: &'a Self) -> LcmIncomplete<'_> {
        LcmIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Finds the least common multiple.
    ///
    /// The result is always positive except when one or both
    /// inputs are zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(10);
    /// // lcm of 10, 25 is 50
    /// let lcm1 = i.lcm_u(25);
    /// assert_eq!(lcm1, 50);
    /// // lcm of 50, 0 is 0
    /// let lcm2 = lcm1.lcm_u(0);
    /// assert_eq!(lcm2, 0);
    /// ```
    #[inline]
    pub fn lcm_u(mut self, other: u32) -> Self {
        self.lcm_u_mut(other);
        self
    }

    /// Finds the least common multiple.
    ///
    /// The result is always positive except when one or both
    /// inputs are zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(10);
    /// // lcm of 10, 25 is 50
    /// i.lcm_u_mut(25);
    /// assert_eq!(i, 50);
    /// // lcm of 50, 0 is 0
    /// i.lcm_u_mut(0);
    /// assert_eq!(i, 0);
    /// ```
    #[inline]
    pub fn lcm_u_mut(&mut self, other: u32) {
        xmpz::lcm_u32(self, (), other);
    }

    /// Finds the least common multiple.
    ///
    /// The result is always positive except when one or both
    /// inputs are zero.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let i = Integer::from(100);
    /// let r = i.lcm_u_ref(125);
    /// // lcm of 100, 125 is 500
    /// assert_eq!(Integer::from(r), 500);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn lcm_u_ref(&self, other: u32) -> LcmUIncomplete<'_> {
        LcmUIncomplete {
            ref_self: self,
            other,
        }
    }

    /// Calculates the Jacobi symbol (`self`/<i>n</i>).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let m = Integer::from(10);
    /// let mut n = Integer::from(13);
    /// assert_eq!(m.jacobi(&n), 1);
    /// n.assign(15);
    /// assert_eq!(m.jacobi(&n), 0);
    /// n.assign(17);
    /// assert_eq!(m.jacobi(&n), -1);
    /// ```
    #[inline]
    pub fn jacobi(&self, n: &Self) -> i32 {
        xmpz::jacobi(self, n).cast()
    }

    /// Calculates the Legendre symbol (`self`/<i>p</i>).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let a = Integer::from(5);
    /// let mut p = Integer::from(7);
    /// assert_eq!(a.legendre(&p), -1);
    /// p.assign(11);
    /// assert_eq!(a.legendre(&p), 1);
    /// ```
    #[inline]
    pub fn legendre(&self, p: &Self) -> i32 {
        xmpz::legendre(self, p).cast()
    }

    /// Calculates the Jacobi symbol (`self`/<i>n</i>) with the
    /// Kronecker extension.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let k = Integer::from(3);
    /// let mut n = Integer::from(16);
    /// assert_eq!(k.kronecker(&n), 1);
    /// n.assign(17);
    /// assert_eq!(k.kronecker(&n), -1);
    /// n.assign(18);
    /// assert_eq!(k.kronecker(&n), 0);
    /// ```
    #[inline]
    pub fn kronecker(&self, n: &Self) -> i32 {
        xmpz::kronecker(self, n).cast()
    }

    /// Removes all occurrences of `factor`, and returns the number of
    /// occurrences removed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(Integer::u_pow_u(13, 50));
    /// i *= 1000;
    /// let (remove, count) = i.remove_factor(&Integer::from(13));
    /// assert_eq!(remove, 1000);
    /// assert_eq!(count, 50);
    /// ```
    #[inline]
    pub fn remove_factor(mut self, factor: &Self) -> (Self, u32) {
        let count = self.remove_factor_mut(factor);
        (self, count)
    }

    /// Removes all occurrences of `factor`, and returns the number of
    /// occurrences removed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let mut i = Integer::from(Integer::u_pow_u(13, 50));
    /// i *= 1000;
    /// let count = i.remove_factor_mut(&Integer::from(13));
    /// assert_eq!(i, 1000);
    /// assert_eq!(count, 50);
    /// ```
    #[inline]
    pub fn remove_factor_mut(&mut self, factor: &Self) -> u32 {
        xmpz::remove(self, (), factor)
    }

    /// Removes all occurrences of `factor`, and counts the number of
    /// occurrences removed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let mut i = Integer::from(Integer::u_pow_u(13, 50));
    /// i *= 1000;
    /// let factor = Integer::from(13);
    /// let r = i.remove_factor_ref(&factor);
    /// let (mut j, mut count) = (Integer::new(), 0);
    /// (&mut j, &mut count).assign(r);
    /// assert_eq!(count, 50);
    /// assert_eq!(j, 1000);
    /// ```
    #[inline]
    pub fn remove_factor_ref<'a>(&'a self, factor: &'a Self) -> RemoveFactorIncomplete<'a> {
        RemoveFactorIncomplete {
            ref_self: self,
            factor,
        }
    }

    /// Computes the factorial of <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 10 × 9 × 8 × 7 × 6 × 5 × 4 × 3 × 2 × 1
    /// let f = Integer::factorial(10);
    /// let i = Integer::from(f);
    /// assert_eq!(i, 3628800);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn factorial(n: u32) -> FactorialIncomplete {
        FactorialIncomplete { n }
    }

    /// Computes the double factorial of <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 10 × 8 × 6 × 4 × 2
    /// let f = Integer::factorial_2(10);
    /// let i = Integer::from(f);
    /// assert_eq!(i, 3840);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn factorial_2(n: u32) -> Factorial2Incomplete {
        Factorial2Incomplete { n }
    }

    /// Computes the <i>m</i>-multi factorial of <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 10 × 7 × 4 × 1
    /// let f = Integer::factorial_m(10, 3);
    /// let i = Integer::from(f);
    /// assert_eq!(i, 280);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn factorial_m(n: u32, m: u32) -> FactorialMIncomplete {
        FactorialMIncomplete { n, m }
    }

    /// Computes the primorial of <i>n</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 × 5 × 3 × 2
    /// let p = Integer::primorial(10);
    /// let i = Integer::from(p);
    /// assert_eq!(i, 210);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn primorial(n: u32) -> PrimorialIncomplete {
        PrimorialIncomplete { n }
    }

    /// Computes the binomial coefficient over <i>k</i>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 choose 2 is 21
    /// let i = Integer::from(7);
    /// let bin = i.binomial(2);
    /// assert_eq!(bin, 21);
    /// ```
    #[inline]
    pub fn binomial(mut self, k: u32) -> Self {
        self.binomial_mut(k);
        self
    }

    /// Computes the binomial coefficient over <i>k</i>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 choose 2 is 21
    /// let mut i = Integer::from(7);
    /// i.binomial_mut(2);
    /// assert_eq!(i, 21);
    /// ```
    #[inline]
    pub fn binomial_mut(&mut self, k: u32) {
        xmpz::bin_ui(self, (), k);
    }

    /// Computes the binomial coefficient over <i>k</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 choose 2 is 21
    /// let i = Integer::from(7);
    /// assert_eq!(Integer::from(i.binomial_ref(2)), 21);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn binomial_ref(&self, k: u32) -> BinomialIncomplete<'_> {
        BinomialIncomplete { ref_self: self, k }
    }

    /// Computes the binomial coefficient <i>n</i> over <i>k</i>.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// // 7 choose 2 is 21
    /// let b = Integer::binomial_u(7, 2);
    /// let i = Integer::from(b);
    /// assert_eq!(i, 21);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn binomial_u(n: u32, k: u32) -> BinomialUIncomplete {
        BinomialUIncomplete { n, k }
    }

    /// Computes the Fibonacci number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// This function is meant for an isolated number. If a
    /// sequence of Fibonacci numbers is required, the first two
    /// values of the sequence should be computed with the
    /// [`fibonacci_2`] method, then iterations should be used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let f = Integer::fibonacci(12);
    /// let i = Integer::from(f);
    /// assert_eq!(i, 144);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`fibonacci_2`]: #method.fibonacci_2
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn fibonacci(n: u32) -> FibonacciIncomplete {
        FibonacciIncomplete { n }
    }

    /// Computes a Fibonacci number, and the previous Fibonacci
    /// number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// This function is meant to calculate isolated numbers. If a
    /// sequence of Fibonacci numbers is required, the first two
    /// values of the sequence should be computed with this function,
    /// then iterations should be used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let f = Integer::fibonacci_2(12);
    /// let mut pair = <(Integer, Integer)>::from(f);
    /// assert_eq!(pair.0, 144);
    /// assert_eq!(pair.1, 89);
    /// // Fibonacci number F[−1] is 1
    /// pair.assign(Integer::fibonacci_2(0));
    /// assert_eq!(pair.0, 0);
    /// assert_eq!(pair.1, 1);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn fibonacci_2(n: u32) -> FibonacciIncomplete {
        FibonacciIncomplete { n }
    }

    /// Computes the Lucas number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// This function is meant for an isolated number. If a
    /// sequence of Lucas numbers is required, the first two
    /// values of the sequence should be computed with the
    /// [`lucas_2`] method, then iterations should be used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::Integer;
    /// let l = Integer::lucas(12);
    /// let i = Integer::from(l);
    /// assert_eq!(i, 322);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [`lucas_2`]: #method.lucas_2
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn lucas(n: u32) -> LucasIncomplete {
        LucasIncomplete { n }
    }

    /// Computes a Lucas number, and the previous Lucas number.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for
    ///     [(][tuple]&amp;mut [Integer][`Integer`],
    ///     &amp;mut [Integer][`Integer`][)][tuple]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for
    ///     [(][tuple][Integer][`Integer`],
    ///     [Integer][`Integer`][)][tuple]</code>
    ///
    /// This function is meant to calculate isolated numbers. If a
    /// sequence of Lucas numbers is required, the first two values of
    /// the sequence should be computed with this function, then
    /// iterations should be used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{Assign, Integer};
    /// let l = Integer::lucas_2(12);
    /// let mut pair = <(Integer, Integer)>::from(l);
    /// assert_eq!(pair.0, 322);
    /// assert_eq!(pair.1, 199);
    /// pair.assign(Integer::lucas_2(0));
    /// assert_eq!(pair.0, 2);
    /// assert_eq!(pair.1, -1);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    /// [tuple]: https://doc.rust-lang.org/nightly/std/primitive.tuple.html
    #[inline]
    pub fn lucas_2(n: u32) -> LucasIncomplete {
        LucasIncomplete { n }
    }

    #[cfg(feature = "rand")]
    /// Generates a random number with a specified maximum number of
    /// bits.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Assign, Integer};
    /// let mut rand = RandState::new();
    /// let mut i = Integer::from(Integer::random_bits(0, &mut rand));
    /// assert_eq!(i, 0);
    /// i.assign(Integer::random_bits(80, &mut rand));
    /// assert!(i.significant_bits() <= 80);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_bits(bits: u32, rng: &mut dyn MutRandState) -> RandomBitsIncomplete {
        RandomBitsIncomplete { bits, rng }
    }

    #[cfg(feature = "rand")]
    /// Generates a non-negative random number below the given
    /// boundary value.
    ///
    /// # Panics
    ///
    /// Panics if the boundary value is less than or equal to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Integer};
    /// let mut rand = RandState::new();
    /// let i = Integer::from(15);
    /// let below = i.random_below(&mut rand);
    /// println!("0 ≤ {} < 15", below);
    /// assert!(below < 15);
    /// ```
    #[inline]
    pub fn random_below(mut self, rng: &mut dyn MutRandState) -> Self {
        self.random_below_mut(rng);
        self
    }

    #[cfg(feature = "rand")]
    /// Generates a non-negative random number below the given
    /// boundary value.
    ///
    /// # Panics
    ///
    /// Panics if the boundary value is less than or equal to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Integer};
    /// let mut rand = RandState::new();
    /// let mut i = Integer::from(15);
    /// i.random_below_mut(&mut rand);
    /// println!("0 ≤ {} < 15", i);
    /// assert!(i < 15);
    /// ```
    #[inline]
    pub fn random_below_mut(&mut self, rng: &mut dyn MutRandState) {
        xmpz::urandomm(self, rng, ());
    }

    #[cfg(feature = "rand")]
    /// Generates a non-negative random number below the given
    /// boundary value.
    ///
    /// The following are implemented with the returned
    /// [incomplete-computation value][icv] as `Src`:
    ///   * <code>[Assign][`Assign`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///   * <code>[From][`From`]&lt;Src&gt; for [Integer][`Integer`]</code>
    ///
    /// # Panics
    ///
    /// Panics if the boundary value is less than or equal to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Integer};
    /// let mut rand = RandState::new();
    /// let bound = Integer::from(15);
    /// let i = Integer::from(bound.random_below_ref(&mut rand));
    /// println!("0 ≤ {} < {}", i, bound);
    /// assert!(i < bound);
    /// ```
    ///
    /// [`Assign`]: trait.Assign.html
    /// [`From`]: https://doc.rust-lang.org/nightly/core/convert/trait.From.html
    /// [`Integer`]: #
    /// [icv]: index.html#incomplete-computation-values
    #[inline]
    pub fn random_below_ref<'a>(
        &'a self,
        rng: &'a mut dyn MutRandState,
    ) -> RandomBelowIncomplete<'a> {
        RandomBelowIncomplete {
            ref_self: self,
            rng,
        }
    }
}

#[derive(Debug)]
pub struct SumIncomplete<'a, I>
where
    I: Iterator<Item = &'a Integer>,
{
    values: I,
}

impl<'a, I> Assign<SumIncomplete<'a, I>> for Integer
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

impl<'a, I> From<SumIncomplete<'a, I>> for Integer
where
    I: Iterator<Item = &'a Self>,
{
    fn from(mut src: SumIncomplete<'a, I>) -> Self {
        let mut dst = match src.values.next() {
            Some(first) => first.clone(),
            None => return Integer::new(),
        };
        dst.add_assign(src);
        dst
    }
}

impl<'a, I> Add<SumIncomplete<'a, I>> for Integer
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

impl<'a, I> AddAssign<SumIncomplete<'a, I>> for Integer
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
    I: Iterator<Item = (&'a Integer, &'a Integer)>,
{
    values: I,
}

impl<'a, I> Assign<DotIncomplete<'a, I>> for Integer
where
    I: Iterator<Item = (&'a Integer, &'a Integer)>,
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

impl<'a, I> From<DotIncomplete<'a, I>> for Integer
where
    I: Iterator<Item = (&'a Integer, &'a Integer)>,
{
    fn from(mut src: DotIncomplete<'a, I>) -> Self {
        let mut dst = match src.values.next() {
            Some(first) => Integer::from(first.0 * first.1),
            None => return Integer::new(),
        };
        dst.add_assign(src);
        dst
    }
}

impl<'a, I> Add<DotIncomplete<'a, I>> for Integer
where
    I: Iterator<Item = (&'a Integer, &'a Integer)>,
{
    type Output = Self;
    #[inline]
    fn add(mut self, rhs: DotIncomplete<'a, I>) -> Self {
        self.add_assign(rhs);
        self
    }
}

impl<'a, I> AddAssign<DotIncomplete<'a, I>> for Integer
where
    I: Iterator<Item = (&'a Integer, &'a Integer)>,
{
    fn add_assign(&mut self, src: DotIncomplete<'a, I>) {
        for i in src.values {
            #[allow(clippy::suspicious_op_assign_impl)]
            AddAssign::add_assign(self, i.0 * i.1);
        }
    }
}

#[derive(Debug)]
pub struct ProductIncomplete<'a, I>
where
    I: Iterator<Item = &'a Integer>,
{
    values: I,
}

impl<'a, I> Assign<ProductIncomplete<'a, I>> for Integer
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

impl<'a, I> From<ProductIncomplete<'a, I>> for Integer
where
    I: Iterator<Item = &'a Self>,
{
    fn from(mut src: ProductIncomplete<'a, I>) -> Self {
        let mut dst = match src.values.next() {
            Some(first) => first.clone(),
            None => return Integer::from(1),
        };
        dst.mul_assign(src);
        dst
    }
}

impl<'a, I> Mul<ProductIncomplete<'a, I>> for Integer
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

impl<'a, I> MulAssign<ProductIncomplete<'a, I>> for Integer
where
    I: Iterator<Item = &'a Self>,
{
    fn mul_assign(&mut self, mut src: ProductIncomplete<'a, I>) {
        let mut other = match src.values.next() {
            Some(next) => Integer::from(&*self * next),
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

ref_math_op1! { Integer; xmpz::abs; struct AbsIncomplete {} }
ref_math_op1! { Integer; xmpz::signum; struct SignumIncomplete {} }

#[derive(Debug)]
pub struct ClampIncomplete<'s, 'min, 'max, Min, Max>
where
    Integer: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
{
    ref_self: &'s Integer,
    min: &'min Min,
    max: &'max Max,
}

impl<Min, Max> Assign<ClampIncomplete<'_, '_, '_, Min, Max>> for Integer
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

impl<Min, Max> From<ClampIncomplete<'_, '_, '_, Min, Max>> for Integer
where
    Self: PartialOrd<Min> + PartialOrd<Max> + for<'a> Assign<&'a Min> + for<'a> Assign<&'a Max>,
{
    #[inline]
    fn from(src: ClampIncomplete<Min, Max>) -> Self {
        let mut dst = Integer::new();
        dst.assign(src);
        dst
    }
}

ref_math_op1! { Integer; xmpz::fdiv_r_2exp; struct KeepBitsIncomplete { n: u32 } }
ref_math_op1! { Integer; xmpz::keep_signed_bits; struct KeepSignedBitsIncomplete { n: u32 } }
ref_math_op1! { Integer; xmpz::next_pow_of_two; struct NextPowerOfTwoIncomplete {} }
ref_math_op2_2! { Integer; xmpz::tdiv_qr; struct DivRemIncomplete { divisor } }
ref_math_op2_2! { Integer; xmpz::cdiv_qr; struct DivRemCeilIncomplete { divisor } }
ref_math_op2_2! { Integer; xmpz::fdiv_qr; struct DivRemFloorIncomplete { divisor } }
ref_math_op2_2! { Integer; xmpz::rdiv_qr; struct DivRemRoundIncomplete { divisor } }
ref_math_op2_2! { Integer; xmpz::ediv_qr; struct DivRemEucIncomplete { divisor } }
ref_math_op2! { Integer; xmpz::divexact; struct DivExactIncomplete { divisor } }
ref_math_op1! { Integer; xmpz::divexact_u32; struct DivExactUIncomplete { divisor: u32 } }

#[derive(Debug)]
pub struct PowModIncomplete<'a> {
    ref_self: Option<&'a Integer>,
    sinverse: Option<Integer>,
    exponent: &'a Integer,
    modulo: &'a Integer,
}

impl Assign<PowModIncomplete<'_>> for Integer {
    #[inline]
    fn assign(&mut self, src: PowModIncomplete<'_>) {
        match (src.ref_self, src.sinverse) {
            (Some(base), None) => {
                debug_assert_ne!(src.exponent.cmp0(), Ordering::Less);
                xmpz::pow_mod(self, base, src.exponent, src.modulo);
            }
            (None, Some(sinverse)) => {
                debug_assert_eq!(src.exponent.cmp0(), Ordering::Less);
                xmpz::pow_mod(self, &sinverse, src.exponent, src.modulo);
            }
            _ => unreachable!(),
        }
    }
}

// do not use from_assign! macro to reuse sinverse
impl From<PowModIncomplete<'_>> for Integer {
    #[inline]
    fn from(src: PowModIncomplete<'_>) -> Self {
        match (src.ref_self, src.sinverse) {
            (Some(base), None) => {
                debug_assert_ne!(src.exponent.cmp0(), Ordering::Less);
                let mut dst = Integer::new();
                xmpz::pow_mod(&mut dst, base, src.exponent, src.modulo);
                dst
            }
            (None, Some(mut sinverse)) => {
                debug_assert_eq!(src.exponent.cmp0(), Ordering::Less);
                xmpz::pow_mod(&mut sinverse, (), src.exponent, src.modulo);
                sinverse
            }
            _ => unreachable!(),
        }
    }
}

pub struct SecurePowModIncomplete<'a> {
    ref_self: &'a Integer,
    exponent: &'a Integer,
    modulo: &'a Integer,
}

impl Assign<SecurePowModIncomplete<'_>> for Integer {
    #[inline]
    fn assign(&mut self, src: SecurePowModIncomplete<'_>) {
        xmpz::powm_sec(self, src.ref_self, src.exponent, src.modulo);
    }
}

from_assign! { SecurePowModIncomplete<'_> => Integer }

ref_math_op0! { Integer; xmpz::ui_pow_ui; struct UPowUIncomplete { base: u32, exponent: u32 } }
ref_math_op0! { Integer; xmpz::si_pow_ui; struct IPowUIncomplete { base: i32, exponent: u32 } }
ref_math_op1! { Integer; xmpz::root; struct RootIncomplete { n: u32 } }
ref_math_op1_2! { Integer; xmpz::rootrem; struct RootRemIncomplete { n: u32 } }
ref_math_op1! { Integer; xmpz::square; struct SquareIncomplete {} }
ref_math_op1! { Integer; xmpz::sqrt; struct SqrtIncomplete {} }
ref_math_op1_2! { Integer; xmpz::sqrtrem; struct SqrtRemIncomplete {} }
ref_math_op1! { Integer; xmpz::nextprime; struct NextPrimeIncomplete {} }
ref_math_op2! { Integer; xmpz::gcd; struct GcdIncomplete { other } }
ref_math_op1! { Integer; xmpz::gcd_u32; struct GcdUIncomplete { other: u32 } }

impl From<GcdUIncomplete<'_>> for Option<u32> {
    #[inline]
    fn from(src: GcdUIncomplete) -> Self {
        let gcd = xmpz::gcd_ui(None, src.ref_self, src.other.into());
        if gcd == 0 && src.ref_self.cmp0() != Ordering::Equal {
            None
        } else {
            gcd.checked_cast()
        }
    }
}

impl Assign<GcdIncomplete<'_>> for (&mut Integer, &mut Integer) {
    #[inline]
    fn assign(&mut self, src: GcdIncomplete<'_>) {
        xmpz::gcdext(self.0, self.1, None, src.ref_self, src.other);
    }
}

impl Assign<GcdIncomplete<'_>> for (Integer, Integer) {
    #[inline]
    fn assign(&mut self, src: GcdIncomplete<'_>) {
        (&mut self.0, &mut self.1).assign(src);
    }
}

from_assign! { GcdIncomplete<'_> => Integer, Integer }

impl Assign<GcdIncomplete<'_>> for (&mut Integer, &mut Integer, &mut Integer) {
    #[inline]
    fn assign(&mut self, src: GcdIncomplete<'_>) {
        xmpz::gcdext(self.0, self.1, Some(self.2), src.ref_self, src.other);
    }
}

impl Assign<GcdIncomplete<'_>> for (Integer, Integer, Integer) {
    #[inline]
    fn assign(&mut self, src: GcdIncomplete<'_>) {
        (&mut self.0, &mut self.1, &mut self.2).assign(src);
    }
}

from_assign! { GcdIncomplete<'_> => Integer, Integer, Integer }

ref_math_op2! { Integer; xmpz::lcm; struct LcmIncomplete { other } }
ref_math_op1! { Integer; xmpz::lcm_u32; struct LcmUIncomplete { other: u32 } }

#[derive(Debug)]
pub struct InvertIncomplete<'a> {
    sinverse: Integer,
    modulo: &'a Integer,
}

impl Assign<InvertIncomplete<'_>> for Integer {
    #[inline]
    fn assign(&mut self, src: InvertIncomplete<'_>) {
        xmpz::finish_invert(self, &src.sinverse, src.modulo);
    }
}

// do not use from_assign! macro to reuse sinverse
impl From<InvertIncomplete<'_>> for Integer {
    #[inline]
    fn from(mut src: InvertIncomplete<'_>) -> Self {
        xmpz::finish_invert(&mut src.sinverse, (), src.modulo);
        src.sinverse
    }
}

#[derive(Debug)]
pub struct RemoveFactorIncomplete<'a> {
    ref_self: &'a Integer,
    factor: &'a Integer,
}

impl Assign<RemoveFactorIncomplete<'_>> for (&mut Integer, &mut u32) {
    #[inline]
    fn assign(&mut self, src: RemoveFactorIncomplete<'_>) {
        *self.1 = xmpz::remove(self.0, src.ref_self, src.factor);
    }
}

impl Assign<RemoveFactorIncomplete<'_>> for (Integer, u32) {
    #[inline]
    fn assign(&mut self, src: RemoveFactorIncomplete<'_>) {
        (&mut self.0, &mut self.1).assign(src);
    }
}

impl From<RemoveFactorIncomplete<'_>> for (Integer, u32) {
    #[inline]
    fn from(src: RemoveFactorIncomplete<'_>) -> Self {
        let mut dst = (Integer::new(), 0u32);
        (&mut dst.0, &mut dst.1).assign(src);
        dst
    }
}

ref_math_op0! { Integer; xmpz::fac_ui; struct FactorialIncomplete { n: u32 } }
ref_math_op0! { Integer; xmpz::twofac_ui; struct Factorial2Incomplete { n: u32 } }
ref_math_op0! { Integer; xmpz::mfac_uiui; struct FactorialMIncomplete { n: u32, m: u32 } }
ref_math_op0! { Integer; xmpz::primorial_ui; struct PrimorialIncomplete { n: u32 } }
ref_math_op1! { Integer; xmpz::bin_ui; struct BinomialIncomplete { k: u32 } }
ref_math_op0! { Integer; xmpz::bin_uiui; struct BinomialUIncomplete { n: u32, k: u32 } }
ref_math_op0! { Integer; xmpz::fib_ui; struct FibonacciIncomplete { n: u32 } }

impl Assign<FibonacciIncomplete> for (&mut Integer, &mut Integer) {
    #[inline]
    fn assign(&mut self, src: FibonacciIncomplete) {
        xmpz::fib2_ui(self.0, self.1, src.n.into())
    }
}

impl Assign<FibonacciIncomplete> for (Integer, Integer) {
    #[inline]
    fn assign(&mut self, src: FibonacciIncomplete) {
        (&mut self.0, &mut self.1).assign(src);
    }
}

from_assign! { FibonacciIncomplete => Integer, Integer }

ref_math_op0! { Integer; xmpz::lucnum_ui; struct LucasIncomplete { n: u32 } }

impl Assign<LucasIncomplete> for (&mut Integer, &mut Integer) {
    #[inline]
    fn assign(&mut self, src: LucasIncomplete) {
        xmpz::lucnum2_ui(self.0, self.1, src.n.into());
    }
}

impl Assign<LucasIncomplete> for (Integer, Integer) {
    #[inline]
    fn assign(&mut self, src: LucasIncomplete) {
        (&mut self.0, &mut self.1).assign(src);
    }
}

from_assign! { LucasIncomplete => Integer, Integer }

#[cfg(feature = "rand")]
pub struct RandomBitsIncomplete<'a> {
    bits: u32,
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl Assign<RandomBitsIncomplete<'_>> for Integer {
    #[inline]
    fn assign(&mut self, src: RandomBitsIncomplete) {
        xmpz::urandomb(self, src.rng, src.bits.into())
    }
}

#[cfg(feature = "rand")]
impl From<RandomBitsIncomplete<'_>> for Integer {
    #[inline]
    fn from(src: RandomBitsIncomplete) -> Self {
        let mut dst = Integer::new();
        dst.assign(src);
        dst
    }
}

#[cfg(feature = "rand")]
pub struct RandomBelowIncomplete<'a> {
    ref_self: &'a Integer,
    rng: &'a mut dyn MutRandState,
}

#[cfg(feature = "rand")]
impl Assign<RandomBelowIncomplete<'_>> for Integer {
    #[inline]
    fn assign(&mut self, src: RandomBelowIncomplete) {
        xmpz::urandomm(self, src.rng, src.ref_self);
    }
}

#[cfg(feature = "rand")]
impl From<RandomBelowIncomplete<'_>> for Integer {
    #[inline]
    fn from(src: RandomBelowIncomplete) -> Self {
        let mut dst = Integer::new();
        dst.assign(src);
        dst
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct BorrowInteger<'a> {
    inner: ManuallyDrop<Integer>,
    phantom: PhantomData<&'a Integer>,
}

impl BorrowInteger<'_> {
    // unsafe because the lifetime is obtained from return type
    pub(crate) unsafe fn from_raw<'a>(raw: mpz_t) -> BorrowInteger<'a> {
        BorrowInteger {
            inner: ManuallyDrop::new(Integer::from_raw(raw)),
            phantom: PhantomData,
        }
    }
}

impl Deref for BorrowInteger<'_> {
    type Target = Integer;
    #[inline]
    fn deref(&self) -> &Integer {
        &*self.inner
    }
}

pub(crate) fn req_chars(i: &Integer, radix: i32, extra: usize) -> usize {
    assert!((2..=36).contains(&radix), "radix out of range");
    let size = unsafe { gmp::mpz_sizeinbase(i.as_raw(), radix) };
    let size_extra = size.checked_add(extra).expect("overflow");
    if i.cmp0() == Ordering::Less {
        size_extra.checked_add(1).expect("overflow")
    } else {
        size_extra
    }
}

pub(crate) fn append_to_string(s: &mut String, i: &Integer, radix: i32, to_upper: bool) {
    // add 1 for nul
    let size = req_chars(i, radix, 1);
    s.reserve(size);
    let reserved_ptr = s.as_ptr();
    let case_radix = if to_upper { -radix } else { radix };
    let orig_len = s.len();
    unsafe {
        let bytes = s.as_mut_vec();
        let start = bytes.as_mut_ptr().add(orig_len);
        gmp::mpz_get_str(cast_ptr_mut!(start, c_char), case_radix.cast(), i.as_raw());
        let added = slice::from_raw_parts(start, size);
        let nul_index = added.iter().position(|&x| x == 0).unwrap();
        bytes.set_len(orig_len + nul_index);
    }
    debug_assert_eq!(reserved_ptr, s.as_ptr());
    #[cfg(not(debug_assertions))]
    {
        let _ = reserved_ptr;
    }
}

#[derive(Debug)]
pub struct ParseIncomplete {
    is_negative: bool,
    digits: Vec<u8>,
    radix: i32,
}

impl Assign<ParseIncomplete> for Integer {
    fn assign(&mut self, src: ParseIncomplete) {
        if src.digits.is_empty() {
            xmpz::set_0(self);
            return;
        }
        xmpz::realloc_for_mpn_set_str(self, src.digits.len(), src.radix);
        unsafe {
            let size = gmp::mpn_set_str(
                self.inner.d.as_ptr(),
                src.digits.as_ptr(),
                src.digits.len(),
                src.radix,
            );
            self.inner.size = (if src.is_negative { -size } else { size }).unwrapped_cast();
        }
    }
}

from_assign! { ParseIncomplete => Integer }

fn parse(bytes: &[u8], radix: i32) -> Result<ParseIncomplete, ParseIntegerError> {
    use self::{ParseErrorKind as Kind, ParseIntegerError as Error};

    assert!((2..=36).contains(&radix), "radix out of range");
    let bradix = radix.unwrapped_as::<u8>();

    let mut digits = Vec::with_capacity(bytes.len());
    let mut has_sign = false;
    let mut is_negative = false;
    let mut has_digits = false;
    for &b in bytes {
        let digit = match b {
            b'+' if !has_sign && !has_digits => {
                has_sign = true;
                continue;
            }
            b'-' if !has_sign && !has_digits => {
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
        };
        has_digits = true;
        if digit > 0 || !digits.is_empty() {
            digits.push(digit);
        }
    }
    if !has_digits {
        return Err(Error {
            kind: Kind::NoDigits,
        });
    }
    Ok(ParseIncomplete {
        is_negative,
        digits,
        radix,
    })
}

#[derive(Debug)]
/**
An error which can be returned when parsing an [`Integer`].

See the
<code>[Integer][`Integer`]::[parse_radix][`parse_radix`]</code> method
for details on what strings are accepted.

# Examples

```rust
use rug::{integer::ParseIntegerError, Integer};
// This string is not an integer.
let s = "something completely different (_!_!_)";
let error: ParseIntegerError = match Integer::parse_radix(s, 4) {
    Ok(_) => unreachable!(),
    Err(error) => error,
};
println!("Parse error: {}", error);
```

[`parse_radix`]: ../struct.Integer.html#method.parse_radix
[`Integer`]: ../struct.Integer.html
*/
pub struct ParseIntegerError {
    kind: ParseErrorKind,
}

#[derive(Debug)]
enum ParseErrorKind {
    InvalidDigit,
    NoDigits,
}

impl ParseIntegerError {
    fn desc(&self) -> &str {
        use self::ParseErrorKind::*;
        match self.kind {
            InvalidDigit => "invalid digit found in string",
            NoDigits => "string has no digits",
        }
    }
}

impl Error for ParseIntegerError {
    fn description(&self) -> &str {
        self.desc()
    }
}

impl Display for ParseIntegerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(self.desc(), f)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/**
Whether a number is prime.

See the
<code>[Integer][`Integer`]::[is_probably_prime][`is_probably_prime`]</code>
method.

# Examples

```rust
use rug::{integer::IsPrime, Integer};
let no = Integer::from(163 * 4003);
assert_eq!(no.is_probably_prime(30), IsPrime::No);
let yes = Integer::from(817_504_243);
assert_eq!(yes.is_probably_prime(30), IsPrime::Yes);
// 16_412_292_043_871_650_369 is actually a prime.
let probably = Integer::from(16_412_292_043_871_650_369_u64);
assert_eq!(probably.is_probably_prime(30), IsPrime::Probably);
```

[`Integer`]: ../struct.Integer.html
[`is_probably_prime`]: ../struct.Integer.html#method.is_probably_prime
*/
pub enum IsPrime {
    /// The number is definitely not prime.
    No,
    /// The number is probably prime.
    Probably,
    /// The number is definitely prime.
    Yes,
}

/// Conversions between [`Integer`] and a [slice] of digits of this
/// type are provided.
///
/// For conversion from digits to [`Integer`], see
/// <code>[Integer][`Integer`]::[from_digits][`from_digits`]</code>
/// and
/// <code>[Integer][`Integer`]::[assign_digits][`assign_digits`]</code>.
/// For conversion from [`Integer`] to digits, see
/// <code>[Integer][`Integer`]::[significant_digits][`significant_digits`]</code>,
/// <code>[Integer][`Integer`]::[to_digits][`to_digits`]</code>, and
/// <code>[Integer][`Integer`]::[write_digits][`write_digits`]</code>.
///
/// This trait is sealed and cannot be implemented for more types; it
/// is implemented for [`bool`] and the unsigned integer types [`u8`],
/// [`u16`], [`u32`], [`u64`], [`u128`] and [`usize`].
///
/// [`Integer`]: ../struct.Integer.html
/// [`assign_digits`]: ../struct.Integer.html#method.assign_digits
/// [`bool`]: https://doc.rust-lang.org/nightly/std/primitive.bool.html
/// [`from_digits`]: ../struct.Integer.html#method.from_digits
/// [`significant_digits`]: ../struct.Integer.html#method.significant_digits
/// [`to_digits`]: ../struct.Integer.html#method.to_digits
/// [`u128`]: https://doc.rust-lang.org/nightly/std/primitive.u128.html
/// [`u16`]: https://doc.rust-lang.org/nightly/std/primitive.u16.html
/// [`u32`]: https://doc.rust-lang.org/nightly/std/primitive.u32.html
/// [`u64`]: https://doc.rust-lang.org/nightly/std/primitive.u64.html
/// [`u8`]: https://doc.rust-lang.org/nightly/std/primitive.u8.html
/// [`usize`]: https://doc.rust-lang.org/nightly/std/primitive.usize.html
/// [`write_digits`]: ../struct.Integer.html#method.write_digits
/// [slice]: https://doc.rust-lang.org/nightly/std/primitive.slice.html
pub trait UnsignedPrimitive: SealedUnsignedPrimitive {}

pub struct PrivateUnsignedPrimitive {
    bytes: usize,
    bits: usize,
    nails: usize,
}

// unsafe because bit patterns can be written to the implementing type
pub unsafe trait SealedUnsignedPrimitive: Sized {
    const PRIVATE: PrivateUnsignedPrimitive = PrivateUnsignedPrimitive {
        bytes: mem::size_of::<Self>(),
        bits: mem::size_of::<Self>() * 8,
        nails: 0,
    };
}

// Safety: We set nails to 7 so that only 0 or 1 can be written into bool.
impl UnsignedPrimitive for bool {}
unsafe impl SealedUnsignedPrimitive for bool {
    const PRIVATE: PrivateUnsignedPrimitive = PrivateUnsignedPrimitive {
        bytes: mem::size_of::<Self>(),
        bits: 1,
        nails: mem::size_of::<Self>() * 8 - 1,
    };
}

impl UnsignedPrimitive for u8 {}
unsafe impl SealedUnsignedPrimitive for u8 {}

impl UnsignedPrimitive for u16 {}
unsafe impl SealedUnsignedPrimitive for u16 {}

impl UnsignedPrimitive for u32 {}
unsafe impl SealedUnsignedPrimitive for u32 {}

impl UnsignedPrimitive for u64 {}
unsafe impl SealedUnsignedPrimitive for u64 {}

impl UnsignedPrimitive for u128 {}
unsafe impl SealedUnsignedPrimitive for u128 {}

impl UnsignedPrimitive for usize {}
unsafe impl SealedUnsignedPrimitive for usize {}
