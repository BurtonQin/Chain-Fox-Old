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
Random number generation.

This module provides two main structs.

 1. [`RandState`] is thread safe and can be shared and sent across threads.
 2. [`ThreadRandState`] is suitable for use in a single thread.

[`RandState`] has constructors for Mersenne Twister and for linear
congruential random number generators. It can also be constructed
using a custom random number generator implementing the [`RandGen`]
trait, which has to implement [`Send`] and [`Sync`] too.

If you need a custom random number generator that cannot be shared or
sent across threads, you can use [`ThreadRandState`] instead.
[`ThreadRandState`] can be constructed using a custom random number
generator implementing the [`ThreadRandGen`] trait, which does *not*
have to implement [`Send`] or [`Sync`].

Both [`RandState`] and [`ThreadRandState`] implement the
[`MutRandState`] trait so that they can be used with methods like
<code>[Integer][`Integer`]::[random_below][`random_below`]</code>.

[`Integer`]: ../struct.Integer.html
[`MutRandState`]: trait.MutRandState.html
[`RandGen`]: trait.RandGen.html
[`RandState`]: struct.RandState.html
[`Send`]: https://doc.rust-lang.org/nightly/core/marker/trait.Send.html
[`Sync`]: https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html
[`ThreadRandGen`]: trait.ThreadRandGen.html
[`ThreadRandState`]: struct.ThreadRandState.html
[`random_below`]: ../struct.Integer.html#method.random_below
*/

use crate::Integer;
use az::{Cast, UnwrappedAs, UnwrappedCast};
use core::{
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ptr::{self, NonNull},
};
use gmp_mpfr_sys::gmp::{self, limb_t, mpz_t, randfnptr_t, randseed_t, randstate_t};
use libc::{c_ulong, c_void};
use std::process;

/**
The state of a random number generator.

# Examples

```rust
use rug::rand::RandState;
let mut rand = RandState::new();
let u = rand.bits(32);
println!("32 random bits: {:032b}", u);
```
*/
#[derive(Debug)]
#[repr(transparent)]
pub struct RandState<'a> {
    inner: randstate_t,
    phantom: PhantomData<&'a dyn RandGen>,
}

impl Default for RandState<'_> {
    #[inline]
    fn default() -> RandState<'static> {
        RandState::new()
    }
}

impl Clone for RandState<'_> {
    #[inline]
    fn clone(&self) -> RandState<'static> {
        unsafe {
            let mut inner = MaybeUninit::uninit();
            gmp::randinit_set(inner.as_mut_ptr(), self.as_raw());
            let inner = inner.assume_init();
            // If algdata is ABORT_FUNCS, then boxed_clone must have returned None.
            if ptr::eq(inner.algdata, &ABORT_FUNCS) {
                panic!("`RandGen::boxed_clone` returned `None`");
            }
            RandState {
                inner,
                phantom: PhantomData,
            }
        }
    }
}

impl Drop for RandState<'_> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            gmp::randclear(self.as_raw_mut());
        }
    }
}

unsafe impl Send for RandState<'_> {}
unsafe impl Sync for RandState<'_> {}

impl RandState<'_> {
    /// Creates a new random generator with a compromise between speed
    /// and randomness.
    ///
    /// Currently this is equivalent to [`new_mersenne_twister`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandState;
    /// let mut rand = RandState::new();
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// ```
    ///
    /// [`new_mersenne_twister`]: #method.new_mersenne_twister
    #[inline]
    pub fn new() -> RandState<'static> {
        RandState::new_mersenne_twister()
    }

    /// Creates a random generator with a Mersenne Twister algorithm.
    ///
    /// This algorithm is fast and has good randomness properties.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandState;
    /// let mut rand = RandState::new_mersenne_twister();
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// ```
    pub fn new_mersenne_twister() -> RandState<'static> {
        unsafe {
            let mut inner = MaybeUninit::uninit();
            gmp::randinit_mt(inner.as_mut_ptr());
            RandState {
                inner: inner.assume_init(),
                phantom: PhantomData,
            }
        }
    }

    /// Creates a new random generator with a linear congruential
    /// algorithm <i>X</i> = (<i>a</i> × <i>X</i> + <i>c</i>) mod 2<sup><i>m</i></sup>.
    ///
    /// The low bits of <i>X</i> in this algorithm are not very
    /// random, so only the high half of each <i>X</i> is actually
    /// used, that is the higher <i>m</i>/2 bits.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Integer};
    /// let a = match Integer::from_str_radix("292787ebd3329ad7e7575e2fd", 16) {
    ///     Ok(i) => i,
    ///     Err(_) => unreachable!(),
    /// };
    /// let c = 1;
    /// let m = 100;
    /// let mut rand = RandState::new_linear_congruential(&a, c, m);
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// ```
    pub fn new_linear_congruential(a: &Integer, c: u32, m: u32) -> RandState<'static> {
        unsafe {
            let mut inner = MaybeUninit::uninit();
            gmp::randinit_lc_2exp(inner.as_mut_ptr(), a.as_raw(), c.into(), m.into());
            RandState {
                inner: inner.assume_init(),
                phantom: PhantomData,
            }
        }
    }

    /// Creates a new random generator with a linear congruential
    /// algorithm like the [`new_linear_congruential`] method.
    ///
    /// For the linear congruential algorithm
    /// <i>X</i> = (<i>a</i> × <i>X</i> + <i>c</i>) mod 2<sup><i>m</i></sup>,
    /// <i>a</i>, <i>c</i> and <i>m</i> are selected from a table
    /// such that at least <i>size</i> bits of each <i>X</i> will be
    /// used, that is <i>m</i>/2 ≥ <i>size</i>. The table only has
    /// values for <i>size</i> ≤ 128; [`None`] will be returned if the
    /// requested size is larger.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandState;
    /// let mut rand = match RandState::new_linear_congruential_size(100) {
    ///     Some(r) => r,
    ///     None => unreachable!(),
    /// };
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`new_linear_congruential`]: #method.new_linear_congruential
    pub fn new_linear_congruential_size(size: u32) -> Option<RandState<'static>> {
        unsafe {
            let mut inner = MaybeUninit::uninit();
            if gmp::randinit_lc_2exp_size(inner.as_mut_ptr(), size.into()) != 0 {
                Some(RandState {
                    inner: inner.assume_init(),
                    phantom: PhantomData,
                })
            } else {
                None
            }
        }
    }

    /// Creates a new custom random generator.
    ///
    /// If the custom random generator is cloned, the implemented
    /// trait method
    /// <code>[RandGen][`RandGen`]::[boxed_clone][`boxed_clone`]</code>
    /// is called; this leads to panic if the method returns [`None`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{
    ///     rand::{RandGen, RandState},
    ///     Integer,
    /// };
    /// struct Seed;
    /// impl RandGen for Seed {
    ///     fn gen(&mut self) -> u32 {
    ///         // not really random
    ///         0x8CEF_7310
    ///     }
    /// }
    /// let mut seed = Seed;
    /// let mut rand = RandState::new_custom(&mut seed);
    /// let mut i = Integer::from(15);
    /// i.random_below_mut(&mut rand);
    /// println!("0 ≤ {} < 15", i);
    /// assert!(i < 15);
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`RandGen`]: trait.RandGen.html
    /// [`boxed_clone`]: trait.RandGen.html#method.boxed_clone
    pub fn new_custom(custom: &mut dyn RandGen) -> RandState<'_> {
        let b = Box::<&mut dyn RandGen>::new(custom);
        let r_ptr = NonNull::<&mut dyn RandGen>::from(Box::leak(b));
        let inner = randstate_t {
            seed: randseed_t {
                alloc: MaybeUninit::uninit(),
                size: MaybeUninit::uninit(),
                d: r_ptr.cast::<c_void>(),
            },
            alg: MaybeUninit::uninit(),
            algdata: &CUSTOM_FUNCS,
        };
        RandState {
            inner,
            phantom: PhantomData,
        }
    }

    /// Creates a new custom random generator.
    ///
    /// If the custom random generator is cloned, the implemented
    /// trait method
    /// <code>[RandGen][`RandGen`]::[boxed_clone][`boxed_clone`]</code>
    /// is called; this leads to panic if the method returns [`None`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{
    ///     rand::{RandGen, RandState},
    ///     Integer,
    /// };
    /// struct Seed;
    /// impl RandGen for Seed {
    ///     fn gen(&mut self) -> u32 {
    ///         // not really random
    ///         0x8CEF_7310
    ///     }
    /// }
    /// let seed = Box::new(Seed);
    /// let mut rand = RandState::new_custom_boxed(seed);
    /// let mut i = Integer::from(15);
    /// i.random_below_mut(&mut rand);
    /// println!("0 ≤ {} < 15", i);
    /// assert!(i < 15);
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`RandGen`]: trait.RandGen.html
    /// [`boxed_clone`]: trait.RandGen.html#method.boxed_clone
    pub fn new_custom_boxed(custom: Box<dyn RandGen>) -> RandState<'static> {
        let b = Box::<Box<dyn RandGen>>::new(custom);
        let r_ptr = NonNull::<Box<dyn RandGen>>::from(Box::leak(b));
        let inner = randstate_t {
            seed: randseed_t {
                alloc: MaybeUninit::uninit(),
                size: MaybeUninit::uninit(),
                d: r_ptr.cast::<c_void>(),
            },
            alg: MaybeUninit::uninit(),
            algdata: &CUSTOM_BOXED_FUNCS,
        };
        RandState {
            inner,
            phantom: PhantomData,
        }
    }

    /// Creates a random generator from an initialized
    /// [GMP random generator][`randstate_t`].
    ///
    /// # Safety
    ///
    ///   * The value must be initialized.
    ///   * The [`randstate_t`] type can be considered as a kind of
    ///     pointer, so there can be multiple copies of it. Since this
    ///     function takes over ownership, no other copies of the
    ///     passed value should exist.
    ///   * The object must be thread safe.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::mem::MaybeUninit;
    /// use gmp_mpfr_sys::gmp;
    /// use rug::rand::RandState;
    /// let mut rand = unsafe {
    ///     let mut raw = MaybeUninit::uninit();
    ///     gmp::randinit_default(raw.as_mut_ptr());
    ///     let raw = raw.assume_init();
    ///     // raw is initialized and unique
    ///     RandState::from_raw(raw)
    /// };
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// // since rand is a RandState now, deallocation is automatic
    /// ```
    ///
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub unsafe fn from_raw(raw: randstate_t) -> RandState<'static> {
        RandState {
            inner: raw,
            phantom: PhantomData,
        }
    }

    /// Converts a random generator into a
    /// [GMP random generator][`randstate_t`].
    ///
    /// The returned object should be freed to avoid memory leaks.
    ///
    /// # Panics
    ///
    /// This method panics if the [`RandState`] object was created
    /// using [`new_custom`], as the borrow into the custom generator
    /// would be terminated once `self` is consumed. This would lead
    /// to undefined behavior if the returned object is used. This
    /// method does work with objects created using
    /// [`new_custom_boxed`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::rand::RandState;
    /// let rand = RandState::new();
    /// let mut raw = rand.into_raw();
    /// unsafe {
    ///     let u = gmp::urandomb_ui(&mut raw, 32) as u32;
    ///     println!("32 random bits: {:032b}", u);
    ///     // free object to prevent memory leak
    ///     gmp::randclear(&mut raw);
    /// }
    /// ```
    ///
    /// [`RandState`]: #
    /// [`new_custom_boxed`]: #method.new_custom_boxed
    /// [`new_custom`]: #method.new_custom
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub fn into_raw(self) -> randstate_t {
        assert!(
            !ptr::eq(self.inner.algdata, &CUSTOM_FUNCS)
                && !ptr::eq(self.inner.algdata, &THREAD_CUSTOM_FUNCS),
            "cannot convert custom `RandState` into raw, \
             consider using `new_custom_boxed` instead of `new_custom`"
        );
        let m = ManuallyDrop::new(self);
        m.inner
    }

    /// Returns a pointer to the inner
    /// [GMP random generator][`randstate_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandState;
    /// let mut rand = RandState::new();
    /// let raw_ptr = rand.as_raw();
    /// // There is not much you can do with an immutable randstate_t pointer.
    /// println!("pointer: {:p}", raw_ptr);
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// ```
    ///
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub fn as_raw(&self) -> *const randstate_t {
        &self.inner
    }

    /// Returns an unsafe mutable pointer to the inner
    /// [GMP random generator][`randstate_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::rand::RandState;
    /// let mut rand = RandState::new();
    /// let raw_ptr = rand.as_raw_mut();
    /// unsafe {
    ///     let u1 = gmp::urandomb_ui(raw_ptr, 32) as u32;
    ///     println!("32 random bits: {:032b}", u1);
    /// }
    /// let u2 = rand.bits(32);
    /// println!("another 32 random bits: {:032b}", u2);
    /// ```
    ///
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub fn as_raw_mut(&mut self) -> *mut randstate_t {
        &mut self.inner
    }

    /// Converts a random generator into
    /// <code>[Box][`Box`]&lt;dyn [RandGen][`RandGen`]&gt;</code>
    /// if possible.
    ///
    /// If the conversion is not possible,
    /// <code>[Err][`Err`](self)</code> is returned.
    ///
    /// This conversion is always possible when the random generator
    /// was created with [`new_custom_boxed`]. It is also possible if
    /// the generator was cloned, directly or indirectly, from another
    /// generator that was created with [`new_custom`] or
    /// [`new_custom_boxed`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::{RandGen, RandState};
    /// struct Seed;
    /// impl RandGen for Seed {
    ///     fn gen(&mut self) -> u32 {
    ///         // not really random
    ///         0x8CEF_7310
    ///     }
    /// }
    /// let seed = Box::new(Seed);
    /// let rand = RandState::new_custom_boxed(seed);
    /// let mut back_to_seed = rand.into_custom_boxed().unwrap();
    /// assert_eq!(back_to_seed.gen(), 0x8CEF_7310);
    /// ```
    ///
    /// [`Box`]: https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html
    /// [`Err`]: https://doc.rust-lang.org/nightly/core/result/enum.Result.html#variant.Err
    /// [`RandGen`]: trait.RandGen.html
    /// [`new_custom_boxed`]: #method.new_custom_boxed
    /// [`new_custom`]: #method.new_custom
    #[inline]
    pub fn into_custom_boxed(self) -> Result<Box<dyn RandGen>, Self> {
        if !ptr::eq(self.inner.algdata, &CUSTOM_BOXED_FUNCS) {
            return Err(self);
        }
        let m = ManuallyDrop::new(self);
        let r_ptr = m.inner.seed.d.cast::<Box<dyn RandGen>>().as_ptr();
        let boxed_box: Box<Box<dyn RandGen>> = unsafe { Box::from_raw(r_ptr) };
        Ok(*boxed_box)
    }

    /// Seeds the random generator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::RandState, Integer};
    /// let seed = Integer::from(123456);
    /// let mut rand = RandState::new();
    /// rand.seed(&seed);
    /// let u1a = rand.bits(32);
    /// let u1b = rand.bits(32);
    /// // reseed with the same seed
    /// rand.seed(&seed);
    /// let u2a = rand.bits(32);
    /// let u2b = rand.bits(32);
    /// assert_eq!(u1a, u2a);
    /// assert_eq!(u1b, u2b);
    /// ```
    #[inline]
    pub fn seed(&mut self, seed: &Integer) {
        unsafe {
            gmp::randseed(self.as_raw_mut(), seed.as_raw());
        }
    }

    /// Generates a random number with the specified number of bits.
    ///
    /// # Panics
    ///
    /// Panics if `bits` is greater than 32.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandState;
    /// let mut rand = RandState::new();
    /// let u = rand.bits(16);
    /// assert!(u < (1 << 16));
    /// println!("16 random bits: {:016b}", u);
    /// ```
    #[inline]
    pub fn bits(&mut self, bits: u32) -> u32 {
        assert!(bits <= 32, "bits out of range");
        unsafe { gmp::urandomb_ui(self.as_raw_mut(), bits.into()) }.cast()
    }

    /// Generates a random number below the given boundary value.
    ///
    /// This function can never return the maximum 32-bit value; in
    /// order to generate a 32-bit random value that covers the whole
    /// range, use the [`bits`] method with `bits` set to 32.
    ///
    /// # Panics
    ///
    /// Panics if the boundary value is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandState;
    /// let mut rand = RandState::new();
    /// let u = rand.below(10000);
    /// assert!(u < 10000);
    /// println!("0 ≤ {} < 10000", u);
    /// ```
    ///
    /// [`bits`]: #method.bits
    #[inline]
    pub fn below(&mut self, bound: u32) -> u32 {
        assert_ne!(bound, 0, "cannot be below zero");
        unsafe { gmp::urandomm_ui(self.as_raw_mut(), bound.into()) }.cast()
    }
}

/**
The state of a random number generator that is suitable for a single thread only.

This is similar to [`RandState`] but can only be used in a single thread.

# Examples

```rust
use rug::rand::ThreadRandState;
# struct Gen { _dummy: *const i32, seed: u64 }
# impl rug::rand::ThreadRandGen for Gen {
#     fn gen(&mut self) -> u32 {
#         self.seed = self.seed.wrapping_mul(0x5851_F42D_4C95_7F2D).wrapping_add(1);
#         (self.seed >> 32) as u32
#     }
# }
# fn create_generator() -> Gen { Gen { _dummy: &0i32, seed: 1 } }
let mut gen = create_generator();
let mut rand = ThreadRandState::new_custom(&mut gen);
let u = rand.bits(32);
println!("32 random bits: {:032b}", u);
```

[`RandState`]: struct.RandState.html
*/
#[derive(Debug)]
#[repr(transparent)]
pub struct ThreadRandState<'a> {
    inner: randstate_t,
    phantom: PhantomData<&'a dyn ThreadRandGen>,
}

impl Clone for ThreadRandState<'_> {
    #[inline]
    fn clone(&self) -> ThreadRandState<'static> {
        unsafe {
            let mut inner = MaybeUninit::uninit();
            gmp::randinit_set(inner.as_mut_ptr(), self.as_raw());
            let inner = inner.assume_init();
            // If algdata is ABORT_FUNCS, then boxed_clone must have returned None.
            if ptr::eq(inner.algdata, &ABORT_FUNCS) {
                panic!("`ThreadRandGen::boxed_clone` returned `None`");
            }
            ThreadRandState {
                inner,
                phantom: PhantomData,
            }
        }
    }
}

impl Drop for ThreadRandState<'_> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            gmp::randclear(self.as_raw_mut());
        }
    }
}

impl ThreadRandState<'_> {
    /// Creates a new custom random generator.
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[new_custom][`new_custom`]</code>.
    /// The difference is that this method takes a [`ThreadRandGen`]
    /// that does not have to implement [`Send`] or [`Sync`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{
    ///     rand::{ThreadRandGen, ThreadRandState},
    ///     Integer,
    /// };
    /// // dummy pointer field to ensure Seed is not Send and not Sync
    /// struct Seed(*const ());
    /// impl ThreadRandGen for Seed {
    ///     fn gen(&mut self) -> u32 {
    ///         // not really random
    ///         0x8CEF_7310
    ///     }
    /// }
    /// let mut seed = Seed(&());
    /// let mut rand = ThreadRandState::new_custom(&mut seed);
    /// let mut i = Integer::from(15);
    /// i.random_below_mut(&mut rand);
    /// println!("0 ≤ {} < 15", i);
    /// assert!(i < 15);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`Send`]: https://doc.rust-lang.org/nightly/core/marker/trait.Send.html
    /// [`Sync`]: https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html
    /// [`ThreadRandGen`]: trait.ThreadRandGen.html
    /// [`new_custom`]: struct.RandState.html#method.new_custom
    pub fn new_custom(custom: &mut dyn ThreadRandGen) -> ThreadRandState<'_> {
        let b = Box::<&mut dyn ThreadRandGen>::new(custom);
        let r_ptr = NonNull::<&mut dyn ThreadRandGen>::from(Box::leak(b));
        let inner = randstate_t {
            seed: randseed_t {
                alloc: MaybeUninit::uninit(),
                size: MaybeUninit::uninit(),
                d: r_ptr.cast::<c_void>(),
            },
            alg: MaybeUninit::uninit(),
            algdata: &THREAD_CUSTOM_FUNCS,
        };
        ThreadRandState {
            inner,
            phantom: PhantomData,
        }
    }

    /// Creates a new custom random generator.
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[new_custom_boxed][`new_custom_boxed`]</code>.
    /// The difference is that this method takes a [`ThreadRandGen`]
    /// that does not have to implement [`Send`] or [`Sync`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{
    ///     rand::{ThreadRandGen, ThreadRandState},
    ///     Integer,
    /// };
    /// // dummy pointer field to ensure Seed is not Send and not Sync
    /// struct Seed(*const ());
    /// impl ThreadRandGen for Seed {
    ///     fn gen(&mut self) -> u32 {
    ///         // not really random
    ///         0x8CEF_7310
    ///     }
    /// }
    /// let seed = Box::new(Seed(&()));
    /// let mut rand = ThreadRandState::new_custom_boxed(seed);
    /// let mut i = Integer::from(15);
    /// i.random_below_mut(&mut rand);
    /// println!("0 ≤ {} < 15", i);
    /// assert!(i < 15);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`Send`]: https://doc.rust-lang.org/nightly/core/marker/trait.Send.html
    /// [`Sync`]: https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html
    /// [`ThreadRandGen`]: trait.ThreadRandGen.html
    /// [`new_custom_boxed`]: struct.RandState.html#method.new_custom_boxed
    pub fn new_custom_boxed(custom: Box<dyn ThreadRandGen>) -> ThreadRandState<'static> {
        let b = Box::<Box<dyn ThreadRandGen>>::new(custom);
        let r_ptr = NonNull::<Box<dyn ThreadRandGen>>::from(Box::leak(b));
        let inner = randstate_t {
            seed: randseed_t {
                alloc: MaybeUninit::uninit(),
                size: MaybeUninit::uninit(),
                d: r_ptr.cast::<c_void>(),
            },
            alg: MaybeUninit::uninit(),
            algdata: &THREAD_CUSTOM_BOXED_FUNCS,
        };
        ThreadRandState {
            inner,
            phantom: PhantomData,
        }
    }

    /// Creates a random generator from an initialized
    /// [GMP random generator][`randstate_t`].
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[from_raw][`from_raw`]</code>,
    /// but the object does not need to be thread safe. You *can* use
    /// this method if the object is thread safe, but in that case
    /// <code>[RandState][`RandState`]::[from_raw][`from_raw`]</code>
    /// is probably better as it allows the returned object to be
    /// shared and transferred across threads.
    ///
    /// # Safety
    ///
    ///   * The value must be initialized.
    ///   * The [`randstate_t`] type can be considered as a kind of
    ///     pointer, so there can be multiple copies of it. Since this
    ///     function takes over ownership, no other copies of the
    ///     passed value should exist.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use core::mem::MaybeUninit;
    /// use gmp_mpfr_sys::gmp;
    /// use rug::rand::ThreadRandState;
    /// let mut rand = unsafe {
    ///     let mut raw = MaybeUninit::uninit();
    ///     gmp::randinit_default(raw.as_mut_ptr());
    ///     let raw = raw.assume_init();
    ///     // raw is initialized and unique
    ///     ThreadRandState::from_raw(raw)
    /// };
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// // since rand is a ThreadRandState now, deallocation is automatic
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`from_raw`]: struct.RandState.html#method.from_raw
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub unsafe fn from_raw(raw: randstate_t) -> ThreadRandState<'static> {
        ThreadRandState {
            inner: raw,
            phantom: PhantomData,
        }
    }

    /// Converts a random generator into a
    /// [GMP random generator][`randstate_t`].
    ///
    /// The returned object should be freed to avoid memory leaks.
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[into_raw][`into_raw`]</code>,
    /// but the returned object is not thread safe. Notably, it should
    /// *not* be used in
    /// <code>[RandState][`RandState`]::[from_raw][`from_raw`]</code>.
    ///
    /// # Panics
    ///
    /// This method panics if the [`ThreadRandState`] object was
    /// created using [`new_custom`], as the borrow into the custom
    /// generator would be terminated once `self` is consumed. This
    /// would lead to undefined behavior if the returned object is
    /// used. This method does work with objects created using
    /// [`new_custom_boxed`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::rand::ThreadRandState;
    /// # struct Gen { _dummy: *const i32, seed: u64 }
    /// # impl rug::rand::ThreadRandGen for Gen {
    /// #     fn gen(&mut self) -> u32 {
    /// #         self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    /// #         (self.seed >> 32) as u32
    /// #     }
    /// # }
    /// # fn create_generator() -> Gen { Gen { _dummy: &0i32, seed: 1 } }
    /// let gen = Box::new(create_generator());
    /// let rand = ThreadRandState::new_custom_boxed(gen);
    /// let mut raw = rand.into_raw();
    /// unsafe {
    ///     let u = gmp::urandomb_ui(&mut raw, 32) as u32;
    ///     println!("32 random bits: {:032b}", u);
    ///     // free object to prevent memory leak
    ///     gmp::randclear(&mut raw);
    /// }
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`ThreadRandState`]: #
    /// [`from_raw`]: struct.RandState.html#method.from_raw
    /// [`into_raw`]: struct.RandState.html#method.into_raw
    /// [`new_custom_boxed`]: #method.new_custom_boxed
    /// [`new_custom`]: #method.new_custom
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub fn into_raw(self) -> randstate_t {
        assert!(
            !ptr::eq(self.inner.algdata, &CUSTOM_FUNCS)
                && !ptr::eq(self.inner.algdata, &THREAD_CUSTOM_FUNCS),
            "cannot convert custom `ThreadRandState` into raw, \
             consider using `new_custom_boxed` instead of `new_custom`"
        );
        let m = ManuallyDrop::new(self);
        m.inner
    }

    /// Returns a pointer to the inner
    /// [GMP random generator][`randstate_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// This is similar to <code>[RandState][`RandState`]::[as_raw][`as_raw`]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::ThreadRandState;
    /// # struct Gen { _dummy: *const i32, seed: u64 }
    /// # impl rug::rand::ThreadRandGen for Gen {
    /// #     fn gen(&mut self) -> u32 {
    /// #         self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    /// #         (self.seed >> 32) as u32
    /// #     }
    /// # }
    /// # fn create_generator() -> Gen { Gen { _dummy: &0i32, seed: 1 } }
    /// let mut gen = create_generator();
    /// let mut rand = ThreadRandState::new_custom(&mut gen);
    /// let raw_ptr = rand.as_raw();
    /// // There is not much you can do with an immutable randstate_t pointer.
    /// println!("pointer: {:p}", raw_ptr);
    /// let u = rand.bits(32);
    /// println!("32 random bits: {:032b}", u);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`as_raw`]: struct.RandState.html#method.as_raw
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub fn as_raw(&self) -> *const randstate_t {
        &self.inner
    }

    /// Returns an unsafe mutable pointer to the inner
    /// [GMP random generator][`randstate_t`].
    ///
    /// The returned pointer will be valid for as long as `self` is
    /// valid.
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[as_raw_mut][`as_raw_mut`]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gmp_mpfr_sys::gmp;
    /// use rug::rand::ThreadRandState;
    /// # struct Gen { _dummy: *const i32, seed: u64 }
    /// # impl rug::rand::ThreadRandGen for Gen {
    /// #     fn gen(&mut self) -> u32 {
    /// #         self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    /// #         (self.seed >> 32) as u32
    /// #     }
    /// # }
    /// # fn create_generator() -> Gen { Gen { _dummy: &0i32, seed: 1 } }
    /// let mut gen = create_generator();
    /// let mut rand = ThreadRandState::new_custom(&mut gen);
    /// let raw_ptr = rand.as_raw_mut();
    /// unsafe {
    ///     let u1 = gmp::urandomb_ui(raw_ptr, 32) as u32;
    ///     println!("32 random bits: {:032b}", u1);
    /// }
    /// let u2 = rand.bits(32);
    /// println!("another 32 random bits: {:032b}", u2);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`as_raw_mut`]: struct.RandState.html#method.as_raw_mut
    /// [`randstate_t`]: https://docs.rs/gmp-mpfr-sys/~1.4/gmp_mpfr_sys/gmp/struct.randstate_t.html
    #[inline]
    pub fn as_raw_mut(&mut self) -> *mut randstate_t {
        &mut self.inner
    }

    /// Converts a random generator into
    /// <code>[Box][`Box`]&lt;dyn [ThreadRandGen][`ThreadRandGen`]&gt;</code>
    /// if possible.
    ///
    /// If the conversion is not possible,
    /// <code>[Err][`Err`](self)</code> is returned.
    ///
    /// This conversion is always possible when the random generator
    /// was created with [`new_custom_boxed`]. It is also possible if
    /// the generator was cloned, directly or indirectly, from another
    /// generator that was created with [`new_custom`] or
    /// [`new_custom_boxed`].
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[into_custom_boxed][`into_custom_boxed`]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::{ThreadRandGen, ThreadRandState};
    /// struct Seed;
    /// impl ThreadRandGen for Seed {
    ///     fn gen(&mut self) -> u32 {
    ///         // not really random
    ///         0x8CEF_7310
    ///     }
    /// }
    /// let seed = Box::new(Seed);
    /// let rand = ThreadRandState::new_custom_boxed(seed);
    /// let mut back_to_seed = rand.into_custom_boxed().unwrap();
    /// assert_eq!(back_to_seed.gen(), 0x8CEF_7310);
    /// ```
    ///
    /// [`Box`]: https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html
    /// [`Err`]: https://doc.rust-lang.org/nightly/core/result/enum.Result.html#variant.Err
    /// [`RandState`]: struct.RandState.html
    /// [`ThreadRandGen`]: trait.ThreadRandGen.html
    /// [`into_custom_boxed`]: struct.RandState.html#method.into_custom_boxed
    /// [`new_custom_boxed`]: #method.new_custom_boxed
    /// [`new_custom`]: #method.new_custom
    #[inline]
    pub fn into_custom_boxed(self) -> Result<Box<dyn ThreadRandGen>, Self> {
        if !ptr::eq(self.inner.algdata, &THREAD_CUSTOM_BOXED_FUNCS) {
            return Err(self);
        }
        let m = ManuallyDrop::new(self);
        let r_ptr = m.inner.seed.d.cast::<Box<dyn ThreadRandGen>>().as_ptr();
        let boxed_box: Box<Box<dyn ThreadRandGen>> = unsafe { Box::from_raw(r_ptr) };
        Ok(*boxed_box)
    }

    /// Seeds the random generator.
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[seed][`seed`]</code>.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{rand::ThreadRandState, Integer};
    /// # use az::WrappingCast;
    /// # struct Gen { _dummy: *const i32, seed: u64 }
    /// # impl rug::rand::ThreadRandGen for Gen {
    /// #     fn gen(&mut self) -> u32 {
    /// #         self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    /// #         (self.seed >> 32) as u32
    /// #     }
    /// #     fn seed(&mut self, seed: &Integer) { self.seed = seed.wrapping_cast() }
    /// # }
    /// # fn create_generator_with_seed() -> Gen { Gen { _dummy: &0i32, seed: 1 } }
    /// let mut gen = create_generator_with_seed();
    /// let seed = Integer::from(123456);
    /// let mut rand = ThreadRandState::new_custom(&mut gen);
    /// rand.seed(&seed);
    /// let u1a = rand.bits(32);
    /// let u1b = rand.bits(32);
    /// // reseed with the same seed
    /// rand.seed(&seed);
    /// let u2a = rand.bits(32);
    /// let u2b = rand.bits(32);
    /// assert_eq!(u1a, u2a);
    /// assert_eq!(u1b, u2b);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`seed`]: struct.RandState.html#method.seed
    #[inline]
    pub fn seed(&mut self, seed: &Integer) {
        unsafe {
            gmp::randseed(self.as_raw_mut(), seed.as_raw());
        }
    }

    /// Generates a random number with the specified number of bits.
    ///
    /// This is similar to
    /// <code>[RandState][`RandState`]::[bits][`bits`]</code>.
    ///
    /// # Panics
    ///
    /// Panics if `bits` is greater than 32.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::ThreadRandState;
    /// # struct Gen { _dummy: *const i32, seed: u64 }
    /// # impl rug::rand::ThreadRandGen for Gen {
    /// #     fn gen(&mut self) -> u32 {
    /// #         self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    /// #         (self.seed >> 32) as u32
    /// #     }
    /// # }
    /// # fn create_generator() -> Gen { Gen { _dummy: &0i32, seed: 1 } }
    /// let mut gen = create_generator();
    /// let mut rand = ThreadRandState::new_custom(&mut gen);
    /// let u = rand.bits(16);
    /// assert!(u < (1 << 16));
    /// println!("16 random bits: {:016b}", u);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`bits`]: struct.RandState.html#method.bits
    #[inline]
    pub fn bits(&mut self, bits: u32) -> u32 {
        assert!(bits <= 32, "bits out of range");
        unsafe { gmp::urandomb_ui(self.as_raw_mut(), bits.into()) }.cast()
    }

    /// Generates a random number below the given boundary value.
    ///
    /// This is similar to <code>[RandState][`RandState`]::[below][`below`]</code>.
    ///
    /// # Panics
    ///
    /// Panics if the boundary value is zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::ThreadRandState;
    /// # struct Gen { _dummy: *const i32, seed: u64 }
    /// # impl rug::rand::ThreadRandGen for Gen {
    /// #     fn gen(&mut self) -> u32 {
    /// #         self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    /// #         (self.seed >> 32) as u32
    /// #     }
    /// # }
    /// # fn create_generator() -> Gen { Gen { _dummy: &0i32, seed: 1 } }
    /// let mut gen = create_generator();
    /// let mut rand = ThreadRandState::new_custom(&mut gen);
    /// let u = rand.below(10000);
    /// assert!(u < 10000);
    /// println!("0 ≤ {} < 10000", u);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`below`]: struct.RandState.html#method.below
    #[inline]
    pub fn below(&mut self, bound: u32) -> u32 {
        assert_ne!(bound, 0, "cannot be below zero");
        unsafe { gmp::urandomm_ui(self.as_raw_mut(), bound.into()) }.cast()
    }
}

/**
Custom random number generator to be used with [`RandState`].

The methods implemented for this trait, as well as possible
destructors, can be used by FFI callback functions. If these methods
panic, they can cause the program to abort.

# Examples

```rust
use rug::{
    rand::{RandGen, RandState},
    Integer,
};
struct SimpleGenerator {
    seed: u64,
}
impl RandGen for SimpleGenerator {
    fn gen(&mut self) -> u32 {
        // linear congruential algorithm with m = 64
        const A: u64 = 0x5851_F42D_4C95_7F2D;
        const C: u64 = 1;
        self.seed = self.seed.wrapping_mul(A).wrapping_add(C);
        (self.seed >> 32) as u32
    }
    fn seed(&mut self, seed: &Integer) {
        self.seed = seed.to_u64_wrapping();
    }
}
let mut gen = SimpleGenerator { seed: 1 };
let mut state = RandState::new_custom(&mut gen);
assert_eq!(state.bits(32), 0x5851_F42D);
assert_eq!(state.bits(32), 0xC0B1_8CCF);
```

[`RandState`]: struct.RandState.html
*/
pub trait RandGen: Send + Sync {
    /// Gets a random 32-bit unsigned integer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandGen;
    /// struct SimpleGenerator {
    ///     seed: u64,
    /// }
    /// impl RandGen for SimpleGenerator {
    ///     fn gen(&mut self) -> u32 {
    ///         // linear congruential algorithm with m = 64
    ///         const A: u64 = 0x5851_F42D_4C95_7F2D;
    ///         const C: u64 = 1;
    ///         self.seed = self.seed.wrapping_mul(A).wrapping_add(C);
    ///         (self.seed >> 32) as u32
    ///     }
    /// }
    /// let mut rand = SimpleGenerator { seed: 1 };
    /// assert_eq!(rand.gen(), 0x5851_F42D);
    /// assert_eq!(rand.seed, 0x5851_F42D_4C95_7F2E);
    /// assert_eq!(rand.gen(), 0xC0B1_8CCF);
    /// assert_eq!(rand.seed, 0xC0B1_8CCF_4E25_2D17);
    /// ```
    fn gen(&mut self) -> u32;

    /// Gets up to 32 random bits.
    ///
    /// The default implementation simply calls the [`gen`] method
    /// once and returns the most significant required bits.
    ///
    /// This method can be overridden to store any unused bits for
    /// later use. This can be useful for example if the random number
    /// generation process is computationally expensive.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandGen;
    /// struct SimpleGenerator {
    ///     seed: u64,
    ///     buffer: u32,
    ///     len: u32,
    /// }
    /// impl RandGen for SimpleGenerator {
    ///     fn gen(&mut self) -> u32 {
    ///         // linear congruential algorithm with m = 64
    ///         const A: u64 = 0x5851_F42D_4C95_7F2D;
    ///         const C: u64 = 1;
    ///         self.seed = self.seed.wrapping_mul(A).wrapping_add(C);
    ///         (self.seed >> 32) as u32
    ///     }
    ///     fn gen_bits(&mut self, bits: u32) -> u32 {
    ///         let mut bits = match bits {
    ///             0 => return 0,
    ///             1..=31 => bits,
    ///             _ => return self.gen(),
    ///         };
    ///         let mut ret = 0;
    ///         if bits > self.len {
    ///             bits -= self.len;
    ///             ret |= self.buffer << bits;
    ///             self.buffer = self.gen();
    ///             self.len = 32;
    ///         }
    ///         self.len -= bits;
    ///         ret |= self.buffer >> self.len;
    ///         self.buffer &= !(!0 << self.len);
    ///         ret
    ///     }
    /// }
    /// let mut rand = SimpleGenerator {
    ///     seed: 1,
    ///     buffer: 0,
    ///     len: 0,
    /// };
    /// let (first_32, second_32) = (0x5851_F42D, 0xC0B1_8CCF);
    /// assert_eq!(rand.gen_bits(24), first_32 >> 8);
    /// assert_eq!(rand.gen_bits(24), ((first_32 & 0xFF) << 16) | (second_32 >> 16));
    /// assert_eq!(rand.gen_bits(16), second_32 & 0xFFFF);
    /// ```
    ///
    /// [`gen`]: #tymethod.gen
    fn gen_bits(&mut self, bits: u32) -> u32 {
        let gen = self.gen();
        match bits {
            0 => 0,
            1..=31 => gen >> (32 - bits),
            _ => gen,
        }
    }

    /// Seeds the random number generator.
    ///
    /// The default implementation of this function does nothing.
    ///
    /// Note that the
    /// <code>[RandState][`RandState`]::[seed][`seed`]</code> method
    /// will pass its seed parameter exactly to this function without
    /// using it otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::{
    ///     rand::{RandGen, RandState},
    ///     Assign, Integer,
    /// };
    /// struct Seed {
    ///     inner: Integer,
    /// }
    /// impl RandGen for Seed {
    ///     fn gen(&mut self) -> u32 {
    ///         self.inner.to_u32_wrapping()
    ///     }
    ///     fn seed(&mut self, seed: &Integer) {
    ///         self.inner.assign(seed);
    ///     }
    /// }
    /// let mut seed = Seed {
    ///     inner: Integer::from(12),
    /// };
    /// let i = Integer::from(12345);
    /// {
    ///     let mut rand = RandState::new_custom(&mut seed);
    ///     rand.seed(&i);
    /// }
    /// assert_eq!(seed.inner, i);
    /// ```
    ///
    /// [`RandState`]: struct.RandState.html
    /// [`seed`]: struct.RandState.html#method.seed
    #[inline]
    fn seed(&mut self, seed: &Integer) {
        let _ = seed;
    }

    /// Optionally clones the random number generator.
    ///
    /// The default implementation returns [`None`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rug::rand::RandGen;
    /// struct SimpleGenerator {
    ///     seed: u64,
    /// }
    /// impl RandGen for SimpleGenerator {
    ///     fn gen(&mut self) -> u32 {
    ///         // linear congruential algorithm with m = 64
    ///         const A: u64 = 0x5851_F42D_4C95_7F2D;
    ///         const C: u64 = 1;
    ///         self.seed = self.seed.wrapping_mul(A).wrapping_add(C);
    ///         (self.seed >> 32) as u32
    ///     }
    ///     fn boxed_clone(&self) -> Option<Box<dyn RandGen>> {
    ///         let other = SimpleGenerator { seed: self.seed };
    ///         let boxed = Box::new(other);
    ///         Some(boxed)
    ///     }
    /// }
    /// let mut rand = SimpleGenerator { seed: 1 };
    /// assert_eq!(rand.gen(), 0x5851_F42D);
    /// assert_eq!(rand.seed, 0x5851_F42D_4C95_7F2E);
    /// let mut other = rand.boxed_clone().unwrap();
    /// assert_eq!(rand.gen(), 0xC0B1_8CCF);
    /// assert_eq!(rand.seed, 0xC0B1_8CCF_4E25_2D17);
    /// assert_eq!(other.gen(), 0xC0B1_8CCF);
    /// ```
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    #[inline]
    fn boxed_clone(&self) -> Option<Box<dyn RandGen>> {
        None
    }
}

/**
Custom random number generator to be used with [`ThreadRandState`].

The methods implemented for this trait, as well as possible
destructors, can be used by FFI callback functions. If these methods
panic, they can cause the program to abort.

This is similar to [`RandGen`] but can only be used in a single thread.

# Examples

```rust
# #[cfg(skip_this)]
use rand::{rngs::ThreadRng, thread_rng, RngCore};
# struct ThreadRng(*const i32, u32);
# impl ThreadRng {
#     pub fn next_u32(&mut self) -> u32 { self.1 = self.1.wrapping_add(1); self.1 }
# }
# fn thread_rng() -> ThreadRng { ThreadRng(&0i32, !0 - 10) }
use rug::rand::{ThreadRandGen, ThreadRandState};
struct Generator(ThreadRng);
impl ThreadRandGen for Generator {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}
let mut rng = Generator(thread_rng());
let mut state = ThreadRandState::new_custom(&mut rng);
let u = state.below(10000);
assert!(u < 10000);
println!("0 ≤ {} < 10000", u);
```

This would not compile, since `ThreadRng` is not [`Send`] and not
[`Sync`].

```compile_fail
# #[cfg(skip_this)]
use rand::{rngs::ThreadRng, thread_rng, RngCore};
# struct ThreadRng(*const i32, u32);
# impl ThreadRng {
#     pub fn next_u32(&mut self) -> u32 { self.1 = self.1.wrapping_add(1); self.1 }
# }
# fn thread_rng() -> ThreadRng { ThreadRng(&0i32, !0 - 10) }
use rug::rand::RandGen;
struct Generator(ThreadRng);
impl RandGen for Generator {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}
```

[`RandGen`]: trait.RandGen.html
[`Send`]: https://doc.rust-lang.org/nightly/core/marker/trait.Send.html
[`Sync`]: https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html
[`ThreadRandState`]: struct.ThreadRandState.html
*/
pub trait ThreadRandGen {
    /// Gets a random 32-bit unsigned integer.
    ///
    /// This is similar to
    /// <code>[RandGen][`RandGen`]::[gen][`gen`]</code>.
    ///
    /// [`RandGen`]: trait.RandGen.html
    /// [`gen`]: trait.RandGen.html#tymethod.gen
    fn gen(&mut self) -> u32;

    /// Gets up to 32 random bits.
    ///
    /// The default implementation simply calls the [`gen`] method
    /// once and returns the most significant required bits.
    ///
    /// This method can be overridden to store any unused bits for
    /// later use. This can be useful for example if the random number
    /// generation process is computationally expensive.
    ///
    /// This method is similar to
    /// <code>[RandGen][`RandGen`]::[gen_bits][`gen_bits`]</code>.
    ///
    /// [`RandGen`]: trait.RandGen.html
    /// [`gen_bits`]: trait.RandGen.html#method.gen_bits
    /// [`gen`]: #tymethod.gen
    fn gen_bits(&mut self, bits: u32) -> u32 {
        let gen = self.gen();
        match bits {
            0 => 0,
            1..=32 => gen >> (32 - bits),
            _ => gen,
        }
    }

    /// Seeds the random number generator.
    ///
    /// The default implementation of this function does nothing.
    ///
    /// Note that the
    /// <code>[ThreadRandState][`ThreadRandState`]::[seed][`seed`]</code>
    /// method will pass its seed parameter exactly to this function
    /// without using it otherwise.
    ///
    /// This method is similar to
    /// <code>[RandGen][`RandGen`]::[seed][`RandGen::seed`]</code>.
    ///
    /// [`RandGen::seed`]: trait.RandGen.html#method.seed
    /// [`RandGen`]: trait.RandGen.html
    /// [`ThreadRandState`]: struct.ThreadRandState.html
    /// [`seed`]: struct.ThreadRandState.html#method.seed
    #[inline]
    fn seed(&mut self, seed: &Integer) {
        let _ = seed;
    }

    /// Optionally clones the random number generator.
    ///
    /// The default implementation returns [`None`].
    ///
    /// This method is similar to
    /// <code>[RandGen][`RandGen`]::[boxed_clone][`boxed_clone`]</code>.
    ///
    /// [`None`]: https://doc.rust-lang.org/nightly/core/option/enum.Option.html#variant.None
    /// [`RandGen`]: trait.RandGen.html
    /// [`boxed_clone`]: trait.RandGen.html#method.boxed_clone
    #[inline]
    fn boxed_clone(&self) -> Option<Box<dyn ThreadRandGen>> {
        None
    }
}

static_assert_same_layout!(RandState<'_>, randstate_t);
static_assert_same_layout!(ThreadRandState<'_>, randstate_t);

static_assert_same_size!(RandState, Option<RandState>);
static_assert_same_size!(ThreadRandState, Option<ThreadRandState>);

// abort functions do not need a wrapper to abort on panic, they never panic and always abort
unsafe extern "C" fn abort_seed(_: *mut randstate_t, _: *const mpz_t) {
    process::abort();
}

unsafe extern "C" fn abort_get(_: *mut randstate_t, _: *mut limb_t, _: c_ulong) {
    process::abort();
}

unsafe extern "C" fn abort_clear(_: *mut randstate_t) {
    process::abort();
}

unsafe extern "C" fn abort_iset(_: *mut randstate_t, _: *const randstate_t) {
    process::abort();
}

unsafe extern "C" fn custom_seed(rstate: *mut randstate_t, seed: *const mpz_t) {
    let r_ptr = (*rstate).seed.d.cast::<&mut dyn RandGen>().as_ptr();
    (*r_ptr).seed(&*cast_ptr!(seed, Integer));
}

unsafe extern "C" fn custom_get(rstate: *mut randstate_t, dest: *mut limb_t, nbits: c_ulong) {
    let r_ptr = (*rstate).seed.d.cast::<&mut dyn RandGen>().as_ptr();
    gen_bits(*r_ptr, dest, nbits);
}

unsafe extern "C" fn custom_clear(rstate: *mut randstate_t) {
    let r_ptr = (*rstate).seed.d.cast::<&mut dyn RandGen>().as_ptr();
    drop(Box::from_raw(r_ptr));
}

unsafe extern "C" fn custom_iset(dst: *mut randstate_t, src: *const randstate_t) {
    let r_ptr = (*src).seed.d.cast::<&mut dyn RandGen>().as_ptr();
    gen_copy(*r_ptr, dst);
}

unsafe extern "C" fn custom_boxed_seed(rstate: *mut randstate_t, seed: *const mpz_t) {
    let r_ptr = (*rstate).seed.d.cast::<Box<dyn RandGen>>().as_ptr();
    (*r_ptr).seed(&*cast_ptr!(seed, Integer));
}

unsafe extern "C" fn custom_boxed_get(rstate: *mut randstate_t, dest: *mut limb_t, nbits: c_ulong) {
    let r_ptr = (*rstate).seed.d.cast::<Box<dyn RandGen>>().as_ptr();
    gen_bits(&mut **r_ptr, dest, nbits);
}

unsafe extern "C" fn custom_boxed_clear(rstate: *mut randstate_t) {
    let r_ptr = (*rstate).seed.d.cast::<Box<dyn RandGen>>().as_ptr();
    drop(Box::from_raw(r_ptr));
}

unsafe extern "C" fn custom_boxed_iset(dst: *mut randstate_t, src: *const randstate_t) {
    let r_ptr = (*src).seed.d.cast::<Box<dyn RandGen>>().as_ptr();
    gen_copy(&**r_ptr, dst);
}

unsafe extern "C" fn thread_custom_seed(rstate: *mut randstate_t, seed: *const mpz_t) {
    let r_ptr = (*rstate).seed.d.cast::<&mut dyn ThreadRandGen>().as_ptr();
    (*r_ptr).seed(&*cast_ptr!(seed, Integer));
}

unsafe extern "C" fn thread_custom_get(
    rstate: *mut randstate_t,
    dest: *mut limb_t,
    nbits: c_ulong,
) {
    let r_ptr = (*rstate).seed.d.cast::<&mut dyn ThreadRandGen>().as_ptr();
    thread_gen_bits(*r_ptr, dest, nbits);
}

unsafe extern "C" fn thread_custom_clear(rstate: *mut randstate_t) {
    let r_ptr = (*rstate).seed.d.cast::<&mut dyn ThreadRandGen>().as_ptr();
    drop(Box::from_raw(r_ptr));
}

unsafe extern "C" fn thread_custom_iset(dst: *mut randstate_t, src: *const randstate_t) {
    let r_ptr = (*src).seed.d.cast::<&mut dyn ThreadRandGen>().as_ptr();
    thread_gen_copy(*r_ptr, dst);
}

unsafe extern "C" fn thread_custom_boxed_seed(rstate: *mut randstate_t, seed: *const mpz_t) {
    let r_ptr = (*rstate).seed.d.cast::<Box<dyn ThreadRandGen>>().as_ptr();
    (*r_ptr).seed(&*cast_ptr!(seed, Integer));
}

unsafe extern "C" fn thread_custom_boxed_get(
    rstate: *mut randstate_t,
    dest: *mut limb_t,
    nbits: c_ulong,
) {
    let r_ptr = (*rstate).seed.d.cast::<Box<dyn ThreadRandGen>>().as_ptr();
    thread_gen_bits(&mut **r_ptr, dest, nbits);
}

unsafe extern "C" fn thread_custom_boxed_clear(rstate: *mut randstate_t) {
    let r_ptr = (*rstate).seed.d.cast::<Box<dyn ThreadRandGen>>().as_ptr();
    drop(Box::from_raw(r_ptr));
}

unsafe extern "C" fn thread_custom_boxed_iset(dst: *mut randstate_t, src: *const randstate_t) {
    let r_ptr = (*src).seed.d.cast::<Box<dyn ThreadRandGen>>().as_ptr();
    thread_gen_copy(&**r_ptr, dst);
}

#[cfg(gmp_limb_bits_64)]
unsafe fn gen_bits(gen: &mut dyn RandGen, dest: *mut limb_t, nbits: c_ulong) {
    let (limbs, rest) = (nbits / 64, nbits % 64);
    let limbs = limbs.unwrapped_as::<isize>();
    for i in 0..limbs {
        let n = u64::from(gen.gen()) | u64::from(gen.gen()) << 32;
        *dest.offset(i) = n.unwrapped_cast();
    }
    if rest >= 32 {
        let mut n = u64::from(gen.gen());
        if rest > 32 {
            let mask = !(!0 << (rest - 32));
            n |= u64::from(gen.gen_bits((rest - 32).unwrapped_cast()) & mask) << 32;
        }
        *dest.offset(limbs) = n.unwrapped_cast();
    } else if rest > 0 {
        let mask = !(!0 << rest);
        let n = u64::from(gen.gen_bits(rest.unwrapped_cast()) & mask);
        *dest.offset(limbs) = n.unwrapped_cast();
    }
}

#[cfg(gmp_limb_bits_32)]
unsafe fn gen_bits(gen: &mut dyn RandGen, dest: *mut limb_t, nbits: c_ulong) {
    let (limbs, rest) = (nbits / 32, nbits % 32);
    let limbs = limbs.unwrapped_as::<isize>();
    for i in 0..limbs {
        *dest.offset(i) = gen.gen().unwrapped_cast();
    }
    if rest > 0 {
        let mask = !(!0 << rest);
        *dest.offset(limbs) = (gen.gen_bits(rest.unwrapped_cast()) & mask).unwrapped_cast();
    }
}

unsafe fn gen_copy(gen: &dyn RandGen, dst: *mut randstate_t) {
    // Do not panic here if boxed_clone returns None, as panics cannot
    // cross FFI boundaries. Instead, set dst_ptr.seed.d to null.
    let (dst_r_ptr, funcs) = if let Some(other) = gen.boxed_clone() {
        let b = Box::<Box<dyn RandGen>>::new(other);
        let dst_r_ptr = NonNull::<Box<dyn RandGen>>::from(Box::leak(b));
        (dst_r_ptr, &CUSTOM_BOXED_FUNCS)
    } else {
        (NonNull::dangling(), &ABORT_FUNCS)
    };
    *dst = randstate_t {
        seed: randseed_t {
            alloc: MaybeUninit::uninit(),
            size: MaybeUninit::uninit(),
            d: dst_r_ptr.cast::<c_void>(),
        },
        alg: MaybeUninit::uninit(),
        algdata: funcs,
    };
}

#[cfg(gmp_limb_bits_64)]
unsafe fn thread_gen_bits(gen: &mut dyn ThreadRandGen, dest: *mut limb_t, nbits: c_ulong) {
    let (limbs, rest) = (nbits / 64, nbits % 64);
    let limbs = limbs.unwrapped_as::<isize>();
    for i in 0..limbs {
        let n = u64::from(gen.gen()) | u64::from(gen.gen()) << 32;
        *dest.offset(i) = n.unwrapped_cast();
    }
    if rest >= 32 {
        let mut n = u64::from(gen.gen());
        if rest > 32 {
            let mask = !(!0 << (rest - 32));
            n |= u64::from(gen.gen_bits((rest - 32).unwrapped_cast()) & mask) << 32;
        }
        *dest.offset(limbs) = n.unwrapped_cast();
    } else if rest > 0 {
        let mask = !(!0 << rest);
        let n = u64::from(gen.gen_bits(rest.unwrapped_cast()) & mask);
        *dest.offset(limbs) = n.unwrapped_cast();
    }
}

#[cfg(gmp_limb_bits_32)]
unsafe fn thread_gen_bits(gen: &mut dyn ThreadRandGen, dest: *mut limb_t, nbits: c_ulong) {
    let (limbs, rest) = (nbits / 32, nbits % 32);
    let limbs = limbs.unwrapped_as::<isize>();
    for i in 0..limbs {
        *dest.offset(i) = gen.gen().unwrapped_cast();
    }
    if rest > 0 {
        let mask = !(!0 << rest);
        *dest.offset(limbs) = (gen.gen_bits(rest.unwrapped_cast()) & mask).unwrapped_cast();
    }
}

unsafe fn thread_gen_copy(gen: &dyn ThreadRandGen, dst: *mut randstate_t) {
    // Do not panic here if boxed_clone returns None, as panics cannot
    // cross FFI boundaries. Instead, set dst_ptr.seed.d to null.
    let (dst_r_ptr, funcs) = if let Some(other) = gen.boxed_clone() {
        let b = Box::<Box<dyn ThreadRandGen>>::new(other);
        let dst_r_ptr = NonNull::<Box<dyn ThreadRandGen>>::from(Box::leak(b));
        (dst_r_ptr, &THREAD_CUSTOM_BOXED_FUNCS)
    } else {
        (NonNull::dangling(), &ABORT_FUNCS)
    };
    *dst = randstate_t {
        seed: randseed_t {
            alloc: MaybeUninit::uninit(),
            size: MaybeUninit::uninit(),
            d: dst_r_ptr.cast::<c_void>(),
        },
        alg: MaybeUninit::uninit(),
        algdata: funcs,
    };
}

static ABORT_FUNCS: randfnptr_t = randfnptr_t {
    seed: abort_seed,
    get: abort_get,
    clear: abort_clear,
    iset: abort_iset,
};

static CUSTOM_FUNCS: randfnptr_t = randfnptr_t {
    seed: custom_seed,
    get: custom_get,
    clear: custom_clear,
    iset: custom_iset,
};

static CUSTOM_BOXED_FUNCS: randfnptr_t = randfnptr_t {
    seed: custom_boxed_seed,
    get: custom_boxed_get,
    clear: custom_boxed_clear,
    iset: custom_boxed_iset,
};

static THREAD_CUSTOM_FUNCS: randfnptr_t = randfnptr_t {
    seed: thread_custom_seed,
    get: thread_custom_get,
    clear: thread_custom_clear,
    iset: thread_custom_iset,
};

static THREAD_CUSTOM_BOXED_FUNCS: randfnptr_t = randfnptr_t {
    seed: thread_custom_boxed_seed,
    get: thread_custom_boxed_get,
    clear: thread_custom_boxed_clear,
    iset: thread_custom_boxed_iset,
};

/// Used to pass the state of random number generators by mutable
/// reference.
///
/// This trait is implemented by
///   1. [`RandState`], which is thread safe and implements [`Send`]
///      and [`Sync`].
///   2. [`ThreadRandState`], which can only be used in a single
///      thread.
///
/// This trait is sealed and cannot be implemented for more types.
///
/// [`RandState`]: struct.RandState.html
/// [`Send`]: https://doc.rust-lang.org/nightly/core/marker/trait.Send.html
/// [`Sync`]: https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html
/// [`ThreadRandState`]: struct.ThreadRandState.html
pub trait MutRandState: SealedMutRandState {}

mod hide {
    use gmp_mpfr_sys::gmp::randstate_t;
    #[repr(transparent)]
    pub struct Private<'a>(pub(crate) &'a mut randstate_t);
    pub trait SealedMutRandState {
        fn private(&mut self) -> Private;
    }
}
use self::hide::{Private, SealedMutRandState};

impl MutRandState for RandState<'_> {}
impl SealedMutRandState for RandState<'_> {
    #[inline]
    fn private(&mut self) -> Private {
        Private(&mut self.inner)
    }
}
impl MutRandState for ThreadRandState<'_> {}
impl SealedMutRandState for ThreadRandState<'_> {
    #[inline]
    fn private(&mut self) -> Private {
        Private(&mut self.inner)
    }
}

#[cfg(test)]
mod tests {
    use crate::rand::{RandGen, RandState, ThreadRandGen, ThreadRandState};
    use az::{Az, Cast};
    use core::ptr;
    use gmp_mpfr_sys::gmp;

    struct SimpleGenerator {
        seed: u64,
    }

    impl RandGen for SimpleGenerator {
        fn gen(&mut self) -> u32 {
            self.seed = self
                .seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (self.seed >> 32).cast()
        }
        fn boxed_clone(&self) -> Option<Box<dyn RandGen>> {
            let other = SimpleGenerator { seed: self.seed };
            let boxed = Box::new(other);
            Some(boxed)
        }
    }

    #[test]
    fn check_custom_clone() {
        let mut gen = SimpleGenerator { seed: 1 };
        let third2;
        {
            let mut rand1 = RandState::new_custom(&mut gen);
            let mut rand2 = rand1.clone();
            let first1 = rand1.bits(32);
            let first2 = rand2.bits(32);
            assert_eq!(first1, first2);
            let second1 = rand1.bits(32);
            let second2 = rand2.bits(32);
            assert_eq!(second1, second2);
            assert_ne!(first1, second1);
            third2 = rand2.bits(32);
            assert_ne!(second2, third2);
        }
        let mut rand3 = RandState::new_custom_boxed(Box::new(gen));
        let mut rand4 = rand3.clone();
        let third3 = rand3.bits(32);
        let third4 = rand4.bits(32);
        assert_eq!(third2, third3);
        assert_eq!(third2, third4);
    }

    struct NoCloneGenerator;

    impl RandGen for NoCloneGenerator {
        fn gen(&mut self) -> u32 {
            0
        }
    }

    #[test]
    #[should_panic(expected = "`RandGen::boxed_clone` returned `None`")]
    fn check_custom_no_clone() {
        let mut gen = NoCloneGenerator;
        let rand1 = RandState::new_custom(&mut gen);
        let _ = rand1.clone();
    }

    #[test]
    #[should_panic(expected = "cannot convert custom `RandState` into raw")]
    fn check_custom_into_raw() {
        let mut gen = NoCloneGenerator;
        let rand1 = RandState::new_custom(&mut gen);
        let _ = rand1.into_raw();
    }

    // include a dummy pointer to make !Send and !Sync
    struct ThreadSimpleGenerator {
        _dummy: *const i32,
        seed: u64,
    }

    impl ThreadRandGen for ThreadSimpleGenerator {
        fn gen(&mut self) -> u32 {
            self.seed = self
                .seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            (self.seed >> 32).cast()
        }
        fn boxed_clone(&self) -> Option<Box<dyn ThreadRandGen>> {
            let other = ThreadSimpleGenerator {
                _dummy: ptr::null(),
                seed: self.seed,
            };
            let boxed = Box::new(other);
            Some(boxed)
        }
    }

    #[test]
    fn thread_check_custom_clone() {
        let mut gen = ThreadSimpleGenerator {
            _dummy: ptr::null(),
            seed: 1,
        };
        let third2;
        {
            let mut rand1 = ThreadRandState::new_custom(&mut gen);
            let mut rand2 = rand1.clone();
            let first1 = rand1.bits(32);
            let first2 = rand2.bits(32);
            assert_eq!(first1, first2);
            let second1 = rand1.bits(32);
            let second2 = rand2.bits(32);
            assert_eq!(second1, second2);
            assert_ne!(first1, second1);
            third2 = rand2.bits(32);
            assert_ne!(second2, third2);
        }
        let mut rand3 = ThreadRandState::new_custom_boxed(Box::new(gen));
        let mut rand4 = rand3.clone();
        let third3 = rand3.bits(32);
        let third4 = rand4.bits(32);
        assert_eq!(third2, third3);
        assert_eq!(third2, third4);
    }

    struct ThreadNoCloneGenerator;

    impl ThreadRandGen for ThreadNoCloneGenerator {
        fn gen(&mut self) -> u32 {
            0
        }
    }

    #[test]
    #[should_panic(expected = "`ThreadRandGen::boxed_clone` returned `None`")]
    fn thread_check_custom_no_clone() {
        let mut gen = ThreadNoCloneGenerator;
        let rand1 = ThreadRandState::new_custom(&mut gen);
        let _ = rand1.clone();
    }

    #[test]
    #[should_panic(expected = "cannot convert custom `ThreadRandState` into raw")]
    fn thread_check_custom_into_raw() {
        let mut gen = ThreadNoCloneGenerator;
        let rand1 = ThreadRandState::new_custom(&mut gen);
        let _ = rand1.into_raw();
    }

    #[test]
    fn thread_check_raw() {
        let mut check = RandState::new();
        // RandState is more restrictive than ThreadRandState; so this
        // conversion is sound.
        let mut state = unsafe { ThreadRandState::from_raw(check.clone().into_raw()) };
        assert_eq!(state.bits(32), check.bits(32));
        assert_eq!(
            unsafe { gmp::urandomb_ui(state.as_raw_mut(), 32) }.az::<u32>(),
            check.bits(32)
        );
        let mut raw = state.into_raw();
        assert_eq!(
            unsafe { gmp::urandomb_ui(&mut raw, 32) }.az::<u32>(),
            check.bits(32)
        );
        let mut state = unsafe { ThreadRandState::from_raw(raw) };
        assert_eq!(state.below(100), check.below(100));
    }

    #[test]
    fn congruential_size() {
        assert!(RandState::new_linear_congruential_size(128).is_some());
        assert!(RandState::new_linear_congruential_size(129).is_none());
    }
}
