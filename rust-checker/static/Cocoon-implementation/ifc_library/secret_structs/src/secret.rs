//#![allow(bare_trait_objects, unused_variables, unused_imports, dead_code)]
#![allow(non_snake_case)]

#[macro_export]
macro_rules! secret_block {
    ($t:ty $e:block) => {
        secret_macros::secret_block!($t $e)
    };
}

#[macro_export]
macro_rules! secret_block_no_return {
    ($t:ty $e:block) => {
        secret_macros::secret_block_no_return!($t $e)
    };
}

use std::mem::ManuallyDrop;
use std::path::PathBuf;

struct Wrapped<T> {
    _pd: PhantomData<T>,
}

use crate::lattice as lattice;
use std::fmt;
use std::{marker::PhantomData};

pub fn call_closure<L, F, R>(clos: F) -> R
where
    F: FnOnce() -> R + VisibleSideEffectFree,
    R: SecretTrait<L>,
{
    clos()
}

pub fn call_closure_no_return<L, F>(clos: F)
where
    F: FnOnce() + VisibleSideEffectFree,
{
    clos()
}

/** This trait helps allow secret closures to return tuples of Secrets. */
pub unsafe trait SecretTrait<L> {}
unsafe impl<T: SecretValueSafe, L: lattice::Label, L1: lattice::Label> SecretTrait<L> for Secret<T, L1> where
    L: lattice::MoreSecretThan<L1>
{
}
unsafe impl<L> SecretTrait<L> for () {}
unsafe impl<T1: SecretValueSafe, T2: SecretValueSafe, L: lattice::Label, L1: lattice::Label, L2: lattice::Label> SecretTrait<L>
    for (Secret<T1, L1>, Secret<T2, L2>)
where
    L: lattice::MoreSecretThan<L1> + lattice::MoreSecretThan<L2>,
{
}
unsafe impl<T1: SecretValueSafe, T2: SecretValueSafe, T3: SecretValueSafe, L: lattice::Label, L1: lattice::Label, L2: lattice::Label, L3: lattice::Label>
    SecretTrait<L> for (Secret<T1, L1>, Secret<T2, L2>, Secret<T3, L3>)
where
    L: lattice::MoreSecretThan<L1> + lattice::MoreSecretThan<L2> + lattice::MoreSecretThan<L3>,
{
}

pub unsafe auto trait NotSecret {}
impl<T: ?Sized, L> !NotSecret for Secret<T, L> {}
unsafe auto trait WrappedNotInvisibleSideEffectFree {}
impl<T: InvisibleSideEffectFree> !WrappedNotInvisibleSideEffectFree for Wrapped<T> {}

pub unsafe auto trait VisibleSideEffectFree {} // For limiting what secret block closures can capture
//unsafe impl VisibleSideEffectFree for dyn FnOnce() {} // This doesn't seem to have any purpose
impl<T> !VisibleSideEffectFree for &T where Wrapped<T>: WrappedNotInvisibleSideEffectFree {}
impl<T: NotSecret> !VisibleSideEffectFree for &mut T {}
impl<T: NotSecret> !VisibleSideEffectFree for *mut T {}
impl<T: NotSecret> !VisibleSideEffectFree for std::cell::UnsafeCell<T> {}
unsafe impl<T: SecretValueSafe, L: lattice::Label> VisibleSideEffectFree for &mut Secret<T, L> {} // not automatically implemented for some reason
unsafe impl<T: SecretValueSafe, L: lattice::Label> VisibleSideEffectFree for &mut &mut Secret<T, L> {} // needed because of the way closures capture mutable variables?
                                                                              //unsafe impl VisibleSideEffectFree for &mut i32 {} // WOULD conflict (as expected)
                                                                              //unsafe impl VisibleSideEffectFree for i32 {} // wouldn't conflict (but is redundant, right?)
unsafe impl<T: InvisibleSideEffectFree> VisibleSideEffectFree for &T {}

pub fn not_mut_secret<T>(x: &mut T) -> &mut T
    where T: NotSecret { x }

// This struct represents the return value of a function guaranteed not to leak certain kinds of information.
pub struct Vetted<T> where T: InvisibleSideEffectFree {
    item: T,
}

impl<T> Vetted<T> where T: InvisibleSideEffectFree {
    // Marks a return value as side-effect free.
    pub unsafe fn wrap(item: T) -> Self {
        Vetted::<T> { item }
    }

    // Extracts the return value.
    pub unsafe fn unwrap(self) -> T {
        self.item
    }
}

pub unsafe trait InvisibleSideEffectFree {
    // Limits what can be used in secret blocks
    unsafe fn check_all_types() {} // Overrided by #[derive(InvisibleSideEffectFree)]
}

pub fn check_type_is_secret_block_safe<T: InvisibleSideEffectFree>() {}

pub fn check_ISEF<T: InvisibleSideEffectFree>(x: T) -> T {
    //std::ptr::read(x)
    x
}
pub unsafe fn check_ISEF_unsafe<T: InvisibleSideEffectFree>(x: &T) -> T {
    std::ptr::read(x)
}
pub fn check_expr_secret_block_safe_ref<T: InvisibleSideEffectFree>(x: &T) -> &T
    where T: ?Sized {
    x
}
pub fn check_ISEF_mut_ref<T: InvisibleSideEffectFree>(x: &mut T) -> &mut T
    where T: ?Sized {
    x
}

// Usage: check_safe_index_expr(e)[check_safe_index(i)]
// Checks that e and i have types such that std::ops::Index<I> for E
pub fn check_safe_index_expr<E: SafeIndexExpr>(e: E) -> E {
    e
}
pub fn check_safe_index<I: SafeIndex>(i: I) -> I {
    i
}

pub fn check_safe_range_bounds<B: SafeRangeBounds>(b: B) -> B {
    b
}

unsafe impl InvisibleSideEffectFree for () {}
unsafe impl<T: SecretValueSafe, L: lattice::Label> InvisibleSideEffectFree for Secret<T, L> {}
unsafe impl<T: InvisibleSideEffectFree, U: InvisibleSideEffectFree> InvisibleSideEffectFree for (T, U) {}
unsafe impl<T: InvisibleSideEffectFree, U: InvisibleSideEffectFree, V: InvisibleSideEffectFree> InvisibleSideEffectFree for (T, U, V) {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for Box<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for Vec<T> {}
unsafe impl InvisibleSideEffectFree for f32 {}
unsafe impl InvisibleSideEffectFree for f64 {}
unsafe impl InvisibleSideEffectFree for isize {}
unsafe impl InvisibleSideEffectFree for i8 {}
unsafe impl InvisibleSideEffectFree for i16 {}
unsafe impl InvisibleSideEffectFree for i32 {}
unsafe impl InvisibleSideEffectFree for i64 {}
unsafe impl InvisibleSideEffectFree for i128 {}
unsafe impl InvisibleSideEffectFree for u8 {}
unsafe impl InvisibleSideEffectFree for u16 {}
unsafe impl InvisibleSideEffectFree for u32 {}
unsafe impl InvisibleSideEffectFree for u64 {}
unsafe impl InvisibleSideEffectFree for u128 {}
unsafe impl InvisibleSideEffectFree for usize {}
unsafe impl InvisibleSideEffectFree for String {}
unsafe impl InvisibleSideEffectFree for str {}
unsafe impl InvisibleSideEffectFree for &str {}
unsafe impl InvisibleSideEffectFree for std::str::Chars<'_> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for *mut T {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for Option<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &T {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &mut T {}
unsafe impl InvisibleSideEffectFree for char {}
unsafe impl InvisibleSideEffectFree for bool {}
unsafe impl InvisibleSideEffectFree for PathBuf {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for [T] {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &[T] {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for &mut [T] {}
unsafe impl<T: InvisibleSideEffectFree, const N: usize> InvisibleSideEffectFree for [T; N] {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for *const T {}
#[cfg(target_arch = "x86_64")]
unsafe impl InvisibleSideEffectFree for std::arch::x86_64::__m256d {}
#[cfg(target_arch = "x86_64")]
unsafe impl InvisibleSideEffectFree for std::arch::x86_64::__m128 {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Copied<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Cycle<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::iter::Take<T> {}
unsafe impl<'a, T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::slice::Iter<'a, T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::mem::MaybeUninit<T> {}
unsafe impl<T: InvisibleSideEffectFree> InvisibleSideEffectFree for std::ops::Range<T> {}
unsafe impl<K: InvisibleSideEffectFree, V: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::HashMap<K, V>  {}
unsafe impl<K: InvisibleSideEffectFree> InvisibleSideEffectFree for std::collections::HashSet<K>  {}
// TODO: lots more

auto trait NotWrappedRef {}
impl<T> !NotWrappedRef for Wrapped<&T> {}
auto trait NotWrappedMutRef {}
impl<T> !NotWrappedMutRef for Wrapped<&mut T> {}
auto trait NotWrappedBox {}
impl<T> !NotWrappedBox for Wrapped<Box<T>> {}

trait Base {}
impl Base for i32 {}
impl Base for i64 {}
impl Base for i128 {}
impl Base for i16 {}
impl Base for i8 {}
impl Base for isize {}
impl<T: Base> Base for Box<T> {}
impl<T: Base> Base for &T {}

/**
 * Struct wrapper containing a secret of type T with secrecy level L
 * Note: PhantomData<L> is just to fix issue that L is otherwise unused.
 * This may not be the best solution.   
 */
#[derive(Clone, Default)]
pub struct Secret<T, L /*,D*/>
where
    T: SecretValueSafe,
    L: lattice::Label
{
    val: ManuallyDrop<T>,
    _pd: PhantomData<L>,
    /*dynamic: D*/
}

//impl<T: SecretValueSafe,L: lattice::Label> UnwindSafe for Secret<T,L> {}

pub unsafe auto trait Immutable {} // interior immutable
impl<T: ?Sized> !Immutable for std::cell::UnsafeCell<T> {}
//impl<T: ?Sized> !Immutable for &T {} // Isn't mutable, but we don't want references wrapped in Secrets?
impl<T: ?Sized> !Immutable for &mut T {}
//impl<T: ?Sized> !UniquePtr for std::rc::Rc<T> {}
//impl<T: ?Sized> !UniquePtr for std::sync::Arc<T> {}

pub unsafe trait SecretValueSafe {} // For limiting what values can be wrapped in a Secret
unsafe impl<T> SecretValueSafe for T where T: Immutable + InvisibleSideEffectFree {}

/*
 * Code to restrict using unary, binary operators in secret closures to only primitive types.
 * Users can't overload (e.g. std::ops::Add) for primitive types so we can safely assume (+) hasn't
 * been overloaded in that case.
 */
// Extends a binary operator trait impl over refs
// Modified from forward_ref::forward_bin_op to use unsafe impls
macro_rules! unsafe_forward_ref_binop {
    // Equivalent to the non-const version, with the addition of `rustc_const_unstable`
    (unsafe impl const $imp:ident, $method:ident for $t:ty, $u:ty) => {
        unsafe impl<'a> const $imp<$u> for &'a $t {
            type Output = <$t as $imp<$u>>::Output;
            #[inline]
            fn $method(self, other: $u) -> <$t as $imp<$u>>::Output {
                $imp::$method(*self, other)
            }
        }
        unsafe impl const $imp<&$u> for $t {
            type Output = <$t as $imp<$u>>::Output;
            #[inline]
            fn $method(self, other: &$u) -> <$t as $imp<$u>>::Output {
                $imp::$method(self, *other)
            }
        }
        unsafe impl const $imp<&$u> for &$t {
            type Output = <$t as $imp<$u>>::Output;
            #[inline]
            fn $method(self, other: &$u) -> <$t as $imp<$u>>::Output {
                $imp::$method(*self, *other)
            }
        }
    };
    (unsafe impl $imp:ident, $method:ident for $t:ty, $u:ty) => {
        unsafe impl<'a> $imp<$u> for &'a $t {
            type Output = <$t as $imp<$u>>::Output;
            #[inline]
            fn $method(self, other: $u) -> <$t as $imp<$u>>::Output {
                $imp::$method(*self, other)
            }
        }
        unsafe impl $imp<&$u> for $t {
            type Output = <$t as $imp<$u>>::Output;
            #[inline]
            fn $method(self, other: &$u) -> <$t as $imp<$u>>::Output {
                $imp::$method(self, *other)
            }
        }
        unsafe impl $imp<&$u> for &$t {
            type Output = <$t as $imp<$u>>::Output;
            #[inline]
            fn $method(self, other: &$u) -> <$t as $imp<$u>>::Output {
                $imp::$method(*self, *other)
            }
        }
    };
}

macro_rules! unsafe_forward_ref_unop {
    // Equivalent to the non-const version
    (unsafe impl const $imp:ident, $method:ident for $t:ty) => {
        unsafe impl const $imp for &$t {
            type Output = <$t as $imp>::Output;
            #[inline]
            fn $method(self) -> <$t as $imp>::Output {
                $imp::$method(*self)
            }
        }
    };
    (unsafe impl $imp:ident, $method:ident for $t:ty) => {
        unsafe impl $imp for &$t {
            type Output = <$t as $imp>::Output;
            #[inline]
            fn $method(self) -> <$t as $imp>::Output {
                $imp::$method(*self)
            }
        }
    };
}

// implements "T op= &U", based on "T op= U"
// where U is expected to be `Copy`able
macro_rules! unsafe_forward_ref_op_assign {
    // Equivalent to the non-const version
    (unsafe impl const $imp:ident, $method:ident for $t:ty, $u:ty) => {
        unsafe impl const $imp<&$u> for $t {
            #[inline]
            fn $method(&mut self, other: &$u) {
                $imp::$method(self, *other);
            }
        }
    };
    (unsafe impl $imp:ident, $method:ident for $t:ty, $u:ty) => {
        unsafe impl $imp<&$u> for $t {
            #[inline]
            fn $method(&mut self, other: &$u) {
                $imp::$method(self, *other);
            }
        }
    };
}

/* Addition */
pub unsafe trait SafeAdd<Rhs = Self> {
    type Output;

    fn safe_add(self, rhs: Rhs) -> Self::Output;
}

// Auto implement SafeAdd for all primitive types
// Modified from source code for std::ops::Add with exception of const
// Const does not appear to behave the same way here as it does in std::ops
// so I'm not using it. This restricts use to non-const settings.
macro_rules! add_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeAdd for $t {
            type Output = $t;

            #[inline]
            fn safe_add(self, other: $t) -> $t { self + other }
        }
        unsafe_forward_ref_binop!{unsafe impl SafeAdd, safe_add for $t, $t}
    )*);
}

add_impl! {usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64}

// String concatenation
unsafe impl SafeAdd<&str> for String {
    type Output = String;

    #[inline]
    fn safe_add(self, other: &str) -> Self::Output {
        self + other
    }
}

pub unsafe trait SafeAddAssign<Rhs = Self> {
    fn safe_add_assign(&mut self, rhs: Rhs);
}
macro_rules! add_assign_impl {
    ($($t:ty)+) => ($(
        unsafe impl SafeAddAssign for $t {
            #[inline]
            fn safe_add_assign(&mut self, other: $t) { *self += other }
        }
        unsafe_forward_ref_op_assign! {unsafe impl SafeAddAssign, safe_add_assign for $t, $t }
    )+)
}
add_assign_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64 }

/* Subtraction */
pub unsafe trait SafeSub<Rhs = Self> {
    type Output;
    fn safe_sub(self, rhs: Rhs) -> Self::Output;
}

macro_rules! sub_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeSub for $t {
            type Output = $t;
            #[inline]
            fn safe_sub(self, other: $t) -> $t { self - other }
        }
        unsafe_forward_ref_binop! { unsafe impl SafeSub, safe_sub for $t, $t }
    )*)
}

sub_impl! {usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64}

pub unsafe trait SafeSubAssign<Rhs = Self> {
    fn safe_sub_assign(&mut self, rhs: Rhs);
}
macro_rules! sub_assign_impl {
    ($($t:ty)+) => ($(
        unsafe impl SafeSubAssign for $t {
            #[inline]
            fn safe_sub_assign(&mut self, other: $t) { *self -= other }
        }
        unsafe_forward_ref_op_assign! {unsafe impl SafeSubAssign, safe_sub_assign for $t, $t }
    )+)
}
sub_assign_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64 }

/* Multiplication */
pub unsafe trait SafeMul<Rhs = Self> {
    type Output;

    fn safe_mul(self, rhs: Rhs) -> Self::Output;
}

macro_rules! mul_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeMul for $t {
            type Output = $t;

            #[inline]
            fn safe_mul(self, other: $t) -> $t {self * other}
        }

        unsafe_forward_ref_binop! { unsafe impl SafeMul, safe_mul for $t, $t }
    )*)
}

mul_impl! {usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64}

pub unsafe trait SafeMulAssign<Rhs = Self> {
    fn safe_mul_assign(&mut self, rhs: Rhs);
}
macro_rules! mul_assign_impl {
    ($($t:ty)+) => ($(
        unsafe impl SafeMulAssign for $t {
            #[inline]
            fn safe_mul_assign(&mut self, other: $t) { *self *= other }
        }
        unsafe_forward_ref_op_assign! {unsafe impl SafeMulAssign, safe_mul_assign for $t, $t }
    )+)
}
mul_assign_impl! { usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64 }

/* Division */
#[const_trait]
pub unsafe trait SafeDiv<Rhs = Self> {
    type Output;
    fn safe_div(self, rhs: Rhs) -> Self::Output;
}

macro_rules! div_impl_integer {
    ($(($($t:ty)*) => $panic:expr),*) => ($($(
        #[doc = $panic]
        //#[stable(feature = "rust1", since = "1.0.0")]
        //#[rustc_const_unstable(feature = "const_ops", issue = "90080")]
        unsafe impl const SafeDiv for $t {
            type Output = $t;

            #[inline]
            fn safe_div(self, other: $t) -> $t { self / other }
        }

        unsafe_forward_ref_binop! { unsafe impl const SafeDiv, safe_div for $t, $t }
    )*)*)

}

div_impl_integer! {
    (usize u8 u16 u32 u64 u128) => "This operation will panic if `other == 0`.",
    (isize i8 i16 i32 i64 i128) => "This operation will panic if `other == 0` or the division results in overflow."
}

macro_rules! div_impl_float {
    ($($t:ty)*) => ($(
        //#[stable(feature = "rust1", since = "1.0.0")]
        //#[rustc_const_unstable(feature = "const_ops", issue = "90080")]
        //NOTE: original code had unsafe impl const SafeDiv both here and in unsafe_forward_ref_binop
        unsafe impl SafeDiv for $t {
            type Output = $t;

            #[inline]
            fn safe_div(self, other: $t) -> $t { self / other }
        }

        unsafe_forward_ref_binop! { unsafe impl SafeDiv, safe_div for $t, $t }
    )*)
}

div_impl_float! { f32 f64 }

pub unsafe trait SafeDivAssign<Rhs = Self> {
    fn safe_div_assign(&mut self, rhs: Rhs);
}
macro_rules! div_assign_impl_integer {
    ($(($($t:ty)*) => $panic:expr),*) => ($($(
        #[doc = $panic]
        //#[stable(feature = "rust1", since = "1.0.0")]
        //#[rustc_const_unstable(feature = "const_ops", issue = "90080")]
        unsafe impl SafeDivAssign for $t {
            #[inline]
            fn safe_div_assign(&mut self, other: $t) { *self /= other }
        }

        unsafe_forward_ref_op_assign! { unsafe impl SafeDivAssign, safe_div_assign for $t, $t }
    )*)*)
}

div_assign_impl_integer! {
    (usize u8 u16 u32 u64 u128) => "This operation will panic if `other == 0`.",
    (isize i8 i16 i32 i64 i128) => "This operation will panic if `other == 0` or the division results in overflow."
}

macro_rules! div_assign_impl_float {
    ($($t:ty)*) => ($(
        //#[stable(feature = "rust1", since = "1.0.0")]
        //#[rustc_const_unstable(feature = "const_ops", issue = "90080")]
        //NOTE: original code had unsafe impl const SafeDiv both here and in unsafe_forward_ref_binop
        unsafe impl SafeDivAssign for $t {
            #[inline]
            fn safe_div_assign(&mut self, other: $t) { *self /= other }
        }

        unsafe_forward_ref_op_assign! { unsafe impl SafeDivAssign, safe_div_assign for $t, $t }
    )*)
}
div_assign_impl_float! { f32 f64 }

/* PartialEq */
pub unsafe trait SafePartialEq<Rhs: ?Sized = Self> {
    /// This method tests for `self` and `other` values to be equal, and is used
    /// by `==`.
    #[must_use]
    fn safe_eq(&self, other: &Rhs) -> bool;

    /// This method tests for `!=`.
    #[inline]
    #[must_use]
    fn safe_ne(&self, other: &Rhs) -> bool {
        !self.safe_eq(other)
    }
}

// had to implement manually since std::cmp uses a compiler built-in and so the macro is not available in
// Rust docs source code
macro_rules! parteq_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafePartialEq for $t {
            #[inline]
            fn safe_eq(&self, other: &$t) -> bool { self == other }

            fn safe_ne(&self, other: &$t) -> bool {
                !self.safe_eq(other)
            }
        }
        //unsafe_forward_ref_binop! {unsafe impl SafePartialEq, safe_eq safe_ne for $t, $t}
    )*)
}

parteq_impl! { bool char f32 f64 i8 i16 i32 i64 i128 isize str u8 u16 u32 u64 u128 usize }

pub unsafe fn safe_max_by<T, F: FnOnce(&T, &T) -> std::cmp::Ordering>(
    v1: T,
    v2: T,
    compare: F,
) -> T {
    match compare(&v1, &v2) {
        std::cmp::Ordering::Less | std::cmp::Ordering::Equal => v2,
        std::cmp::Ordering::Greater => v1,
    }
}

pub unsafe fn safe_min_by<T, F: FnOnce(&T, &T) -> std::cmp::Ordering>(
    v1: T,
    v2: T,
    compare: F,
) -> T {
    match compare(&v1, &v2) {
        std::cmp::Ordering::Less | std::cmp::Ordering::Equal => v1,
        std::cmp::Ordering::Greater => v2,
    }
}

pub unsafe trait SafeOrd: Eq + PartialOrd<Self> {
    #[must_use]
    fn safe_cmp(&self, other: &Self) -> std::cmp::Ordering;

    #[inline]
    #[must_use]
    unsafe fn safe_max(self, other: Self) -> Self
    where
        Self: Sized,
    {
        safe_max_by(self, other, SafeOrd::safe_cmp)
    }

    #[inline]
    #[must_use]
    unsafe fn safe_min(self, other: Self) -> Self
    where
        Self: Sized,
    {
        safe_min_by(self, other, SafeOrd::safe_cmp)
    }

    #[must_use]
    fn safe_clamp(self, min: Self, max: Self) -> Self
    where
        Self: Sized,
    {
        assert!(min <= max);
        if self < min {
            min
        } else if self > max {
            max
        } else {
            self
        }
    }
}

unsafe impl SafeOrd for std::cmp::Ordering {
    #[inline]
    fn safe_cmp(&self, other: &std::cmp::Ordering) -> std::cmp::Ordering {
        (*self as i32).cmp(&(*other as i32))
    }
}

unsafe impl SafePartialOrd for std::cmp::Ordering {
    #[inline]
    fn safe_partial_cmp(&self, other: &std::cmp::Ordering) -> Option<std::cmp::Ordering> {
        (*self as i32).partial_cmp(&(*other as i32))
    }
}

pub unsafe trait SafePartialOrd<Rhs: ?Sized = Self>: PartialEq<Rhs> {
    #[must_use]
    fn safe_partial_cmp(&self, other: &Rhs) -> Option<std::cmp::Ordering>;

    #[inline]
    #[must_use]
    fn safe_lt(&self, other: &Rhs) -> bool {
        matches!(self.safe_partial_cmp(other), Some(std::cmp::Ordering::Less))
    }

    #[inline]
    #[must_use]
    fn safe_le(&self, other: &Rhs) -> bool {
        !matches!(
            self.safe_partial_cmp(other),
            None | Some(std::cmp::Ordering::Greater)
        )
    }

    #[inline]
    #[must_use]
    fn safe_gt(&self, other: &Rhs) -> bool {
        matches!(
            self.safe_partial_cmp(other),
            Some(std::cmp::Ordering::Greater)
        )
    }

    #[inline]
    #[must_use]
    fn safe_ge(&self, other: &Rhs) -> bool {
        matches!(
            self.safe_partial_cmp(other),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        )
    }
}
macro_rules! partial_ord_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafePartialOrd for $t {
            fn safe_partial_cmp(&self, other: &$t) -> Option<std::cmp::Ordering> {
                match (*self <= *other, *self >= *other) {
                    (false, false) => None,
                    (false, true) => Some(std::cmp::Ordering::Greater),
                    (true, false) => Some(std::cmp::Ordering::Less),
                    (true, true) => Some(std::cmp::Ordering::Equal),
                }
            }
            #[inline]
            fn safe_lt(&self, other: &$t) -> bool { (*self) < (*other) }
            #[inline]
            fn safe_le(&self, other: &$t) -> bool { (*self) <= (*other) }
            #[inline]
            fn safe_ge(&self, other: &$t) -> bool { (*self) >= (*other) }
            #[inline]
            fn safe_gt(&self, other: &$t) -> bool { (*self) > (*other) }
        }
    )*)
}

partial_ord_impl! {f32 f64}

// Negation
pub unsafe trait SafeNeg {
    type Output;
    fn safe_neg(self) -> Self::Output;
}

macro_rules! ord_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafePartialOrd for $t {
            #[inline]
            fn safe_partial_cmp(&self, other: &$t) -> Option<std::cmp::Ordering> {
                Some(self.safe_cmp(other))
            }
            #[inline]
            fn safe_lt(&self, other: &$t) -> bool { (*self) < (*other) }
            #[inline]
            fn safe_le(&self, other: &$t) -> bool { (*self) <= (*other) }
            #[inline]
            fn safe_ge(&self, other: &$t) -> bool { (*self) >= (*other) }
            #[inline]
            fn safe_gt(&self, other: &$t) -> bool { (*self) > (*other) }
        }

        unsafe impl SafeOrd for $t {
            #[inline]
            fn safe_cmp(&self, other: &$t) -> std::cmp::Ordering {
                if *self < *other { return std::cmp::Ordering::Less }
                else if *self == *other { return std::cmp::Ordering::Equal }
                else { return std::cmp::Ordering::Greater}
            }
        }
    )*)
}

ord_impl! { char usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128}

macro_rules! neg_impl {
    (f $($t:ty)*) => ($(
        unsafe impl SafeNeg for $t {
            type Output = $t;
            #[inline]
            fn safe_neg(self) -> $t { -self }
        }
        unsafe_forward_ref_unop! {unsafe impl SafeNeg, safe_neg for $t }
    )*);
    ($($t:ty)*) => ($(
        unsafe impl SafeNeg for $t {
            type Output = $t;
            #[inline]
            fn safe_neg(self) -> $t { -self }
        }
        unsafe_forward_ref_unop! {unsafe impl SafeNeg, safe_neg for $t }
    )*);
}

neg_impl! {isize i8 i16 i32 i64 i128}
neg_impl! {f f32 f64}

/* Not */
pub unsafe trait SafeNot {
    type Output;
    fn safe_not(self) -> Self::Output;
}

macro_rules! not_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeNot for $t {
            type Output = $t;
            #[inline]
            fn safe_not(self) -> $t { !self }
        }
        unsafe_forward_ref_unop! { unsafe impl SafeNot, safe_not for $t }
    )*)
}

not_impl! {bool usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128}

/* Traits for all other overloadable operators (not implemented = disallowed by macro)
TODO: implement these */
pub unsafe trait SafeBitAndAssign {}
pub unsafe trait SafeBitOr {}
pub unsafe trait SafeBitOrAssign {}
pub unsafe trait SafeBitXorAssign {}
pub unsafe trait SafeDrop {}
pub unsafe trait SafeFn {}
pub unsafe trait SafeFnMut {}
pub unsafe trait SafeFnOnce {}
#[const_trait]

pub unsafe trait SafeBitXor<Rhs = Self> {
    type Output;
    fn safe_bitxor(self, rhs: Rhs) -> Self::Output;
}

macro_rules! bitxor_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeBitXor for $t {
            type Output = $t;

            #[inline]
            fn safe_bitxor(self, other: $t) -> $t { self ^ other }
        }

        unsafe_forward_ref_binop! { unsafe impl SafeBitXor, safe_bitxor for $t, $t }
    )*)
}

bitxor_impl! { bool usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 }

pub unsafe trait SafeBitAnd<Rhs = Self> {
    /// The resulting type after applying the `&` operator.
    type Output;
    fn safe_bitand(self, rhs: Rhs) -> Self::Output;
}

macro_rules! bitand_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeBitAnd for $t {
            type Output = $t;

            #[inline]
            fn safe_bitand(self, rhs: $t) -> $t { self & rhs }
        }

        unsafe_forward_ref_binop! { unsafe impl SafeBitAnd, safe_bitand for $t, $t }
    )*)
}

bitand_impl! { bool usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 }

pub unsafe trait SafeIndex {}
unsafe impl SafeIndex for std::ops::Range<usize> {}
unsafe impl SafeIndex for std::ops::RangeFrom<usize> {}
unsafe impl SafeIndex for std::ops::RangeFull {}
unsafe impl SafeIndex for std::ops::RangeInclusive<usize> {}
unsafe impl SafeIndex for std::ops::RangeTo<usize> {}
// duplicate definition given Range types
//unsafe impl<T> SafeIndex for T where T: std::slice::SliceIndex<str>, {}
//unsafe impl<T> SafeIndex for T where T: std::slice::SliceIndex<[T]> {}
unsafe impl<Q> SafeIndex for &Q where Q: std::cmp::Ord + ?Sized, {}
unsafe impl SafeIndex for usize {}

pub unsafe trait SafeIndexExpr {}
unsafe impl SafeIndexExpr for std::string::String {}
unsafe impl SafeIndexExpr for &std::string::String {}
unsafe impl SafeIndexExpr for &mut std::string::String {}
unsafe impl SafeIndexExpr for std::ffi::CStr {}
unsafe impl SafeIndexExpr for &std::ffi::CStr {}
unsafe impl SafeIndexExpr for &mut std::ffi::CStr {}
unsafe impl SafeIndexExpr for std::ffi::CString {}
unsafe impl SafeIndexExpr for &std::ffi::CString {}
unsafe impl SafeIndexExpr for &mut std::ffi::CString{}
unsafe impl SafeIndexExpr for std::ffi::OsString {}
unsafe impl SafeIndexExpr for &std::ffi::OsString {}
unsafe impl SafeIndexExpr for &mut std::ffi::OsString{}
unsafe impl SafeIndexExpr for str {}
unsafe impl SafeIndexExpr for &str {}
unsafe impl SafeIndexExpr for &mut str {}
unsafe impl<K, V, A> SafeIndexExpr for std::collections::BTreeMap<K, V, A> 
    where A: std::alloc::Allocator + std::clone::Clone, K: std::cmp::Ord, {}
unsafe impl<K, V, A> SafeIndexExpr for &std::collections::BTreeMap<K, V, A> 
    where A: std::alloc::Allocator + std::clone::Clone, K: std::cmp::Ord, {}
unsafe impl<K, V, A> SafeIndexExpr for &mut std::collections::BTreeMap<K, V, A> 
    where A: std::alloc::Allocator + std::clone::Clone, K: std::cmp::Ord, {}
unsafe impl<K, V, S> SafeIndexExpr for std::collections::HashMap<K, V, S>
    where K: std::cmp::Eq + std::hash::Hash, S: std::hash::BuildHasher, {}
unsafe impl<K, V, S> SafeIndexExpr for &std::collections::HashMap<K, V, S>
    where K: std::cmp::Eq + std::hash::Hash, S: std::hash::BuildHasher, {}
unsafe impl<K, V, S> SafeIndexExpr for &mut std::collections::HashMap<K, V, S>
        where K: std::cmp::Eq + std::hash::Hash, S: std::hash::BuildHasher, {}
unsafe impl<T, A> SafeIndexExpr for std::collections::VecDeque<T, A> where A: std::alloc::Allocator, {}
unsafe impl<T, A> SafeIndexExpr for &std::collections::VecDeque<T, A> where A: std::alloc::Allocator, {}
unsafe impl<T, A> SafeIndexExpr for &mut std::collections::VecDeque<T, A> where A: std::alloc::Allocator, {}
unsafe impl<T> SafeIndexExpr for [T] {}
unsafe impl<T> SafeIndexExpr for &[T] {}
unsafe impl<T> SafeIndexExpr for &mut [T] {}
unsafe impl<T, A> SafeIndexExpr for std::vec::Vec<T, A> where A: std::alloc::Allocator, {}
unsafe impl<T, A> SafeIndexExpr for &std::vec::Vec<T, A> where A: std::alloc::Allocator, {}
unsafe impl<T, A> SafeIndexExpr for &mut std::vec::Vec<T, A> where A: std::alloc::Allocator, {}
unsafe impl<T, const N: usize> SafeIndexExpr for [T; N] where [T]: SafeIndexExpr, {}
unsafe impl<T, const N: usize> SafeIndexExpr for &[T; N] where [T]: SafeIndexExpr, {}
unsafe impl<T, const N: usize> SafeIndexExpr for &mut [T; N] where [T]: SafeIndexExpr, {}

pub unsafe trait SafeRangeBounds {}

// only allow ranges to be of Rust numeric types
pub unsafe trait SafeRangeTypes {}
macro_rules! safe_range_types_impl {
    ($($t:ty)*) => ($(
        unsafe impl SafeRangeTypes for $t {}
    )*)
}
safe_range_types_impl! {usize u8 u16 u32 u64 u128 isize i8 i16 i32 i64 i128 f32 f64}

// unsafe impl<'a, T: SafeRangeTypes + 'a + ?Sized> SafeRangeBounds for (std::ops::Bound<&'a T>, std::ops::Bound<&'a T>) {}
unsafe impl<T: SafeRangeTypes> SafeRangeBounds for (std::ops::Bound<T>, std::ops::Bound<T>) {}
// unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::Range<&T> {}
unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::Range<T> {}
// unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::RangeFrom<&T> {}
unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::RangeFrom<T> {}
unsafe impl SafeRangeBounds for std::ops::RangeFull {}
//unsafe impl<T: SafeRangeTypes: SafeRangeTypes> SafeRangeBounds for std::ops::RangeInclusive<&T> {}
unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::RangeInclusive<T> {}
//unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::RangeTo<&T> {}
unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::RangeTo<T> {}
// unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::RangeToInclusive<&T> {}
unsafe impl<T: SafeRangeTypes> SafeRangeBounds for std::ops::RangeToInclusive<T> {}

pub unsafe trait SafeRem {}
pub unsafe trait SafeRemAssign {}
pub unsafe trait SafeShl {}
pub unsafe trait SafeShlAssign {}
pub unsafe trait SafeShr {}
pub unsafe trait SafeShrAssign {}

impl<T, L: lattice::Label> Secret<T, L>
where
    T: SecretValueSafe,
{
    pub unsafe fn new(val: T) -> Secret<T, L> {
        Secret::<T, L> {
            val: ManuallyDrop::new(val),
            _pd: PhantomData,
        }
    }

    /*
     * Returns a new SecretI64 with Nonetom level secrecy. This function does not modify
     * the original SecretI64 object.
     *
     * This function is the intended way for the public to access SecretI64 values.
     */
    /*pub fn declassify(&self) -> Secret<T,lattice::Label_Empty> where T : Copy { // returning an i64 would be another option
        Secret::<T,lattice::Label_Empty>::new(self.val)
    }*/

    // Returning the interior value here, since it's not possible to return a reference to a new Secret (?)
    pub fn declassify_ref(&self) -> &T {
        // returning an i64 would be another option
        &self.val
        //&Secret::<T,lattice::Label_Empty>::new(self.val)
    }

    pub fn declassify_ref_mut(&mut self) -> &mut T {
        &mut self.val
    }

    pub fn declassify(self) -> Secret<T, lattice::Label_Empty> {
        // returning an i64 would be another option
        unsafe { Secret::<T, lattice::Label_Empty>::new(ManuallyDrop::into_inner(self.val)) }
    }

    pub fn declassify_to_consume<M: lattice::Label>(self, _level: PhantomData<M>) -> Secret<T, M>
    where
        L: lattice::MoreSecretThan<M>,
    {
        unsafe { Secret::<T, M>::new(ManuallyDrop::into_inner(self.val)) }
    }

    pub fn clone(&self) -> Secret<T, L>
    where
        T: Clone,
    {
        Secret::<T, L> {
            val: self.val.clone(),
            _pd: PhantomData,
        }
    }

    /** (Unsafe) unwrap if label of M allows it.
    Called from secret closures. */
    pub unsafe fn unwrap_unsafe<M>(&self) -> &T
    where
        M: lattice::MoreSecretThan<L>,
    {
        &self.val
    }

    /** (Unsafe) mutable unwrap if label is exactly M
    (since this allows both read and write access).
    Called from secret closures. */
    pub unsafe fn unwrap_mut_unsafe<M>(&mut self) -> &mut T
    where
        M: lattice::MoreSecretThan<L>,
        L: lattice::MoreSecretThan<M>,
    {
        &mut self.val
    }

    pub unsafe fn unwrap_consume_unsafe<M>(self) -> T
    where
        M: lattice::MoreSecretThan<L>,
    {
        self.unwrap()
    }

    fn unwrap(self) -> T {
        ManuallyDrop::into_inner(self.val)
    }
}

// Note: Cannot print value if L: lattice::Label_Empty since it results in conflicting
// implementations and negative impls aren't supported
impl<T: SecretValueSafe, L: lattice::Label> fmt::Display for Secret<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(secret)")
    }
}

impl<T: SecretValueSafe, L: lattice::Label> fmt::Debug for Secret<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(secret)")
    }
}

impl<T> Secret<T, lattice::Label_Empty>
where
    T: SecretValueSafe,
{
    /**
     * Returns a borrow of the interior value of self.
     * Only valid on public data.
     */
    pub fn get_value_ref(&self) -> &T {
        &self.val
    }

    /**
     * Returns the interior value of self, consuming self in the process.
     * Only valid on public data.
     */
    pub fn get_value_consume(self) -> T {
        ManuallyDrop::into_inner(self.val)
    }
}
