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
use crate::{misc::NegAbs, ops::NegAssign, Integer};
use az::{Az, Cast, UnwrappedAs, UnwrappedCast, WrappingAs, WrappingCast};
use core::{
    cmp::Ordering,
    i16, i8,
    mem::MaybeUninit,
    ptr::{self, NonNull},
    u16, u8,
};
use gmp_mpfr_sys::gmp::{self, bitcnt_t, limb_t, mpz_t, size_t};
use libc::{c_int, c_long, c_ulong};

#[cfg(gmp_limb_bits_32)]
pub use crate::ext::xmpz32::*;
#[cfg(gmp_limb_bits_64)]
pub use crate::ext::xmpz64::*;

pub trait OptInteger: Copy {
    const IS_SOME: bool;
    fn mpz(self) -> *const mpz_t;
    fn mpz_or(self, default: *mut mpz_t) -> *const mpz_t;
    fn unwrap<'a>(self) -> &'a Integer
    where
        Self: 'a;
    fn unwrap_or<'a>(self, default: &'a mut Integer) -> &'a Integer
    where
        Self: 'a;
}

impl OptInteger for () {
    const IS_SOME: bool = false;
    #[inline(always)]
    fn mpz(self) -> *const mpz_t {
        panic!("unwrapping ()");
    }
    #[inline(always)]
    fn mpz_or(self, default: *mut mpz_t) -> *const mpz_t {
        default as *const mpz_t
    }
    #[inline(always)]
    fn unwrap<'a>(self) -> &'a Integer
    where
        Self: 'a,
    {
        panic!("unwrapping ()");
    }
    #[inline(always)]
    fn unwrap_or<'a>(self, default: &'a mut Integer) -> &'a Integer
    where
        Self: 'a,
    {
        &*default
    }
}

impl<'a> OptInteger for &'a Integer {
    const IS_SOME: bool = true;
    #[inline(always)]
    fn mpz(self) -> *const mpz_t {
        self.as_raw()
    }
    #[inline(always)]
    fn mpz_or(self, _default: *mut mpz_t) -> *const mpz_t {
        self.as_raw()
    }
    #[inline(always)]
    fn unwrap<'b>(self) -> &'b Integer
    where
        Self: 'b,
    {
        self
    }
    #[inline(always)]
    fn unwrap_or<'b>(self, _default: &'b mut Integer) -> &'b Integer
    where
        Self: 'b,
    {
        self
    }
}

macro_rules! unsafe_wrap {
    (fn $fn:ident($($op:ident: $O:ident),* $(; $param:ident: $T:ty)*) -> $deleg:path) => {
        #[inline]
        pub fn $fn<$($O: OptInteger),*>(rop: &mut Integer $(, $op: $O)* $(, $param: $T)*) {
            let rop = rop.as_raw_mut();
            $(let $op = $op.mpz_or(rop);)*
            unsafe {
                $deleg(rop $(, $op)* $(, $param.into())*);
            }
        }
    };
}

macro_rules! unsafe_wrap0 {
    (fn $fn:ident($($param:ident: $T:ty),*) -> $deleg:path) => {
        #[inline]
        pub fn $fn(rop: &mut Integer, $($param: $T),*) {
            unsafe {
                $deleg(rop.as_raw_mut(), $($param.into()),*);
            }
        }
    };
}

macro_rules! unsafe_wrap_p {
    (fn $fn:ident($($op:ident),* $(; $param:ident: $T:ty)*) -> $deleg:path) => {
        #[inline]
        pub fn $fn(n: &Integer $(, $op: &Integer)* $(, $param: $T)*) -> bool{
            (unsafe { $deleg(n.as_raw() $(, $op.as_raw())* $(, $param.into())*) }) != 0
        }
    };
}

#[inline]
pub fn check_div0(divisor: &Integer) {
    assert_ne!(divisor.cmp0(), Ordering::Equal, "division by zero");
}

#[inline]
fn check_div0_or<O: OptInteger>(divisor: O, or: &mut Integer) {
    assert_ne!(sgn_or(divisor, or), Ordering::Equal, "division by zero");
}

#[inline]
pub fn set<O: OptInteger>(rop: &mut Integer, op: O) {
    if O::IS_SOME {
        unsafe {
            gmp::mpz_set(rop.as_raw_mut(), op.mpz());
        }
    }
}

#[inline]
pub const fn owned_init() -> mpz_t {
    const UNO_DIEGO_10: &limb_t = &0x1D1E_6010;
    // use NonNull::new_unchecked because NonNull::from is not usable in const
    mpz_t {
        alloc: 0,
        size: 0,
        d: unsafe { NonNull::new_unchecked(UNO_DIEGO_10 as *const limb_t as *mut limb_t) },
    }
}

#[inline]
pub unsafe fn init2(rop: *mut Integer, bits: usize) {
    let rop = cast_ptr_mut!(rop, mpz_t);
    gmp::mpz_init2(rop, bits.unwrapped_cast());
}

#[inline]
pub unsafe fn init_set(rop: *mut Integer, op: &Integer) {
    let rop = cast_ptr_mut!(rop, mpz_t);
    gmp::mpz_init_set(rop, op.as_raw());
}

#[inline]
pub unsafe fn clear(rop: &mut Integer) {
    gmp::mpz_clear(rop.as_raw_mut());
}

#[inline]
pub fn si_pow_ui(rop: &mut Integer, base: i32, exp: u32) {
    let (base_neg, base_abs) = base.neg_abs();
    ui_pow_ui(rop, base_abs, exp);
    if base_neg && (exp & 1) == 1 {
        neg(rop, ());
    }
}

#[inline]
pub fn signum<O: OptInteger>(rop: &mut Integer, op: O) {
    match sgn_or(op, rop) {
        Ordering::Less => set_m1(rop),
        Ordering::Equal => set_0(rop),
        Ordering::Greater => set_1(rop),
    }
}

#[inline]
pub fn keep_signed_bits<O: OptInteger>(rop: &mut Integer, op: O, b: u32) {
    let rop = rop.as_raw_mut();
    let op = op.mpz_or(rop);
    let b = b.into();
    unsafe {
        if b > 0 && gmp::mpz_tstbit(op, b - 1) != 0 {
            gmp::mpz_cdiv_r_2exp(rop, op, b);
        } else {
            gmp::mpz_fdiv_r_2exp(rop, op, b);
        }
    }
}

pub fn next_pow_of_two<O: OptInteger>(rop: &mut Integer, op: O) {
    let op = op.unwrap_or(rop);
    let size = op.inner().size;
    if size <= 0 {
        set_1(rop);
        return;
    }
    let significant = significant_bits(op).unwrapped_cast();
    let first_one = unsafe { gmp::mpn_scan1(op.inner().d.as_ptr(), 0) };
    let bit = if first_one == significant - 1 {
        if !O::IS_SOME {
            return;
        }
        first_one
    } else {
        significant
    };
    set_0(rop);
    setbit(rop, bit);
}

#[inline]
pub fn divexact_ui<O: OptInteger>(q: &mut Integer, dividend: O, divisor: c_ulong) {
    assert_ne!(divisor, 0, "division by zero");
    let q = q.as_raw_mut();
    let dividend = dividend.mpz_or(q);
    unsafe {
        gmp::mpz_divexact_ui(q, dividend, divisor);
    }
}

#[inline]
pub fn divexact_u32<O: OptInteger>(q: &mut Integer, dividend: O, divisor: u32) {
    divexact_ui(q, dividend, divisor.into())
}

#[inline]
pub fn gcd_ui<O: OptInteger>(rop: Option<&mut Integer>, op1: O, op2: c_ulong) -> c_ulong {
    let (rop, op1) = match rop {
        Some(rop) => {
            let rop = rop.as_raw_mut();
            (rop, op1.mpz_or(rop))
        }
        None if O::IS_SOME => (ptr::null_mut(), op1.mpz()),
        None => panic!("no operand"),
    };
    unsafe { gmp::mpz_gcd_ui(rop, op1, op2) }
}

#[inline]
pub fn gcd_u32<O: OptInteger>(rop: &mut Integer, op1: O, op2: u32) {
    gcd_ui(Some(rop), op1, op2.into());
}

#[inline]
pub fn lcm_u32<O: OptInteger>(rop: &mut Integer, op1: O, op2: u32) {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpz_or(rop);
    unsafe {
        gmp::mpz_lcm_ui(rop, op1, op2.into());
    }
}

#[inline]
pub fn root<O: OptInteger>(rop: &mut Integer, op: O, n: u32) {
    assert_ne!(n, 0, "zeroth root");
    let even_root_of_neg = n & 1 == 0 && sgn_or(op, rop) == Ordering::Less;
    assert!(!even_root_of_neg, "even root of negative");
    let rop = rop.as_raw_mut();
    let op = op.mpz_or(rop);
    unsafe {
        gmp::mpz_root(rop, op, n.into());
    }
}

#[inline]
pub fn square<O: OptInteger>(rop: &mut Integer, op: O) {
    let rop = rop.as_raw_mut();
    let op = op.mpz_or(rop);
    unsafe {
        gmp::mpz_mul(rop, op, op);
    }
}

#[inline]
pub fn sqrt<O: OptInteger>(rop: &mut Integer, op: O) {
    let square_root_of_neg = sgn_or(op, rop) == Ordering::Less;
    assert!(!square_root_of_neg, "square root of negative");
    let rop = rop.as_raw_mut();
    let op = op.mpz_or(rop);
    unsafe {
        gmp::mpz_sqrt(rop, op);
    }
}

#[inline]
pub fn rootrem<O: OptInteger>(root: &mut Integer, rem: &mut Integer, op: O, n: u32) {
    assert_ne!(n, 0, "zeroth root");
    let even_root_of_neg = n & 1 == 0 && sgn_or(op, root) == Ordering::Less;
    assert!(!even_root_of_neg, "even root of negative");
    let root = root.as_raw_mut();
    let op = op.mpz_or(root);
    unsafe {
        gmp::mpz_rootrem(root, rem.as_raw_mut(), op, n.into());
    }
}

#[inline]
pub fn sqrtrem<O: OptInteger>(root: &mut Integer, rem: &mut Integer, op: O) {
    let square_root_of_neg = sgn_or(op, root) == Ordering::Less;
    assert!(!square_root_of_neg, "square root of negative");
    let root = root.as_raw_mut();
    let op = op.mpz_or(root);
    unsafe {
        gmp::mpz_sqrtrem(root, rem.as_raw_mut(), op);
    }
}

#[inline]
pub fn divexact<O: OptInteger, P: OptInteger>(q: &mut Integer, dividend: O, divisor: P) {
    check_div0_or(divisor, q);
    let q = q.as_raw_mut();
    let dividend = dividend.mpz_or(q);
    let divisor = divisor.mpz_or(q);
    unsafe {
        gmp::mpz_divexact(q, dividend, divisor);
    }
}

#[inline]
pub fn gcd<O: OptInteger>(rop: &mut Integer, op1: O, op2: &Integer) {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpz_or(rop);
    unsafe {
        gmp::mpz_gcd(rop, op1, op2.as_raw());
    }
}

#[inline]
pub fn lcm<O: OptInteger>(rop: &mut Integer, op1: O, op2: &Integer) {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpz_or(rop);
    unsafe {
        gmp::mpz_lcm(rop, op1, op2.as_raw());
    }
}

pub fn tdiv_qr<O: OptInteger, P: OptInteger>(q: &mut Integer, r: &mut Integer, n: O, d: P) {
    check_div0_or(d, r);
    let q = q.as_raw_mut();
    let r = r.as_raw_mut();
    let n = n.mpz_or(q);
    let d = d.mpz_or(r);
    unsafe {
        gmp::mpz_tdiv_qr(q, r, n, d);
    }
}

pub fn cdiv_qr<O: OptInteger, P: OptInteger>(q: &mut Integer, r: &mut Integer, n: O, d: P) {
    check_div0_or(d, r);
    let q = q.as_raw_mut();
    let r = r.as_raw_mut();
    let n = n.mpz_or(q);
    let d = d.mpz_or(r);
    unsafe {
        gmp::mpz_cdiv_qr(q, r, n, d);
    }
}

#[inline]
pub fn fdiv_qr<O: OptInteger, P: OptInteger>(q: &mut Integer, r: &mut Integer, n: O, d: P) {
    check_div0_or(d, r);
    let q = q.as_raw_mut();
    let r = r.as_raw_mut();
    let n = n.mpz_or(q);
    let d = d.mpz_or(r);
    unsafe {
        gmp::mpz_fdiv_qr(q, r, n, d);
    }
}

pub fn rdiv_qr<O: OptInteger, P: OptInteger>(q: &mut Integer, r: &mut Integer, n: O, d: P) {
    // make sure d is not going to be aliased and overwritten
    let r_clone;
    let d = if P::IS_SOME {
        d.unwrap()
    } else {
        r_clone = r.clone();
        &r_clone
    };
    check_div0(d);
    tdiv_qr(q, r, n, d);
    if round_away(r, d) {
        if (r.cmp0() == Ordering::Less) == (d.cmp0() == Ordering::Less) {
            // positive q
            add_ui(q, (), 1);
            sub(r, (), d);
        } else {
            // negative q
            sub_ui(q, (), 1);
            add(r, (), d);
        }
    }
}

#[inline]
pub fn ediv_qr<O: OptInteger, P: OptInteger>(q: &mut Integer, r: &mut Integer, n: O, d: P) {
    if d.unwrap_or(r).cmp0() == Ordering::Less {
        cdiv_qr(q, r, n, d)
    } else {
        fdiv_qr(q, r, n, d)
    }
}

#[inline]
pub fn gcdext<O: OptInteger, P: OptInteger>(
    g: &mut Integer,
    s: &mut Integer,
    t: Option<&mut Integer>,
    op1: O,
    op2: P,
) {
    let g = g.as_raw_mut();
    let s = s.as_raw_mut();
    let op1 = op1.mpz_or(g);
    let op2 = op2.mpz_or(s);
    unsafe {
        gmp::mpz_gcdext(
            g,
            s,
            t.map(Integer::as_raw_mut).unwrap_or_else(ptr::null_mut),
            op1,
            op2,
        );
    }
}

#[inline]
pub fn tdiv_q<O: OptInteger, P: OptInteger>(q: &mut Integer, n: O, d: P) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let n = n.mpz_or(q);
    let d = d.mpz_or(q);
    unsafe {
        gmp::mpz_tdiv_q(q, n, d);
    }
}

#[inline]
pub fn tdiv_r<O: OptInteger, P: OptInteger>(r: &mut Integer, n: O, d: P) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let n = n.mpz_or(r);
    let d = d.mpz_or(r);
    unsafe {
        gmp::mpz_tdiv_r(r, n, d);
    }
}

#[inline]
pub fn cdiv_q<O: OptInteger, P: OptInteger>(q: &mut Integer, n: O, d: P) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let n = n.mpz_or(q);
    let d = d.mpz_or(q);
    unsafe {
        gmp::mpz_cdiv_q(q, n, d);
    }
}

#[inline]
pub fn cdiv_r<O: OptInteger, P: OptInteger>(r: &mut Integer, n: O, d: P) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let n = n.mpz_or(r);
    let d = d.mpz_or(r);
    unsafe {
        gmp::mpz_cdiv_r(r, n, d);
    }
}

#[inline]
pub fn fdiv_q<O: OptInteger, P: OptInteger>(q: &mut Integer, n: O, d: P) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let n = n.mpz_or(q);
    let d = d.mpz_or(q);
    unsafe {
        gmp::mpz_fdiv_q(q, n, d);
    }
}

#[inline]
pub fn fdiv_r<O: OptInteger, P: OptInteger>(r: &mut Integer, n: O, d: P) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let n = n.mpz_or(r);
    let d = d.mpz_or(r);
    unsafe {
        gmp::mpz_fdiv_r(r, n, d);
    }
}

#[inline]
pub fn ediv_q<O: OptInteger, P: OptInteger>(q: &mut Integer, n: O, d: P) {
    if d.unwrap_or(q).cmp0() == Ordering::Less {
        cdiv_q(q, n, d)
    } else {
        fdiv_q(q, n, d)
    }
}

#[inline]
pub fn ediv_r<O: OptInteger, P: OptInteger>(r: &mut Integer, n: O, d: P) {
    if d.unwrap_or(r).cmp0() == Ordering::Less {
        cdiv_r(r, n, d)
    } else {
        fdiv_r(r, n, d)
    }
}

#[inline]
pub fn remove<O: OptInteger>(rop: &mut Integer, op: O, f: &Integer) -> u32 {
    let rop = rop.as_raw_mut();
    let op = op.mpz_or(rop);
    let count = unsafe { gmp::mpz_remove(rop, op, f.as_raw()) };
    count.unwrapped_cast()
}

#[inline]
pub fn powm_sec<O: OptInteger>(rop: &mut Integer, base: O, exp: &Integer, modu: &Integer) {
    assert_eq!(
        exp.cmp0(),
        Ordering::Greater,
        "exponent not greater than zero"
    );
    assert!(modu.is_odd(), "modulo not odd");
    let rop = rop.as_raw_mut();
    let base = base.mpz_or(rop);
    unsafe {
        gmp::mpz_powm_sec(rop, base, exp.as_raw(), modu.as_raw());
    }
}

#[inline]
#[cfg(feature = "rand")]
pub fn urandomb(rop: &mut Integer, rng: &mut dyn MutRandState, n: bitcnt_t) {
    unsafe {
        gmp::mpz_urandomb(rop.as_raw_mut(), rng.private().0, n);
    }
}

#[cfg(feature = "rand")]
#[inline]
pub fn urandomm<O: OptInteger>(rop: &mut Integer, rng: &mut dyn MutRandState, n: O) {
    assert_eq!(
        n.unwrap_or(rop).cmp0(),
        Ordering::Greater,
        "cannot be below zero"
    );
    let rop = rop.as_raw_mut();
    let n = n.mpz_or(rop);
    unsafe {
        gmp::mpz_urandomm(rop, rng.private().0, n);
    }
}

unsafe_wrap0! { fn ui_pow_ui(base: u32, exponent: u32) -> gmp::mpz_ui_pow_ui }
unsafe_wrap0! { fn fac_ui(n: u32) -> gmp::mpz_fac_ui }
unsafe_wrap0! { fn twofac_ui(n: u32) -> gmp::mpz_2fac_ui }
unsafe_wrap0! { fn mfac_uiui(n: u32, m: u32) -> gmp::mpz_mfac_uiui }
unsafe_wrap0! { fn primorial_ui(n: u32) -> gmp::mpz_primorial_ui }
unsafe_wrap0! { fn bin_uiui(n: u32, k: u32) -> gmp::mpz_bin_uiui }
unsafe_wrap0! { fn fib_ui(n: u32) -> gmp::mpz_fib_ui }
unsafe_wrap0! { fn lucnum_ui(n: u32) -> gmp::mpz_lucnum_ui }
unsafe_wrap! { fn neg(op: O) -> gmp::mpz_neg }
unsafe_wrap! { fn com(op: O) -> gmp::mpz_com }
unsafe_wrap! { fn add(op1: O, op2: P) -> gmp::mpz_add }
unsafe_wrap! { fn sub(op1: O, op2: P) -> gmp::mpz_sub }
unsafe_wrap! { fn mul(op1: O, op2: P) -> gmp::mpz_mul }
unsafe_wrap! { fn and(op1: O, op2: P) -> gmp::mpz_and }
unsafe_wrap! { fn ior(op1: O, op2: P) -> gmp::mpz_ior }
unsafe_wrap! { fn xor(op1: O, op2: P) -> gmp::mpz_xor }
unsafe_wrap! { fn shl_u32(op1: O; op2: u32) -> gmp::mpz_mul_2exp }
unsafe_wrap! { fn shr_u32(op1: O; op2: u32) -> gmp::mpz_fdiv_q_2exp }
unsafe_wrap! { fn pow_u32(op1: O; op2: u32) -> gmp::mpz_pow_ui }
unsafe_wrap! { fn abs(op: O) -> gmp::mpz_abs }
unsafe_wrap! { fn fdiv_r_2exp(op: O; n: u32) -> gmp::mpz_fdiv_r_2exp }
unsafe_wrap! { fn nextprime(op: O) -> gmp::mpz_nextprime }
unsafe_wrap! { fn bin_ui(op: O; k: u32) -> gmp::mpz_bin_ui }
unsafe_wrap! { fn add_ui(op1: O; op2: c_ulong) -> gmp::mpz_add_ui }
unsafe_wrap! { fn sub_ui(op1: O; op2: c_ulong) -> gmp::mpz_sub_ui }
unsafe_wrap! { fn mul_ui(op1: O; op2: c_ulong) -> gmp::mpz_mul_ui }
unsafe_wrap! { fn mul_si(op1: O; op2: c_long) -> gmp::mpz_mul_si }
unsafe_wrap0! { fn setbit(bit_index: bitcnt_t) -> gmp::mpz_setbit }
unsafe_wrap0! { fn clrbit(bit_index: bitcnt_t) -> gmp::mpz_clrbit }
unsafe_wrap0! { fn combit(bit_index: bitcnt_t) -> gmp::mpz_combit }
unsafe_wrap_p! { fn even_p() -> gmp::mpz_even_p }
unsafe_wrap_p! { fn odd_p() -> gmp::mpz_odd_p }
unsafe_wrap_p! { fn divisible_p(d) -> gmp::mpz_divisible_p }
unsafe_wrap_p! { fn divisible_ui_p(; d: c_ulong) -> gmp::mpz_divisible_ui_p }
unsafe_wrap_p! { fn divisible_2exp_p(; b: bitcnt_t) -> gmp::mpz_divisible_2exp_p }
unsafe_wrap_p! { fn congruent_p(c, d) -> gmp::mpz_congruent_p }
unsafe_wrap_p! { fn congruent_ui_p(; c: c_ulong; d: c_ulong) -> gmp::mpz_congruent_ui_p }
unsafe_wrap_p! { fn congruent_2exp_p(c; b: bitcnt_t) -> gmp::mpz_congruent_2exp_p }
unsafe_wrap_p! { fn perfect_power_p() -> gmp::mpz_perfect_power_p }
unsafe_wrap_p! { fn perfect_square_p() -> gmp::mpz_perfect_square_p }
unsafe_wrap_p! { fn tstbit(; bit_index: bitcnt_t) -> gmp::mpz_tstbit }

#[cold]
#[inline]
pub fn cold_realloc(rop: &mut Integer, limbs: size_t) {
    unsafe {
        cold_realloc_raw(rop.as_raw_mut(), limbs);
    }
}

#[inline]
pub fn sgn(op: &Integer) -> Ordering {
    (unsafe { gmp::mpz_sgn(op.as_raw()) }).cmp(&0)
}

#[inline]
pub fn sgn_or<O: OptInteger>(op: O, or: &mut Integer) -> Ordering {
    (unsafe { gmp::mpz_sgn(op.mpz_or(or.as_raw_mut())) }).cmp(&0)
}

#[inline]
pub fn is_1(op: &Integer) -> bool {
    op.inner().size == 1 && unsafe { limb(op, 0) == 1 }
}

#[inline]
pub fn set_0(rop: &mut Integer) {
    unsafe {
        set_0_raw(rop.as_raw_mut());
    }
}

#[inline]
pub fn set_1(rop: &mut Integer) {
    unsafe {
        set_1_raw(rop.as_raw_mut());
    }
}

#[inline]
pub fn set_m1(rop: &mut Integer) {
    unsafe {
        set_m1_raw(rop.as_raw_mut());
    }
}

#[inline]
pub fn set_nonzero(rop: &mut Integer, limb: limb_t) {
    if rop.inner().alloc < 1 {
        cold_realloc(rop, 1);
    }
    unsafe {
        *limb_mut(rop, 0) = limb;
        rop.inner_mut().size = 1;
    }
}

#[inline]
pub fn set_limb(rop: &mut Integer, limb: limb_t) {
    if limb == 0 {
        set_0(rop);
    } else {
        set_nonzero(rop, limb);
    }
}

#[cold]
#[inline]
unsafe fn cold_realloc_raw(rop: *mut mpz_t, limbs: size_t) {
    gmp::_mpz_realloc(rop, limbs);
}

#[inline]
unsafe fn set_0_raw(rop: *mut mpz_t) {
    (*rop).size = 0;
}

#[inline]
unsafe fn set_1_raw(rop: *mut mpz_t) {
    if (*rop).alloc < 1 {
        cold_realloc_raw(rop, 1);
    }
    *(*rop).d.as_ptr() = 1;
    (*rop).size = 1;
}

#[inline]
unsafe fn set_m1_raw(rop: *mut mpz_t) {
    if (*rop).alloc < 1 {
        cold_realloc_raw(rop, 1);
    }
    *(*rop).d.as_ptr() = 1;
    (*rop).size = -1;
}

#[inline]
pub fn fdiv_u32(n: &Integer, d: u32) -> u32 {
    assert_ne!(d, 0, "division by zero");
    unsafe { gmp::mpz_fdiv_ui(n.as_raw(), d.into()) }.cast()
}

#[inline]
pub fn shl_i32<O: OptInteger>(rop: &mut Integer, op1: O, op2: i32) {
    let (op2_neg, op2_abs) = op2.neg_abs();
    if !op2_neg {
        shl_u32(rop, op1, op2_abs);
    } else {
        shr_u32(rop, op1, op2_abs);
    }
}

#[inline]
pub fn shr_i32<O: OptInteger>(rop: &mut Integer, op1: O, op2: i32) {
    let (op2_neg, op2_abs) = op2.neg_abs();
    if !op2_neg {
        shr_u32(rop, op1, op2_abs);
    } else {
        shl_u32(rop, op1, op2_abs);
    }
}

#[inline]
pub fn get_abs_u32(op: &Integer) -> u32 {
    unsafe {
        match op.inner().size {
            0 => 0,
            _ => limb(op, 0).wrapping_cast(),
        }
    }
}

#[inline]
pub fn get_abs_u16(op: &Integer) -> u16 {
    unsafe {
        match op.inner().size {
            0 => 0,
            _ => limb(op, 0).wrapping_cast(),
        }
    }
}

#[inline]
pub fn get_abs_u8(op: &Integer) -> u8 {
    unsafe {
        match op.inner().size {
            0 => 0,
            _ => limb(op, 0).wrapping_cast(),
        }
    }
}

#[inline]
pub fn set_i128(rop: &mut Integer, i: i128) {
    let (neg_i, abs_i) = i.neg_abs();
    set_u128(rop, abs_i);
    if neg_i {
        rop.neg_assign();
    }
}

#[inline]
pub fn set_i64(rop: &mut Integer, i: i64) {
    let (neg_i, abs_i) = i.neg_abs();
    set_u64(rop, abs_i);
    if neg_i {
        rop.neg_assign();
    }
}

#[inline]
pub fn set_i32(rop: &mut Integer, i: i32) {
    let (neg_i, abs_i) = i.neg_abs();
    set_u32(rop, abs_i);
    if neg_i {
        rop.neg_assign();
    }
}

#[inline]
pub unsafe fn init_set_i128(rop: *mut Integer, i: i128) {
    let (neg_i, abs_i) = i.neg_abs();
    init_set_u128(rop, abs_i);
    if neg_i {
        (*rop).neg_assign();
    }
}

#[inline]
pub unsafe fn init_set_i64(rop: *mut Integer, i: i64) {
    let (neg_i, abs_i) = i.neg_abs();
    init_set_u64(rop, abs_i);
    if neg_i {
        (*rop).neg_assign();
    }
}

#[inline]
pub unsafe fn init_set_i32(rop: *mut Integer, i: i32) {
    let (neg_i, abs_i) = i.neg_abs();
    init_set_u32(rop, abs_i);
    if neg_i {
        (*rop).neg_assign();
    }
}

#[inline]
pub fn fits_u8(op: &Integer) -> bool {
    match op.inner().size {
        0 => true,
        1 => (unsafe { limb(op, 0) }) <= limb_t::from(u8::MAX),
        _ => false,
    }
}

#[inline]
pub fn fits_i8(op: &Integer) -> bool {
    match op.inner().size {
        0 => true,
        1 => (unsafe { limb(op, 0) }) <= limb_t::from(i8::MAX.wrapping_as::<u8>()),
        -1 => (unsafe { limb(op, 0) }) <= limb_t::from(i8::MIN.wrapping_as::<u8>()),
        _ => false,
    }
}

#[inline]
pub fn fits_u16(op: &Integer) -> bool {
    match op.inner().size {
        0 => true,
        1 => (unsafe { limb(op, 0) }) <= limb_t::from(u16::MAX),
        _ => false,
    }
}

#[inline]
pub fn fits_i16(op: &Integer) -> bool {
    match op.inner().size {
        0 => true,
        1 => (unsafe { limb(op, 0) }) <= limb_t::from(i16::MAX.wrapping_as::<u16>()),
        -1 => (unsafe { limb(op, 0) }) <= limb_t::from(i16::MIN.wrapping_as::<u16>()),
        _ => false,
    }
}

#[inline]
pub fn addmul(rop: &mut Integer, op1: &Integer, op2: &Integer) {
    unsafe {
        gmp::mpz_addmul(rop.as_raw_mut(), op1.as_raw(), op2.as_raw());
    }
}

#[inline]
pub fn addmul_ui(rop: &mut Integer, op1: &Integer, op2: c_ulong) {
    unsafe {
        gmp::mpz_addmul_ui(rop.as_raw_mut(), op1.as_raw(), op2);
    }
}

#[inline]
pub fn addmul_si(rop: &mut Integer, op1: &Integer, op2: c_long) {
    let (op2_neg, op2_abs) = op2.neg_abs();
    if !op2_neg {
        addmul_ui(rop, op1, op2_abs);
    } else {
        submul_ui(rop, op1, op2_abs);
    }
}

#[inline]
pub fn submul(rop: &mut Integer, op1: &Integer, op2: &Integer) {
    unsafe {
        gmp::mpz_submul(rop.as_raw_mut(), op1.as_raw(), op2.as_raw());
    }
}

// rop = op1 * op2 - rop
#[inline]
pub fn mulsub(rop: &mut Integer, op1: &Integer, op2: &Integer) {
    submul(rop, op1, op2);
    rop.neg_assign();
}

#[inline]
pub fn submul_ui(rop: &mut Integer, op1: &Integer, op2: c_ulong) {
    unsafe {
        gmp::mpz_submul_ui(rop.as_raw_mut(), op1.as_raw(), op2);
    }
}

#[inline]
pub fn mulsub_ui(rop: &mut Integer, op1: &Integer, op2: c_ulong) {
    submul_ui(rop, op1, op2);
    rop.neg_assign();
}

#[inline]
pub fn submul_si(rop: &mut Integer, op1: &Integer, op2: c_long) {
    let (op2_neg, op2_abs) = op2.neg_abs();
    if !op2_neg {
        submul_ui(rop, op1, op2_abs);
    } else {
        addmul_ui(rop, op1, op2_abs);
    }
}

#[inline]
pub fn mulsub_si(rop: &mut Integer, op1: &Integer, op2: c_long) {
    submul_si(rop, op1, op2);
    rop.neg_assign();
}

#[inline]
fn bitcount_to_u32(bits: bitcnt_t) -> Option<u32> {
    if bits == !0 {
        None
    } else {
        Some(bits.unwrapped_cast())
    }
}

#[inline]
pub fn popcount(op: &Integer) -> Option<u32> {
    bitcount_to_u32(unsafe { gmp::mpz_popcount(op.as_raw()) })
}

#[inline]
pub fn zerocount(op: &Integer) -> Option<u32> {
    if op.cmp0() == Ordering::Less {
        let size = size_t::from(op.inner().size);
        let abs_size = size.wrapping_neg();
        let d = op.inner().d.as_ptr();
        let count = unsafe {
            let abs_popcount = gmp::mpn_popcount(d, abs_size);
            let first_one = gmp::mpn_scan1(d, 0);
            abs_popcount + first_one - 1
        };
        bitcount_to_u32(count)
    } else {
        None
    }
}

#[inline]
pub fn scan0(op: &Integer, start: u32) -> Option<u32> {
    bitcount_to_u32(unsafe { gmp::mpz_scan0(op.as_raw(), start.into()) })
}

#[inline]
pub fn scan1(op: &Integer, start: u32) -> Option<u32> {
    bitcount_to_u32(unsafe { gmp::mpz_scan1(op.as_raw(), start.into()) })
}

#[inline]
pub fn hamdist(op1: &Integer, op2: &Integer) -> Option<u32> {
    bitcount_to_u32(unsafe { gmp::mpz_hamdist(op1.as_raw(), op2.as_raw()) })
}

#[inline]
pub fn significant_bits(op: &Integer) -> usize {
    let size = op.inner().size;
    if size == 0 {
        return 0;
    }
    let size = size.neg_abs().1;
    unsafe { gmp::mpn_sizeinbase(op.inner().d.as_ptr(), size.unwrapped_cast(), 2) }
}

pub fn signed_bits(op: &Integer) -> u32 {
    let significant = significant_bits(op);
    if op.cmp0() == Ordering::Less {
        let first_one =
            (unsafe { gmp::mpn_scan1(op.inner().d.as_ptr(), 0) }).unwrapped_as::<usize>();
        if first_one == significant - 1 {
            return significant.unwrapped_cast();
        }
    }
    significant
        .checked_add(1)
        .expect("overflow")
        .unwrapped_cast()
}

pub fn power_of_two_p(op: &Integer) -> bool {
    if op.cmp0() != Ordering::Greater {
        return false;
    }
    let significant = significant_bits(op);
    let first_one = (unsafe { gmp::mpn_scan1(op.inner().d.as_ptr(), 0) }).unwrapped_as::<usize>();
    first_one == significant - 1
}

#[inline]
pub unsafe fn limb(z: &Integer, index: isize) -> limb_t {
    *z.inner().d.as_ptr().offset(index)
}

#[inline]
pub unsafe fn limb_mut(z: &mut Integer, index: isize) -> &mut limb_t {
    &mut *z.inner_mut().d.as_ptr().offset(index)
}

pub fn realloc_for_mpn_set_str(rop: &mut Integer, len: usize, radix: i32) {
    // add 1 for possible rounding errors
    let bits = (f64::from(radix).log2() * len.az::<f64>()).ceil() + 1.0;
    // add 1 because mpn_set_str requires an extra limb
    let limbs = (bits / f64::from(gmp::LIMB_BITS)).ceil() + 1.0;
    unsafe {
        gmp::_mpz_realloc(rop.as_raw_mut(), limbs.unwrapped_cast());
    }
}

pub fn round_away(rem: &Integer, divisor: &Integer) -> bool {
    let s_rem = rem.inner().size.checked_abs().expect("overflow");
    if s_rem == 0 {
        return false;
    }
    let s_divisor = divisor.inner().size.checked_abs().expect("overflow");
    assert!(s_divisor > 0);
    debug_assert!(s_rem <= s_divisor);
    if s_rem < s_divisor - 1 {
        return false;
    }

    let mut rem_limb = if s_rem == s_divisor {
        let rem_next_limb = unsafe { limb(rem, (s_rem - 1).unwrapped_cast()) };
        if (rem_next_limb >> (gmp::LIMB_BITS - 1)) != 0 {
            return true;
        }
        rem_next_limb << 1
    } else {
        0
    };
    for i in (1..s_divisor).rev() {
        let div_limb = unsafe { limb(divisor, i.unwrapped_cast()) };
        let rem_next_limb = unsafe { limb(rem, (i - 1).unwrapped_cast()) };
        rem_limb |= (rem_next_limb >> (gmp::LIMB_BITS - 1)) & 1;
        if rem_limb > div_limb {
            return true;
        }
        if rem_limb < div_limb {
            return false;
        }
        rem_limb = rem_next_limb << 1;
    }
    let div_limb = unsafe { limb(divisor, 0) };
    rem_limb >= div_limb
}

#[inline]
pub fn start_invert(op: &Integer, modulo: &Integer) -> Option<Integer> {
    if modulo.cmp0() == Ordering::Equal {
        return None;
    }
    let (gcd, sinverse) = <(Integer, Integer)>::from(op.gcd_cofactors_ref(modulo));
    if is_1(&gcd) {
        Some(sinverse)
    } else {
        None
    }
}

#[inline]
pub fn finish_invert<O: OptInteger>(rop: &mut Integer, s: O, modulo: &Integer) {
    if s.unwrap_or(rop).cmp0() == Ordering::Less {
        if modulo.cmp0() == Ordering::Less {
            sub(rop, s, modulo)
        } else {
            add(rop, s, modulo)
        }
    } else {
        set(rop, s)
    }
}

#[inline]
pub fn pow_mod<O: OptInteger>(rop: &mut Integer, base: O, exponent: &Integer, modulo: &Integer) {
    if exponent.cmp0() == Ordering::Less {
        finish_invert(rop, base, modulo);
        let rop = rop.as_raw_mut();
        unsafe {
            gmp::mpz_powm(
                rop,
                rop as *const mpz_t,
                exponent.as_neg().as_raw(),
                modulo.as_raw(),
            );
        }
    } else {
        let rop = rop.as_raw_mut();
        let base = base.mpz_or(rop);
        unsafe {
            gmp::mpz_powm(rop, base, exponent.as_raw(), modulo.as_raw());
        }
    }
}

#[inline]
pub fn set_f64(rop: &mut Integer, op: f64) -> Result<(), ()> {
    if op.is_finite() {
        unsafe {
            gmp::mpz_set_d(rop.as_raw_mut(), op);
        }
        Ok(())
    } else {
        Err(())
    }
}

#[inline]
pub fn get_f64(op: &Integer) -> f64 {
    unsafe { gmp::mpz_get_d(op.as_raw()) }
}

#[inline]
pub fn get_f64_2exp(op: &Integer) -> (f64, c_long) {
    unsafe {
        let mut exp = MaybeUninit::uninit();
        let f = gmp::mpz_get_d_2exp(exp.as_mut_ptr(), op.as_raw());
        (f, exp.assume_init())
    }
}

#[inline]
pub fn probab_prime_p(n: &Integer, reps: c_int) -> c_int {
    unsafe { gmp::mpz_probab_prime_p(n.as_raw(), reps) }
}

#[inline]
pub fn jacobi(a: &Integer, b: &Integer) -> c_int {
    unsafe { gmp::mpz_jacobi(a.as_raw(), b.as_raw()) }
}

#[inline]
pub fn legendre(a: &Integer, p: &Integer) -> c_int {
    unsafe { gmp::mpz_legendre(a.as_raw(), p.as_raw()) }
}

#[inline]
pub fn kronecker(a: &Integer, b: &Integer) -> c_int {
    unsafe { gmp::mpz_kronecker(a.as_raw(), b.as_raw()) }
}

#[inline]
pub fn fib2_ui(f_n: &mut Integer, fnsub1: &mut Integer, n: c_ulong) {
    unsafe {
        gmp::mpz_fib2_ui(f_n.as_raw_mut(), fnsub1.as_raw_mut(), n);
    }
}

#[inline]
pub fn lucnum2_ui(ln: &mut Integer, lnsub1: &mut Integer, n: c_ulong) {
    unsafe {
        gmp::mpz_lucnum2_ui(ln.as_raw_mut(), lnsub1.as_raw_mut(), n);
    }
}

#[inline]
pub fn cmp(op1: &Integer, op2: &Integer) -> Ordering {
    (unsafe { gmp::mpz_cmp(op1.as_raw(), op2.as_raw()) }).cmp(&0)
}

#[inline]
pub fn cmpabs(op1: &Integer, op2: &Integer) -> Ordering {
    (unsafe { gmp::mpz_cmpabs(op1.as_raw(), op2.as_raw()) }).cmp(&0)
}

#[inline]
pub fn cmp_f64(op1: &Integer, op2: f64) -> Option<Ordering> {
    if op2.is_nan() {
        None
    } else {
        let ord = unsafe { gmp::mpz_cmp_d(op1.as_raw(), op2) };
        Some(ord.cmp(&0))
    }
}

unsafe fn ui_tdiv_q_raw(q: *mut mpz_t, n: c_ulong, d: *const mpz_t) {
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_n = gmp::mpz_cmpabs_ui(d, n) > 0;
    if abs_d_greater_n {
        // n / +abs_d -> 0, n
        // n / -abs_d -> 0, n
        set_0_raw(q);
    } else {
        // n / +abs_d -> +abs_q, +abs_r
        // n / -abs_d -> -abs_q, +abs_r
        let abs_d = gmp::mpz_get_ui(d);
        let abs_q = n / abs_d;
        gmp::mpz_set_ui(q, abs_q);
        if neg_d {
            gmp::mpz_neg(q, q);
        }
    }
}

unsafe fn ui_tdiv_r_raw(r: *mut mpz_t, n: c_ulong, d: *const mpz_t) {
    let abs_d_greater_n = gmp::mpz_cmpabs_ui(d, n) > 0;
    if abs_d_greater_n {
        // n / +abs_d -> 0, n
        // n / -abs_d -> 0, n
        gmp::mpz_set_ui(r, n);
    } else {
        // n / +abs_d -> +abs_q, +abs_r
        // n / -abs_d -> -abs_q, +abs_r
        let abs_d = gmp::mpz_get_ui(d);
        let abs_r = n % abs_d;
        gmp::mpz_set_ui(r, abs_r);
    }
}

unsafe fn ui_cdiv_q_raw(q: *mut mpz_t, n: c_ulong, d: *const mpz_t) {
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_n = gmp::mpz_cmpabs_ui(d, n) > 0;
    if abs_d_greater_n {
        // n / +abs_d -> 0, n + if n > 0 { 1, -abs_d }
        // n / -abs_d -> 0, n
        if n > 0 && !neg_d {
            set_1_raw(q);
        } else {
            set_0_raw(q);
        }
    } else {
        // n / +abs_d -> +abs_q, +abs_r + if abs_r > 0 { 1, -abs_d }
        // n / -abs_d -> -abs_q, +abs_r
        let abs_d = gmp::mpz_get_ui(d);
        let (mut abs_q, abs_r) = (n / abs_d, n % abs_d);
        if neg_d {
            gmp::mpz_set_ui(q, abs_q);
            gmp::mpz_neg(q, q);
        } else {
            if abs_r > 0 {
                abs_q += 1;
            }
            gmp::mpz_set_ui(q, abs_q);
        }
    }
}

unsafe fn ui_cdiv_r_raw(r: *mut mpz_t, n: c_ulong, d: *const mpz_t) {
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_n = gmp::mpz_cmpabs_ui(d, n) > 0;
    if abs_d_greater_n {
        // n / +abs_d -> 0, n + if n > 0 { 1, -abs_d }
        // n / -abs_d -> 0, n
        if n > 0 && !neg_d {
            gmp::mpz_ui_sub(r, n, d);
        } else {
            gmp::mpz_set_ui(r, n);
        }
    } else {
        // n / +abs_d -> +abs_q, +abs_r + if abs_r > 0 { 1, -abs_d }
        // n / -abs_d -> -abs_q, +abs_r
        let abs_d = gmp::mpz_get_ui(d);
        let abs_r = n % abs_d;
        if neg_d {
            gmp::mpz_set_ui(r, abs_r);
        } else if abs_r > 0 {
            gmp::mpz_set_ui(r, abs_d - abs_r);
            gmp::mpz_neg(r, r);
        } else {
            set_0_raw(r);
        }
    }
}

unsafe fn si_cdiv_q_raw(q: *mut mpz_t, n: c_long, d: *const mpz_t) {
    let (neg_n, abs_n) = n.neg_abs();
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_abs_n = gmp::mpz_cmpabs_ui(d, abs_n) > 0;
    if abs_d_greater_abs_n {
        // +abs_n / +abs_d -> 0, +abs_n + if abs_n > 0 { 1, -abs_d }
        // +abs_n / -abs_d -> 0, +abs_n
        // -abs_n / +abs_d -> 0, -abs_n
        // -abs_n / -abs_d -> 0, -abs_n + if abs_n > 0 { 1, +abs_d }
        if (n > 0 && !neg_d) || (neg_n && neg_d) {
            set_1_raw(q);
        } else {
            set_0_raw(q);
        }
    } else {
        // +abs_n / +abs_d -> +abs_q, +abs_r + if abs_r > 0 { 1, -abs_d }
        // +abs_n / -abs_d -> -abs_q, +abs_r
        // -abs_n / +abs_d -> -abs_q, -abs_r
        // -abs_n / -abs_d -> +abs_q, -abs_r + if abs_r > 0 { 1, +abs_d }
        let abs_d = gmp::mpz_get_ui(d);
        let (mut abs_q, abs_r) = (abs_n / abs_d, abs_n % abs_d);
        if (n > 0 && neg_d) || (neg_n && !neg_d) {
            gmp::mpz_set_ui(q, abs_q);
            gmp::mpz_neg(q, q);
        } else {
            if abs_r > 0 {
                abs_q += 1;
            }
            gmp::mpz_set_ui(q, abs_q);
        }
    }
}

unsafe fn si_cdiv_r_raw(r: *mut mpz_t, n: c_long, d: *const mpz_t) {
    let (neg_n, abs_n) = n.neg_abs();
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_abs_n = gmp::mpz_cmpabs_ui(d, abs_n) > 0;
    if abs_d_greater_abs_n {
        // +abs_n / +abs_d -> 0, +abs_n + if abs_n > 0 { 1, -abs_d }
        // +abs_n / -abs_d -> 0, +abs_n
        // -abs_n / +abs_d -> 0, -abs_n
        // -abs_n / -abs_d -> 0, -abs_n + if abs_n > 0 { 1, +abs_d }
        if n > 0 && !neg_d {
            gmp::mpz_ui_sub(r, abs_n, d);
        } else if neg_n && neg_d {
            gmp::mpz_add_ui(r, d, abs_n);
            gmp::mpz_neg(r, r);
        } else {
            gmp::mpz_set_si(r, n);
        }
    } else {
        // +abs_n / +abs_d -> +abs_q, +abs_r + if abs_r > 0 { 1, -abs_d }
        // +abs_n / -abs_d -> -abs_q, +abs_r
        // -abs_n / +abs_d -> -abs_q, -abs_r
        // -abs_n / -abs_d -> +abs_q, -abs_r + if abs_r > 0 { 1, +abs_d }
        let abs_d = gmp::mpz_get_ui(d);
        let abs_r = abs_n % abs_d;
        if n > 0 && neg_d {
            gmp::mpz_set_ui(r, abs_r);
        } else if neg_n && !neg_d {
            gmp::mpz_set_ui(r, abs_r);
            gmp::mpz_neg(r, r);
        } else if abs_r > 0 {
            gmp::mpz_set_ui(r, abs_d - abs_r);
            if !neg_d {
                gmp::mpz_neg(r, r);
            }
        } else {
            set_0_raw(r);
        }
    }
}

unsafe fn ui_fdiv_q_raw(q: *mut mpz_t, n: c_ulong, d: *const mpz_t) {
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_n = gmp::mpz_cmpabs_ui(d, n) > 0;
    if abs_d_greater_n {
        // n / +abs_d -> 0, n
        // n / -abs_d -> 0, n + if n > 0 { -1, -abs_d }
        if n > 0 && neg_d {
            set_m1_raw(q);
        } else {
            set_0_raw(q);
        }
    } else {
        // n / +abs_d -> +abs_q, +abs_r
        // n / -abs_d -> -abs_q, +abs_r + if abs_r > 0 { -1, -abs_d }
        let abs_d = gmp::mpz_get_ui(d);
        let (mut abs_q, abs_r) = (n / abs_d, n % abs_d);
        if !neg_d {
            gmp::mpz_set_ui(q, abs_q);
        } else {
            if abs_r > 0 {
                abs_q += 1;
            }
            gmp::mpz_set_ui(q, abs_q);
            gmp::mpz_neg(q, q);
        }
    }
}

unsafe fn ui_fdiv_r_raw(r: *mut mpz_t, n: c_ulong, d: *const mpz_t) {
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_n = gmp::mpz_cmpabs_ui(d, n) > 0;
    if abs_d_greater_n {
        // n / +abs_d -> 0, n
        // n / -abs_d -> 0, n + if n > 0 { -1, -abs_d }
        if n > 0 && neg_d {
            gmp::mpz_add_ui(r, d, n);
        } else {
            gmp::mpz_set_ui(r, n);
        }
    } else {
        // n / +abs_d -> +abs_q, +abs_r
        // n / -abs_d -> -abs_q, +abs_r + if abs_r > 0 { -1, -abs_d }
        let abs_d = gmp::mpz_get_ui(d);
        let abs_r = n % abs_d;
        if !neg_d {
            gmp::mpz_set_ui(r, abs_r);
        } else if abs_r > 0 {
            gmp::mpz_set_ui(r, abs_d - abs_r);
            gmp::mpz_neg(r, r);
        } else {
            set_0_raw(r);
        }
    }
}

unsafe fn si_fdiv_q_raw(q: *mut mpz_t, n: c_long, d: *const mpz_t) {
    let (neg_n, abs_n) = n.neg_abs();
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_abs_n = gmp::mpz_cmpabs_ui(d, abs_n) > 0;
    if abs_d_greater_abs_n {
        // +abs_n / +abs_d -> 0, +abs_n
        // +abs_n / -abs_d -> 0, +abs_n + if abs_n > 0 { -1, -abs_d }
        // -abs_n / +abs_d -> 0, -abs_n + if abs_n > 0 { -1, +abs_d }
        // -abs_n / -abs_d -> 0, -abs_n
        if (n > 0 && neg_d) || (neg_n && !neg_d) {
            set_m1_raw(q);
        } else {
            set_0_raw(q);
        }
    } else {
        // +abs_n / +abs_d -> +abs_q, +abs_r
        // +abs_n / -abs_d -> -abs_q, +abs_r + if abs_r > 0 { -1, -abs_d }
        // -abs_n / +abs_d -> -abs_q, -abs_r + if abs_r > 0 { -1, +abs_d }
        // -abs_n / -abs_d -> +abs_q, -abs_r
        let abs_d = gmp::mpz_get_ui(d);
        let (mut abs_q, abs_r) = (abs_n / abs_d, abs_n % abs_d);
        if (n > 0 && !neg_d) || (neg_n && neg_d) {
            gmp::mpz_set_ui(q, abs_q);
        } else {
            if abs_r > 0 {
                abs_q += 1;
            }
            gmp::mpz_set_ui(q, abs_q);
            gmp::mpz_neg(q, q);
        }
    }
}

unsafe fn si_fdiv_r_raw(r: *mut mpz_t, n: c_long, d: *const mpz_t) {
    let (neg_n, abs_n) = n.neg_abs();
    let neg_d = gmp::mpz_sgn(d) < 0;
    let abs_d_greater_abs_n = gmp::mpz_cmpabs_ui(d, abs_n) > 0;
    if abs_d_greater_abs_n {
        // +abs_n / +abs_d -> 0, +abs_n
        // +abs_n / -abs_d -> 0, +abs_n + if abs_n > 0 { -1, -abs_d }
        // -abs_n / +abs_d -> 0, -abs_n + if abs_n > 0 { -1, +abs_d }
        // -abs_n / -abs_d -> 0, -abs_n
        if n > 0 && neg_d {
            gmp::mpz_add_ui(r, d, abs_n);
        } else if neg_n && !neg_d {
            gmp::mpz_sub_ui(r, d, abs_n);
        } else {
            gmp::mpz_set_si(r, n);
        }
    } else {
        // +abs_n / +abs_d -> +abs_q, +abs_r
        // +abs_n / -abs_d -> -abs_q, +abs_r + if abs_r > 0 { -1, -abs_d }
        // -abs_n / +abs_d -> -abs_q, -abs_r + if abs_r > 0 { -1, +abs_d }
        // -abs_n / -abs_d -> +abs_q, -abs_r
        let abs_d = gmp::mpz_get_ui(d);
        let abs_r = abs_n % abs_d;
        if n > 0 && !neg_d {
            gmp::mpz_set_ui(r, abs_r);
        } else if neg_n && neg_d {
            gmp::mpz_set_ui(r, abs_r);
            gmp::mpz_neg(r, r);
        } else if abs_r > 0 {
            gmp::mpz_set_ui(r, abs_d - abs_r);
            if neg_d {
                gmp::mpz_neg(r, r);
            }
        } else {
            set_0_raw(r);
        }
    }
}

#[inline]
pub fn ui_sub<O: OptInteger>(rop: &mut Integer, op1: c_ulong, op2: O) {
    let rop = rop.as_raw_mut();
    let op2 = op2.mpz_or(rop);
    unsafe {
        gmp::mpz_ui_sub(rop, op1, op2);
    }
}

#[inline]
pub fn add_si<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_long) {
    match op2.neg_abs() {
        (false, op2_abs) => {
            add_ui(rop, op1, op2_abs);
        }
        (true, op2_abs) => {
            sub_ui(rop, op1, op2_abs);
        }
    }
}

#[inline]
pub fn sub_si<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_long) {
    match op2.neg_abs() {
        (false, op2_abs) => {
            sub_ui(rop, op1, op2_abs);
        }
        (true, op2_abs) => {
            add_ui(rop, op1, op2_abs);
        }
    }
}

#[inline]
pub fn si_sub<O: OptInteger>(rop: &mut Integer, op1: c_long, op2: O) {
    match op1.neg_abs() {
        (false, op1_abs) => {
            ui_sub(rop, op1_abs, op2);
        }
        (true, op1_abs) => {
            add_ui(rop, op2, op1_abs);
            neg(rop, ());
        }
    }
}

#[inline]
pub fn tdiv_q_ui<O: OptInteger>(q: &mut Integer, n: O, d: c_ulong) {
    assert_ne!(d, 0, "division by zero");
    let q = q.as_raw_mut();
    let n = n.mpz_or(q);
    unsafe {
        gmp::mpz_tdiv_q_ui(q, n, d);
    }
}

#[inline]
pub fn cdiv_q_ui<O: OptInteger>(q: &mut Integer, n: O, d: c_ulong) -> bool {
    assert_ne!(d, 0, "division by zero");
    let q = q.as_raw_mut();
    let n = n.mpz_or(q);
    (unsafe { gmp::mpz_cdiv_q_ui(q, n, d) }) != 0
}

#[inline]
pub fn fdiv_q_ui<O: OptInteger>(q: &mut Integer, n: O, d: c_ulong) -> bool {
    assert_ne!(d, 0, "division by zero");
    let q = q.as_raw_mut();
    let n = n.mpz_or(q);
    (unsafe { gmp::mpz_fdiv_q_ui(q, n, d) }) != 0
}

#[inline]
pub fn ediv_q_ui<O: OptInteger>(q: &mut Integer, n: O, d: c_ulong) {
    fdiv_q_ui(q, n, d);
}

#[inline]
pub fn ui_tdiv_q<O: OptInteger>(q: &mut Integer, n: c_ulong, d: O) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let d = d.mpz_or(q);
    unsafe {
        ui_tdiv_q_raw(q, n, d);
    }
}

#[inline]
pub fn ui_cdiv_q<O: OptInteger>(q: &mut Integer, n: c_ulong, d: O) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let d = d.mpz_or(q);
    unsafe {
        ui_cdiv_q_raw(q, n, d);
    }
}

#[inline]
pub fn ui_fdiv_q<O: OptInteger>(q: &mut Integer, n: c_ulong, d: O) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let d = d.mpz_or(q);
    unsafe {
        ui_fdiv_q_raw(q, n, d);
    }
}

#[inline]
pub fn ui_ediv_q<O: OptInteger>(q: &mut Integer, n: c_ulong, d: O) {
    if d.unwrap_or(q).cmp0() == Ordering::Less {
        ui_cdiv_q(q, n, d);
    } else {
        ui_fdiv_q(q, n, d);
    }
}

#[inline]
pub fn tdiv_r_ui<O: OptInteger>(r: &mut Integer, n: O, d: c_ulong) {
    assert_ne!(d, 0, "division by zero");
    let r = r.as_raw_mut();
    let n = n.mpz_or(r);
    unsafe {
        gmp::mpz_tdiv_r_ui(r, n, d);
    }
}

#[inline]
pub fn cdiv_r_ui<O: OptInteger>(r: &mut Integer, n: O, d: c_ulong) -> bool {
    assert_ne!(d, 0, "division by zero");
    let r = r.as_raw_mut();
    let n = n.mpz_or(r);
    (unsafe { gmp::mpz_cdiv_r_ui(r, n, d) }) != 0
}

#[inline]
pub fn fdiv_r_ui<O: OptInteger>(r: &mut Integer, n: O, d: c_ulong) -> bool {
    assert_ne!(d, 0, "division by zero");
    let r = r.as_raw_mut();
    let n = n.mpz_or(r);
    (unsafe { gmp::mpz_fdiv_r_ui(r, n, d) }) != 0
}

#[inline]
pub fn ediv_r_ui<O: OptInteger>(r: &mut Integer, n: O, d: c_ulong) {
    fdiv_r_ui(r, n, d);
}

#[inline]
pub fn ui_tdiv_r<O: OptInteger>(r: &mut Integer, n: c_ulong, d: O) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let d = d.mpz_or(r);
    unsafe {
        ui_tdiv_r_raw(r, n, d);
    }
}

#[inline]
pub fn ui_cdiv_r<O: OptInteger>(r: &mut Integer, n: c_ulong, d: O) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let d = d.mpz_or(r);
    unsafe {
        ui_cdiv_r_raw(r, n, d);
    }
}

#[inline]
pub fn ui_fdiv_r<O: OptInteger>(r: &mut Integer, n: c_ulong, d: O) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let d = d.mpz_or(r);
    unsafe {
        ui_fdiv_r_raw(r, n, d);
    }
}

#[inline]
pub fn ui_ediv_r<O: OptInteger>(r: &mut Integer, n: c_ulong, d: O) {
    if d.unwrap_or(r).cmp0() == Ordering::Less {
        ui_cdiv_r(r, n, d);
    } else {
        ui_fdiv_r(r, n, d);
    }
}

#[inline]
pub fn tdiv_q_si<O: OptInteger>(q: &mut Integer, n: O, d: c_long) {
    // +abs_n / +abs_d -> +abs_q, +abs_r
    // +abs_n / -abs_d -> -abs_q, +abs_r
    // -abs_n / +abs_d -> -abs_q, -abs_r
    // -abs_n / -abs_d -> +abs_q, -abs_r
    let (neg_d, abs_d) = d.neg_abs();
    tdiv_q_ui(q, n, abs_d);
    if neg_d {
        neg(q, ());
    }
}

#[inline]
pub fn cdiv_q_si<O: OptInteger>(q: &mut Integer, n: O, d: c_long) {
    // +abs_n / +abs_d -> +abs_q, +abs_r + if abs_r > 0 { 1, -abs_d }
    // +abs_n / -abs_d -> -abs_q, +abs_r
    // -abs_n / +abs_d -> -abs_q, -abs_r
    // -abs_n / -abs_d -> +abs_q, -abs_r + if abs_r > 0 { 1, +abs_d }
    let (neg_d, abs_d) = d.neg_abs();
    let some_r = cdiv_q_ui(q, n, abs_d);
    if neg_d {
        if some_r {
            ui_sub(q, 1, ());
        } else {
            neg(q, ());
        }
    }
}

#[inline]
pub fn fdiv_q_si<O: OptInteger>(q: &mut Integer, n: O, d: c_long) {
    // +abs_n / +abs_d -> +abs_q, +abs_r
    // +abs_n / -abs_d -> -abs_q, +abs_r + if abs_r > 0 { -1, -abs_d }
    // -abs_n / +abs_d -> -abs_q, -abs_r + if abs_r > 0 { -1, +abs_d }
    // -abs_n / -abs_d -> +abs_q, -abs_r
    let (neg_d, abs_d) = d.neg_abs();
    let some_r = fdiv_q_ui(q, n, abs_d);
    if neg_d {
        if some_r {
            si_sub(q, -1, ());
        } else {
            neg(q, ());
        }
    }
}

#[inline]
pub fn ediv_q_si<O: OptInteger>(q: &mut Integer, n: O, d: c_long) {
    if d < 0 {
        cdiv_q_si(q, n, d);
    } else {
        fdiv_q_si(q, n, d);
    }
}

#[inline]
pub fn si_tdiv_q<O: OptInteger>(q: &mut Integer, n: c_long, d: O) {
    // +abs_n / +abs_d -> +abs_q, +abs_r
    // +abs_n / -abs_d -> -abs_q, +abs_r
    // -abs_n / +abs_d -> -abs_q, -abs_r
    // -abs_n / -abs_d -> +abs_q, -abs_r
    let (neg_n, abs_n) = n.neg_abs();
    ui_tdiv_q(q, abs_n, d);
    if neg_n {
        neg(q, ());
    }
}

#[inline]
pub fn si_cdiv_q<O: OptInteger>(q: &mut Integer, n: c_long, d: O) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let d = d.mpz_or(q);
    unsafe {
        si_cdiv_q_raw(q, n, d);
    }
}

#[inline]
pub fn si_fdiv_q<O: OptInteger>(q: &mut Integer, n: c_long, d: O) {
    check_div0_or(d, q);
    let q = q.as_raw_mut();
    let d = d.mpz_or(q);
    unsafe {
        si_fdiv_q_raw(q, n, d);
    }
}

#[inline]
pub fn si_ediv_q<O: OptInteger>(q: &mut Integer, n: c_long, d: O) {
    if d.unwrap_or(q).cmp0() == Ordering::Less {
        si_cdiv_q(q, n, d);
    } else {
        si_fdiv_q(q, n, d);
    }
}

#[inline]
pub fn tdiv_r_si<O: OptInteger>(r: &mut Integer, n: O, d: c_long) {
    // +abs_n / +abs_d -> +abs_q, +abs_r
    // +abs_n / -abs_d -> -abs_q, +abs_r
    // -abs_n / +abs_d -> -abs_q, -abs_r
    // -abs_n / -abs_d -> +abs_q, -abs_r
    tdiv_r_ui(r, n, d.neg_abs().1);
}

#[inline]
pub fn cdiv_r_si<O: OptInteger>(r: &mut Integer, n: O, d: c_long) {
    // +abs_n / +abs_d -> +abs_q, +abs_r + if abs_r > 0 { 1, -abs_d }
    // +abs_n / -abs_d -> -abs_q, +abs_r
    // -abs_n / +abs_d -> -abs_q, -abs_r
    // -abs_n / -abs_d -> +abs_q, -abs_r + if abs_r > 0 { 1, +abs_d }
    let (neg_d, abs_d) = d.neg_abs();
    let some_r = cdiv_r_ui(r, n, abs_d);
    if neg_d && some_r {
        add_ui(r, (), abs_d);
    }
}

#[inline]
pub fn fdiv_r_si<O: OptInteger>(r: &mut Integer, n: O, d: c_long) {
    // +abs_n / +abs_d -> +abs_q, +abs_r
    // +abs_n / -abs_d -> -abs_q, +abs_r + if abs_r > 0 { -1, -abs_d }
    // -abs_n / +abs_d -> -abs_q, -abs_r + if abs_r > 0 { -1, +abs_d }
    // -abs_n / -abs_d -> +abs_q, -abs_r
    let (neg_d, abs_d) = d.neg_abs();
    let some_r = fdiv_r_ui(r, n, abs_d);
    if neg_d && some_r {
        sub_ui(r, (), abs_d);
    }
}

#[inline]
pub fn ediv_r_si<O: OptInteger>(r: &mut Integer, n: O, d: c_long) {
    if d < 0 {
        cdiv_r_si(r, n, d);
    } else {
        fdiv_r_si(r, n, d);
    }
}

#[inline]
pub fn si_tdiv_r<O: OptInteger>(r: &mut Integer, n: c_long, d: O) {
    // +abs_n / +abs_d -> +abs_q, +abs_r
    // +abs_n / -abs_d -> -abs_q, +abs_r
    // -abs_n / +abs_d -> -abs_q, -abs_r
    // -abs_n / -abs_d -> +abs_q, -abs_r
    let (neg_n, abs_n) = n.neg_abs();
    ui_tdiv_r(r, abs_n, d);
    if neg_n {
        neg(r, ());
    }
}

#[inline]
pub fn si_cdiv_r<O: OptInteger>(r: &mut Integer, n: c_long, d: O) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let d = d.mpz_or(r);
    unsafe {
        si_cdiv_r_raw(r, n, d);
    }
}

#[inline]
pub fn si_fdiv_r<O: OptInteger>(r: &mut Integer, n: c_long, d: O) {
    check_div0_or(d, r);
    let r = r.as_raw_mut();
    let d = d.mpz_or(r);
    unsafe {
        si_fdiv_r_raw(r, n, d);
    }
}

#[inline]
pub fn si_ediv_r<O: OptInteger>(r: &mut Integer, n: c_long, d: O) {
    if d.unwrap_or(r).cmp0() == Ordering::Less {
        si_cdiv_r(r, n, d);
    } else {
        si_fdiv_r(r, n, d);
    }
}

pub fn and_ui<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_ulong) {
    let lop2 = limb_t::from(op2);
    let ans_limb0 = {
        let op1 = op1.unwrap_or(rop);
        match op1.cmp0() {
            Ordering::Equal => 0,
            Ordering::Greater => (unsafe { limb(op1, 0) }) & lop2,
            Ordering::Less => (unsafe { limb(op1, 0) }).wrapping_neg() & lop2,
        }
    };
    set_limb(rop, ans_limb0);
}

pub fn ior_ui<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_ulong) {
    let lop2 = limb_t::from(op2);
    match op1.unwrap_or(rop).cmp0() {
        Ordering::Equal => unsafe {
            gmp::mpz_set_ui(rop.as_raw_mut(), op2);
        },
        Ordering::Greater => {
            set(rop, op1);
            unsafe {
                *limb_mut(rop, 0) |= lop2;
            }
        }
        Ordering::Less => {
            com(rop, op1);
            if rop.cmp0() != Ordering::Equal {
                unsafe {
                    *limb_mut(rop, 0) &= !lop2;
                    if rop.inner().size == 1 && limb(rop, 0) == 0 {
                        set_0(rop);
                    }
                }
            }
            com(rop, ());
        }
    }
}

pub fn xor_ui<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_ulong) {
    let lop2 = limb_t::from(op2);
    match op1.unwrap_or(rop).cmp0() {
        Ordering::Equal => unsafe {
            gmp::mpz_set_ui(rop.as_raw_mut(), op2);
        },
        Ordering::Greater => {
            set(rop, op1);
            unsafe {
                *limb_mut(rop, 0) ^= lop2;
                if rop.inner().size == 1 && limb(rop, 0) == 0 {
                    set_0(rop);
                }
            }
        }
        Ordering::Less => {
            com(rop, op1);
            if rop.cmp0() == Ordering::Equal {
                if lop2 != 0 {
                    set_nonzero(rop, lop2);
                }
            } else {
                unsafe {
                    *limb_mut(rop, 0) ^= lop2;
                    if rop.inner().size == 1 && limb(rop, 0) == 0 {
                        set_0(rop);
                    }
                }
            }
            com(rop, ());
        }
    }
}

pub fn and_si<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_long) {
    let lop2 = op2.wrapping_as::<limb_t>();
    match op1.unwrap_or(rop).cmp0() {
        Ordering::Equal => {
            set_0(rop);
        }
        Ordering::Greater => {
            if op2 >= 0 {
                let cur_limb = unsafe { limb(op1.unwrap_or(rop), 0) };
                set_limb(rop, cur_limb & lop2);
            } else {
                set(rop, op1);
                unsafe {
                    *limb_mut(rop, 0) &= lop2;
                    if rop.inner().size == 1 && limb(rop, 0) == 0 {
                        set_0(rop);
                    }
                }
            }
        }
        Ordering::Less => {
            if op2 >= 0 {
                let cur_limb = unsafe { limb(op1.unwrap_or(rop), 0) };
                set_limb(rop, cur_limb.wrapping_neg() & lop2);
            } else {
                com(rop, op1);
                if rop.cmp0() == Ordering::Equal {
                    if !lop2 != 0 {
                        set_nonzero(rop, !lop2);
                    }
                } else {
                    unsafe {
                        *limb_mut(rop, 0) |= !lop2;
                    }
                }
                com(rop, ());
            }
        }
    }
}

pub fn ior_si<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_long) {
    let lop2 = op2.wrapping_as::<limb_t>();
    match op1.unwrap_or(rop).cmp0() {
        Ordering::Equal => unsafe {
            gmp::mpz_set_si(rop.as_raw_mut(), op2);
        },
        Ordering::Greater => {
            if op2 >= 0 {
                set(rop, op1);
                unsafe {
                    *limb_mut(rop, 0) |= lop2;
                }
            } else {
                let cur_limb = unsafe { limb(op1.unwrap_or(rop), 0) };
                set_limb(rop, !cur_limb & !lop2);
                com(rop, ());
            }
        }
        Ordering::Less => {
            if op2 >= 0 {
                com(rop, op1);
                if rop.cmp0() != Ordering::Equal {
                    unsafe {
                        *limb_mut(rop, 0) &= !lop2;
                        if rop.inner().size == 1 && limb(rop, 0) == 0 {
                            set_0(rop);
                        }
                    }
                }
                com(rop, ());
            } else {
                let cur_limb = unsafe { limb(op1.unwrap_or(rop), 0) };
                set_limb(rop, cur_limb.wrapping_sub(1) & !lop2);
                com(rop, ());
            }
        }
    }
}

pub fn xor_si<O: OptInteger>(rop: &mut Integer, op1: O, op2: c_long) {
    let lop2 = op2.wrapping_as::<limb_t>();
    match op1.unwrap_or(rop).cmp0() {
        Ordering::Equal => unsafe {
            gmp::mpz_set_si(rop.as_raw_mut(), op2);
        },
        Ordering::Greater => {
            if op2 >= 0 {
                set(rop, op1);
                unsafe {
                    *limb_mut(rop, 0) ^= lop2;
                    if rop.inner().size == 1 && limb(rop, 0) == 0 {
                        set_0(rop);
                    }
                }
            } else {
                set(rop, op1);
                unsafe {
                    *limb_mut(rop, 0) ^= !lop2;
                    if rop.inner().size == 1 && limb(rop, 0) == 0 {
                        set_0(rop);
                    }
                }
                com(rop, ());
            }
        }
        Ordering::Less => {
            if op2 >= 0 {
                com(rop, op1);
                if rop.cmp0() == Ordering::Equal {
                    if lop2 != 0 {
                        set_nonzero(rop, lop2);
                    }
                } else {
                    unsafe {
                        *limb_mut(rop, 0) ^= lop2;
                        if rop.inner().size == 1 && limb(rop, 0) == 0 {
                            set_0(rop);
                        }
                    }
                }
                com(rop, ());
            } else {
                com(rop, op1);
                if rop.cmp0() == Ordering::Equal {
                    if !lop2 != 0 {
                        set_nonzero(rop, !lop2);
                    }
                } else {
                    unsafe {
                        *limb_mut(rop, 0) ^= !lop2;
                        if rop.inner().size == 1 && limb(rop, 0) == 0 {
                            set_0(rop);
                        }
                    }
                }
            }
        }
    }
}
