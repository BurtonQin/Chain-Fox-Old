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

#[cfg(feature = "integer")]
use crate::Integer;
#[cfg(feature = "rational")]
use crate::Rational;
use crate::{
    complex::SmallComplex,
    ext::xmpfr::{self, ordering1, raw_round, OptFloat, EXP_ZERO},
    float::Round,
    Complex, Float,
};
use az::UnwrappedCast;
use core::{cmp::Ordering, mem::MaybeUninit, ptr::NonNull};
use gmp_mpfr_sys::{
    gmp::{self, limb_t},
    mpc::{self, mpc_t, rnd_t},
    mpfr::{mpfr_t, prec_t},
};
use libc::{c_int, c_long, c_ulong};

pub trait OptComplex: Copy {
    const IS_SOME: bool;
    type Part: OptFloat;
    fn mpc(self) -> *const mpc_t;
    fn mpc_or(self, default: *mut mpc_t) -> *const mpc_t;
    fn parts(self) -> (Self::Part, Self::Part);
    fn unwrap<'a>(self) -> &'a Complex
    where
        Self: 'a;
}

impl OptComplex for () {
    const IS_SOME: bool = false;
    type Part = ();
    #[inline(always)]
    fn mpc(self) -> *const mpc_t {
        panic!("unwrapping ()");
    }
    #[inline(always)]
    fn mpc_or(self, default: *mut mpc_t) -> *const mpc_t {
        default as *const mpc_t
    }
    #[inline(always)]
    fn parts(self) -> ((), ()) {
        ((), ())
    }
    #[inline(always)]
    fn unwrap<'a>(self) -> &'a Complex
    where
        Self: 'a,
    {
        panic!("unwrapping ()");
    }
}

impl<'a> OptComplex for &'a Complex {
    const IS_SOME: bool = true;
    type Part = &'a Float;
    #[inline(always)]
    fn mpc(self) -> *const mpc_t {
        self.as_raw()
    }
    #[inline(always)]
    fn mpc_or(self, _default: *mut mpc_t) -> *const mpc_t {
        self.as_raw()
    }
    #[inline(always)]
    fn parts(self) -> (&'a Float, &'a Float) {
        (self.real(), self.imag())
    }
    #[inline(always)]
    fn unwrap<'b>(self) -> &'b Complex
    where
        Self: 'b,
    {
        self
    }
}

pub type Round2 = (Round, Round);
pub const NEAREST2: Round2 = (Round::Nearest, Round::Nearest);

pub type Ordering2 = (Ordering, Ordering);

#[inline]
pub fn raw_round2(round: Round2) -> rnd_t {
    match (round.0, round.1) {
        (Round::Nearest, Round::Nearest) => mpc::RNDNN,
        (Round::Nearest, Round::Zero) => mpc::RNDNZ,
        (Round::Nearest, Round::Up) => mpc::RNDNU,
        (Round::Nearest, Round::Down) => mpc::RNDND,
        (Round::Zero, Round::Nearest) => mpc::RNDZN,
        (Round::Zero, Round::Zero) => mpc::RNDZZ,
        (Round::Zero, Round::Up) => mpc::RNDZU,
        (Round::Zero, Round::Down) => mpc::RNDZD,
        (Round::Up, Round::Nearest) => mpc::RNDUN,
        (Round::Up, Round::Zero) => mpc::RNDUZ,
        (Round::Up, Round::Up) => mpc::RNDUU,
        (Round::Up, Round::Down) => mpc::RNDUD,
        (Round::Down, Round::Nearest) => mpc::RNDDN,
        (Round::Down, Round::Zero) => mpc::RNDDZ,
        (Round::Down, Round::Up) => mpc::RNDDU,
        (Round::Down, Round::Down) => mpc::RNDDD,
        _ => unreachable!(),
    }
}

#[inline]
pub fn ordering2(ord: c_int) -> Ordering2 {
    // ord == first + 4 * second
    let first = mpc::INEX_RE(ord).cmp(&0);
    let second = mpc::INEX_IM(ord).cmp(&0);
    (first, second)
}

#[inline]
fn ordering4(ord: c_int) -> (Ordering2, Ordering2) {
    (ordering2(mpc::INEX1(ord)), ordering2(mpc::INEX2(ord)))
}

macro_rules! unsafe_wrap {
    (fn $fn:ident($($op:ident: $O:ident),* $(; $param:ident: $T:ty)*) -> $deleg:path) => {
        #[inline]
        pub fn $fn<$($O: OptComplex),*>(
            rop: &mut Complex,
            $($op: $O,)*
            $($param: $T,)*
            rnd: Round2,
        ) -> Ordering2 {
            let rop = rop.as_raw_mut();
            $(let $op = $op.mpc_or(rop);)*
            ordering2(unsafe { $deleg(rop, $($op,)* $($param.into(),)* raw_round2(rnd)) })
        }
    };
}

// do not use mpc::neg for op is () to avoid function call
#[inline]
pub fn neg<O: OptComplex>(rop: &mut Complex, op: O, rnd: Round2) -> Ordering2 {
    if O::IS_SOME {
        ordering2(unsafe { mpc::neg(rop.as_raw_mut(), op.mpc(), raw_round2(rnd)) })
    } else {
        (
            xmpfr::neg(rop.mut_real(), (), rnd.0),
            xmpfr::neg(rop.mut_imag(), (), rnd.1),
        )
    }
}

#[inline]
pub fn mul_i<O: OptComplex>(rop: &mut Complex, op: O, neg: bool, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op = op.mpc_or(rop);
    ordering2(unsafe { mpc::mul_i(rop, op, if neg { -1 } else { 0 }, raw_round2(rnd)) })
}

#[inline]
pub fn recip<O: OptComplex>(rop: &mut Complex, op: O, rnd: Round2) -> Ordering2 {
    ui_div(rop, 1, op, rnd)
}

#[inline]
pub fn rootofunity(rop: &mut Complex, n: u32, k: u32, rnd: Round2) -> Ordering2 {
    ordering2(unsafe { mpc::rootofunity(rop.as_raw_mut(), n.into(), k.into(), raw_round2(rnd)) })
}

#[inline]
pub fn sin_cos<O: OptComplex>(
    rop_sin: &mut Complex,
    rop_cos: &mut Complex,
    op: O,
    rnd: Round2,
) -> (Ordering2, Ordering2) {
    let rop_sin = rop_sin.as_raw_mut();
    let rop_cos = rop_cos.as_raw_mut();
    let op = op.mpc_or(rop_sin);
    ordering4(unsafe { mpc::sin_cos(rop_sin, rop_cos, op, raw_round2(rnd), raw_round2(rnd)) })
}

pub fn sum<'a, I>(rop: &mut Complex, values: I, rnd: Round2) -> Ordering2
where
    I: Iterator<Item = &'a Complex>,
{
    let pointers = values.map(Complex::as_raw).collect::<Vec<_>>();
    unsafe { sum_raw(rop.as_raw_mut(), &pointers, rnd) }
}

// add original value of rop to sum
pub fn sum_including_old<'a, I>(rop: &mut Complex, values: I, rnd: Round2) -> Ordering2
where
    I: Iterator<Item = &'a Complex>,
{
    let rop = rop.as_raw_mut();
    let capacity = values.size_hint().0.checked_add(1).expect("overflow");
    let mut pointers = Vec::with_capacity(capacity);
    pointers.push(rop as *const mpc_t);
    pointers.extend(values.map(Complex::as_raw));
    unsafe { sum_raw(rop, &pointers, rnd) }
}

pub unsafe fn sum_raw(rop: *mut mpc_t, pointers: &[*const mpc_t], rnd: Round2) -> Ordering2 {
    let n = pointers.len().unwrapped_cast();
    let tab = cast_ptr!(pointers.as_ptr(), *mut mpc_t);
    ordering2(mpc::sum(rop, tab, n, raw_round2(rnd)))
}

pub fn dot<'a, I>(rop: &mut Complex, values: I, rnd: Round2) -> Ordering2
where
    I: Iterator<Item = (&'a Complex, &'a Complex)>,
{
    let (pointers_a, pointers_b): (Vec<_>, Vec<_>) =
        values.map(|(a, b)| (a.as_raw(), b.as_raw())).unzip();
    unsafe { dot_raw(rop.as_raw_mut(), &pointers_a, &pointers_b, rnd) }
}

// add original value of rop to dot
pub fn dot_including_old<'a, I>(rop: &mut Complex, values: I, rnd: Round2) -> Ordering2
where
    I: Iterator<Item = (&'a Complex, &'a Complex)>,
{
    const LIMB_ONE: limb_t = 1;
    const LIMB_MSB: limb_t = LIMB_ONE << (gmp::LIMB_BITS - 1);
    const ONE: mpc_t = mpc_t {
        re: mpfr_t {
            prec: 1,
            sign: 1,
            exp: 1,
            d: unsafe { NonNull::new_unchecked(&LIMB_MSB as *const limb_t as *mut limb_t) },
        },
        im: mpfr_t {
            prec: 1,
            sign: 1,
            exp: EXP_ZERO,
            d: unsafe { NonNull::new_unchecked(&LIMB_MSB as *const limb_t as *mut limb_t) },
        },
    };

    let rop = rop.as_raw_mut();
    let capacity = values.size_hint().0.checked_add(1).expect("overflow");
    let mut pointers_a = Vec::with_capacity(capacity);
    let mut pointers_b = Vec::with_capacity(capacity);
    pointers_a.push(rop as *const mpc_t);
    pointers_b.push(&ONE as *const mpc_t);
    for a_b in values {
        pointers_a.push(a_b.0.as_raw());
        pointers_b.push(a_b.1.as_raw());
    }
    unsafe { dot_raw(rop, &pointers_a, &pointers_b, rnd) }
}

// pointers_a and pointers_b must have same length
unsafe fn dot_raw(
    rop: *mut mpc_t,
    pointers_a: &[*const mpc_t],
    pointers_b: &[*const mpc_t],
    rnd: Round2,
) -> Ordering2 {
    debug_assert_eq!(pointers_a.len(), pointers_b.len());
    let n = pointers_a.len().unwrapped_cast();
    let a = cast_ptr!(pointers_a.as_ptr(), *mut mpc_t);
    let b = cast_ptr!(pointers_b.as_ptr(), *mut mpc_t);
    ordering2(mpc::dot(rop, a, b, n, raw_round2(rnd)))
}

unsafe_wrap! { fn set(op: O) -> mpc::set }
unsafe_wrap! { fn proj(op: O) -> mpc::proj }
unsafe_wrap! { fn sqr(op: O) -> mpc::sqr }
unsafe_wrap! { fn sqrt(op: O) -> mpc::sqrt }
unsafe_wrap! { fn conj(op: O) -> mpc::conj }
unsafe_wrap! { fn log(op: O) -> mpc::log }
unsafe_wrap! { fn log10(op: O) -> mpc::log10 }
unsafe_wrap! { fn exp(op: O) -> mpc::exp }
unsafe_wrap! { fn sin(op: O) -> mpc::sin }
unsafe_wrap! { fn cos(op: O) -> mpc::cos }
unsafe_wrap! { fn tan(op: O) -> mpc::tan }
unsafe_wrap! { fn sinh(op: O) -> mpc::sinh }
unsafe_wrap! { fn cosh(op: O) -> mpc::cosh }
unsafe_wrap! { fn tanh(op: O) -> mpc::tanh }
unsafe_wrap! { fn asin(op: O) -> mpc::asin }
unsafe_wrap! { fn acos(op: O) -> mpc::acos }
unsafe_wrap! { fn atan(op: O) -> mpc::atan }
unsafe_wrap! { fn asinh(op: O) -> mpc::asinh }
unsafe_wrap! { fn acosh(op: O) -> mpc::acosh }
unsafe_wrap! { fn atanh(op: O) -> mpc::atanh }
unsafe_wrap! { fn fma(op1: O, op2: P, op3: Q) -> mpc::fma }
unsafe_wrap! { fn add(op1: O, op2: P) -> mpc::add }
unsafe_wrap! { fn sub(op1: O, op2: P) -> mpc::sub }
unsafe_wrap! { fn mul(op1: O, op2: P) -> mpc::mul }
unsafe_wrap! { fn div(op1: O, op2: P) -> mpc::div }
unsafe_wrap! { fn pow(op1: O, op2: P) -> mpc::pow }
unsafe_wrap! { fn shl_i32(op1: O; op2: i32) -> mpc::mul_2si }
unsafe_wrap! { fn shr_i32(op1: O; op2: i32) -> mpc::div_2si }
unsafe_wrap! { fn shl_u32(op1: O; op2: u32) -> mpc::mul_2ui }
unsafe_wrap! { fn shr_u32(op1: O; op2: u32) -> mpc::div_2ui }

#[inline]
pub fn write_new_nan(dst: &mut MaybeUninit<Complex>, prec_real: prec_t, prec_imag: prec_t) {
    // Safety: we can cast pointers to/from Complex/mpc_t as they are repr(transparent).
    unsafe {
        let inner_ptr = cast_ptr_mut!(dst.as_mut_ptr(), mpc_t);
        mpc::init3(inner_ptr, prec_real, prec_imag);
    }
}

#[inline]
pub fn write_real_imag(dst: &mut MaybeUninit<Complex>, real: Float, imag: Float) {
    // Safety:
    //   * We can cast pointers to/from Complex/mpc_t as they are repr(transparent).
    //   * We can cast pointers to/from Float/mpfr_t as they are repr(transparent).
    //   * realref/imagref only offset the pointers, and can operate on uninit memory.
    unsafe {
        let inner_ptr = cast_ptr_mut!(dst.as_mut_ptr(), mpc_t);
        let real_ptr = cast_ptr_mut!(mpc::realref(inner_ptr), Float);
        real_ptr.write(real);
        let imag_ptr = cast_ptr_mut!(mpc::imagref(inner_ptr), Float);
        imag_ptr.write(imag);
    }
}

#[inline]
pub fn realref_const(c: &Complex) -> &Float {
    unsafe { &*cast_ptr!(mpc::realref_const(c.as_raw()), Float) }
}

#[inline]
pub fn imagref_const(c: &Complex) -> &Float {
    unsafe { &*cast_ptr!(mpc::imagref_const(c.as_raw()), Float) }
}

#[inline]
pub fn realref(c: &mut Complex) -> &mut Float {
    unsafe { &mut *cast_ptr_mut!(mpc::realref(c.as_raw_mut()), Float) }
}

#[inline]
pub fn imagref(c: &mut Complex) -> &mut Float {
    unsafe { &mut *cast_ptr_mut!(mpc::imagref(c.as_raw_mut()), Float) }
}

#[inline]
pub fn realref_imagref(c: &mut Complex) -> (&mut Float, &mut Float) {
    let c = c.as_raw_mut();
    unsafe {
        (
            &mut *cast_ptr_mut!(mpc::realref(c), Float),
            &mut *cast_ptr_mut!(mpc::imagref(c), Float),
        )
    }
}

#[inline]
pub fn split(c: Complex) -> (Float, Float) {
    let raw = c.into_raw();
    // raw has no Drop
    unsafe { (Float::from_raw(raw.re), Float::from_raw(raw.im)) }
}

#[inline]
pub fn abs(f: &mut Float, c: &Complex, round: Round) -> Ordering {
    ordering1(unsafe { mpc::abs(f.as_raw_mut(), c.as_raw(), raw_round(round)) })
}

#[inline]
pub fn arg(f: &mut Float, c: &Complex, round: Round) -> Ordering {
    ordering1(unsafe { mpc::arg(f.as_raw_mut(), c.as_raw(), raw_round(round)) })
}

#[inline]
pub fn norm(f: &mut Float, c: &Complex, round: Round) -> Ordering {
    ordering1(unsafe { mpc::norm(f.as_raw_mut(), c.as_raw(), raw_round(round)) })
}

#[inline]
pub fn cmp_abs(op1: &Complex, op2: &Complex) -> Ordering {
    ordering1(unsafe { mpc::cmp_abs(op1.as_raw(), op2.as_raw()) })
}

macro_rules! sum_forward {
    (fn $name:ident($T:ty) -> $func:path) => {
        #[inline]
        pub fn $name<O: OptComplex>(rop: &mut Complex, op1: O, op2: $T, rnd: Round2) -> Ordering2 {
            let op1 = op1.parts();
            (
                $func(rop.mut_real(), op1.0, op2, rnd.0),
                xmpfr::set(rop.mut_imag(), op1.1, rnd.1),
            )
        }
    };
}

macro_rules! sub_reverse {
    (fn $name:ident($T:ty) -> $func:path) => {
        #[inline]
        pub fn $name<O: OptComplex>(rop: &mut Complex, op1: $T, op2: O, rnd: Round2) -> Ordering2 {
            let op2 = op2.parts();
            (
                $func(rop.mut_real(), op1, op2.0, rnd.0),
                xmpfr::neg(rop.mut_imag(), op2.1, rnd.1),
            )
        }
    };
}

macro_rules! prod_forward {
    (fn $name:ident($T:ty) -> $func:path) => {
        #[inline]
        pub fn $name<O: OptComplex>(rop: &mut Complex, op1: O, op2: $T, rnd: Round2) -> Ordering2 {
            let op1 = op1.parts();
            (
                $func(rop.mut_real(), op1.0, op2, rnd.0),
                $func(rop.mut_imag(), op1.1, op2, rnd.1),
            )
        }
    };
}

macro_rules! div_reverse {
    (fn $name:ident($T:ty) -> $func:path) => {
        #[inline]
        pub fn $name<O: OptComplex>(rop: &mut Complex, op1: $T, op2: O, rnd: Round2) -> Ordering2 {
            let op1 = SmallComplex::from(op1);
            div(rop, &*op1, op2, rnd)
        }
    };
}

sum_forward! { fn add_ui(c_ulong) -> xmpfr::add_ui }
sum_forward! { fn add_si(c_long) -> xmpfr::add_si }
sum_forward! { fn add_d(f64) -> xmpfr::add_d }
#[cfg(feature = "integer")]
sum_forward! { fn add_z(&Integer) -> xmpfr::add_z }
#[cfg(feature = "rational")]
sum_forward! { fn add_q(&Rational) -> xmpfr::add_q }

sum_forward! { fn sub_ui(c_ulong) -> xmpfr::sub_ui }
sum_forward! { fn sub_si(c_long) -> xmpfr::sub_si }
sum_forward! { fn sub_d(f64) -> xmpfr::sub_d }
#[cfg(feature = "integer")]
sum_forward! { fn sub_z(&Integer) -> xmpfr::sub_z }
#[cfg(feature = "rational")]
sum_forward! { fn sub_q(&Rational) -> xmpfr::sub_q }

sub_reverse! { fn ui_sub(c_ulong) -> xmpfr::ui_sub }
sub_reverse! { fn si_sub(c_long) -> xmpfr::si_sub }
sub_reverse! { fn d_sub(f64) -> xmpfr::d_sub }
#[cfg(feature = "integer")]
sub_reverse! { fn z_sub(&Integer) -> xmpfr::z_sub }
#[cfg(feature = "rational")]
sub_reverse! { fn q_sub(&Rational) -> xmpfr::q_sub }

prod_forward! { fn mul_ui(c_ulong) -> xmpfr::mul_ui }
prod_forward! { fn mul_si(c_long) -> xmpfr::mul_si }
prod_forward! { fn mul_d(f64) -> xmpfr::mul_d }
#[cfg(feature = "integer")]
prod_forward! { fn mul_z(&Integer) -> xmpfr::mul_z }
#[cfg(feature = "rational")]
prod_forward! { fn mul_q(&Rational) -> xmpfr::mul_q }

prod_forward! { fn div_ui(c_ulong) -> xmpfr::div_ui }
prod_forward! { fn div_si(c_long) -> xmpfr::div_si }
prod_forward! { fn div_d(f64) -> xmpfr::div_d }
#[cfg(feature = "integer")]
prod_forward! { fn div_z(&Integer) -> xmpfr::div_z }
#[cfg(feature = "rational")]
prod_forward! { fn div_q(&Rational) -> xmpfr::div_q }

div_reverse! { fn ui_div(c_ulong) -> xmpfr::ui_div }
div_reverse! { fn si_div(c_long) -> xmpfr::si_div }
div_reverse! { fn d_div(f64) -> xmpfr::d_div }

#[inline]
pub fn mulsub<O: OptComplex>(
    rop: &mut Complex,
    mul1: &Complex,
    mul2: &Complex,
    sub: O,
    rnd: Round2,
) -> Ordering2 {
    if O::IS_SOME {
        let sub = sub.unwrap();
        fma(rop, mul1, mul2, &*sub.as_neg(), rnd)
    } else {
        neg(rop, (), (Round::Zero, Round::Zero));
        fma(rop, mul1, mul2, (), rnd)
    }
}

#[inline]
pub fn submul<O: OptComplex>(
    rop: &mut Complex,
    add: O,
    mul1: &Complex,
    mul2: &Complex,
    rnd: Round2,
) -> Ordering2 {
    fma(rop, &*mul1.as_neg(), mul2, add, rnd)
}

#[inline]
pub fn add_fr<O: OptComplex>(rop: &mut Complex, op1: O, op2: &Float, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpc_or(rop);
    ordering2(unsafe { mpc::add_fr(rop, op1, op2.as_raw(), raw_round2(rnd)) })
}

#[inline]
pub fn sub_fr<O: OptComplex>(rop: &mut Complex, op1: O, op2: &Float, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpc_or(rop);
    ordering2(unsafe { mpc::sub_fr(rop, op1, op2.as_raw(), raw_round2(rnd)) })
}

#[inline]
pub fn fr_sub<O: OptComplex>(rop: &mut Complex, op1: &Float, op2: O, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op2 = op2.mpc_or(rop);
    ordering2(unsafe { mpc::fr_sub(rop, op1.as_raw(), op2, raw_round2(rnd)) })
}

#[inline]
pub fn mul_fr<O: OptComplex>(rop: &mut Complex, op1: O, op2: &Float, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpc_or(rop);
    ordering2(unsafe { mpc::mul_fr(rop, op1, op2.as_raw(), raw_round2(rnd)) })
}

#[inline]
pub fn div_fr<O: OptComplex>(rop: &mut Complex, op1: O, op2: &Float, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpc_or(rop);
    ordering2(unsafe { mpc::div_fr(rop, op1, op2.as_raw(), raw_round2(rnd)) })
}

#[inline]
pub fn fr_div<O: OptComplex>(rop: &mut Complex, op1: &Float, op2: O, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op2 = op2.mpc_or(rop);
    ordering2(unsafe { mpc::fr_div(rop, op1.as_raw(), op2, raw_round2(rnd)) })
}

#[inline]
pub fn pow_fr<O: OptComplex>(rop: &mut Complex, op1: O, op2: &Float, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpc_or(rop);
    ordering2(unsafe { mpc::pow_fr(rop, op1, op2.as_raw(), raw_round2(rnd)) })
}

#[inline]
#[cfg(feature = "integer")]
pub fn pow_z<O: OptComplex>(rop: &mut Complex, op1: O, op2: &Integer, rnd: Round2) -> Ordering2 {
    let rop = rop.as_raw_mut();
    let op1 = op1.mpc_or(rop);
    ordering2(unsafe { mpc::pow_z(rop, op1, op2.as_raw(), raw_round2(rnd)) })
}
