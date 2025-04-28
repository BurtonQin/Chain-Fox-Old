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
    ext::xmpz::{self, OptInteger},
    misc::NegAbs,
    ops::{NegAssign, SubFrom},
    rational::SmallRational,
    Assign, Integer, Rational,
};
use az::{Az, CheckedAs, UnwrappedAs, UnwrappedCast};
use core::{
    cmp::Ordering,
    mem::{self, MaybeUninit},
};
use gmp_mpfr_sys::gmp::{self, mpq_t};
use libc::{c_int, c_long, c_ulong};

pub trait OptRational: Copy {
    const IS_SOME: bool;
    type Part: OptInteger;
    fn mpq(self) -> *const mpq_t;
    fn mpq_or(self, default: *mut mpq_t) -> *const mpq_t;
    fn parts(self) -> (Self::Part, Self::Part);
    fn unwrap_parts<'a>(self) -> (&'a Integer, &'a Integer)
    where
        Self: 'a;
}

impl OptRational for () {
    const IS_SOME: bool = false;
    type Part = ();
    #[inline(always)]
    fn mpq(self) -> *const mpq_t {
        panic!("unwrapping ()");
    }
    #[inline(always)]
    fn mpq_or(self, default: *mut mpq_t) -> *const mpq_t {
        default as *const mpq_t
    }
    #[inline(always)]
    fn parts(self) -> ((), ()) {
        ((), ())
    }
    #[inline(always)]
    fn unwrap_parts<'a>(self) -> (&'a Integer, &'a Integer) {
        panic!("unwrapping ()");
    }
}

impl<'a> OptRational for &'a Rational {
    const IS_SOME: bool = true;
    type Part = &'a Integer;
    #[inline(always)]
    fn mpq(self) -> *const mpq_t {
        self.as_raw()
    }
    #[inline(always)]
    fn mpq_or(self, _default: *mut mpq_t) -> *const mpq_t {
        self.as_raw()
    }
    #[inline(always)]
    fn parts(self) -> (&'a Integer, &'a Integer) {
        (self.numer(), self.denom())
    }
    #[inline(always)]
    fn unwrap_parts<'b>(self) -> (&'b Integer, &'b Integer)
    where
        Self: 'b,
    {
        (self.numer(), self.denom())
    }
}

macro_rules! unsafe_wrap {
    (fn $fn:ident($($op:ident: $O:ident),* $(; $param:ident: $T:ty)*) -> $deleg:path) => {
        #[inline]
        pub fn $fn<$($O: OptRational),*>(rop: &mut Rational $(, $op: $O)* $(, $param: $T)*) {
            let rop = rop.as_raw_mut();
            $(let $op = $op.mpq_or(rop);)*
            unsafe {
                $deleg(rop $(, $op)* $(, $param.into())*);
            }
        }
    };
}

#[inline]
pub fn set<O: OptRational>(rop: &mut Rational, op: O) {
    if O::IS_SOME {
        unsafe {
            gmp::mpq_set(rop.as_raw_mut(), op.mpq());
        }
    }
}

#[inline]
pub fn set_f64(rop: &mut Rational, op: f64) {
    unsafe {
        gmp::mpq_set_d(rop.as_raw_mut(), op);
    }
}

#[inline]
pub fn get_f64(op: &Rational) -> f64 {
    unsafe { gmp::mpq_get_d(op.as_raw()) }
}

#[inline]
pub unsafe fn clear(rop: &mut Rational) {
    gmp::mpq_clear(rop.as_raw_mut());
}

#[inline]
pub unsafe fn init_set(rop: *mut Rational, op: &Rational) {
    let rop = cast_ptr_mut!(rop, mpq_t);
    let num = cast_ptr_mut!(gmp::mpq_numref(rop), Integer);
    let den = cast_ptr_mut!(gmp::mpq_denref(rop), Integer);
    xmpz::init_set(num, op.numer());
    xmpz::init_set(den, op.denom());
}

macro_rules! int_rat {
    (fn $fn:ident, $fn_int:ident, |$rop:ident, $num:ident, $den:ident| $body:block) => {
        #[inline]
        pub fn $fn(rat: &mut Rational) {
            let (num, den) = unsafe { rat.as_mut_numer_denom_no_canonicalization() };
            let $rop: &mut Integer = num;
            let $num = ();
            let $den: &Integer = &*den;
            $body
            xmpz::set_1(den);
        }

        #[inline]
        pub fn $fn_int(rop: &mut Integer, op: &Rational) {
            let $rop: &mut Integer = rop;
            let $num = op.numer();
            let $den: &Integer = op.denom();
            $body
        }
    };
}

int_rat! { fn signum, signum_int, |rop, num, _den| {
    xmpz::signum(rop, num);
} }

int_rat! { fn trunc, trunc_int, |rop, num, den| {
    xmpz::tdiv_q(rop, num, den);
} }

int_rat! { fn ceil, ceil_int, |rop, num, den| {
    // use tdiv_q rather than cdiv_q to let GMP not keep remainder
    if xmpz::is_1(den) {
        xmpz::set(rop, num);
    } else {
        let neg = unsafe { gmp::mpz_sgn(num.mpz_or(rop.as_raw_mut())) < 0 };
        xmpz::tdiv_q(rop, num, den);
        if !neg {
            xmpz::add_ui(rop, (), 1);
        }
    }
} }

int_rat! { fn floor, floor_int, |rop, num, den| {
    // use tdiv_q rather than fdiv_q to let GMP not keep remainder
    if xmpz::is_1(den) {
        xmpz::set(rop, num);
    } else {
        let neg = unsafe { gmp::mpz_sgn(num.mpz_or(rop.as_raw_mut())) < 0 };
        xmpz::tdiv_q(rop, num, den);
        if neg {
            xmpz::sub_ui(rop, (), 1);
        }
    }
} }

int_rat! { fn round, round_int, |rop, num, den| {
    // The remainder cannot be larger than the divisor, but we
    // allocate an extra limb because the GMP docs suggest we should.
    let limbs = den.inner().size.abs().unwrapped_as::<usize>() + 1;
    let bits = limbs
        .checked_mul(gmp::LIMB_BITS.az::<usize>())
        .expect("overflow");
    let mut rem = Integer::with_capacity(bits);
    xmpz::tdiv_qr(rop, &mut rem, num, den);
    if xmpz::round_away(&rem, den) {
        if rem.cmp0() == Ordering::Less {
            // negative number
            xmpz::sub_ui(rop, (), 1);
        } else {
            // positive number
            xmpz::add_ui(rop, (), 1);
        }
    }
} }

#[inline]
pub fn inv<O: OptRational>(rop: &mut Rational, op: O) {
    let rop = rop.as_raw_mut();
    let op = op.mpq_or(rop);
    unsafe {
        assert_ne!(gmp::mpq_sgn(op), 0, "division by zero");
        gmp::mpq_inv(rop, op);
    }
}

pub fn trunc_fract<O: OptRational>(fract: &mut Rational, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    xmpz::tdiv_r(fract_num, op_num, &*fract_den);
}

pub fn trunc_fract_whole<O: OptRational>(fract: &mut Rational, trunc: &mut Integer, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    let fract = fract_num.as_raw_mut();
    let op = op_num.mpz_or(fract);
    unsafe {
        gmp::mpz_tdiv_qr(trunc.as_raw_mut(), fract, op, fract_den.as_raw());
    }
}

pub fn ceil_fract<O: OptRational>(fract: &mut Rational, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    xmpz::cdiv_r(fract_num, op_num, &*fract_den);
}

pub fn ceil_fract_whole<O: OptRational>(fract: &mut Rational, ceil: &mut Integer, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    let fract = fract_num.as_raw_mut();
    let op = op_num.mpz_or(fract);
    unsafe {
        gmp::mpz_cdiv_qr(ceil.as_raw_mut(), fract, op, fract_den.as_raw());
    }
}

pub fn floor_fract<O: OptRational>(fract: &mut Rational, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    xmpz::fdiv_r(fract_num, op_num, &*fract_den);
}

pub fn floor_fract_whole<O: OptRational>(fract: &mut Rational, floor: &mut Integer, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    let fract = fract_num.as_raw_mut();
    let op = op_num.mpz_or(fract);
    unsafe {
        gmp::mpz_fdiv_qr(floor.as_raw_mut(), fract, op, fract_den.as_raw());
    }
}

pub fn round_fract<O: OptRational>(fract: &mut Rational, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    xmpz::tdiv_r(fract_num, op_num, &*fract_den);
    if xmpz::round_away(fract_num, fract_den) {
        if fract_num.cmp0() == Ordering::Less {
            // negative number
            xmpz::add(fract_num, (), &*fract_den);
        } else {
            // positive number
            xmpz::sub(fract_num, (), &*fract_den);
        }
    }
}

pub fn round_fract_whole<O: OptRational>(fract: &mut Rational, round: &mut Integer, op: O) {
    let (fract_num, fract_den) = unsafe { fract.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::set(fract_den, op_den);
    let fract = fract_num.as_raw_mut();
    let op = op_num.mpz_or(fract);
    unsafe {
        gmp::mpz_tdiv_qr(round.as_raw_mut(), fract, op, fract_den.as_raw());
    }
    if xmpz::round_away(fract_num, fract_den) {
        if fract_num.cmp0() == Ordering::Less {
            // negative number
            xmpz::sub_ui(round, (), 1);
            xmpz::add(fract_num, (), &*fract_den);
        } else {
            // positive number
            xmpz::add_ui(round, (), 1);
            xmpz::sub(fract_num, (), &*fract_den);
        }
    }
}

pub fn square<O: OptRational>(rop: &mut Rational, op: O) {
    let (rop_num, rop_den) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    let (op_num, op_den) = op.parts();
    xmpz::square(rop_num, op_num);
    xmpz::square(rop_den, op_den);
}

unsafe_wrap! { fn neg(op: O) -> gmp::mpq_neg }
unsafe_wrap! { fn abs(op: O) -> gmp::mpq_abs }
unsafe_wrap! { fn add(op1: O, op2: P) -> gmp::mpq_add }
unsafe_wrap! { fn sub(op1: O, op2: P) -> gmp::mpq_sub }
unsafe_wrap! { fn mul(op1: O, op2: P) -> gmp::mpq_mul }
unsafe_wrap! { fn div(op1: O, op2: P) -> gmp::mpq_div }
unsafe_wrap! { fn mul_2exp(op1: O; op2: u32) -> gmp::mpq_mul_2exp }
unsafe_wrap! { fn div_2exp(op1: O; op2: u32) -> gmp::mpq_div_2exp }

// num and den must form a canonical pair
#[inline]
pub unsafe fn write_num_den_unchecked(dst: &mut MaybeUninit<Rational>, num: Integer, den: Integer) {
    let inner_ptr = cast_ptr_mut!(dst.as_mut_ptr(), mpq_t);
    let num_ptr = cast_ptr_mut!(gmp::mpq_numref(inner_ptr), Integer);
    num_ptr.write(num);
    let den_ptr = cast_ptr_mut!(gmp::mpq_denref(inner_ptr), Integer);
    den_ptr.write(den);
}

#[inline]
pub fn write_num_den_canonicalize(dst: &mut MaybeUninit<Rational>, num: Integer, den: Integer) {
    assert_ne!(den.cmp0(), Ordering::Equal, "division by zero");
    // Safety:
    //   * We can cast pointers to/from Rational/mpq_t as they are repr(transparent).
    //   * We can cast pointers to/from Integer/mpz_t as they are repr(transparent).
    //   * numref/denref only offset the pointers, and can operate on uninit memory.
    unsafe {
        let inner_ptr = cast_ptr_mut!(dst.as_mut_ptr(), mpq_t);
        let num_ptr = cast_ptr_mut!(gmp::mpq_numref(inner_ptr), Integer);
        num_ptr.write(num);
        let den_ptr = cast_ptr_mut!(gmp::mpq_denref(inner_ptr), Integer);
        den_ptr.write(den);
        gmp::mpq_canonicalize(inner_ptr);
    }
}

#[inline]
pub fn canonicalize(r: &mut Rational) {
    assert_ne!(r.denom().cmp0(), Ordering::Equal, "division by zero");
    unsafe {
        gmp::mpq_canonicalize(r.as_raw_mut());
    }
}

#[inline]
pub fn numref_const(r: &Rational) -> &Integer {
    unsafe { &*cast_ptr!(gmp::mpq_numref_const(r.as_raw()), Integer) }
}

#[inline]
pub fn denref_const(r: &Rational) -> &Integer {
    unsafe { &*cast_ptr!(gmp::mpq_denref_const(r.as_raw()), Integer) }
}

// unsafe because this can be used to leave Rational in a non-canonical state
#[inline]
pub unsafe fn numref_denref(r: &mut Rational) -> (&mut Integer, &mut Integer) {
    let r = r.as_raw_mut();
    (
        &mut *cast_ptr_mut!(gmp::mpq_numref(r), Integer),
        &mut *cast_ptr_mut!(gmp::mpq_denref(r), Integer),
    )
}

#[inline]
pub fn set_0(rop: &mut Rational) {
    unsafe {
        let (num, den) = rop.as_mut_numer_denom_no_canonicalization();
        xmpz::set_0(num);
        xmpz::set_1(den);
    }
}

#[inline]
pub fn lshift_i32<O: OptRational>(rop: &mut Rational, op1: O, op2: i32) {
    let (op2_neg, op2_abs) = op2.neg_abs();
    if !op2_neg {
        mul_2exp(rop, op1, op2_abs);
    } else {
        div_2exp(rop, op1, op2_abs);
    }
}

#[inline]
pub fn rshift_i32<O: OptRational>(rop: &mut Rational, op1: O, op2: i32) {
    let (op2_neg, op2_abs) = op2.neg_abs();
    if !op2_neg {
        div_2exp(rop, op1, op2_abs);
    } else {
        mul_2exp(rop, op1, op2_abs);
    }
}

#[inline]
pub fn pow_u32<O: OptRational>(rop: &mut Rational, op1: O, op2: u32) {
    unsafe {
        let (rop_num, rop_den) = rop.as_mut_numer_denom_no_canonicalization();
        let (op1_num, op1_den) = op1.parts();
        xmpz::pow_u32(rop_num, op1_num, op2);
        xmpz::pow_u32(rop_den, op1_den, op2);
    }
}

#[inline]
pub fn pow_i32<O: OptRational>(rop: &mut Rational, op1: O, op2: i32) {
    let (op2_neg, op2_abs) = op2.neg_abs();
    pow_u32(rop, op1, op2_abs);
    if op2_neg {
        inv(rop, ());
    }
}

#[inline]
fn ord(o: c_int) -> Ordering {
    o.cmp(&0)
}

#[inline]
pub fn cmp(op1: &Rational, op2: &Rational) -> Ordering {
    ord(unsafe { gmp::mpq_cmp(op1.as_raw(), op2.as_raw()) })
}

#[inline]
pub fn equal(op1: &Rational, op2: &Rational) -> bool {
    (unsafe { gmp::mpq_equal(op1.as_raw(), op2.as_raw()) }) != 0
}

#[inline]
pub fn cmp_z(op1: &Rational, op2: &Integer) -> Ordering {
    ord(unsafe { gmp::mpq_cmp_z(op1.as_raw(), op2.as_raw()) })
}

#[inline]
pub fn cmp_u32(op1: &Rational, n2: u32, d2: u32) -> Ordering {
    ord(unsafe { gmp::mpq_cmp_ui(op1.as_raw(), n2.into(), d2.into()) })
}

#[inline]
pub fn cmp_i32(op1: &Rational, n2: i32, d2: u32) -> Ordering {
    ord(unsafe { gmp::mpq_cmp_si(op1.as_raw(), n2.into(), d2.into()) })
}

#[inline]
pub fn cmp_u64(op1: &Rational, n2: u64, d2: u64) -> Ordering {
    if let Some(n2) = n2.checked_as() {
        if let Some(d2) = d2.checked_as() {
            return ord(unsafe { gmp::mpq_cmp_ui(op1.as_raw(), n2, d2) });
        }
    }
    let small = SmallRational::from((n2, d2));
    ord(unsafe { gmp::mpq_cmp(op1.as_raw(), small.as_raw()) })
}

#[inline]
pub fn cmp_i64(op1: &Rational, n2: i64, d2: u64) -> Ordering {
    if let Some(n2) = n2.checked_as() {
        if let Some(d2) = d2.checked_as() {
            return ord(unsafe { gmp::mpq_cmp_si(op1.as_raw(), n2, d2) });
        }
    }
    let small = SmallRational::from((n2, d2));
    ord(unsafe { gmp::mpq_cmp(op1.as_raw(), small.as_raw()) })
}

#[inline]
pub fn cmp_u128(op1: &Rational, n2: u128, d2: u128) -> Ordering {
    if let Some(n2) = n2.checked_as() {
        if let Some(d2) = d2.checked_as() {
            return ord(unsafe { gmp::mpq_cmp_ui(op1.as_raw(), n2, d2) });
        }
    }
    let small = SmallRational::from((n2, d2));
    ord(unsafe { gmp::mpq_cmp(op1.as_raw(), small.as_raw()) })
}

#[inline]
pub fn cmp_i128(op1: &Rational, n2: i128, d2: u128) -> Ordering {
    if let Some(n2) = n2.checked_as() {
        if let Some(d2) = d2.checked_as() {
            return ord(unsafe { gmp::mpq_cmp_si(op1.as_raw(), n2, d2) });
        }
    }
    let small = SmallRational::from((n2, d2));
    ord(unsafe { gmp::mpq_cmp(op1.as_raw(), small.as_raw()) })
}

pub fn cmp_finite_d(op1: &Rational, op2: f64) -> Ordering {
    let num1 = op1.numer();
    let den1 = op1.denom();
    let den1_bits = den1.significant_bits();
    // cmp(num1, op2 * den1)
    let cmp;
    unsafe {
        let mut op2_f = MaybeUninit::uninit();
        gmp::mpf_init2(op2_f.as_mut_ptr(), 53);
        let mut op2_f = op2_f.assume_init();
        gmp::mpf_set_d(&mut op2_f, op2);
        let mut rhs = MaybeUninit::uninit();
        gmp::mpf_init2(rhs.as_mut_ptr(), (den1_bits + 53).unwrapped_cast());
        let mut rhs = rhs.assume_init();
        gmp::mpf_set_z(&mut rhs, den1.as_raw());
        gmp::mpf_mul(&mut rhs, &rhs, &op2_f);
        cmp = -gmp::mpf_cmp_z(&rhs, num1.as_raw());
        gmp::mpf_clear(&mut rhs);
        gmp::mpf_clear(&mut op2_f);
    }
    ord(cmp)
}

pub fn add_z<O: OptRational>(rop: &mut Rational, lhs: O, rhs: &Integer) {
    set(rop, lhs);
    // No canonicalization is necessary, as (numer + rhs * denom) is
    // not divisible by denom when numer is not divisible by denom.
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    *numer += rhs * &*denom;
}

pub fn sub_z<O: OptRational>(rop: &mut Rational, lhs: O, rhs: &Integer) {
    set(rop, lhs);
    // No canonicalization is necessary, as (numer - rhs * denom) is
    // not divisible by denom when numer is not divisible by denom.
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    *numer -= rhs * &*denom;
}

pub fn z_sub<O: OptRational>(rop: &mut Rational, lhs: &Integer, rhs: O) {
    set(rop, rhs);
    // No canonicalization is necessary, as (lhs * denom - numer) is
    // not divisible by denom when numer is not divisible by denom.
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    numer.sub_from(lhs * &*denom);
}

pub fn mul_z<O: OptRational>(rop: &mut Rational, lhs: O, rhs: &Integer) {
    if rhs.cmp0() == Ordering::Equal {
        set_0(rop);
        return;
    }
    // Canonicalization is done in this function.
    //     gcd = gcd(lhs.denom, rhs)
    //     (numer, denom) = (rhs / gcd * lhs.numer, lhs.denom / gcd)
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    if O::IS_SOME {
        let (lhs_num, lhs_den) = lhs.unwrap_parts();
        // store gcd temporarily in numer
        numer.assign(lhs_den.gcd_ref(rhs));
        if !xmpz::is_1(numer) {
            denom.assign(lhs_den.div_exact_ref(numer));
            numer.div_exact_from(rhs);
            *numer *= lhs_num;
        } else {
            numer.assign(lhs_num * rhs);
            denom.assign(lhs_den);
        }
    } else {
        let mut gcd = Integer::from(denom.gcd_ref(rhs));
        if !xmpz::is_1(&gcd) {
            denom.div_exact_mut(&gcd);
            gcd.div_exact_from(rhs);
            *numer *= gcd;
        } else {
            *numer *= rhs;
        }
    }
}

pub fn div_z<O: OptRational>(rop: &mut Rational, lhs: O, rhs: &Integer) {
    xmpz::check_div0(rhs);
    // Canonicalization is done in this function.
    //     gcd = gcd(lhs.numer, rhs)
    //     (numer, denom) = (lhs.numer / gcd, rhs / gcd * lhs.denom)
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    if O::IS_SOME {
        let (lhs_num, lhs_den) = lhs.unwrap_parts();
        // store gcd temporarily in numer
        numer.assign(lhs_num.gcd_ref(rhs));
        if !xmpz::is_1(numer) {
            denom.assign(rhs.div_exact_ref(numer));
            *denom *= lhs_den;
            numer.div_exact_from(lhs_num);
        } else {
            numer.assign(lhs_num);
            denom.assign(lhs_den * rhs);
        }
    } else {
        let mut gcd = Integer::from(numer.gcd_ref(rhs));
        if !xmpz::is_1(&gcd) {
            numer.div_exact_mut(&gcd);
            gcd.div_exact_from(rhs);
            *denom *= gcd;
        } else {
            *denom *= rhs;
        }
    }
    if denom.cmp0() == Ordering::Less {
        numer.neg_assign();
        denom.neg_assign();
    }
}

pub fn z_div<O: OptRational>(rop: &mut Rational, lhs: &Integer, rhs: O) {
    if O::IS_SOME {
        xmpz::check_div0(rhs.unwrap_parts().0);
    } else {
        xmpz::check_div0(rop.numer());
    }
    // Canonicalization is done in this function.
    //     gcd = gcd(lhs, rhs.numer)
    //     (numer, denom) = (lhs / gcd * rhs.denom, rhs.numer / gcd)
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    if O::IS_SOME {
        let (rhs_num, rhs_den) = rhs.unwrap_parts();
        // store gcd temporarily in numer
        numer.assign(rhs_num.gcd_ref(lhs));
        if !xmpz::is_1(numer) {
            denom.assign(rhs_num.div_exact_ref(numer));
            numer.div_exact_from(lhs);
            *numer *= rhs_den;
        } else {
            numer.assign(lhs * rhs_den);
            denom.assign(rhs_num);
        }
    } else {
        let mut gcd = Integer::from(numer.gcd_ref(lhs));
        mem::swap(numer, denom);
        if !xmpz::is_1(&gcd) {
            denom.div_exact_mut(&gcd);
            gcd.div_exact_from(lhs);
            *numer *= gcd;
        } else {
            *numer *= lhs;
        }
    }
    if denom.cmp0() == Ordering::Less {
        numer.neg_assign();
        denom.neg_assign();
    }
}

pub fn add_ui<O: OptRational>(rop: &mut Rational, lhs: O, rhs: c_ulong) {
    set(rop, lhs);
    // No canonicalization is necessary, as (numer + rhs * denom) is
    // not divisible by denom when numer is not divisible by denom.
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    *numer += rhs * &*denom;
}

pub fn sub_ui<O: OptRational>(rop: &mut Rational, lhs: O, rhs: c_ulong) {
    set(rop, lhs);
    // No canonicalization is necessary, as (numer + rhs * denom) is
    // not divisible by denom when numer is not divisible by denom.
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    *numer -= rhs * &*denom;
}

pub fn ui_sub<O: OptRational>(rop: &mut Rational, lhs: c_ulong, rhs: O) {
    set(rop, rhs);
    // No canonicalization is necessary, as (numer + rhs * denom) is
    // not divisible by denom when numer is not divisible by denom.
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    numer.sub_from(lhs * &*denom);
}

#[inline]
pub fn add_si<O: OptRational>(rop: &mut Rational, op1: O, op2: c_long) {
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
pub fn sub_si<O: OptRational>(rop: &mut Rational, lhs: O, rhs: c_long) {
    match rhs.neg_abs() {
        (false, rhs_abs) => {
            sub_ui(rop, lhs, rhs_abs);
        }
        (true, rhs_abs) => {
            add_ui(rop, lhs, rhs_abs);
        }
    }
}

#[inline]
pub fn si_sub<O: OptRational>(rop: &mut Rational, lhs: c_long, rhs: O) {
    match lhs.neg_abs() {
        (false, lhs_abs) => {
            ui_sub(rop, lhs_abs, rhs);
        }
        (true, lhs_abs) => {
            add_ui(rop, rhs, lhs_abs);
            neg(rop, ());
        }
    }
}

pub fn mul_ui<O: OptRational>(rop: &mut Rational, lhs: O, rhs: c_ulong) {
    if rhs == 0 {
        set_0(rop);
        return;
    }
    // Canonicalization is done in this function.
    //     gcd = gcd(lhs.denom, rhs), cannot be zero because rhs ≠ 0
    //     (numer, denom) = (rhs / gcd * lhs.numer, lhs.denom / gcd)
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    if O::IS_SOME {
        let (lhs_num, lhs_den) = lhs.unwrap_parts();
        let gcd = xmpz::gcd_ui(None, lhs_den, rhs);
        if gcd != 1 {
            numer.assign(rhs / gcd * lhs_num);
            xmpz::divexact_ui(denom, lhs_den, gcd);
        } else {
            numer.assign(rhs * lhs_num);
            denom.assign(lhs_den);
        }
    } else {
        let gcd = xmpz::gcd_ui(None, &*denom, rhs);
        if gcd != 1 {
            *numer *= rhs / gcd;
            xmpz::divexact_ui(denom, (), gcd);
        } else {
            *numer *= rhs;
        }
    }
}

pub fn div_ui<O: OptRational>(rop: &mut Rational, lhs: O, rhs: c_ulong) {
    assert_ne!(rhs, 0, "division by zero");
    // Canonicalization is done in this function.
    //     gcd = gcd(lhs.numer, rhs), cannot be zero because rhs ≠ 0
    //     (numer, denom) = (lhs.numer / gcd, rhs / gcd * lhs.denom)
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    if O::IS_SOME {
        let (lhs_num, lhs_den) = lhs.unwrap_parts();
        let gcd = xmpz::gcd_ui(None, lhs_num, rhs);
        if gcd != 1 {
            xmpz::divexact_ui(numer, lhs_num, gcd);
            denom.assign(rhs / gcd * lhs_den);
        } else {
            numer.assign(lhs_num);
            denom.assign(rhs * lhs_den);
        }
    } else {
        let gcd = xmpz::gcd_ui(None, &*numer, rhs);
        if gcd != 1 {
            xmpz::divexact_ui(numer, (), gcd);
            *denom *= rhs / gcd;
        } else {
            *denom *= rhs;
        }
    }
    // since rhs is positive, denom is positive
}

pub fn ui_div<O: OptRational>(rop: &mut Rational, lhs: c_ulong, rhs: O) {
    if O::IS_SOME {
        xmpz::check_div0(rhs.unwrap_parts().0);
    } else {
        xmpz::check_div0(rop.numer());
    }
    if lhs == 0 {
        set_0(rop);
        return;
    }
    // Canonicalization is done in this function.
    //     gcd = gcd(lhs, rhs.numer), cannot be zero because lhs ≠ 0
    //     (numer, denom) = (lhs / gcd * rhs.denom, rhs.numer / gcd)
    let (numer, denom) = unsafe { rop.as_mut_numer_denom_no_canonicalization() };
    if O::IS_SOME {
        let (rhs_num, rhs_den) = rhs.unwrap_parts();
        let gcd = xmpz::gcd_ui(None, rhs_num, lhs);
        if gcd != 1 {
            numer.assign(lhs / gcd * rhs_den);
            xmpz::divexact_ui(denom, rhs_num, gcd);
        } else {
            numer.assign(lhs * rhs_den);
            denom.assign(rhs_num);
        }
    } else {
        let gcd = xmpz::gcd_ui(None, &*numer, lhs);
        mem::swap(numer, denom);
        if gcd != 1 {
            *numer *= lhs / gcd;
            xmpz::divexact_ui(denom, (), gcd);
        } else {
            *numer *= lhs;
        }
    }
    if denom.cmp0() == Ordering::Less {
        numer.neg_assign();
        denom.neg_assign();
    }
}

#[inline]
pub fn mul_si<O: OptRational>(rop: &mut Rational, lhs: O, rhs: c_long) {
    let (rhs_neg, rhs_abs) = rhs.neg_abs();
    mul_ui(rop, lhs, rhs_abs);
    if rhs_neg {
        neg(rop, ());
    }
}

#[inline]
pub fn div_si<O: OptRational>(rop: &mut Rational, lhs: O, rhs: c_long) {
    let (rhs_neg, rhs_abs) = rhs.neg_abs();
    div_ui(rop, lhs, rhs_abs);
    if rhs_neg {
        neg(rop, ());
    }
}

#[inline]
pub fn si_div<O: OptRational>(rop: &mut Rational, lhs: c_long, rhs: O) {
    let (lhs_neg, lhs_abs) = lhs.neg_abs();
    ui_div(rop, lhs_abs, rhs);
    if lhs_neg {
        neg(rop, ());
    }
}

#[cfg(test)]
mod tests {
    use crate::{ext::xmpq, Assign, Integer, Rational};

    #[test]
    fn check_add_sub_z() {
        let mut r = Rational::from((13, 7));
        let i = Integer::from(-5);

        // 13/7 + -5 = -22/7
        xmpq::add_z(&mut r, (), &i);
        assert_eq!(*r.numer(), -22);
        assert_eq!(*r.denom(), 7);

        // -22/7 - -5 = 13/7
        xmpq::sub_z(&mut r, (), &i);
        assert_eq!(*r.numer(), 13);
        assert_eq!(*r.denom(), 7);

        // -5 - 13/7 = -48/7
        xmpq::z_sub(&mut r, &i, ());
        assert_eq!(*r.numer(), -48);
        assert_eq!(*r.denom(), 7);
    }

    #[test]
    fn check_mul_z() {
        let mut r = Rational::from((13, 10));
        let mut rr = Rational::new();
        let mut i = Integer::from(-6);

        // 13/10 * -6 = -39/5
        xmpq::mul_z(&mut rr, &r, &i);
        assert_eq!(*rr.numer(), -39);
        assert_eq!(*rr.denom(), 5);
        // 13/10 * 6 = 39/5
        xmpq::mul_z(&mut r, (), &i.as_neg());
        assert_eq!(*r.numer(), 39);
        assert_eq!(*r.denom(), 5);

        rr.assign(0);

        // 39/5 * -6 = -234/5
        xmpq::mul_z(&mut rr, &r, &i);
        assert_eq!(*rr.numer(), -234);
        assert_eq!(*rr.denom(), 5);
        // 39/5 * 6 = 234/5
        xmpq::mul_z(&mut r, (), &i.as_neg());
        assert_eq!(*r.numer(), 234);
        assert_eq!(*r.denom(), 5);

        i.assign(0);
        xmpq::mul_z(&mut r, (), &i);
        assert_eq!(*r.numer(), 0);
        assert_eq!(*r.denom(), 1);
    }

    #[test]
    fn check_div_z() {
        let mut r = Rational::from((10, 13));
        let mut rr = Rational::new();
        let i = Integer::from(-6);

        // 10/13 / -6 = -5/39
        xmpq::div_z(&mut rr, &r, &i);
        assert_eq!(*rr.numer(), -5);
        assert_eq!(*rr.denom(), 39);
        // 10/13 / 6 = 5/39
        xmpq::div_z(&mut r, (), &i.as_neg());
        assert_eq!(*r.numer(), 5);
        assert_eq!(*r.denom(), 39);

        rr.assign(0);

        // 5/39 / -6 = -5/234
        xmpq::div_z(&mut rr, &r, &i);
        assert_eq!(*rr.numer(), -5);
        assert_eq!(*rr.denom(), 234);
        // 5/39 / 6 = 5/234
        xmpq::div_z(&mut r, (), &i.as_neg());
        assert_eq!(*r.numer(), 5);
        assert_eq!(*r.denom(), 234);
    }

    #[test]
    fn check_z_div() {
        let mut r = Rational::from((10, 13));
        let mut rr = Rational::new();
        let i = Integer::from(-6);

        // -6 / 10/13 = -39/5
        xmpq::z_div(&mut rr, &i, &r);
        assert_eq!(*rr.numer(), -39);
        assert_eq!(*rr.denom(), 5);
        // 6 / 10/13 / 6 = 39/5
        xmpq::z_div(&mut r, &i.as_neg(), ());
        assert_eq!(*r.numer(), 39);
        assert_eq!(*r.denom(), 5);

        rr.assign(0);
        r.recip_mut();

        // -6 / 39/5 = -234/5
        xmpq::z_div(&mut rr, &i, &r);
        assert_eq!(*rr.numer(), -234);
        assert_eq!(*rr.denom(), 5);
        // 6 / 39/5 = 234/5
        xmpq::z_div(&mut r, &i.as_neg(), ());
        assert_eq!(*r.numer(), 234);
        assert_eq!(*r.denom(), 5);
    }

    #[test]
    fn check_add_sub_ui_si() {
        let mut r = Rational::from((13, 7));
        let mut rr = Rational::new();

        // 13/7 + -5 = -22/7
        xmpq::add_si(&mut rr, &r, -5);
        assert_eq!(*rr.numer(), -22);
        assert_eq!(*rr.denom(), 7);
        // 13/7 + 5 = 48/7
        xmpq::add_si(&mut rr, &r, 5);
        assert_eq!(*rr.numer(), 48);
        assert_eq!(*rr.denom(), 7);
        xmpq::add_ui(&mut r, (), 5);
        assert_eq!(*r.numer(), 48);
        assert_eq!(*r.denom(), 7);

        rr.assign(0);

        // 48/7 - -5 = 83/7
        xmpq::sub_si(&mut rr, &r, -5);
        assert_eq!(*rr.numer(), 83);
        assert_eq!(*rr.denom(), 7);
        // 48/7 - 5 = 13/7
        xmpq::sub_si(&mut rr, &r, 5);
        assert_eq!(*rr.numer(), 13);
        assert_eq!(*rr.denom(), 7);
        xmpq::sub_ui(&mut r, (), 5);
        assert_eq!(*r.numer(), 13);
        assert_eq!(*r.denom(), 7);

        rr.assign(0);

        // -5 - 13/7 = -48/7
        xmpq::si_sub(&mut rr, -5, &r);
        assert_eq!(*rr.numer(), -48);
        assert_eq!(*rr.denom(), 7);
        // 5 - 13/7 = 22/7
        xmpq::si_sub(&mut rr, 5, &r);
        assert_eq!(*rr.numer(), 22);
        assert_eq!(*rr.denom(), 7);
        xmpq::ui_sub(&mut r, 5, ());
        assert_eq!(*r.numer(), 22);
        assert_eq!(*r.denom(), 7);
    }

    #[test]
    fn check_mul_ui_si() {
        let mut r = Rational::from((13, 10));
        let mut rr = Rational::new();

        // 13/10 * -6 = -39/5
        xmpq::mul_si(&mut rr, &r, -6);
        assert_eq!(*rr.numer(), -39);
        assert_eq!(*rr.denom(), 5);
        // 13/10 * 6 = 39/5
        xmpq::mul_si(&mut rr, &r, 6);
        assert_eq!(*rr.numer(), 39);
        assert_eq!(*rr.denom(), 5);
        xmpq::mul_ui(&mut r, (), 6);
        assert_eq!(*r.numer(), 39);
        assert_eq!(*r.denom(), 5);

        rr.assign(0);

        // 39/5 * -6 = -234/5
        xmpq::mul_si(&mut rr, &r, -6);
        assert_eq!(*rr.numer(), -234);
        assert_eq!(*rr.denom(), 5);
        // 39/5 * 6 = 234/5
        xmpq::mul_si(&mut rr, &r, 6);
        assert_eq!(*rr.numer(), 234);
        assert_eq!(*rr.denom(), 5);
        xmpq::mul_ui(&mut r, (), 6);
        assert_eq!(*r.numer(), 234);
        assert_eq!(*r.denom(), 5);

        xmpq::mul_si(&mut rr, &r, 0);
        assert_eq!(*rr.numer(), 0);
        assert_eq!(*rr.denom(), 1);
        xmpq::mul_ui(&mut r, (), 0);
        assert_eq!(*r.numer(), 0);
        assert_eq!(*r.denom(), 1);
    }

    #[test]
    fn check_div_ui_si() {
        let mut r = Rational::from((10, 13));
        let mut rr = Rational::new();

        // 10/13 / -6 = -5/39
        xmpq::div_si(&mut rr, &r, -6);
        assert_eq!(*rr.numer(), -5);
        assert_eq!(*rr.denom(), 39);
        // 10/13 / 6 = 5/39
        xmpq::div_si(&mut rr, &r, 6);
        assert_eq!(*rr.numer(), 5);
        assert_eq!(*rr.denom(), 39);
        xmpq::div_ui(&mut r, (), 6);
        assert_eq!(*r.numer(), 5);
        assert_eq!(*r.denom(), 39);

        rr.assign(0);

        // 5/39 / -6 = -5/234
        xmpq::div_si(&mut rr, &r, -6);
        assert_eq!(*rr.numer(), -5);
        assert_eq!(*rr.denom(), 234);
        // 5/39 / 6 = 5/234
        xmpq::div_si(&mut rr, &r, 6);
        assert_eq!(*rr.numer(), 5);
        assert_eq!(*rr.denom(), 234);
        xmpq::div_ui(&mut r, (), 6);
        assert_eq!(*r.numer(), 5);
        assert_eq!(*r.denom(), 234);
    }

    #[test]
    fn check_ui_si_div() {
        let mut r = Rational::from((10, 13));
        let mut rr = Rational::new();

        // -6 / 10/13 = -39/5
        xmpq::si_div(&mut rr, -6, &r);
        assert_eq!(*rr.numer(), -39);
        assert_eq!(*rr.denom(), 5);
        // 6 / 10/13 / 6 = 39/5
        xmpq::si_div(&mut rr, 6, &r);
        assert_eq!(*rr.numer(), 39);
        assert_eq!(*rr.denom(), 5);
        xmpq::ui_div(&mut r, 6, ());
        assert_eq!(*r.numer(), 39);
        assert_eq!(*r.denom(), 5);

        rr.assign(0);
        r.recip_mut();

        // -6 / 39/5 = -234/5
        xmpq::si_div(&mut rr, -6, &r);
        assert_eq!(*rr.numer(), -234);
        assert_eq!(*rr.denom(), 5);
        // 6 / 39/5 = 234/5
        xmpq::si_div(&mut rr, 6, &r);
        assert_eq!(*rr.numer(), 234);
        assert_eq!(*rr.denom(), 5);
        xmpq::ui_div(&mut r, 6, ());
        assert_eq!(*r.numer(), 234);
        assert_eq!(*r.denom(), 5);
    }
}
