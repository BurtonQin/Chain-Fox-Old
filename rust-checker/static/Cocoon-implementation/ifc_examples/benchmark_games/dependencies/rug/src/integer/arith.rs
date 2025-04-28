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
    integer::SmallInteger,
    ops::{
        AddFrom, BitAndFrom, BitOrFrom, BitXorFrom, DivFrom, MulFrom, NegAssign, NotAssign, Pow,
        PowAssign, RemFrom, SubFrom,
    },
    Assign, Integer,
};
use az::{CheckedAs, CheckedCast};
use core::{
    iter::{Product, Sum},
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div,
        DivAssign, Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub,
        SubAssign,
    },
};
use libc::{c_long, c_ulong};

arith_unary! {
    Integer;
    xmpz::neg;
    Neg { neg }
    NegAssign { neg_assign }
    NegIncomplete
}
arith_binary_self! {
    Integer;
    xmpz::add;
    Add { add }
    AddAssign { add_assign }
    AddFrom { add_from }
    AddIncomplete;
    rhs_has_more_alloc
}
arith_binary_self! {
    Integer;
    xmpz::sub;
    Sub { sub }
    SubAssign { sub_assign }
    SubFrom { sub_from }
    SubIncomplete;
    rhs_has_more_alloc
}
arith_binary_self! {
    Integer;
    xmpz::mul;
    Mul { mul }
    MulAssign { mul_assign }
    MulFrom { mul_from }
    MulIncomplete;
    rhs_has_more_alloc
}
arith_binary_self! {
    Integer;
    xmpz::tdiv_q;
    Div { div }
    DivAssign { div_assign }
    DivFrom { div_from }
    DivIncomplete;
    rhs_has_more_alloc
}
arith_binary_self! {
    Integer;
    xmpz::tdiv_r;
    Rem { rem }
    RemAssign { rem_assign }
    RemFrom { rem_from }
    RemIncomplete;
    rhs_has_more_alloc
}
arith_unary! {
    Integer;
    xmpz::com;
    Not { not }
    NotAssign { not_assign }
    NotIncomplete
}
arith_binary_self! {
    Integer;
    xmpz::and;
    BitAnd { bitand }
    BitAndAssign { bitand_assign }
    BitAndFrom { bitand_from }
    BitAndIncomplete;
    rhs_has_more_alloc
}
arith_binary_self! {
    Integer;
    xmpz::ior;
    BitOr { bitor }
    BitOrAssign { bitor_assign }
    BitOrFrom { bitor_from }
    BitOrIncomplete;
    rhs_has_more_alloc
}
arith_binary_self! {
    Integer;
    xmpz::xor;
    BitXor { bitxor }
    BitXorAssign { bitxor_assign }
    BitXorFrom { bitxor_from }
    BitXorIncomplete;
    rhs_has_more_alloc
}

arith_prim_commut! {
    Integer;
    PrimOps::add;
    Add { add }
    AddAssign { add_assign }
    AddFrom { add_from }
    i8, AddI8Incomplete;
    i16, AddI16Incomplete;
    i32, AddI32Incomplete;
    i64, AddI64Incomplete;
    i128, AddI128Incomplete;
    u8, AddU8Incomplete;
    u16, AddU16Incomplete;
    u32, AddU32Incomplete;
    u64, AddU64Incomplete;
    u128, AddU128Incomplete;
}
arith_prim_noncommut! {
    Integer;
    PrimOps::sub, PrimOps::sub_from;
    Sub { sub }
    SubAssign { sub_assign }
    SubFrom { sub_from }
    i8, SubI8Incomplete, SubFromI8Incomplete;
    i16, SubI16Incomplete, SubFromI16Incomplete;
    i32, SubI32Incomplete, SubFromI32Incomplete;
    i64, SubI64Incomplete, SubFromI64Incomplete;
    i128, SubI128Incomplete, SubFromI128Incomplete;
    u8, SubU8Incomplete, SubFromU8Incomplete;
    u16, SubU16Incomplete, SubFromU16Incomplete;
    u32, SubU32Incomplete, SubFromU32Incomplete;
    u64, SubU64Incomplete, SubFromU64Incomplete;
    u128, SubU128Incomplete, SubFromU128Incomplete;
}
arith_prim_commut! {
    Integer;
    PrimOps::mul;
    Mul { mul }
    MulAssign { mul_assign }
    MulFrom { mul_from }
    i8, MulI8Incomplete;
    i16, MulI16Incomplete;
    i32, MulI32Incomplete;
    i64, MulI64Incomplete;
    i128, MulI128Incomplete;
    u8, MulU8Incomplete;
    u16, MulU16Incomplete;
    u32, MulU32Incomplete;
    u64, MulU64Incomplete;
    u128, MulU128Incomplete;
}
arith_prim_noncommut! {
    Integer;
    PrimOps::div, PrimOps::div_from;
    Div { div }
    DivAssign { div_assign }
    DivFrom { div_from }
    i8, DivI8Incomplete, DivFromI8Incomplete;
    i16, DivI16Incomplete, DivFromI16Incomplete;
    i32, DivI32Incomplete, DivFromI32Incomplete;
    i64, DivI64Incomplete, DivFromI64Incomplete;
    i128, DivI128Incomplete, DivFromI128Incomplete;
    u8, DivU8Incomplete, DivFromU8Incomplete;
    u16, DivU16Incomplete, DivFromU16Incomplete;
    u32, DivU32Incomplete, DivFromU32Incomplete;
    u64, DivU64Incomplete, DivFromU64Incomplete;
    u128, DivU128Incomplete, DivFromU128Incomplete;
}
arith_prim_noncommut! {
    Integer;
    PrimOps::rem, PrimOps::rem_from;
    Rem { rem }
    RemAssign { rem_assign }
    RemFrom { rem_from }
    i8, RemI8Incomplete, RemFromI8Incomplete;
    i16, RemI16Incomplete, RemFromI16Incomplete;
    i32, RemI32Incomplete, RemFromI32Incomplete;
    i64, RemI64Incomplete, RemFromI64Incomplete;
    i128, RemI128Incomplete, RemFromI128Incomplete;
    u8, RemU8Incomplete, RemFromU8Incomplete;
    u16, RemU16Incomplete, RemFromU16Incomplete;
    u32, RemU32Incomplete, RemFromU32Incomplete;
    u64, RemU64Incomplete, RemFromU64Incomplete;
    u128, RemU128Incomplete, RemFromU128Incomplete;
}
arith_prim_commut! {
    Integer;
    PrimOps::and;
    BitAnd { bitand }
    BitAndAssign { bitand_assign }
    BitAndFrom { bitand_from }
    i8, BitAndI8Incomplete;
    i16, BitAndI16Incomplete;
    i32, BitAndI32Incomplete;
    i64, BitAndI64Incomplete;
    i128, BitAndI128Incomplete;
    u8, BitAndU8Incomplete;
    u16, BitAndU16Incomplete;
    u32, BitAndU32Incomplete;
    u64, BitAndU64Incomplete;
    u128, BitAndU128Incomplete;
}
arith_prim_commut! {
    Integer;
    PrimOps::ior;
    BitOr { bitor }
    BitOrAssign { bitor_assign }
    BitOrFrom { bitor_from }
    i8, BitOrI8Incomplete;
    i16, BitOrI16Incomplete;
    i32, BitOrI32Incomplete;
    i64, BitOrI64Incomplete;
    i128, BitOrI128Incomplete;
    u8, BitOrU8Incomplete;
    u16, BitOrU16Incomplete;
    u32, BitOrU32Incomplete;
    u64, BitOrU64Incomplete;
    u128, BitOrU128Incomplete;
}
arith_prim_commut! {
    Integer;
    PrimOps::xor;
    BitXor { bitxor }
    BitXorAssign { bitxor_assign }
    BitXorFrom { bitxor_from }
    i8, BitXorI8Incomplete;
    i16, BitXorI16Incomplete;
    i32, BitXorI32Incomplete;
    i64, BitXorI64Incomplete;
    i128, BitXorI128Incomplete;
    u8, BitXorU8Incomplete;
    u16, BitXorU16Incomplete;
    u32, BitXorU32Incomplete;
    u64, BitXorU64Incomplete;
    u128, BitXorU128Incomplete;
}

arith_prim! {
    Integer;
    xmpz::shl_i32;
    Shl { shl }
    ShlAssign { shl_assign }
    i32, ShlI32Incomplete;
}
arith_prim! {
    Integer;
    xmpz::shr_i32;
    Shr { shr }
    ShrAssign { shr_assign }
    i32, ShrI32Incomplete;
}
arith_prim! {
    Integer;
    xmpz::shl_u32;
    Shl { shl }
    ShlAssign { shl_assign }
    u32, ShlU32Incomplete;
}
arith_prim! {
    Integer;
    xmpz::shr_u32;
    Shr { shr }
    ShrAssign { shr_assign }
    u32, ShrU32Incomplete;
}
arith_prim! {
    Integer;
    xmpz::pow_u32;
    Pow { pow }
    PowAssign { pow_assign }
    u32, PowU32Incomplete;
}

mul_op_commut! {
    Integer;
    xmpz::addmul;
    Add { add }
    AddAssign { add_assign }
    AddFrom { add_from }
    MulIncomplete, AddMulIncomplete;
}
mul_op_noncommut! {
    Integer;
    xmpz::submul, xmpz::mulsub;
    Sub { sub }
    SubAssign { sub_assign }
    SubFrom { sub_from }
    MulIncomplete, SubMulIncomplete, SubMulFromIncomplete;
}
mul_op_commut! {
    Integer;
    PrimOps::addmul;
    Add { add }
    AddAssign { add_assign }
    AddFrom { add_from }
    MulI8Incomplete, AddMulI8Incomplete;
    MulI16Incomplete, AddMulI16Incomplete;
    MulI32Incomplete, AddMulI32Incomplete;
    MulI64Incomplete, AddMulI64Incomplete;
    MulI128Incomplete, AddMulI128Incomplete;
    MulU8Incomplete, AddMulU8Incomplete;
    MulU16Incomplete, AddMulU16Incomplete;
    MulU32Incomplete, AddMulU32Incomplete;
    MulU64Incomplete, AddMulU64Incomplete;
    MulU128Incomplete, AddMulU128Incomplete;
}
mul_op_noncommut! {
    Integer;
    PrimOps::submul, PrimOps::mulsub;
    Sub { sub }
    SubAssign { sub_assign }
    SubFrom { sub_from }
    MulI8Incomplete, SubMulI8Incomplete, SubMulFromI8Incomplete;
    MulI16Incomplete, SubMulI16Incomplete, SubMulFromI16Incomplete;
    MulI32Incomplete, SubMulI32Incomplete, SubMulFromI32Incomplete;
    MulI64Incomplete, SubMulI64Incomplete, SubMulFromI64Incomplete;
    MulI128Incomplete, SubMulI128Incomplete, SubMulFromI128Incomplete;
    MulU8Incomplete, SubMulU8Incomplete, SubMulFromU8Incomplete;
    MulU16Incomplete, SubMulU16Incomplete, SubMulFromU16Incomplete;
    MulU32Incomplete, SubMulU32Incomplete, SubMulFromU32Incomplete;
    MulU64Incomplete, SubMulU64Incomplete, SubMulFromU64Incomplete;
    MulU128Incomplete, SubMulU128Incomplete, SubMulFromU128Incomplete;
}

trait PrimOps<Long>: AsLong {
    fn add<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn sub<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn sub_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn mul<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn div<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn div_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn rem<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn rem_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn and<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn ior<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn xor<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn addmul(rop: &mut Integer, op1: &Integer, op2: Self);
    fn submul(rop: &mut Integer, op1: &Integer, op2: Self);
    fn mulsub(rop: &mut Integer, op1: &Integer, op2: Self);
}

pub trait AsLong: Copy {
    type Long;
}

macro_rules! as_long {
    ($Long:ty: $($Prim:ty)*) => { $(
        impl AsLong for $Prim {
            type Long = $Long;
        }
    )* }
}

as_long! { c_long: i8 i16 i32 i64 i128 isize }
as_long! { c_ulong: u8 u16 u32 u64 u128 usize }

macro_rules! forward {
    (fn $fn:ident() -> $deleg_long:path, $deleg:path) => {
        #[inline]
        fn $fn<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self) {
            if let Some(op2) = op2.checked_as() {
                $deleg_long(rop, op1, op2);
            } else {
                let small: SmallInteger = op2.into();
                $deleg(rop, op1, &*small);
            }
        }
    };
}
macro_rules! reverse {
    (fn $fn:ident() -> $deleg_long:path, $deleg:path) => {
        #[inline]
        fn $fn<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O) {
            if let Some(op1) = op1.checked_as() {
                $deleg_long(rop, op1, op2);
            } else {
                let small: SmallInteger = op1.into();
                $deleg(rop, &*small, op2);
            }
        }
    };
}

impl<T> PrimOps<c_long> for T
where
    T: AsLong<Long = c_long> + CheckedCast<c_long> + Into<SmallInteger>,
{
    forward! { fn add() -> xmpz::add_si, xmpz::add }
    forward! { fn sub() -> xmpz::sub_si, xmpz::sub }
    reverse! { fn sub_from() -> xmpz::si_sub, xmpz::sub }
    forward! { fn mul() -> xmpz::mul_si, xmpz::mul }
    forward! { fn div() -> xmpz::tdiv_q_si, xmpz::tdiv_q }
    reverse! { fn div_from() -> xmpz::si_tdiv_q, xmpz::tdiv_q }
    forward! { fn rem() -> xmpz::tdiv_r_si, xmpz::tdiv_r }
    reverse! { fn rem_from() -> xmpz::si_tdiv_r, xmpz::tdiv_r }
    forward! { fn and() -> xmpz::and_si, xmpz::and }
    forward! { fn ior() -> xmpz::ior_si, xmpz::ior }
    forward! { fn xor() -> xmpz::xor_si, xmpz::xor }

    #[inline]
    fn addmul(rop: &mut Integer, op1: &Integer, op2: Self) {
        if let Some(op2) = op2.checked_as() {
            xmpz::addmul_si(rop, op1, op2);
        } else {
            let small: SmallInteger = op2.into();
            xmpz::addmul(rop, op1, &*small);
        }
    }

    #[inline]
    fn submul(rop: &mut Integer, op1: &Integer, op2: Self) {
        if let Some(op2) = op2.checked_as() {
            xmpz::submul_si(rop, op1, op2);
        } else {
            let small: SmallInteger = op2.into();
            xmpz::submul(rop, op1, &*small);
        }
    }

    #[inline]
    fn mulsub(rop: &mut Integer, op1: &Integer, op2: Self) {
        if let Some(op2) = op2.checked_as() {
            xmpz::mulsub_si(rop, op1, op2);
        } else {
            let small: SmallInteger = op2.into();
            xmpz::mulsub(rop, op1, &*small);
        }
    }
}

impl<T> PrimOps<c_ulong> for T
where
    T: AsLong<Long = c_ulong> + CheckedCast<c_ulong> + Into<SmallInteger>,
{
    forward! { fn add() -> xmpz::add_ui, xmpz::add }
    forward! { fn sub() -> xmpz::sub_ui, xmpz::sub }
    reverse! { fn sub_from() -> xmpz::ui_sub, xmpz::sub }
    forward! { fn mul() -> xmpz::mul_ui, xmpz::mul }
    forward! { fn div() -> xmpz::tdiv_q_ui, xmpz::tdiv_q }
    reverse! { fn div_from() -> xmpz::ui_tdiv_q, xmpz::tdiv_q }
    forward! { fn rem() -> xmpz::tdiv_r_ui, xmpz::tdiv_r }
    reverse! { fn rem_from() -> xmpz::ui_tdiv_r, xmpz::tdiv_r }
    forward! { fn and() -> xmpz::and_ui, xmpz::and }
    forward! { fn ior() -> xmpz::ior_ui, xmpz::ior }
    forward! { fn xor() -> xmpz::xor_ui, xmpz::xor }

    #[inline]
    fn addmul(rop: &mut Integer, op1: &Integer, op2: Self) {
        if let Some(op2) = op2.checked_as() {
            xmpz::addmul_ui(rop, op1, op2);
        } else {
            let small: SmallInteger = op2.into();
            xmpz::addmul(rop, op1, &*small);
        }
    }

    #[inline]
    fn submul(rop: &mut Integer, op1: &Integer, op2: Self) {
        if let Some(op2) = op2.checked_as() {
            xmpz::submul_ui(rop, op1, op2);
        } else {
            let small: SmallInteger = op2.into();
            xmpz::submul(rop, op1, &*small);
        }
    }

    #[inline]
    fn mulsub(rop: &mut Integer, op1: &Integer, op2: Self) {
        if let Some(op2) = op2.checked_as() {
            xmpz::mulsub_ui(rop, op1, op2);
        } else {
            let small: SmallInteger = op2.into();
            xmpz::mulsub(rop, op1, &*small);
        }
    }
}

impl<T> Sum<T> for Integer
where
    Integer: AddAssign<T>,
{
    fn sum<I>(iter: I) -> Integer
    where
        I: Iterator<Item = T>,
    {
        let mut ret = Integer::new();
        for i in iter {
            ret.add_assign(i);
        }
        ret
    }
}

impl<T> Product<T> for Integer
where
    Integer: MulAssign<T>,
{
    fn product<I>(iter: I) -> Integer
    where
        I: Iterator<Item = T>,
    {
        let mut ret = Integer::from(1);
        for i in iter {
            ret.mul_assign(i);
        }
        ret
    }
}

#[inline]
fn rhs_has_more_alloc(lhs: &Integer, rhs: &Integer) -> bool {
    lhs.inner().alloc < rhs.inner().alloc
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod tests {
    use crate::{
        ops::{AddFrom, Pow, SubFrom},
        Integer,
    };
    use core::{
        cmp::Ordering,
        ops::{AddAssign, SubAssign},
    };

    macro_rules! test_op {
        ($lhs:ident $op:tt $rhs:ident) => {
            let ans = $lhs.clone() $op $rhs.clone();
            assert_eq!(ans, $lhs.clone() $op $rhs);
            assert_eq!(ans, $lhs $op $rhs.clone());
            assert_eq!(ans, Integer::from($lhs $op $rhs));
        };
    }

    #[test]
    fn check_arith() {
        use crate::tests::{I128, I32, I64, U128, U32, U64};
        let large = [(1, 100), (-11, 200), (33, 150)];
        let all = (large.iter().map(|&(n, s)| Integer::from(n) << s))
            .chain(U32.iter().map(|&x| Integer::from(x)))
            .chain(I32.iter().map(|&x| Integer::from(x)))
            .chain(U64.iter().map(|&x| Integer::from(x)))
            .chain(I64.iter().map(|&x| Integer::from(x)))
            .chain(U128.iter().map(|&x| Integer::from(x)))
            .chain(I128.iter().map(|&x| Integer::from(x)))
            .collect::<Vec<Integer>>();

        for l in &all {
            for r in &all {
                test_op!(l + r);
                test_op!(l - r);
                test_op!(l * r);
                if r.cmp0() != Ordering::Equal {
                    test_op!(l / r);
                }
                test_op!(l & r);
                test_op!(l | r);
                test_op!(l ^ r);
            }
        }
    }

    macro_rules! check_u_s {
        ($list:expr, $against:expr) => {
            for &op in $list {
                let iop = Integer::from(op);
                for b in &$against {
                    assert_eq!(b.clone() + op, b.clone() + &iop);
                    assert_eq!(b.clone() - op, b.clone() - &iop);
                    assert_eq!(b.clone() * op, b.clone() * &iop);
                    if op != 0 {
                        assert_eq!(b.clone() / op, b.clone() / &iop);
                        assert_eq!(b.clone() % op, b.clone() % &iop);
                    }
                    assert_eq!(b.clone() & op, b.clone() & &iop);
                    assert_eq!(b.clone() | op, b.clone() | &iop);
                    assert_eq!(b.clone() ^ op, b.clone() ^ &iop);
                    assert_eq!(op + b.clone(), iop.clone() + b);
                    assert_eq!(op - b.clone(), iop.clone() - b);
                    assert_eq!(op * b.clone(), iop.clone() * b);
                    if b.cmp0() != Ordering::Equal {
                        assert_eq!(op / b.clone(), iop.clone() / b);
                        assert_eq!(op % b.clone(), iop.clone() % b);
                    }
                    assert_eq!(op & b.clone(), iop.clone() & b);
                    assert_eq!(op | b.clone(), iop.clone() | b);
                    assert_eq!(op ^ b.clone(), iop.clone() ^ b);
                }
            }
        };
    }

    #[test]
    fn check_arith_u_s() {
        use crate::tests::{I128, I16, I32, I64, I8, U128, U16, U32, U64, U8};
        let large = [(1, 100), (-11, 200), (33, 150)];
        let against = (large.iter().map(|&(n, s)| Integer::from(n) << s))
            .chain(U32.iter().map(|&x| Integer::from(x)))
            .chain(I32.iter().map(|&x| Integer::from(x)))
            .chain(U64.iter().map(|&x| Integer::from(x)))
            .chain(I64.iter().map(|&x| Integer::from(x)))
            .chain(U128.iter().map(|&x| Integer::from(x)))
            .chain(I128.iter().map(|&x| Integer::from(x)))
            .collect::<Vec<Integer>>();

        check_u_s!(I8, against);
        check_u_s!(I16, against);
        check_u_s!(I32, against);
        check_u_s!(I64, against);
        check_u_s!(I128, against);
        check_u_s!(U8, against);
        check_u_s!(U16, against);
        check_u_s!(U32, against);
        check_u_s!(U64, against);
        check_u_s!(U128, against);
    }

    macro_rules! test_ref_op {
        ($first:expr, $second:expr) => {
            assert_eq!(
                Integer::from($first),
                $second,
                "({}) != ({})",
                stringify!($first),
                stringify!($second)
            );
        };
    }

    #[test]
    fn check_ref_op() {
        let lhs = &Integer::from(0x00ff);
        let rhs = &Integer::from(0x0f0f);
        let pu = 30_u32;
        let pi = -15_i32;
        test_ref_op!(-lhs, -lhs.clone());
        test_ref_op!(lhs + rhs, lhs.clone() + rhs);
        test_ref_op!(lhs - rhs, lhs.clone() - rhs);
        test_ref_op!(lhs * rhs, lhs.clone() * rhs);
        test_ref_op!(lhs / rhs, lhs.clone() / rhs);
        test_ref_op!(lhs % rhs, lhs.clone() % rhs);
        test_ref_op!(!lhs, !lhs.clone());
        test_ref_op!(lhs & rhs, lhs.clone() & rhs);
        test_ref_op!(lhs | rhs, lhs.clone() | rhs);
        test_ref_op!(lhs ^ rhs, lhs.clone() ^ rhs);

        test_ref_op!(lhs + pu, lhs.clone() + pu);
        test_ref_op!(lhs - pu, lhs.clone() - pu);
        test_ref_op!(lhs * pu, lhs.clone() * pu);
        test_ref_op!(lhs / pu, lhs.clone() / pu);
        test_ref_op!(lhs % pu, lhs.clone() % pu);
        test_ref_op!(lhs & pu, lhs.clone() & pu);
        test_ref_op!(lhs | pu, lhs.clone() | pu);
        test_ref_op!(lhs ^ pu, lhs.clone() ^ pu);
        test_ref_op!(lhs << pu, lhs.clone() << pu);
        test_ref_op!(lhs >> pu, lhs.clone() >> pu);
        test_ref_op!(lhs.pow(pu), lhs.clone().pow(pu));

        test_ref_op!(lhs + pi, lhs.clone() + pi);
        test_ref_op!(lhs - pi, lhs.clone() - pi);
        test_ref_op!(lhs * pi, lhs.clone() * pi);
        test_ref_op!(lhs / pi, lhs.clone() / pi);
        test_ref_op!(lhs % pi, lhs.clone() % pi);
        test_ref_op!(lhs & pi, lhs.clone() & pi);
        test_ref_op!(lhs | pi, lhs.clone() | pi);
        test_ref_op!(lhs ^ pi, lhs.clone() ^ pi);
        test_ref_op!(lhs << pi, lhs.clone() << pi);
        test_ref_op!(lhs >> pi, lhs.clone() >> pi);

        test_ref_op!(pu + lhs, pu + lhs.clone());
        test_ref_op!(pu - lhs, pu - lhs.clone());
        test_ref_op!(pu * lhs, pu * lhs.clone());
        test_ref_op!(pu / lhs, pu / lhs.clone());
        test_ref_op!(pu % lhs, pu % lhs.clone());
        test_ref_op!(pu & lhs, pu & lhs.clone());
        test_ref_op!(pu | lhs, pu | lhs.clone());
        test_ref_op!(pu ^ lhs, pu ^ lhs.clone());

        test_ref_op!(pi + lhs, pi + lhs.clone());
        test_ref_op!(pi - lhs, pi - lhs.clone());
        test_ref_op!(pi * lhs, pi * lhs.clone());
        test_ref_op!(pi / lhs, pi / lhs.clone());
        test_ref_op!(pi % lhs, pi % lhs.clone());
        test_ref_op!(pi & lhs, pi & lhs.clone());
        test_ref_op!(pi | lhs, pi | lhs.clone());
        test_ref_op!(pi ^ lhs, pi ^ lhs.clone());
    }

    #[test]
    fn check_shift_u_s() {
        let pos = &(Integer::from(11) << 100u32);
        let neg = &(Integer::from(-33) << 50u32);
        assert_eq!(pos.clone() << 10, pos.clone() >> -10);
        assert_eq!(pos.clone() << 10, Integer::from(11) << 110);
        assert_eq!(pos.clone() << -100, pos.clone() >> 100);
        assert_eq!(pos.clone() << -100, 11);
        assert_eq!(neg.clone() << 10, neg.clone() >> -10);
        assert_eq!(neg.clone() << 10, Integer::from(-33) << 60);
        assert_eq!(neg.clone() << -100, neg.clone() >> 100);
        assert_eq!(neg.clone() << -100, -1);
    }

    fn check_single_addmul<F, T>(i: &mut Integer, j: &mut i32, f: F, u: i32)
    where
        F: Fn() -> T,
        Integer: AddAssign<T> + AddFrom<T>,
    {
        *i += f();
        *j += u;
        assert_eq!(i, j);
        i.add_from(f());
        j.add_from(u);
        assert_eq!(i, j);
    }

    fn check_single_submul<F, T>(i: &mut Integer, j: &mut i32, f: F, u: i32)
    where
        F: Fn() -> T,
        Integer: SubAssign<T> + SubFrom<T>,
    {
        *i -= f();
        *j -= u;
        assert_eq!(i, j);
        i.sub_from(f());
        j.sub_from(u);
        assert_eq!(i, j);
    }

    #[test]
    fn check_addmul() {
        let mut i = Integer::from(10);
        let mut j = 10i32;
        let two = Integer::from(2);

        check_single_addmul(&mut i, &mut j, || &two * &two, 2 * 2);
        check_single_addmul(&mut i, &mut j, || &two * 12u32, 2 * 12);
        check_single_addmul(&mut i, &mut j, || 13u32 * &two, 13 * 2);
        check_single_addmul(&mut i, &mut j, || &two * 14i32, 2 * 14);
        check_single_addmul(&mut i, &mut j, || 15i32 * &two, 15 * 2);
        check_single_addmul(&mut i, &mut j, || &two * -16i32, 2 * -16);
        check_single_addmul(&mut i, &mut j, || -17i32 * &two, -17 * 2);
    }

    #[test]
    fn check_submul() {
        let mut i = Integer::from(10);
        let mut j = 10i32;
        let two = Integer::from(2);

        check_single_submul(&mut i, &mut j, || &two * &two, 2 * 2);
        check_single_submul(&mut i, &mut j, || &two * 12u32, 2 * 12);
        check_single_submul(&mut i, &mut j, || 13u32 * &two, 13 * 2);
        check_single_submul(&mut i, &mut j, || &two * 14i32, 2 * 14);
        check_single_submul(&mut i, &mut j, || 15i32 * &two, 15 * 2);
        check_single_submul(&mut i, &mut j, || &two * -16i32, 2 * -16);
        check_single_submul(&mut i, &mut j, || -17i32 * &two, -17 * 2);
    }
}
