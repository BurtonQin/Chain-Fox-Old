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
        DivRounding, DivRoundingAssign, DivRoundingFrom, RemRounding, RemRoundingAssign,
        RemRoundingFrom,
    },
    Assign, Integer,
};
use az::{CheckedAs, CheckedCast};
use libc::{c_long, c_ulong};

// big / big -> Big
// big / &big -> Big
// &big / big -> Big
// &big / &big -> Incomplete
// big /= big
// big /= &big
// big /-> big
// &big /-> big
// struct Incomplete
// Incomplete -> Big
// big = Incomplete
macro_rules! div_op {
    (
        $trunc_fn:path, $ceil_fn:path, $floor_fn:path, $euc_fn:path;
        $Imp:ident $trunc:ident $ceil:ident $floor:ident $euc:ident;
        $ImpAssign:ident
            $trunc_assign:ident $ceil_assign:ident $floor_assign:ident $euc_assign:ident;
        $ImpFrom:ident $trunc_from:ident $ceil_from:ident $floor_from:ident $euc_from:ident;
        $Incomplete:ident
    ) => {
        impl $Imp for Integer {
            type Output = Integer;
            #[inline]
            fn $trunc(mut self, rhs: Integer) -> Integer {
                self.$trunc_assign(&rhs);
                self
            }
            #[inline]
            fn $ceil(mut self, rhs: Integer) -> Integer {
                self.$ceil_assign(&rhs);
                self
            }
            #[inline]
            fn $floor(mut self, rhs: Integer) -> Integer {
                self.$floor_assign(&rhs);
                self
            }
            #[inline]
            fn $euc(mut self, rhs: Integer) -> Integer {
                self.$euc_assign(&rhs);
                self
            }
        }

        impl $Imp<&Integer> for Integer {
            type Output = Integer;
            #[inline]
            fn $trunc(mut self, rhs: &Integer) -> Integer {
                self.$trunc_assign(rhs);
                self
            }
            #[inline]
            fn $ceil(mut self, rhs: &Integer) -> Integer {
                self.$ceil_assign(rhs);
                self
            }
            #[inline]
            fn $floor(mut self, rhs: &Integer) -> Integer {
                self.$floor_assign(rhs);
                self
            }
            #[inline]
            fn $euc(mut self, rhs: &Integer) -> Integer {
                self.$euc_assign(rhs);
                self
            }
        }

        impl $Imp<Integer> for &Integer {
            type Output = Integer;
            #[inline]
            fn $trunc(self, mut rhs: Integer) -> Integer {
                rhs.$trunc_from(self);
                rhs
            }
            #[inline]
            fn $ceil(self, mut rhs: Integer) -> Integer {
                rhs.$ceil_from(self);
                rhs
            }
            #[inline]
            fn $floor(self, mut rhs: Integer) -> Integer {
                rhs.$floor_from(self);
                rhs
            }
            #[inline]
            fn $euc(self, mut rhs: Integer) -> Integer {
                rhs.$euc_from(self);
                rhs
            }
        }

        impl<'i> $Imp for &'i Integer {
            type Output = $Incomplete<'i>;
            #[inline]
            fn $trunc(self, rhs: &'i Integer) -> $Incomplete<'_> {
                $Incomplete::Trunc(self, rhs)
            }
            #[inline]
            fn $ceil(self, rhs: &'i Integer) -> $Incomplete<'_> {
                $Incomplete::Ceil(self, rhs)
            }
            #[inline]
            fn $floor(self, rhs: &'i Integer) -> $Incomplete<'_> {
                $Incomplete::Floor(self, rhs)
            }
            #[inline]
            fn $euc(self, rhs: &'i Integer) -> $Incomplete<'_> {
                $Incomplete::Euc(self, rhs)
            }
        }

        impl $ImpAssign for Integer {
            #[inline]
            fn $trunc_assign(&mut self, rhs: Integer) {
                self.$trunc_assign(&rhs);
            }
            #[inline]
            fn $ceil_assign(&mut self, rhs: Integer) {
                self.$ceil_assign(&rhs);
            }
            #[inline]
            fn $floor_assign(&mut self, rhs: Integer) {
                self.$floor_assign(&rhs);
            }
            #[inline]
            fn $euc_assign(&mut self, rhs: Integer) {
                self.$euc_assign(&rhs);
            }
        }

        impl $ImpAssign<&Integer> for Integer {
            #[inline]
            fn $trunc_assign(&mut self, rhs: &Integer) {
                $trunc_fn(self, (), rhs);
            }
            #[inline]
            fn $ceil_assign(&mut self, rhs: &Integer) {
                $ceil_fn(self, (), rhs);
            }
            #[inline]
            fn $floor_assign(&mut self, rhs: &Integer) {
                $floor_fn(self, (), rhs);
            }
            #[inline]
            fn $euc_assign(&mut self, rhs: &Integer) {
                $euc_fn(self, (), rhs);
            }
        }

        impl $ImpFrom for Integer {
            #[inline]
            fn $trunc_from(&mut self, lhs: Integer) {
                self.$trunc_from(&lhs);
            }
            #[inline]
            fn $ceil_from(&mut self, lhs: Integer) {
                self.$ceil_from(&lhs);
            }
            #[inline]
            fn $floor_from(&mut self, lhs: Integer) {
                self.$floor_from(&lhs);
            }
            #[inline]
            fn $euc_from(&mut self, lhs: Integer) {
                self.$euc_from(&lhs);
            }
        }

        impl $ImpFrom<&Integer> for Integer {
            #[inline]
            fn $trunc_from(&mut self, lhs: &Integer) {
                $trunc_fn(self, lhs, ());
            }
            #[inline]
            fn $ceil_from(&mut self, lhs: &Integer) {
                $ceil_fn(self, lhs, ());
            }
            #[inline]
            fn $floor_from(&mut self, lhs: &Integer) {
                $floor_fn(self, lhs, ());
            }
            #[inline]
            fn $euc_from(&mut self, lhs: &Integer) {
                $euc_fn(self, lhs, ());
            }
        }

        #[derive(Debug)]
        pub enum $Incomplete<'i> {
            Trunc(&'i Integer, &'i Integer),
            Ceil(&'i Integer, &'i Integer),
            Floor(&'i Integer, &'i Integer),
            Euc(&'i Integer, &'i Integer),
        }

        impl Assign<$Incomplete<'_>> for Integer {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                match src {
                    $Incomplete::Trunc(lhs, rhs) => {
                        $trunc_fn(self, lhs, rhs);
                    }
                    $Incomplete::Ceil(lhs, rhs) => {
                        $ceil_fn(self, lhs, rhs);
                    }
                    $Incomplete::Floor(lhs, rhs) => {
                        $floor_fn(self, lhs, rhs);
                    }
                    $Incomplete::Euc(lhs, rhs) => {
                        $euc_fn(self, lhs, rhs);
                    }
                }
            }
        }

        impl From<$Incomplete<'_>> for Integer {
            #[inline]
            fn from(src: $Incomplete<'_>) -> Self {
                let mut dst = Integer::new();
                dst.assign(src);
                dst
            }
        }
    };
}

// big / prim -> Big
// big / &prim -> Big
// &big / prim -> Incomplete
// &big / &prim -> Incomplete
// big /= prim
// big /= &prim
// struct Incomplete
// Incomplete -> Big
// big = Incomplete
// prim / big -> Big
// prim / &big -> FromIncomplete
// &prim / big -> Big
// &prim / &big -> FromIncomplete
// prim /-> big
// &prim /-> big
// struct FromIncomplete
// FromIncomplete -> Big
// big = FromIncomplete
macro_rules! div_prim {
    (
        $trunc_fn:path, $ceil_fn:path, $floor_fn:path, $euc_fn:path;
        $trunc_from_fn:path, $ceil_from_fn:path, $floor_from_fn:path, $euc_from_fn:path;
        $Imp:ident $trunc:ident $ceil:ident $floor:ident $euc:ident;
        $ImpAssign:ident
            $trunc_assign:ident $ceil_assign:ident $floor_assign:ident $euc_assign:ident;
        $ImpFrom:ident $trunc_from:ident $ceil_from:ident $floor_from:ident $euc_from:ident;
        $($T:ty, $Incomplete:ident, $FromIncomplete:ident;)*
    ) => { $(
        impl $Imp<$T> for Integer {
            type Output = Integer;
            #[inline]
            fn $trunc(mut self, rhs: $T) -> Integer {
                self.$trunc_assign(rhs);
                self
            }
            #[inline]
            fn $ceil(mut self, rhs: $T) -> Integer {
                self.$ceil_assign(rhs);
                self
            }
            #[inline]
            fn $floor(mut self, rhs: $T) -> Integer {
                self.$floor_assign(rhs);
                self
            }
            #[inline]
            fn $euc(mut self, rhs: $T) -> Integer {
                self.$euc_assign(rhs);
                self
            }
        }

        impl $Imp<&$T> for Integer {
            type Output = Integer;
            #[inline]
            fn $trunc(mut self, rhs: &$T) -> Integer {
                self.$trunc_assign(*rhs);
                self
            }
            #[inline]
            fn $ceil(mut self, rhs: &$T) -> Integer {
                self.$ceil_assign(*rhs);
                self
            }
            #[inline]
            fn $floor(mut self, rhs: &$T) -> Integer {
                self.$floor_assign(*rhs);
                self
            }
            #[inline]
            fn $euc(mut self, rhs: &$T) -> Integer {
                self.$euc_assign(*rhs);
                self
            }
        }

        impl<'i> $Imp<$T> for &'i Integer {
            type Output = $Incomplete<'i>;
            #[inline]
            fn $trunc(self, rhs: $T) -> $Incomplete<'i> {
                $Incomplete::Trunc(self, rhs)
            }
            #[inline]
            fn $ceil(self, rhs: $T) -> $Incomplete<'i> {
                $Incomplete::Ceil(self, rhs)
            }
            #[inline]
            fn $floor(self, rhs: $T) -> $Incomplete<'i> {
                $Incomplete::Floor(self, rhs)
            }
            #[inline]
            fn $euc(self, rhs: $T) -> $Incomplete<'i> {
                $Incomplete::Euc(self, rhs)
            }
        }

        impl<'t, 'i> $Imp<&'t $T> for &'i Integer {
            type Output = $Incomplete<'i>;
            #[inline]
            fn $trunc(self, rhs: &$T) -> $Incomplete<'i> {
                self.$trunc(*rhs)
            }
            #[inline]
            fn $ceil(self, rhs: &$T) -> $Incomplete<'i> {
                self.$ceil(*rhs)
            }
            #[inline]
            fn $floor(self, rhs: &$T) -> $Incomplete<'i> {
                self.$floor(*rhs)
            }
            #[inline]
            fn $euc(self, rhs: &$T) -> $Incomplete<'i> {
                self.$euc(*rhs)
            }
        }

        impl $ImpAssign<$T> for Integer {
            #[inline]
            fn $trunc_assign(&mut self, rhs: $T) {
                $trunc_fn(self, (), rhs);
            }
            #[inline]
            fn $ceil_assign(&mut self, rhs: $T) {
                $ceil_fn(self, (), rhs);
            }
            #[inline]
            fn $floor_assign(&mut self, rhs: $T) {
                $floor_fn(self, (), rhs);
            }
            #[inline]
            fn $euc_assign(&mut self, rhs: $T) {
                $euc_fn(self, (), rhs);
            }
        }

        impl $ImpAssign<&$T> for Integer {
            #[inline]
            fn $trunc_assign(&mut self, rhs: &$T) {
                self.$trunc_assign(*rhs);
            }
            #[inline]
            fn $ceil_assign(&mut self, rhs: &$T) {
                self.$ceil_assign(*rhs);
            }
            #[inline]
            fn $floor_assign(&mut self, rhs: &$T) {
                self.$floor_assign(*rhs);
            }
            #[inline]
            fn $euc_assign(&mut self, rhs: &$T) {
                self.$euc_assign(*rhs);
            }
        }

        #[derive(Debug)]
        pub enum $Incomplete<'i> {
            Trunc(&'i Integer, $T),
            Ceil(&'i Integer, $T),
            Floor(&'i Integer, $T),
            Euc(&'i Integer, $T),
        }

        impl Assign<$Incomplete<'_>> for Integer {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                match src {
                    $Incomplete::Trunc(lhs, rhs) => {
                        $trunc_fn(self, lhs, rhs);
                    }
                    $Incomplete::Ceil(lhs, rhs) => {
                        $ceil_fn(self, lhs, rhs);
                    }
                    $Incomplete::Floor(lhs, rhs) => {
                        $floor_fn(self, lhs, rhs);
                    }
                    $Incomplete::Euc(lhs, rhs) => {
                        $euc_fn(self, lhs, rhs);
                    }
                }
            }
        }

        impl From<$Incomplete<'_>> for Integer {
            #[inline]
            fn from(src: $Incomplete<'_>) -> Self {
                let mut dst = Integer::new();
                dst.assign(src);
                dst
            }
        }

        impl $Imp<Integer> for $T {
            type Output = Integer;
            #[inline]
            fn $trunc(self, mut rhs: Integer) -> Integer {
                rhs.$trunc_from(self);
                rhs
            }
            #[inline]
            fn $ceil(self, mut rhs: Integer) -> Integer {
                rhs.$ceil_from(self);
                rhs
            }
            #[inline]
            fn $floor(self, mut rhs: Integer) -> Integer {
                rhs.$floor_from(self);
                rhs
            }
            #[inline]
            fn $euc(self, mut rhs: Integer) -> Integer {
                rhs.$euc_from(self);
                rhs
            }
        }

        impl<'i> $Imp<&'i Integer> for $T {
            type Output = $FromIncomplete<'i>;
            #[inline]
            fn $trunc(self, rhs: &Integer) -> $FromIncomplete<'_> {
                $FromIncomplete::Trunc(self, rhs)
            }
            #[inline]
            fn $ceil(self, rhs: &Integer) -> $FromIncomplete<'_> {
                $FromIncomplete::Ceil(self, rhs)
            }
            #[inline]
            fn $floor(self, rhs: &Integer) -> $FromIncomplete<'_> {
                $FromIncomplete::Floor(self, rhs)
            }
            #[inline]
            fn $euc(self, rhs: &Integer) -> $FromIncomplete<'_> {
                $FromIncomplete::Euc(self, rhs)
            }
        }

        impl $Imp<Integer> for &$T {
            type Output = Integer;
            #[inline]
            fn $trunc(self, mut rhs: Integer) -> Integer {
                rhs.$trunc_from(*self);
                rhs
            }
            #[inline]
            fn $ceil(self, mut rhs: Integer) -> Integer {
                rhs.$ceil_from(*self);
                rhs
            }
            #[inline]
            fn $floor(self, mut rhs: Integer) -> Integer {
                rhs.$floor_from(*self);
                rhs
            }
            #[inline]
            fn $euc(self, mut rhs: Integer) -> Integer {
                rhs.$euc_from(*self);
                rhs
            }
        }

        impl<'i> $Imp<&'i Integer> for &$T {
            type Output = $FromIncomplete<'i>;
            #[inline]
            fn $trunc(self, rhs: &'i Integer) -> $FromIncomplete<'i> {
                $Imp::$trunc(*self, rhs)
            }
            #[inline]
            fn $ceil(self, rhs: &'i Integer) -> $FromIncomplete<'i> {
                $Imp::$ceil(*self, rhs)
            }
            #[inline]
            fn $floor(self, rhs: &'i Integer) -> $FromIncomplete<'i> {
                $Imp::$floor(*self, rhs)
            }
            #[inline]
            fn $euc(self, rhs: &'i Integer) -> $FromIncomplete<'i> {
                $Imp::$euc(*self, rhs)
            }
        }

        impl $ImpFrom<$T> for Integer {
            #[inline]
            fn $trunc_from(&mut self, lhs: $T) {
                $trunc_from_fn(self, lhs, ());
            }
            #[inline]
            fn $ceil_from(&mut self, lhs: $T) {
                $ceil_from_fn(self, lhs, ());
            }
            #[inline]
            fn $floor_from(&mut self, lhs: $T) {
                $floor_from_fn(self, lhs, ());
            }
            #[inline]
            fn $euc_from(&mut self, lhs: $T) {
                $euc_from_fn(self, lhs, ());
            }
        }

        impl $ImpFrom<&$T> for Integer {
            #[inline]
            fn $trunc_from(&mut self, lhs: &$T) {
                self.$trunc_from(*lhs);
            }
            #[inline]
            fn $ceil_from(&mut self, lhs: &$T) {
                self.$ceil_from(*lhs);
            }
            #[inline]
            fn $floor_from(&mut self, lhs: &$T) {
                self.$floor_from(*lhs);
            }
            #[inline]
            fn $euc_from(&mut self, lhs: &$T) {
                self.$euc_from(*lhs);
            }
        }

        #[derive(Debug)]
        pub enum $FromIncomplete<'i> {
            Trunc($T, &'i Integer),
            Ceil($T, &'i Integer),
            Floor($T, &'i Integer),
            Euc($T, &'i Integer),
        }

        impl Assign<$FromIncomplete<'_>> for Integer {
            #[inline]
            fn assign(&mut self, src: $FromIncomplete<'_>) {
                match src {
                    $FromIncomplete::Trunc(lhs, rhs) => {
                        $trunc_from_fn(self, lhs, rhs);
                    }
                    $FromIncomplete::Ceil(lhs, rhs) => {
                        $ceil_from_fn(self, lhs, rhs);
                    }
                    $FromIncomplete::Floor(lhs, rhs) => {
                        $floor_from_fn(self, lhs, rhs);
                    }
                    $FromIncomplete::Euc(lhs, rhs) => {
                        $euc_from_fn(self, lhs, rhs);
                    }
                }
            }
        }

        impl From<$FromIncomplete<'_>> for Integer {
            #[inline]
            fn from(src: $FromIncomplete<'_>) -> Self {
                let mut dst = Integer::new();
                dst.assign(src);
                dst
            }
        }
    )* };
}

div_op! {
    xmpz::tdiv_q, xmpz::cdiv_q, xmpz::fdiv_q, xmpz::ediv_q;
    DivRounding div_trunc div_ceil div_floor div_euc;
    DivRoundingAssign div_trunc_assign div_ceil_assign div_floor_assign div_euc_assign;
    DivRoundingFrom div_trunc_from div_ceil_from div_floor_from div_euc_from;
    DivRoundingIncomplete
}
div_op! {
    xmpz::tdiv_r, xmpz::cdiv_r, xmpz::fdiv_r, xmpz::ediv_r;
    RemRounding rem_trunc rem_ceil rem_floor rem_euc;
    RemRoundingAssign rem_trunc_assign rem_ceil_assign rem_floor_assign rem_euc_assign;
    RemRoundingFrom rem_trunc_from rem_ceil_from rem_floor_from rem_euc_from;
    RemRoundingIncomplete
}

div_prim! {
    PrimOps::tdiv_q, PrimOps::cdiv_q, PrimOps::fdiv_q, PrimOps::ediv_q;
    PrimOps::tdiv_q_from, PrimOps::cdiv_q_from, PrimOps::fdiv_q_from, PrimOps::ediv_q_from;
    DivRounding div_trunc div_ceil div_floor div_euc;
    DivRoundingAssign div_trunc_assign div_ceil_assign div_floor_assign div_euc_assign;
    DivRoundingFrom div_trunc_from div_ceil_from div_floor_from div_euc_from;
    i8, DivRoundingI8Incomplete, DivRoundingFromI8Incomplete;
    i16, DivRoundingI16Incomplete, DivRoundingFromI16Incomplete;
    i32, DivRoundingI32Incomplete, DivRoundingFromI32Incomplete;
    i64, DivRoundingI64Incomplete, DivRoundingFromI64Incomplete;
    i128, DivRoundingI128Incomplete, DivRoundingFromI128Incomplete;
    u8, DivRoundingU8Incomplete, DivRoundingFromU8Incomplete;
    u16, DivRoundingU16Incomplete, DivRoundingFromU16Incomplete;
    u32, DivRoundingU32Incomplete, DivRoundingFromU32Incomplete;
    u64, DivRoundingU64Incomplete, DivRoundingFromU64Incomplete;
    u128, DivRoundingU128Incomplete, DivRoundingFromU128Incomplete;
}
div_prim! {
    PrimOps::tdiv_r, PrimOps::cdiv_r, PrimOps::fdiv_r, PrimOps::ediv_r;
    PrimOps::tdiv_r_from, PrimOps::cdiv_r_from, PrimOps::fdiv_r_from, PrimOps::ediv_r_from;
    RemRounding rem_trunc rem_ceil rem_floor rem_euc;
    RemRoundingAssign rem_trunc_assign rem_ceil_assign rem_floor_assign rem_euc_assign;
    RemRoundingFrom rem_trunc_from rem_ceil_from rem_floor_from rem_euc_from;
    i8, RemRoundingI8Incomplete, RemRoundingFromI8Incomplete;
    i16, RemRoundingI16Incomplete, RemRoundingFromI16Incomplete;
    i32, RemRoundingI32Incomplete, RemRoundingFromI32Incomplete;
    i64, RemRoundingI64Incomplete, RemRoundingFromI64Incomplete;
    i128, RemRoundingI128Incomplete, RemRoundingFromI128Incomplete;
    u8, RemRoundingU8Incomplete, RemRoundingFromU8Incomplete;
    u16, RemRoundingU16Incomplete, RemRoundingFromU16Incomplete;
    u32, RemRoundingU32Incomplete, RemRoundingFromU32Incomplete;
    u64, RemRoundingU64Incomplete, RemRoundingFromU64Incomplete;
    u128, RemRoundingU128Incomplete, RemRoundingFromU128Incomplete;
}

trait PrimOps<Long>: AsLong {
    fn tdiv_q<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn cdiv_q<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn fdiv_q<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn ediv_q<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn tdiv_q_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn cdiv_q_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn fdiv_q_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn ediv_q_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn tdiv_r<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn cdiv_r<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn fdiv_r<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn ediv_r<O: OptInteger>(rop: &mut Integer, op1: O, op2: Self);
    fn tdiv_r_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn cdiv_r_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn fdiv_r_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
    fn ediv_r_from<O: OptInteger>(rop: &mut Integer, op1: Self, op2: O);
}

trait AsLong: Copy {
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
    forward! { fn tdiv_q() -> xmpz::tdiv_q_si, xmpz::tdiv_q }
    forward! { fn cdiv_q() -> xmpz::cdiv_q_si, xmpz::cdiv_q }
    forward! { fn fdiv_q() -> xmpz::fdiv_q_si, xmpz::fdiv_q }
    forward! { fn ediv_q() -> xmpz::ediv_q_si, xmpz::ediv_q }
    reverse! { fn tdiv_q_from() -> xmpz::si_tdiv_q, xmpz::tdiv_q }
    reverse! { fn cdiv_q_from() -> xmpz::si_cdiv_q, xmpz::cdiv_q }
    reverse! { fn fdiv_q_from() -> xmpz::si_fdiv_q, xmpz::fdiv_q }
    reverse! { fn ediv_q_from() -> xmpz::si_ediv_q, xmpz::ediv_q }
    forward! { fn tdiv_r() -> xmpz::tdiv_r_si, xmpz::tdiv_r }
    forward! { fn cdiv_r() -> xmpz::cdiv_r_si, xmpz::cdiv_r }
    forward! { fn fdiv_r() -> xmpz::fdiv_r_si, xmpz::fdiv_r }
    forward! { fn ediv_r() -> xmpz::ediv_r_si, xmpz::ediv_r }
    reverse! { fn tdiv_r_from() -> xmpz::si_tdiv_r, xmpz::tdiv_r }
    reverse! { fn cdiv_r_from() -> xmpz::si_cdiv_r, xmpz::cdiv_r }
    reverse! { fn fdiv_r_from() -> xmpz::si_fdiv_r, xmpz::fdiv_r }
    reverse! { fn ediv_r_from() -> xmpz::si_ediv_r, xmpz::ediv_r }
}

impl<T> PrimOps<c_ulong> for T
where
    T: AsLong<Long = c_ulong> + CheckedCast<c_ulong> + Into<SmallInteger>,
{
    forward! { fn tdiv_q() -> xmpz::tdiv_q_ui, xmpz::tdiv_q }
    forward! { fn cdiv_q() -> xmpz::cdiv_q_ui, xmpz::cdiv_q }
    forward! { fn fdiv_q() -> xmpz::fdiv_q_ui, xmpz::fdiv_q }
    forward! { fn ediv_q() -> xmpz::ediv_q_ui, xmpz::ediv_q }
    reverse! { fn tdiv_q_from() -> xmpz::ui_tdiv_q, xmpz::tdiv_q }
    reverse! { fn cdiv_q_from() -> xmpz::ui_cdiv_q, xmpz::cdiv_q }
    reverse! { fn fdiv_q_from() -> xmpz::ui_fdiv_q, xmpz::fdiv_q }
    reverse! { fn ediv_q_from() -> xmpz::ui_ediv_q, xmpz::ediv_q }
    forward! { fn tdiv_r() -> xmpz::tdiv_r_ui, xmpz::tdiv_r }
    forward! { fn cdiv_r() -> xmpz::cdiv_r_ui, xmpz::cdiv_r }
    forward! { fn fdiv_r() -> xmpz::fdiv_r_ui, xmpz::fdiv_r }
    forward! { fn ediv_r() -> xmpz::ediv_r_ui, xmpz::ediv_r }
    reverse! { fn tdiv_r_from() -> xmpz::ui_tdiv_r, xmpz::tdiv_r }
    reverse! { fn cdiv_r_from() -> xmpz::ui_cdiv_r, xmpz::cdiv_r }
    reverse! { fn fdiv_r_from() -> xmpz::ui_fdiv_r, xmpz::fdiv_r }
    reverse! { fn ediv_r_from() -> xmpz::ui_ediv_r, xmpz::ediv_r }
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod tests {
    use crate::{
        ops::{DivRounding, RemRounding},
        Integer,
    };

    macro_rules! check_div_rem_prim {
        ($list:expr, $against:expr) => {
            for &op in $list {
                let iop = Integer::from(op);
                for b in &$against {
                    if op != 0 {
                        assert_eq!(b.clone().div_trunc(op), b.clone().div_trunc(&iop));
                        assert_eq!(b.clone().div_ceil(op), b.clone().div_ceil(&iop));
                        assert_eq!(b.clone().div_floor(op), b.clone().div_floor(&iop));
                        assert_eq!(b.clone().div_euc(op), b.clone().div_euc(&iop));
                        assert_eq!(b.clone().rem_trunc(op), b.clone().rem_trunc(&iop));
                        assert_eq!(b.clone().rem_ceil(op), b.clone().rem_ceil(&iop));
                        assert_eq!(b.clone().rem_floor(op), b.clone().rem_floor(&iop));
                        assert_eq!(b.clone().rem_euc(op), b.clone().rem_euc(&iop));
                    }
                    if *b != 0 {
                        assert_eq!(
                            DivRounding::div_trunc(op, b.clone()),
                            iop.clone().div_trunc(b)
                        );
                        assert_eq!(
                            DivRounding::div_ceil(op, b.clone()),
                            iop.clone().div_ceil(b)
                        );
                        assert_eq!(
                            DivRounding::div_floor(op, b.clone()),
                            iop.clone().div_floor(b)
                        );
                        assert_eq!(DivRounding::div_euc(op, b.clone()), iop.clone().div_euc(b));
                        assert_eq!(
                            RemRounding::rem_trunc(op, b.clone()),
                            iop.clone().rem_trunc(b)
                        );
                        assert_eq!(
                            RemRounding::rem_ceil(op, b.clone()),
                            iop.clone().rem_ceil(b)
                        );
                        assert_eq!(
                            RemRounding::rem_floor(op, b.clone()),
                            iop.clone().rem_floor(b)
                        );
                        assert_eq!(RemRounding::rem_euc(op, b.clone()), iop.clone().rem_euc(b));
                    }
                }
            }
        };
    }
    #[test]
    fn check_div_rem_prim() {
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

        check_div_rem_prim!(I8, against);
        check_div_rem_prim!(I16, against);
        check_div_rem_prim!(I32, against);
        check_div_rem_prim!(I64, against);
        check_div_rem_prim!(I128, against);
        check_div_rem_prim!(U8, against);
        check_div_rem_prim!(U16, against);
        check_div_rem_prim!(U32, against);
        check_div_rem_prim!(U64, against);
        check_div_rem_prim!(U128, against);
    }

    #[test]
    fn check_trunc() {
        let ndqr = [
            (23, 10, 2, 3),
            (23, -10, -2, 3),
            (-23, 10, -2, -3),
            (-23, -10, 2, -3),
            (20, 10, 2, 0),
            (20, -10, -2, 0),
            (-20, 10, -2, 0),
            (-20, -10, 2, 0),
            (3, 10, 0, 3),
            (3, -10, 0, 3),
            (-3, 10, 0, -3),
            (-3, -10, 0, -3),
            (0, 10, 0, 0),
            (0, -10, 0, 0),
        ];
        for &(n, d, q, r) in ndqr.iter() {
            assert_eq!(Integer::from(n) / d, q);
            assert_eq!(Integer::from(n).div_trunc(d), q);
            assert_eq!(Integer::from(n) % d, r);
            assert_eq!(Integer::from(n).rem_trunc(d), r);
            let qr = Integer::from(n).div_rem(Integer::from(d));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            let (mut nq, mut dr) = (Integer::from(n), Integer::from(d));
            let qr = <(Integer, Integer)>::from(nq.div_rem_ref(&dr));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            nq.div_rem_mut(&mut dr);
            assert_eq!(nq, q);
            assert_eq!(dr, r);
        }
    }

    #[test]
    fn check_ceil() {
        let ndqr = [
            (23, 10, 3, -7),
            (23, -10, -2, 3),
            (-23, 10, -2, -3),
            (-23, -10, 3, 7),
            (20, 10, 2, 0),
            (20, -10, -2, 0),
            (-20, 10, -2, 0),
            (-20, -10, 2, 0),
            (3, 10, 1, -7),
            (3, -10, 0, 3),
            (-3, 10, 0, -3),
            (-3, -10, 1, 7),
            (0, 10, 0, 0),
            (0, -10, 0, 0),
        ];
        for &(n, d, q, r) in ndqr.iter() {
            assert_eq!(Integer::from(n).div_ceil(d), q);
            assert_eq!(Integer::from(n).rem_ceil(d), r);
            let qr = Integer::from(n).div_rem_ceil(Integer::from(d));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            let (mut nq, mut dr) = (Integer::from(n), Integer::from(d));
            let qr = <(Integer, Integer)>::from(nq.div_rem_ceil_ref(&dr));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            nq.div_rem_ceil_mut(&mut dr);
            assert_eq!(nq, q);
            assert_eq!(dr, r);
        }
    }

    #[test]
    fn check_floor() {
        let ndqr = [
            (23, 10, 2, 3),
            (23, -10, -3, -7),
            (-23, 10, -3, 7),
            (-23, -10, 2, -3),
            (20, 10, 2, 0),
            (20, -10, -2, 0),
            (-20, 10, -2, 0),
            (-20, -10, 2, 0),
            (3, 10, 0, 3),
            (3, -10, -1, -7),
            (-3, 10, -1, 7),
            (-3, -10, 0, -3),
            (0, 10, 0, 0),
            (0, -10, 0, 0),
        ];
        for &(n, d, q, r) in ndqr.iter() {
            assert_eq!(Integer::from(n).div_floor(d), q);
            assert_eq!(Integer::from(n).rem_floor(d), r);
            let qr = Integer::from(n).div_rem_floor(Integer::from(d));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            let (mut nq, mut dr) = (Integer::from(n), Integer::from(d));
            let qr = <(Integer, Integer)>::from(nq.div_rem_floor_ref(&dr));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            nq.div_rem_floor_mut(&mut dr);
            assert_eq!(nq, q);
            assert_eq!(dr, r);
        }
    }

    #[test]
    fn check_euc() {
        let ndqr = [
            (23, 10, 2, 3),
            (23, -10, -2, 3),
            (-23, 10, -3, 7),
            (-23, -10, 3, 7),
            (20, 10, 2, 0),
            (20, -10, -2, 0),
            (-20, 10, -2, 0),
            (-20, -10, 2, 0),
            (3, 10, 0, 3),
            (3, -10, 0, 3),
            (-3, 10, -1, 7),
            (-3, -10, 1, 7),
            (0, 10, 0, 0),
            (0, -10, 0, 0),
        ];
        for &(n, d, q, r) in ndqr.iter() {
            assert_eq!(Integer::from(n).div_euc(d), q);
            assert_eq!(Integer::from(n).rem_euc(d), r);
            let qr = Integer::from(n).div_rem_euc(Integer::from(d));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            let (mut nq, mut dr) = (Integer::from(n), Integer::from(d));
            let qr = <(Integer, Integer)>::from(nq.div_rem_euc_ref(&dr));
            assert_eq!(qr.0, q);
            assert_eq!(qr.1, r);
            nq.div_rem_euc_mut(&mut dr);
            assert_eq!(nq, q);
            assert_eq!(dr, r);
        }
    }
}
