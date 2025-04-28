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
    ops::{
        AddFrom, BitAndFrom, BitOrFrom, BitXorFrom, DivFrom, DivRounding, DivRoundingAssign,
        DivRoundingFrom, MulFrom, NegAssign, NotAssign, Pow, PowAssign, PowFrom, RemFrom,
        RemRounding, RemRoundingAssign, RemRoundingFrom, ShlFrom, ShrFrom, SubFrom,
    },
    Assign,
};
use core::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Rem, Shl, Shr, Sub};
use std::borrow::Cow;

macro_rules! assign_from {
    ($T:ty; $op:ident; $Imp:ident $method:ident) => {
        impl $Imp for $T {
            #[inline]
            fn $method(&mut self, lhs: $T) {
                *self = lhs.$op(*self);
            }
        }
        impl $Imp<&$T> for $T {
            #[inline]
            fn $method(&mut self, lhs: &$T) {
                *self = (*lhs).$op(*self);
            }
        }
    };
}
macro_rules! int_ops {
    ($($T:ty)*) => { $(
        impl Assign for $T {
            #[inline]
            fn assign(&mut self, src: $T) {
                *self = src;
            }
        }
        impl Assign<&$T> for $T {
            #[inline]
            fn assign(&mut self, src: &$T) {
                *self = *src;
            }
        }
        impl NotAssign for $T {
            #[inline]
            fn not_assign(&mut self) {
                *self = !*self;
            }
        }
        impl Pow<u32> for $T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: u32) -> $T {
                self.pow(rhs)
            }
        }
        impl Pow<u32> for &$T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: u32) -> $T {
                (*self).pow(rhs)
            }
        }
        impl Pow<&u32> for $T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: &u32) -> $T {
                self.pow(*rhs)
            }
        }
        impl Pow<&u32> for &$T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: &u32) -> $T {
                (*self).pow(*rhs)
            }
        }
        impl PowAssign<u32> for $T {
            #[inline]
            fn pow_assign(&mut self, rhs: u32) {
                *self = self.pow(rhs);
            }
        }
        impl PowAssign<&u32> for $T {
            #[inline]
            fn pow_assign(&mut self, rhs: &u32) {
                *self = self.pow(*rhs);
            }
        }
        assign_from! { $T; add; AddFrom add_from }
        assign_from! { $T; sub; SubFrom sub_from }
        assign_from! { $T; mul; MulFrom mul_from }
        assign_from! { $T; div; DivFrom div_from }
        assign_from! { $T; rem; RemFrom rem_from }
        assign_from! { $T; bitand; BitAndFrom bitand_from }
        assign_from! { $T; bitor; BitOrFrom bitor_from }
        assign_from! { $T; bitxor; BitXorFrom bitxor_from }
        assign_from! { $T; shl; ShlFrom shl_from }
        assign_from! { $T; shr; ShrFrom shr_from }
    )* };
}
macro_rules! int_neg {
    ($($T:ty)*) => { $(
        impl NegAssign for $T {
            #[inline]
            fn neg_assign(&mut self) {
                *self = -*self;
            }
        }
    )* };
}
macro_rules! float_ops {
    ($($T:ty)*) => { $(
        impl Assign for $T {
            #[inline]
            fn assign(&mut self, src: $T) {
                *self = src;
            }
        }
        impl Assign<&$T> for $T {
            #[inline]
            fn assign(&mut self, src: &$T) {
                *self = *src;
            }
        }
        impl NegAssign for $T {
            #[inline]
            fn neg_assign(&mut self) {
                *self = -*self;
            }
        }
        impl Pow<i32> for $T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: i32) -> $T {
                self.powi(rhs)
            }
        }
        impl Pow<i32> for &$T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: i32) -> $T {
                self.powi(rhs)
            }
        }
        impl Pow<&i32> for $T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: &i32) -> $T {
                self.powi(*rhs)
            }
        }
        impl Pow<&i32> for &$T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: &i32) -> $T {
                self.powi(*rhs)
            }
        }
        impl PowAssign<i32> for $T {
            #[inline]
            fn pow_assign(&mut self, rhs: i32) {
                *self = self.powi(rhs);
            }
        }
        impl PowAssign<&i32> for $T {
            #[inline]
            fn pow_assign(&mut self, rhs: &i32) {
                *self = self.powi(*rhs);
            }
        }
        impl Pow<$T> for $T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: $T) -> $T {
                self.powf(rhs)
            }
        }
        impl Pow<$T> for &$T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: $T) -> $T {
                self.powf(rhs)
            }
        }
        impl Pow<&$T> for $T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: &$T) -> $T {
                self.powf(*rhs)
            }
        }
        impl Pow<&$T> for &$T {
            type Output = $T;
            #[inline]
            fn pow(self, rhs: &$T) -> $T {
                self.powf(*rhs)
            }
        }
        impl PowAssign<$T> for $T {
            #[inline]
            fn pow_assign(&mut self, rhs: $T) {
                *self = self.powf(rhs);
            }
        }
        impl PowAssign<&$T> for $T {
            #[inline]
            fn pow_assign(&mut self, rhs: &$T) {
                *self = self.powf(*rhs);
            }
        }
        assign_from! { $T; add; AddFrom add_from }
        assign_from! { $T; sub; SubFrom sub_from }
        assign_from! { $T; mul; MulFrom mul_from }
        assign_from! { $T; div; DivFrom div_from }
        assign_from! { $T; rem; RemFrom rem_from }
        assign_from! { $T; pow; PowFrom pow_from }
    )* };
}

macro_rules! rounding_fill {
    (
        $T:ty,
        $Imp:ident
        $ImpAssign:ident
        $ImpFrom:ident,
        $trunc:ident
        $ceil:ident
        $floor:ident
        $euc:ident,
        $trunc_ass:ident
        $ceil_ass:ident
        $floor_ass:ident
        $euc_ass:ident,
        $trunc_from:ident
        $ceil_from:ident
        $floor_from:ident
        $euc_from:ident
    ) => {
        impl $Imp<&$T> for $T {
            type Output = <$T as $Imp>::Output;
            #[inline]
            fn $trunc(self, rhs: &$T) -> Self::Output {
                $Imp::$trunc(self, *rhs)
            }
            #[inline]
            fn $ceil(self, rhs: &$T) -> Self::Output {
                $Imp::$ceil(self, *rhs)
            }
            #[inline]
            fn $floor(self, rhs: &$T) -> Self::Output {
                $Imp::$floor(self, *rhs)
            }
            #[inline]
            fn $euc(self, rhs: &$T) -> Self::Output {
                $Imp::$euc(self, *rhs)
            }
        }

        impl $Imp<$T> for &$T {
            type Output = <$T as $Imp>::Output;
            #[inline]
            fn $trunc(self, rhs: $T) -> Self::Output {
                $Imp::$trunc(*self, rhs)
            }
            #[inline]
            fn $ceil(self, rhs: $T) -> Self::Output {
                $Imp::$ceil(*self, rhs)
            }
            #[inline]
            fn $floor(self, rhs: $T) -> Self::Output {
                $Imp::$floor(*self, rhs)
            }
            #[inline]
            fn $euc(self, rhs: $T) -> Self::Output {
                $Imp::$euc(*self, rhs)
            }
        }

        impl $Imp<&$T> for &$T {
            type Output = <$T as $Imp>::Output;
            #[inline]
            fn $trunc(self, rhs: &$T) -> Self::Output {
                $Imp::$trunc(*self, *rhs)
            }
            #[inline]
            fn $ceil(self, rhs: &$T) -> Self::Output {
                $Imp::$ceil(*self, *rhs)
            }
            #[inline]
            fn $floor(self, rhs: &$T) -> Self::Output {
                $Imp::$floor(*self, *rhs)
            }
            #[inline]
            fn $euc(self, rhs: &$T) -> Self::Output {
                $Imp::$euc(*self, *rhs)
            }
        }

        impl $ImpAssign for $T {
            #[inline]
            fn $trunc_ass(&mut self, rhs: $T) {
                *self = $Imp::$trunc(*self, rhs);
            }
            #[inline]
            fn $ceil_ass(&mut self, rhs: $T) {
                *self = $Imp::$ceil(*self, rhs);
            }
            #[inline]
            fn $floor_ass(&mut self, rhs: $T) {
                *self = $Imp::$floor(*self, rhs);
            }
            #[inline]
            fn $euc_ass(&mut self, rhs: $T) {
                *self = $Imp::$euc(*self, rhs);
            }
        }

        impl $ImpAssign<&$T> for $T {
            #[inline]
            fn $trunc_ass(&mut self, rhs: &$T) {
                *self = $Imp::$trunc(*self, *rhs);
            }
            #[inline]
            fn $ceil_ass(&mut self, rhs: &$T) {
                *self = $Imp::$ceil(*self, *rhs);
            }
            #[inline]
            fn $floor_ass(&mut self, rhs: &$T) {
                *self = $Imp::$floor(*self, *rhs);
            }
            #[inline]
            fn $euc_ass(&mut self, rhs: &$T) {
                *self = $Imp::$euc(*self, *rhs);
            }
        }

        impl $ImpFrom for $T {
            #[inline]
            fn $trunc_from(&mut self, lhs: $T) {
                *self = $Imp::$trunc(lhs, *self);
            }
            #[inline]
            fn $ceil_from(&mut self, lhs: $T) {
                *self = $Imp::$ceil(lhs, *self);
            }
            #[inline]
            fn $floor_from(&mut self, lhs: $T) {
                *self = $Imp::$floor(lhs, *self);
            }
            #[inline]
            fn $euc_from(&mut self, lhs: $T) {
                *self = $Imp::$euc(lhs, *self);
            }
        }

        impl $ImpFrom<&$T> for $T {
            #[inline]
            fn $trunc_from(&mut self, lhs: &$T) {
                *self = $Imp::$trunc(*lhs, *self);
            }
            #[inline]
            fn $ceil_from(&mut self, lhs: &$T) {
                *self = $Imp::$ceil(*lhs, *self);
            }
            #[inline]
            fn $floor_from(&mut self, lhs: &$T) {
                *self = $Imp::$floor(*lhs, *self);
            }
            #[inline]
            fn $euc_from(&mut self, lhs: &$T) {
                *self = $Imp::$euc(*lhs, *self);
            }
        }
    };
}

macro_rules! rounding_signed {
    ($($T:ty)*) => { $(
        impl DivRounding for $T {
            type Output = $T;
            #[inline]
            fn div_trunc(self, rhs: $T) -> $T {
                self / rhs
            }
            #[inline]
            fn div_ceil(self, rhs: $T) -> $T {
                let (q, r) = (self / rhs, self % rhs);
                let change = if rhs > 0 { r > 0 } else { r < 0 };
                if change {
                    q + 1
                } else {
                    q
                }
            }
            #[inline]
            fn div_floor(self, rhs: $T) -> $T {
                let (q, r) = (self / rhs, self % rhs);
                let change = if rhs > 0 { r < 0 } else { r > 0 };
                if change {
                    q - 1
                } else {
                    q
                }
            }
            #[inline]
            fn div_euc(self, rhs: $T) -> $T {
                let (q, r) = (self / rhs, self % rhs);
                if r < 0 {
                    if rhs < 0 {
                        q + 1
                    } else {
                        q - 1
                    }
                } else {
                    q
                }
            }
        }

        rounding_fill! {
            $T,
            DivRounding DivRoundingAssign DivRoundingFrom,
            div_trunc div_ceil div_floor div_euc,
            div_trunc_assign div_ceil_assign div_floor_assign div_euc_assign,
            div_trunc_from div_ceil_from div_floor_from div_euc_from
        }

        impl RemRounding for $T {
            type Output = $T;
            #[inline]
            fn rem_trunc(self, rhs: $T) -> $T {
                self % rhs
            }
            #[inline]
            fn rem_ceil(self, rhs: $T) -> $T {
                let r = self % rhs;
                let change = if rhs > 0 { r > 0 } else { r < 0 };
                if change {
                    r - rhs
                } else {
                    r
                }
            }
            #[inline]
            fn rem_floor(self, rhs: $T) -> $T {
                let r = self % rhs;
                let change = if rhs > 0 { r < 0 } else { r > 0 };
                if change {
                    r + rhs
                } else {
                    r
                }
            }
            #[inline]
            fn rem_euc(self, rhs: $T) -> $T {
                let r = self % rhs;
                if r < 0 {
                    if rhs < 0 {
                        r - rhs
                    } else {
                        r + rhs
                    }
                } else {
                    r
                }
            }
        }

        rounding_fill! {
            $T,
            RemRounding RemRoundingAssign RemRoundingFrom,
            rem_trunc rem_ceil rem_floor rem_euc,
            rem_trunc_assign rem_ceil_assign rem_floor_assign rem_euc_assign,
            rem_trunc_from rem_ceil_from rem_floor_from rem_euc_from
        }

    )* };
}

macro_rules! rounding_unsigned {
    ($($T:ty)*) => { $(
        impl DivRounding for $T {
            type Output = $T;
            #[inline]
            fn div_trunc(self, rhs: $T) -> $T {
                self / rhs
            }
            #[inline]
            fn div_ceil(self, rhs: $T) -> $T {
                let (q, r) = (self / rhs, self % rhs);
                if r > 0 {
                    q + 1
                } else {
                    q
                }
            }
            #[inline]
            fn div_floor(self, rhs: $T) -> $T {
                self / rhs
            }
            #[inline]
            fn div_euc(self, rhs: $T) -> $T {
                self / rhs
            }
        }

        rounding_fill! {
            $T,
            DivRounding DivRoundingAssign DivRoundingFrom,
            div_trunc div_ceil div_floor div_euc,
            div_trunc_assign div_ceil_assign div_floor_assign div_euc_assign,
            div_trunc_from div_ceil_from div_floor_from div_euc_from
        }
    )* };
}

macro_rules! rounding_float {
    ($($T:ty)*) => { $(
        impl DivRounding for $T {
            type Output = $T;
            #[inline]
            fn div_trunc(self, rhs: $T) -> $T {
                (self / rhs).trunc()
            }
            #[inline]
            fn div_ceil(self, rhs: $T) -> $T {
                let (q, r) = ((self / rhs).trunc(), self % rhs);
                let change = if rhs > 0.0 { r > 0.0 } else { r < 0.0 };
                if change {
                    q + 1.0
                } else {
                    q
                }
            }
            #[inline]
            fn div_floor(self, rhs: $T) -> $T {
                let (q, r) = ((self / rhs).trunc(), self % rhs);
                let change = if rhs > 0.0 { r < 0.0 } else { r > 0.0 };
                if change {
                    q - 1.0
                } else {
                    q
                }
            }
            #[inline]
            fn div_euc(self, rhs: $T) -> $T {
                let (q, r) = ((self / rhs).trunc(), self % rhs);
                if r < 0.0 {
                    if rhs < 0.0 {
                        q + 1.0
                    } else {
                        q - 1.0
                    }
                } else {
                    q
                }
            }
        }

        rounding_fill! {
            $T,
            DivRounding DivRoundingAssign DivRoundingFrom,
            div_trunc div_ceil div_floor div_euc,
            div_trunc_assign div_ceil_assign div_floor_assign div_euc_assign,
            div_trunc_from div_ceil_from div_floor_from div_euc_from
        }

        impl RemRounding for $T {
            type Output = $T;
            #[inline]
            fn rem_trunc(self, rhs: $T) -> $T {
                self % rhs
            }
            #[inline]
            fn rem_ceil(self, rhs: $T) -> $T {
                let r = self % rhs;
                let change = if rhs > 0.0 { r > 0.0 } else { r < 0.0 };
                if change {
                    r - rhs
                } else {
                    r
                }
            }
            #[inline]
            fn rem_floor(self, rhs: $T) -> $T {
                let r = self % rhs;
                let change = if rhs > 0.0 { r < 0.0 } else { r > 0.0 };
                if change {
                    r + rhs
                } else {
                    r
                }
            }
            #[inline]
            fn rem_euc(self, rhs: $T) -> $T {
                let r = self % rhs;
                if r < 0.0 {
                    if rhs < 0.0 {
                        r - rhs
                    } else {
                        r + rhs
                    }
                } else {
                    r
                }
            }
        }

        rounding_fill! {
            $T,
            RemRounding RemRoundingAssign RemRoundingFrom,
            rem_trunc rem_ceil rem_floor rem_euc,
            rem_trunc_assign rem_ceil_assign rem_floor_assign rem_euc_assign,
            rem_trunc_from rem_ceil_from rem_floor_from rem_euc_from
        }

    )* };
}

impl NotAssign for bool {
    #[inline]
    fn not_assign(&mut self) {
        *self = !*self;
    }
}
assign_from! { bool; bitand; BitAndFrom bitand_from }
assign_from! { bool; bitor; BitOrFrom bitor_from }
assign_from! { bool; bitxor; BitXorFrom bitxor_from }

int_ops! { i8 i16 i32 i64 i128 isize }
int_ops! { u8 u16 u32 u64 u128 usize }
int_neg! { i8 i16 i32 i64 i128 isize }
assign_from! { u32; pow; PowFrom pow_from }
float_ops! { f32 f64 }

rounding_signed! { i8 i16 i32 i64 i128 isize }

// For unsigned primitives, RemRounding is not implemented. Ignoring
// the issue that we cannot have negative numbers, if r == n % d then
//
// n.rem_trunc(d) -> r
// n.rem_ceil(d) -> if r > 0 { r - d } else { 0 }
// n.rem_floor(d) -> r
// n.rem_euc(d) -> r

rounding_unsigned! { u8 u16 u32 u64 u128 usize }

rounding_float! { f32 f64 }

impl Assign<&str> for String {
    #[inline]
    fn assign(&mut self, src: &str) {
        self.clear();
        self.push_str(src);
    }
}

impl<'a> Assign<&'a str> for Cow<'a, str> {
    #[inline]
    fn assign(&mut self, src: &'a str) {
        *self = Cow::Borrowed(src);
    }
}

impl<'a> Assign<Cow<'a, str>> for Cow<'a, str> {
    #[inline]
    fn assign(&mut self, src: Cow<'a, str>) {
        *self = src;
    }
}

impl AddFrom<&str> for String {
    #[inline]
    fn add_from(&mut self, lhs: &str) {
        self.insert_str(0, lhs);
    }
}

impl<'a> AddFrom<&'a str> for Cow<'a, str> {
    fn add_from(&mut self, lhs: &'a str) {
        if lhs.is_empty() {
        } else if self.is_empty() {
            *self = Cow::Borrowed(lhs)
        } else {
            match *self {
                Cow::Borrowed(rhs) => {
                    let mut s = String::with_capacity(lhs.len() + rhs.len());
                    s.push_str(lhs);
                    s.push_str(rhs);
                    *self = Cow::Owned(s);
                }
                Cow::Owned(ref mut s) => {
                    s.insert_str(0, lhs);
                }
            }
        }
    }
}

impl<'a> AddFrom<Cow<'a, str>> for Cow<'a, str> {
    fn add_from(&mut self, lhs: Cow<'a, str>) {
        if lhs.is_empty() {
        } else if self.is_empty() {
            *self = lhs;
        } else {
            match *self {
                Cow::Borrowed(rhs) => {
                    let mut s = String::with_capacity(lhs.len() + rhs.len());
                    s.push_str(&lhs);
                    s.push_str(rhs);
                    *self = Cow::Owned(s);
                }
                Cow::Owned(ref mut s) => {
                    s.insert_str(0, &lhs);
                }
            }
        }
    }
}
