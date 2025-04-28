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
macro_rules! from_assign {
    ($Src:ty => $Dst:ty) => {
        impl From<$Src> for $Dst {
            #[inline]
            fn from(src: $Src) -> Self {
                let mut dst = Self::default();
                dst.assign(src);
                dst
            }
        }
    };

    ($Src:ty => $Dst1:ty, $Dst2:ty) => {
        impl From<$Src> for ($Dst1, $Dst2) {
            #[inline]
            fn from(src: $Src) -> Self {
                let mut dst = Self::default();
                Assign::assign(&mut (&mut dst.0, &mut dst.1), src);
                dst
            }
        }
    };

    ($Src:ty => $Dst1:ty, $Dst2:ty, $Dst3:ty) => {
        impl From<$Src> for ($Dst1, $Dst2, $Dst3) {
            #[inline]
            fn from(src: $Src) -> Self {
                let mut dst = Self::default();
                Assign::assign(&mut (&mut dst.0, &mut dst.1, &mut dst.2), src);
                dst
            }
        }
    };
}

// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "integer")]
macro_rules! ref_math_op0 {
    (
        $Big:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete {
            $($param: $T,)*
        }

        impl Assign<$Incomplete> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete) {
                $func(self, $(src.$param),*);
            }
        }

        from_assign! { $Incomplete => $Big }
    };
}

// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "integer")]
macro_rules! ref_math_op1 {
    (
        $Big:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a $Big,
            $($param: $T,)*
        }

        impl Assign<$Incomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self, src.ref_self, $(src.$param),*);
            }
        }

        from_assign! { $Incomplete<'_> => $Big }
    };
}

// struct Incomplete
// (Big, Big) = Incomplete
// Incomplete -> (Big, Big)
#[cfg(feature = "integer")]
macro_rules! ref_math_op1_2 {
    (
        $Big:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a $Big,
            $($param: $T,)*
        }

        impl Assign<$Incomplete<'_>> for (&mut $Big, &mut $Big) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self.0, self.1, src.ref_self, $(src.$param),*);
            }
        }

        impl Assign<$Incomplete<'_>> for ($Big, $Big) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                Assign::assign(&mut (&mut self.0, &mut self.1), src);
            }
        }

        from_assign! { $Incomplete<'_> => $Big, $Big }
    };
}

// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "integer")]
macro_rules! ref_math_op2 {
    (
        $Big:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $op:ident $(, $param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a $Big,
            $op: &'a $Big,
            $($param: $T,)*
        }

        impl Assign<$Incomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self, src.ref_self, src.$op, $(src.$param),*);
            }
        }

        from_assign! { $Incomplete<'_> => $Big }
    };
}

// struct Incomplete
// (Big, Big) = Incomplete
// Incomplete -> (Big, Big)
#[cfg(feature = "integer")]
macro_rules! ref_math_op2_2 {
    (
        $Big:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $op:ident $(, $param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a $Big,
            $op: &'a $Big,
            $($param: $T,)*
        }

        impl Assign<$Incomplete<'_>> for (&mut $Big, &mut $Big) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(
                    self.0,
                    self.1,
                    src.ref_self,
                    src.$op,
                    $(src.$param,)*
                );
            }
        }

        impl Assign<$Incomplete<'_>> for ($Big, $Big) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                Assign::assign(&mut (&mut self.0, &mut self.1), src);
            }
        }

        from_assign! { $Incomplete<'_> => $Big, $Big }
    };
}

// #big -> Big
// big #=
// #&big -> Incomplete
// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "integer")]
macro_rules! arith_unary {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $Incomplete:ident
    ) => {
        impl $Imp for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self) -> $Big {
                self.$method_assign();
                self
            }
        }

        impl $ImpAssign for $Big {
            #[inline]
            fn $method_assign(&mut self) {
                $func(self, ());
            }
        }

        impl<'a> $Imp for &'a $Big {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self) -> $Incomplete<'a> {
                $Incomplete { op: self }
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            op: &'a $Big,
        }

        impl Assign<$Incomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self, src.op);
            }
        }

        from_assign! { $Incomplete<'_> => $Big }
    };
}

// big # big -> Big
// big # &big -> Big
// &big # big -> Big
// &big # &big -> Incomplete
// big #= big
// big #= &big
// big #-> big
// &big #-> big
// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "integer")]
macro_rules! arith_binary_self {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpFrom:ident { $method_from:ident }
        $Incomplete:ident;
        $rhs_has_more_alloc:path
    ) => {
        impl $Imp<$Big> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, mut rhs: $Big) -> $Big {
                // use the allocation with the larger capacity
                if $rhs_has_more_alloc(&self, &rhs) {
                    rhs.$method_from(&self);
                    rhs
                } else {
                    self.$method_assign(&rhs);
                    self
                }
            }
        }

        impl $Imp<&$Big> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: &$Big) -> $Big {
                self.$method_assign(rhs);
                self
            }
        }

        impl $Imp<$Big> for &$Big {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from(self);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for &'a $Big {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $Incomplete<'_> {
                $Incomplete { lhs: self, rhs }
            }
        }

        impl $ImpAssign<$Big> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: $Big) {
                self.$method_assign(&rhs);
            }
        }

        impl $ImpAssign<&$Big> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: &$Big) {
                $func(self, (), rhs);
            }
        }

        impl $ImpFrom<$Big> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $Big) {
                self.$method_from(&lhs);
            }
        }

        impl $ImpFrom<&$Big> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$Big) {
                $func(self, lhs, ());
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            lhs: &'a $Big,
            rhs: &'a $Big,
        }

        impl Assign<$Incomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self, src.lhs, src.rhs);
            }
        }

        from_assign! { $Incomplete<'_> => $Big }
    };
}

// big # t -> Big
// big # &t -> Big
// &big # t -> OwnedIncomplete
// &big # &t -> Incomplete
// big #= t
// big #= &t
// struct OwnedIncomplete
// Big = OwnedIncomplete
// OwnedIncomplete -> Big
// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "rational")]
macro_rules! arith_binary {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $T:ty;
        $Incomplete:ident, $OwnedIncomplete:ident
    ) => {
        impl $Imp<$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: $T) -> $Big {
                self.$method_assign(&rhs);
                self
            }
        }

        impl $Imp<&$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: &$T) -> $Big {
                self.$method_assign(rhs);
                self
            }
        }

        impl<'a> $Imp<$T> for &'a $Big {
            type Output = $OwnedIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: $T) -> $OwnedIncomplete<'a> {
                $OwnedIncomplete { lhs: self, rhs }
            }
        }

        impl<'a> $Imp<&'a $T> for &'a $Big {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $T) -> $Incomplete<'_> {
                $Incomplete { lhs: self, rhs }
            }
        }

        impl $ImpAssign<$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: $T) {
                self.$method_assign(&rhs);
            }
        }

        impl $ImpAssign<&$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: &$T) {
                $func(self, (), rhs);
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            lhs: &'a $Big,
            rhs: &'a $T,
        }

        impl Assign<$Incomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self, src.lhs, src.rhs);
            }
        }

        from_assign! { $Incomplete<'_> => $Big }

        #[derive(Debug)]
        pub struct $OwnedIncomplete<'a> {
            lhs: &'a $Big,
            rhs: $T,
        }

        impl Assign<$OwnedIncomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $OwnedIncomplete<'_>) {
                $func(self, src.lhs, &src.rhs);
            }
        }

        from_assign! { $OwnedIncomplete<'_> => $Big }
    };
}

// arith_binary!
// t # big -> Big
// t # &big -> OwnedIncomplete
// &t # big -> Big
// &t # &big -> Incomplete
// t #-> big
// &t #-> big
#[cfg(feature = "rational")]
macro_rules! arith_commut {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpFrom:ident { $method_from:ident }
        $T:ty;
        $Incomplete:ident, $OwnedIncomplete:ident
    ) => {
        arith_binary! {
            $Big;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $T;
            $Incomplete, $OwnedIncomplete
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, rhs: $Big) -> $Big {
                rhs.$method(self)
            }
        }

        impl<'a> $Imp<&'a $Big> for $T {
            type Output = $OwnedIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $OwnedIncomplete<'a> {
                rhs.$method(self)
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, rhs: $Big) -> $Big {
                rhs.$method(self)
            }
        }

        impl<'a> $Imp<&'a $Big> for &'a $T {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $Incomplete<'_> {
                rhs.$method(self)
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                self.$method_assign(lhs);
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                self.$method_assign(lhs);
            }
        }
    };
}

// arith_binary!
// t # big -> Big
// t # &big -> FromOwnedIncomplete
// &t # big -> Big
// &t # &big -> FromIncomplete
// t #-> big
// &t #-> big
// struct FromIncomplete
// Big = FromIncomplete
// FromIncomplete -> Big
// struct FromOwnedIncomplete
// Big = FromOwnedIncomplete
// FromOwnedIncomplete -> Big
#[cfg(feature = "rational")]
macro_rules! arith_noncommut {
    (
        $Big:ty;
        $func:path;
        $func_from:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpFrom:ident { $method_from:ident }
        $T:ty;
        $Incomplete:ident, $OwnedIncomplete:ident;
        $FromIncomplete:ident, $FromOwnedIncomplete:ident
    ) => {
        arith_binary! {
            $Big;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $T;
            $Incomplete, $OwnedIncomplete
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from(&self);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $T {
            type Output = $FromOwnedIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $FromOwnedIncomplete<'_> {
                $FromOwnedIncomplete { lhs: self, rhs }
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from(self);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for &'a $T {
            type Output = $FromIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $FromIncomplete<'_> {
                $FromIncomplete { lhs: self, rhs }
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                self.$method_from(&lhs);
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                $func_from(self, lhs, ());
            }
        }

        #[derive(Debug)]
        pub struct $FromIncomplete<'a> {
            lhs: &'a $T,
            rhs: &'a $Big,
        }

        impl Assign<$FromIncomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $FromIncomplete<'_>) {
                $func_from(self, src.lhs, src.rhs);
            }
        }

        from_assign! { $FromIncomplete<'_> => $Big }

        #[derive(Debug)]
        pub struct $FromOwnedIncomplete<'a> {
            lhs: $T,
            rhs: &'a $Big,
        }

        impl Assign<$FromOwnedIncomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $FromOwnedIncomplete<'_>) {
                $func_from(self, &src.lhs, src.rhs);
            }
        }

        from_assign! { $FromOwnedIncomplete<'_> => $Big }
    };
}

// big # prim -> Big
// big # &prim -> Big
// &big # prim -> Incomplete
// &big # &prim -> Incomplete
// big #= prim
// big #= &prim
// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "integer")]
macro_rules! arith_prim {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $($T:ty, $Incomplete:ident;)*
    ) => { $(
        impl $Imp<$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: $T) -> $Big {
                self.$method_assign(rhs);
                self
            }
        }

        impl $Imp<&$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: &$T) -> $Big {
                self.$method_assign(*rhs);
                self
            }
        }

        impl<'b> $Imp<$T> for &'b $Big {
            type Output = $Incomplete<'b>;
            #[inline]
            fn $method(self, rhs: $T) -> $Incomplete<'b> {
                $Incomplete { lhs: self, rhs }
            }
        }

        impl<'b> $Imp<&$T> for &'b $Big {
            type Output = $Incomplete<'b>;
            #[inline]
            fn $method(self, rhs: &$T) -> $Incomplete<'b> {
                self.$method(*rhs)
            }
        }

        impl $ImpAssign<$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: $T) {
                $func(self, (), rhs);
            }
        }

        impl $ImpAssign<&$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: &$T) {
                self.$method_assign(*rhs);
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            lhs: &'a $Big,
            rhs: $T,
        }

        impl Assign<$Incomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                $func(self, src.lhs, src.rhs);
            }
        }

        from_assign! { $Incomplete<'_> => $Big }
    )* };
}

// arith_prim!
// prim # big -> Big
// prim # &big -> Incomplete
// &prim # big -> Big
// &prim # &big -> <prim # &big>::Output
// prim #-> big
// &prim #-> big
#[cfg(feature = "integer")]
macro_rules! arith_prim_commut {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpFrom:ident { $method_from:ident }
        $($T:ty, $Incomplete:ident;)*
    ) => { $(
        arith_prim! {
            $Big;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $T, $Incomplete;
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign(self);
                rhs
            }
        }

        impl<'b> $Imp<&'b $Big> for $T {
            type Output = $Incomplete<'b>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $Incomplete<'_> {
                rhs.$method(self)
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign(*self);
                rhs
            }
        }

        impl<'b> $Imp<&'b $Big> for &$T {
            type Output = $Incomplete<'b>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $Incomplete<'_> {
                rhs.$method(*self)
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                self.$method_assign(lhs);
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                self.$method_assign(*lhs);
            }
        }
    )* };
}

// arith_prim!
// prim # big -> Big
// prim # &big -> FromIncomplete
// &prim # big -> Big
// &prim # &big -> FromIncomplete
// prim #-> big
// &prim #-> big
// struct FromIncomplete
// Big = FromIncomplete
// FromIncomplete -> Big
#[cfg(feature = "integer")]
macro_rules! arith_prim_noncommut {
    (
        $Big:ty;
        $func:path, $func_from:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpFrom:ident { $method_from:ident }
        $($T:ty, $Incomplete:ident, $FromIncomplete:ident;)*
    ) => { $(
        arith_prim! {
            $Big;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $T, $Incomplete;
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from(self);
                rhs
            }
        }

        impl<'b> $Imp<&'b $Big> for $T {
            type Output = $FromIncomplete<'b>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $FromIncomplete<'_> {
                $FromIncomplete { lhs: self, rhs }
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from(*self);
                rhs
            }
        }

        impl<'b> $Imp<&'b $Big> for &$T {
            type Output = $FromIncomplete<'b>;
            #[inline]
            fn $method(self, rhs: &'b $Big) -> $FromIncomplete<'b> {
                $Imp::$method(*self, rhs)
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                $func_from(self, lhs, ());
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                self.$method_from(*lhs);
            }
        }

        #[derive(Debug)]
        pub struct $FromIncomplete<'a> {
            lhs: $T,
            rhs: &'a $Big,
        }

        impl Assign<$FromIncomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $FromIncomplete<'_>) {
                $func_from(self, src.lhs, src.rhs);
            }
        }

        from_assign! { $FromIncomplete<'_> => $Big }
    )* };
}

// big # mul -> Big
// &big # mul -> Incomplete
// big #= mul
// struct Incomplete
// Big = Incomplete
// Incomplete -> Big
#[cfg(feature = "integer")]
macro_rules! mul_op {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $Mul:ident;
        $Incomplete:ident
    ) => {
        impl $Imp<$Mul<'_>> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: $Mul<'_>) -> $Big {
                self.$method_assign(rhs);
                self
            }
        }

        impl<'a> $Imp<$Mul<'a>> for &'a $Big {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: $Mul<'a>) -> $Incomplete<'_> {
                $Incomplete { lhs: self, rhs }
            }
        }

        impl $ImpAssign<$Mul<'_>> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: $Mul<'_>) {
                $func(self, rhs.lhs, rhs.rhs);
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            lhs: &'a $Big,
            rhs: $Mul<'a>,
        }

        impl Assign<$Incomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                self.assign(src.lhs);
                self.$method_assign(src.rhs);
            }
        }

        from_assign! { $Incomplete<'_> => $Big }
    };
}

// mul_op!
// mul # big -> Big
// mul # &big -> Incomplete
// mul #-> big
#[cfg(feature = "integer")]
macro_rules! mul_op_commut {
    (
        $Big:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpFrom:ident { $method_from:ident }
        $($Mul:ident, $Incomplete:ident;)*
    ) => { $(
        mul_op! {
            $Big;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $Mul;
            $Incomplete
        }

        impl $Imp<$Big> for $Mul<'_> {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign(self);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $Mul<'a> {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $Incomplete<'_> {
                rhs.$method(self)
            }
        }

        impl $ImpFrom<$Mul<'_>> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $Mul<'_>) {
                self.$method_assign(lhs);
            }
        }
    )* };
}

// mul_op!
// mul # big -> Big
// mul # &big -> FromIncomplete
// mul #-> big
// struct FromIncomplete
// Big = FromIncomplete
// FromIncomplete -> Big
#[cfg(feature = "integer")]
macro_rules! mul_op_noncommut {
    (
        $Big:ty;
        $func:path, $func_from:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpFrom:ident { $method_from:ident }
        $($Mul:ident, $Incomplete:ident, $FromIncomplete:ident;)*
    ) => { $(
        mul_op! {
            $Big;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $Mul;
            $Incomplete
        }

        impl $Imp<$Big> for $Mul<'_> {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from(self);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $Mul<'a> {
            type Output = $FromIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $FromIncomplete<'_> {
                $FromIncomplete { lhs: self, rhs }
            }
        }

        impl $ImpFrom<$Mul<'_>> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $Mul<'_>) {
                $func_from(self, lhs.lhs, lhs.rhs);
            }
        }

        #[derive(Debug)]
        pub struct $FromIncomplete<'a> {
            lhs: $Mul<'a>,
            rhs: &'a $Big,
        }

        impl Assign<$FromIncomplete<'_>> for $Big {
            #[inline]
            fn assign(&mut self, src: $FromIncomplete<'_>) {
                self.assign(src.rhs);
                self.$method_from(src.lhs);
            }
        }

        from_assign! { $FromIncomplete<'_> => $Big }
    )* };
}

#[cfg(feature = "float")]
macro_rules! assign_round_deref {
    ($Src:ty => $Dst:ty) => {
        impl AssignRound<&$Src> for $Dst {
            type Round = <$Dst as AssignRound<$Src>>::Round;
            type Ordering = <$Dst as AssignRound<$Src>>::Ordering;
            #[inline]
            fn assign_round(&mut self, src: &$Src, round: Self::Round) -> Self::Ordering {
                self.assign_round(*src, round)
            }
        }
    };
}

// struct Incomplete
// Big = Incomplete
#[cfg(feature = "float")]
macro_rules! ref_math_op0_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete {
            $($param: $T,)*
        }

        impl AssignRound<$Incomplete> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(
                &mut self,
                src: $Incomplete,
                round: $Round,
            ) -> $Ordering {
                $func(self, $(src.$param,)* round)
            }
        }
    };
}

// struct Incomplete
// Big = Incomplete
#[cfg(feature = "float")]
macro_rules! ref_math_op1_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a $Big,
            $($param: $T,)*
        }

        impl AssignRound<$Incomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(
                &mut self,
                src: $Incomplete<'_>,
                round: $Round,
            ) -> $Ordering {
                $func(self, src.ref_self, $(src.$param,)* round)
            }
        }
    };
}

// struct Incomplete
// (Big, Big) = Incomplete
#[cfg(feature = "float")]
macro_rules! ref_math_op1_2_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $($param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a $Big,
            $($param: $T,)*
        }

        impl AssignRound<$Incomplete<'_>> for (&mut $Big, &mut $Big) {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(
                &mut self,
                src: $Incomplete<'_>,
                round: $Round,
            ) -> $Ordering {
                $func(self.0, self.1, src.ref_self, $(src.$param,)* round)
            }
        }

        impl AssignRound<$Incomplete<'_>> for ($Big, $Big) {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(
                &mut self,
                src: $Incomplete<'_>,
                round: $Round,
            ) -> $Ordering {
                AssignRound::assign_round(&mut (&mut self.0, &mut self.1), src, round)
            }
        }

        impl Assign<$Incomplete<'_>> for (&mut $Big, &mut $Big) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                AssignRound::assign_round(self, src, $Nearest);
            }
        }

        impl Assign<$Incomplete<'_>> for ($Big, $Big) {
            #[inline]
            fn assign(&mut self, src: $Incomplete<'_>) {
                AssignRound::assign_round(&mut (&mut self.0, &mut self.1), src, $Nearest);
            }
        }
    };
}

// struct Incomplete
// Big = Incomplete
#[cfg(feature = "float")]
macro_rules! ref_math_op2_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $(#[$attr_ref:meta])*
        struct $Incomplete:ident { $op:ident $(, $param:ident: $T:ty),* }
    ) => {
        $(#[$attr_ref])*
        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            ref_self: &'a $Big,
            $op: &'a $Big,
            $($param: $T,)*
        }

        impl AssignRound<$Incomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(
                &mut self,
                src: $Incomplete<'_>,
                round: $Round,
            ) -> $Ordering {
                $func(self, src.ref_self, src.$op, $(src.$param,)* round)
            }
        }
    };
}

// big # t -> Big
// big # &t -> Big
// &big # &t -> Incomplete
// big #= t
// big #= &t
// big #= t, Round -> Ordering
// big #= &t, Round -> Ordering
// struct Incomplete
// Big = Incomplete
#[cfg(feature = "float")]
macro_rules! arith_binary_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $T:ty;
        $Incomplete:ident
    ) => {
        impl $Imp<$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: $T) -> $Big {
                self.$method_assign_round(&rhs, $Nearest);
                self
            }
        }

        impl $Imp<&$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: &$T) -> $Big {
                self.$method_assign_round(rhs, $Nearest);
                self
            }
        }

        impl<'a> $Imp<&'a $T> for &'a $Big {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $T) -> $Incomplete<'_> {
                $Incomplete { lhs: self, rhs }
            }
        }

        impl $ImpAssign<$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: $T) {
                self.$method_assign_round(&rhs, $Nearest);
            }
        }

        impl $ImpAssign<&$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: &$T) {
                self.$method_assign_round(rhs, $Nearest);
            }
        }

        impl $ImpAssignRound<$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_assign_round(&mut self, rhs: $T, round: $Round) -> $Ordering {
                self.$method_assign_round(&rhs, round)
            }
        }

        impl $ImpAssignRound<&$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_assign_round(&mut self, rhs: &$T, round: $Round) -> $Ordering {
                $func(self, (), rhs, round)
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            lhs: &'a $Big,
            rhs: &'a $T,
        }

        impl AssignRound<$Incomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $Incomplete<'_>, round: $Round) -> $Ordering {
                $func(self, src.lhs, src.rhs, round)
            }
        }
    };
}

// arith_binary_round!
// &big # big -> Big
// big #-> big
// &big #-> big
// big #-> big; Round -> Ordering
// &big #-> big; Round -> Ordering
#[cfg(feature = "float")]
macro_rules! arith_binary_self_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $ImpFrom:ident { $method_from:ident }
        $ImpFromRound:ident { $method_from_round:ident }
        $Incomplete:ident
    ) => {
        arith_binary_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $Big;
            $Incomplete
        }

        impl $Imp<$Big> for &$Big {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from_round(self, $Nearest);
                rhs
            }
        }

        impl $ImpFrom<$Big> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $Big) {
                self.$method_from_round(&lhs, $Nearest);
            }
        }

        impl $ImpFrom<&$Big> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$Big) {
                self.$method_from_round(lhs, $Nearest);
            }
        }

        impl $ImpFromRound<$Big> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: $Big, round: $Round) -> $Ordering {
                self.$method_from_round(&lhs, round)
            }
        }

        impl $ImpFromRound<&$Big> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: &$Big, round: $Round) -> $Ordering {
                $func(self, lhs, (), round)
            }
        }
    };
}

// arith_binary_round!
// &big # t -> OwnedIncomplete
// struct OwnedIncomplete
// Big = OwnedIncomplete
#[cfg(all(feature = "float", any(feature = "integer", feature = "complex")))]
macro_rules! arith_forward_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $T:ty;
        $Incomplete:ident,
        $OwnedIncomplete:ident
    ) => {
        arith_binary_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $T;
            $Incomplete
        }

        impl<'a> $Imp<$T> for &'a $Big {
            type Output = $OwnedIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: $T) -> $OwnedIncomplete<'a> {
                $OwnedIncomplete { lhs: self, rhs }
            }
        }

        #[derive(Debug)]
        pub struct $OwnedIncomplete<'a> {
            lhs: &'a $Big,
            rhs: $T,
        }

        impl AssignRound<$OwnedIncomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $OwnedIncomplete<'_>, round: $Round) -> $Ordering {
                self.assign_round(&src, round)
            }
        }

        impl AssignRound<&$OwnedIncomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: &$OwnedIncomplete<'_>, round: $Round) -> $Ordering {
                $func(self, src.lhs, &src.rhs, round)
            }
        }
    };
}

// arith_forward_round!
// t # big -> big
// t # &big -> OwnedIncomplete
// &t # big -> big
// &t # &big -> Incomplete
// t #-> big
// &t #-> big
// t #-> big; Round -> Ordering
// &t #-> big; Round -> Ordering
#[cfg(all(feature = "float", any(feature = "integer", feature = "complex")))]
macro_rules! arith_commut_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $ImpFrom:ident { $method_from:ident }
        $ImpFromRound:ident { $method_from_round:ident }
        $T:ty;
        $Incomplete:ident,
        $OwnedIncomplete:ident
    ) => {
        arith_forward_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $T;
            $Incomplete, $OwnedIncomplete
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign_round(&self, $Nearest);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $T {
            type Output = $OwnedIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $OwnedIncomplete<'_> {
                rhs.$method(self)
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign_round(self, $Nearest);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for &'a $T {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $Incomplete<'_> {
                rhs.$method(self)
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                self.$method_from_round(&lhs, $Nearest);
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                self.$method_from_round(lhs, $Nearest);
            }
        }

        impl $ImpFromRound<$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: $T, round: $Round) -> $Ordering {
                self.$method_from_round(&lhs, round)
            }
        }

        impl $ImpFromRound<&$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: &$T, round: $Round) -> $Ordering {
                self.$method_assign_round(lhs, round)
            }
        }
    };
}

// arith_forward_round!
// t # big -> big
// t # &big -> FromOwnedIncomplete
// &t # big -> big
// &t # &big -> FromIncomplete
// t #-> big
// &t #-> big
// t #-> big; Round -> Ordering
// &t #-> big; Round -> Ordering
// struct FromIncomplete
// Big = FromIncomplete
// struct FromOwnedIncomplete
// Big = FromOwnedIncomplete
#[cfg(all(feature = "float", any(feature = "integer", feature = "complex")))]
macro_rules! arith_noncommut_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path, $func_from:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $ImpFrom:ident { $method_from:ident }
        $ImpFromRound:ident { $method_from_round:ident }
        $T:ty;
        $Incomplete:ident, $OwnedIncomplete:ident;
        $FromIncomplete:ident, $FromOwnedIncomplete:ident
    ) => {
        arith_forward_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $T;
            $Incomplete, $OwnedIncomplete
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from_round(&self, $Nearest);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $T {
            type Output = $FromOwnedIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $FromOwnedIncomplete<'_> {
                $FromOwnedIncomplete { lhs: self, rhs }
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from_round(self, $Nearest);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for &'a $T {
            type Output = $FromIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $FromIncomplete<'_> {
                $FromIncomplete { lhs: self, rhs }
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                self.$method_from_round(&lhs, $Nearest);
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                self.$method_from_round(lhs, $Nearest);
            }
        }

        impl $ImpFromRound<$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: $T, round: $Round) -> $Ordering {
                self.$method_from_round(&lhs, round)
            }
        }

        impl $ImpFromRound<&$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: &$T, round: $Round) -> $Ordering {
                $func_from(self, lhs, (), round)
            }
        }

        #[derive(Debug)]
        pub struct $FromIncomplete<'a> {
            lhs: &'a $T,
            rhs: &'a $Big,
        }

        impl AssignRound<$FromIncomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $FromIncomplete<'_>, round: $Round) -> $Ordering {
                $func_from(self, src.lhs, src.rhs, round)
            }
        }

        #[derive(Debug)]
        pub struct $FromOwnedIncomplete<'a> {
            lhs: $T,
            rhs: &'a $Big,
        }

        impl AssignRound<$FromOwnedIncomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $FromOwnedIncomplete<'_>, round: $Round) -> $Ordering {
                self.assign_round(&src, round)
            }
        }

        impl AssignRound<&$FromOwnedIncomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: &$FromOwnedIncomplete<'_>, round: $Round) -> $Ordering {
                $func_from(self, &src.lhs, src.rhs, round)
            }
        }
    };
}

// big # prim -> Big
// big # &prim -> Big
// &big # prim -> Incomplete
// &big # &prim -> Incomplete
// big #= prim
// big #= &prim
// struct Incomplete
// Big = Incomplete
#[cfg(feature = "float")]
macro_rules! arith_prim_exact_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $($T:ty, $Incomplete:ident;)*
    ) => { $(
        impl $Imp<$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: $T) -> $Big {
                self.$method_assign(rhs);
                self
            }
        }

        impl $Imp<&$T> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: &$T) -> $Big {
                self.$method_assign(*rhs);
                self
            }
        }

        impl<'b> $Imp<$T> for &'b $Big {
            type Output = $Incomplete<'b>;
            #[inline]
            fn $method(self, rhs: $T) -> $Incomplete<'b> {
                $Incomplete { lhs: self, rhs }
            }
        }

        impl<'b> $Imp<&$T> for &'b $Big {
            type Output = $Incomplete<'b>;
            #[inline]
            fn $method(self, rhs: &$T) -> $Incomplete<'b> {
                self.$method(*rhs)
            }
        }

        impl $ImpAssign<$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: $T) {
                $func(self, (), rhs, $Nearest);
            }
        }

        impl $ImpAssign<&$T> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: &$T) {
                self.$method_assign(*rhs);
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            lhs: &'a $Big,
            rhs: $T,
        }

        impl AssignRound<$Incomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $Incomplete<'_>, round: $Round) -> $Ordering {
                $func(self, src.lhs, src.rhs,round)
            }
        }
    )* };
}

// arith_prim_exact_round!
// big #= prim, Round -> Ordering
// big #= &prim, Round -> Ordering
#[cfg(feature = "float")]
macro_rules! arith_prim_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $($T:ty, $Incomplete:ident;)*
    ) => { $(
        arith_prim_exact_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $T, $Incomplete;
        }

        impl $ImpAssignRound<$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_assign_round(&mut self, rhs: $T, round: $Round) -> $Ordering {
                $func(self, (), rhs, round)
            }
        }

        impl $ImpAssignRound<&$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_assign_round(&mut self, rhs: &$T, round: $Round) -> $Ordering {
                self.$method_assign_round(*rhs, round)
            }
        }
    )* };
}

// arith_prim_round!
// prim # big -> Big
// prim # &big -> Incomplete
// &prim # big -> Big
// &prim # &big -> Incomplete
// prim #-> big
// &prim #-> big
// prim #-> big; Round -> Ordering
// &prim #-> big; Round -> Ordering
#[cfg(feature = "float")]
macro_rules! arith_prim_commut_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $ImpFrom:ident { $method_from:ident }
        $ImpFromRound:ident { $method_from_round:ident }
        $($T:ty, $Incomplete:ident;)*
    ) => { $(
        arith_prim_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $T, $Incomplete;
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign(self);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $T {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $Incomplete<'_> {
                rhs.$method(self)
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign(*self);
                rhs
            }
        }

        impl<'b> $Imp<&'b $Big> for &$T {
            type Output = $Incomplete<'b>;
            #[inline]
            fn $method(self, rhs: &'b $Big) -> $Incomplete<'b> {
                rhs.$method(*self)
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                self.$method_assign_round(lhs, $Nearest);
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                self.$method_assign_round(*lhs, $Nearest);
            }
        }

        impl $ImpFromRound<$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: $T, round: $Round) -> $Ordering {
                self.$method_assign_round(lhs, round)
            }
        }

        impl $ImpFromRound<&$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: &$T, round: $Round) -> $Ordering {
                self.$method_from_round(*lhs, round)
            }
        }
    )* };
}

// arith_prim_round!
// prim # big -> Big
// prim # &big -> FromIncomplete
// &prim # big -> Big
// &prim # &big -> FromIncomplete
// prim #-> big
// &prim #-> big
// prim #-> big; Round -> Ordering
// &prim #-> big; Round -> Ordering
// struct FromIncomplete
// Big = FromIncomplete
#[cfg(feature = "float")]
macro_rules! arith_prim_noncommut_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path, $func_from:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $ImpFrom:ident { $method_from:ident }
        $ImpFromRound:ident { $method_from_round:ident }
        $($T:ty, $Incomplete:ident, $FromIncomplete:ident;)*
    ) => { $(
        arith_prim_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $T, $Incomplete;
        }

        impl $Imp<$Big> for $T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from_round(self, $Nearest);
                rhs
            }
        }

        impl<'b> $Imp<&'b $Big> for $T {
            type Output = $FromIncomplete<'b>;
            #[inline]
            fn $method(self, rhs: &$Big) -> $FromIncomplete<'_> {
                $FromIncomplete { lhs: self, rhs }
            }
        }

        impl $Imp<$Big> for &$T {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from_round(*self, $Nearest);
                rhs
            }
        }

        impl<'b> $Imp<&'b $Big> for &$T {
            type Output = $FromIncomplete<'b>;
            #[inline]
            fn $method(self, rhs: &'b $Big) -> $FromIncomplete<'b> {
                $Imp::$method(*self, rhs)
            }
        }

        impl $ImpFrom<$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $T) {
                self.$method_from_round(lhs, $Nearest);
            }
        }

        impl $ImpFrom<&$T> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: &$T) {
                self.$method_from_round(*lhs, $Nearest);
            }
        }

        impl $ImpFromRound<$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: $T, round: $Round) -> $Ordering {
                $func_from(self, lhs, (), round)
            }
        }

        impl $ImpFromRound<&$T> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: &$T, round: $Round) -> $Ordering {
                self.$method_from_round(*lhs, round)
            }
        }

        #[derive(Debug)]
        pub struct $FromIncomplete<'a> {
            lhs: $T,
            rhs: &'a $Big,
        }

        impl AssignRound<$FromIncomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $FromIncomplete<'_>, round: $Round) -> $Ordering {
                $func_from(self, src.lhs, src.rhs, round)
            }
        }
    )* };
}

// big # mul -> Big
// &big # mul -> Incomplete
// big #= mul
// big #= mul, Round -> Ordering
// struct Incomplete
// Big = Incomplete
#[cfg(feature = "float")]
macro_rules! mul_op_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $Mul:ident;
        $Incomplete:ident
    ) => {
        impl $Imp<$Mul<'_>> for $Big {
            type Output = $Big;
            #[inline]
            fn $method(mut self, rhs: $Mul<'_>) -> $Big {
                self.$method_assign_round(rhs, $Nearest);
                self
            }
        }

        impl<'a> $Imp<$Mul<'a>> for &'a $Big {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: $Mul<'a>) -> $Incomplete<'_> {
                $Incomplete { lhs: self, rhs }
            }
        }

        impl $ImpAssign<$Mul<'_>> for $Big {
            #[inline]
            fn $method_assign(&mut self, rhs: $Mul<'_>) {
                self.$method_assign_round(rhs, $Nearest);
            }
        }

        impl $ImpAssignRound<$Mul<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_assign_round(&mut self, rhs: $Mul<'_>, round: $Round) -> $Ordering {
                $func(self, (), rhs, round)
            }
        }

        #[derive(Debug)]
        pub struct $Incomplete<'a> {
            lhs: &'a $Big,
            rhs: $Mul<'a>,
        }

        impl AssignRound<$Incomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $Incomplete<'_>, round: $Round) -> $Ordering {
                $func(self, src.lhs, src.rhs, round)
            }
        }
    };
}

// mul_op_round!
// mul # big -> Big
// mul # &big -> Incomplete
// mul #-> big
// mul #-> big; Round -> Ordering
#[cfg(feature = "float")]
macro_rules! mul_op_commut_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $ImpFrom:ident { $method_from:ident }
        $ImpFromRound:ident { $method_from_round:ident }
        $Mul:ident;
        $Incomplete:ident
    ) => {
        mul_op_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $Mul;
            $Incomplete
        }

        impl $Imp<$Big> for $Mul<'_> {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_assign_round(self, $Nearest);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $Mul<'a> {
            type Output = $Incomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $Incomplete<'_> {
                rhs.$method(self)
            }
        }

        impl $ImpFrom<$Mul<'_>> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $Mul<'_>) {
                self.$method_assign_round(lhs, $Nearest);
            }
        }

        impl $ImpFromRound<$Mul<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: $Mul<'_>, round: $Round) -> $Ordering {
                self.$method_assign_round(lhs, round)
            }
        }
    };
}

// mul_op_round!
// mul # big -> Big
// mul # &big -> FromIncomplete
// mul #-> big
// mul #-> big; Round -> Ordering
// struct FromIncomplete
// Big = FromIncomplete
#[cfg(feature = "float")]
macro_rules! mul_op_noncommut_round {
    (
        $Big:ty, $Round:ty, $Nearest:expr, $Ordering:ty;
        $func:path, $func_from:path;
        $Imp:ident { $method:ident }
        $ImpAssign:ident { $method_assign:ident }
        $ImpAssignRound:ident { $method_assign_round:ident }
        $ImpFrom:ident { $method_from:ident }
        $ImpFromRound:ident { $method_from_round:ident }
        $Mul:ident;
        $Incomplete:ident,
        $FromIncomplete:ident
    ) => {
        mul_op_round! {
            $Big, $Round, $Nearest, $Ordering;
            $func;
            $Imp { $method }
            $ImpAssign { $method_assign }
            $ImpAssignRound { $method_assign_round }
            $Mul;
            $Incomplete
        }

        impl $Imp<$Big> for $Mul<'_> {
            type Output = $Big;
            #[inline]
            fn $method(self, mut rhs: $Big) -> $Big {
                rhs.$method_from_round(self, $Nearest);
                rhs
            }
        }

        impl<'a> $Imp<&'a $Big> for $Mul<'a> {
            type Output = $FromIncomplete<'a>;
            #[inline]
            fn $method(self, rhs: &'a $Big) -> $FromIncomplete<'_> {
                $FromIncomplete { lhs: self, rhs }
            }
        }

        impl $ImpFrom<$Mul<'_>> for $Big {
            #[inline]
            fn $method_from(&mut self, lhs: $Mul<'_>) {
                self.$method_from_round(lhs, $Nearest);
            }
        }

        impl $ImpFromRound<$Mul<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn $method_from_round(&mut self, lhs: $Mul<'_>, round: $Round) -> $Ordering {
                $func_from(self, lhs, (), round)
            }
        }

        #[derive(Debug)]
        pub struct $FromIncomplete<'a> {
            lhs: $Mul<'a>,
            rhs: &'a $Big,
        }

        impl AssignRound<$FromIncomplete<'_>> for $Big {
            type Round = $Round;
            type Ordering = $Ordering;
            #[inline]
            fn assign_round(&mut self, src: $FromIncomplete<'_>, round: $Round) -> $Ordering {
                $func_from(self, src.lhs, src.rhs, round)
            }
        }
    };
}

#[cfg(any(feature = "integer", feature = "float"))]
macro_rules! static_assert {
    ($cond:expr) => {
        const _: [(); (!$cond) as usize] = [];
    };
}

#[cfg(any(feature = "integer", feature = "float"))]
macro_rules! static_assert_same_layout {
    ($T:ty, $U:ty) => {
        static_assert!(core::mem::size_of::<$T>() == core::mem::size_of::<$U>());
        static_assert!(core::mem::align_of::<$T>() == core::mem::align_of::<$U>());
    };
}

#[cfg(any(feature = "integer", feature = "float"))]
macro_rules! static_assert_same_size {
    ($T:ty, $U:ty) => {
        static_assert!(core::mem::size_of::<$T>() == core::mem::size_of::<$U>());
    };
}

#[cfg(any(feature = "integer", feature = "float"))]
pub struct CastPtr<Src>(pub *const Src);
#[cfg(any(feature = "integer", feature = "float"))]
impl<Src> CastPtr<Src> {
    #[inline(always)]
    pub fn static_check_size(&self) -> Src {
        unreachable!()
    }
    #[inline(always)]
    pub fn get<Dst>(self) -> *const Dst {
        debug_assert_eq!(core::mem::align_of::<Dst>(), core::mem::align_of::<Src>());
        self.0 as *const Dst
    }
}

#[cfg(any(feature = "integer", feature = "float"))]
pub struct CastPtrMut<Src>(pub *mut Src);
#[cfg(any(feature = "integer", feature = "float"))]
impl<Src> CastPtrMut<Src> {
    #[inline(always)]
    pub fn static_check_size(&self) -> Src {
        unreachable!()
    }
    #[inline(always)]
    pub fn get<Dst>(self) -> *mut Dst {
        debug_assert_eq!(core::mem::align_of::<Dst>(), core::mem::align_of::<Src>());
        self.0 as *mut Dst
    }
}

#[cfg(any(feature = "integer", feature = "float"))]
macro_rules! cast_ptr {
    ($src:expr, $T:ty) => {{
        let ptr = crate::macros::CastPtr($src);
        if false {
            #[allow(unused_unsafe)]
            // clippy false positive. We are transmuting pointees, not pointers.
            #[allow(clippy::transmute_ptr_to_ptr)]
            unsafe {
                let _ = core::mem::transmute::<_, $T>(ptr.static_check_size());
            }
        }
        ptr.get::<$T>()
    }};
}

#[cfg(any(feature = "integer", feature = "float"))]
macro_rules! cast_ptr_mut {
    ($src:expr, $T:ty) => {{
        let ptr = crate::macros::CastPtrMut($src);
        if false {
            #[allow(unused_unsafe)]
            // clippy false positive. We are transmuting pointees, not pointers.
            #[allow(clippy::transmute_ptr_to_ptr)]
            unsafe {
                let _ = core::mem::transmute::<_, $T>(ptr.static_check_size());
            }
        }
        ptr.get::<$T>()
    }};
}

#[cfg(gmp_limb_bits_64)]
#[cfg(any(feature = "integer", feature = "float"))]
macro_rules! small_limbs {
    () => {
        [
            core::mem::MaybeUninit::uninit(),
            core::mem::MaybeUninit::uninit(),
        ]
    };
    ($limb:expr) => {
        [
            core::mem::MaybeUninit::new($limb),
            core::mem::MaybeUninit::uninit(),
        ]
    };
}

#[cfg(gmp_limb_bits_32)]
#[cfg(any(feature = "integer", feature = "float"))]
macro_rules! small_limbs {
    () => {
        [
            core::mem::MaybeUninit::uninit(),
            core::mem::MaybeUninit::uninit(),
            core::mem::MaybeUninit::uninit(),
            core::mem::MaybeUninit::uninit(),
        ]
    };
    ($limb:expr) => {
        [
            core::mem::MaybeUninit::new($limb),
            core::mem::MaybeUninit::uninit(),
            core::mem::MaybeUninit::uninit(),
            core::mem::MaybeUninit::uninit(),
        ]
    };
}
