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

use crate::{ext::xmpq, misc::NegAbs, Integer, Rational};
use az::{UnwrappedAs, UnwrappedCast};
use core::cmp::Ordering;

impl Eq for Rational {}

impl Ord for Rational {
    #[inline]
    fn cmp(&self, other: &Rational) -> Ordering {
        xmpq::cmp(self, other)
    }
}

impl PartialEq for Rational {
    #[inline]
    fn eq(&self, other: &Rational) -> bool {
        xmpq::equal(self, other)
    }
}

impl PartialOrd for Rational {
    #[inline]
    fn partial_cmp(&self, other: &Rational) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<Integer> for Rational {
    #[inline]
    fn eq(&self, other: &Integer) -> bool {
        xmpq::cmp_z(self, other) == Ordering::Equal
    }
}

impl PartialEq<Rational> for Integer {
    #[inline]
    fn eq(&self, other: &Rational) -> bool {
        other.eq(self)
    }
}

impl PartialOrd<Integer> for Rational {
    #[inline]
    fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
        Some(xmpq::cmp_z(self, other))
    }
}

impl PartialOrd<Rational> for Integer {
    #[inline]
    fn partial_cmp(&self, other: &Rational) -> Option<Ordering> {
        other.partial_cmp(self).map(Ordering::reverse)
    }
}

macro_rules! cmp_common {
    ($T:ty) => {
        impl PartialEq<$T> for Rational {
            #[inline]
            fn eq(&self, other: &$T) -> bool {
                self.partial_cmp(other) == Some(Ordering::Equal)
            }
        }

        impl PartialEq<Rational> for $T {
            #[inline]
            fn eq(&self, other: &Rational) -> bool {
                other.eq(self)
            }
        }

        impl PartialOrd<Rational> for $T {
            #[inline]
            fn partial_cmp(&self, other: &Rational) -> Option<Ordering> {
                other.partial_cmp(self).map(Ordering::reverse)
            }
        }
    };
}

macro_rules! cmp_num {
    ($Num:ty, $cmp:path) => {
        impl PartialOrd<$Num> for Rational {
            #[inline]
            fn partial_cmp(&self, other: &$Num) -> Option<Ordering> {
                Some($cmp(self, *other, 1))
            }
        }
        cmp_common! { $Num }
    };
}

macro_rules! cmp_num_cast {
    ($New:ty, $Existing:ty) => {
        impl PartialOrd<$New> for Rational {
            #[inline]
            fn partial_cmp(&self, other: &$New) -> Option<Ordering> {
                self.partial_cmp(&(*other).unwrapped_as::<$Existing>())
            }
        }
        cmp_common! { $New }
    };
}

cmp_num_cast! { i8, i32 }
cmp_num_cast! { i16, i32 }
cmp_num! { i32, xmpq::cmp_i32 }
cmp_num! { i64, xmpq::cmp_i64 }
cmp_num! { i128, xmpq::cmp_i128 }
#[cfg(target_pointer_width = "32")]
cmp_num_cast! { isize, i32 }
#[cfg(target_pointer_width = "64")]
cmp_num_cast! { isize, i64 }

cmp_num_cast! { u8, u32 }
cmp_num_cast! { u16, u32 }
cmp_num! { u32, xmpq::cmp_u32 }
cmp_num! { u64, xmpq::cmp_u64 }
cmp_num! { u128, xmpq::cmp_u128 }
#[cfg(target_pointer_width = "32")]
cmp_num_cast! { usize, u32 }
#[cfg(target_pointer_width = "64")]
cmp_num_cast! { usize, u64 }

macro_rules! cmp_num_iden {
    ($func:path; $Num:ty; $($Den:ty)*) => { $(
        impl PartialOrd<($Num, $Den)> for Rational {
            #[inline]
            fn partial_cmp(&self, other: &($Num, $Den)) -> Option<Ordering> {
                assert_ne!(other.1, 0, "division by zero");
                let (neg_den, abs_den) = other.1.neg_abs();
                let as_neg;
                let to_compare = if neg_den {
                    as_neg = self.as_neg();
                    &*as_neg
                } else {
                    self
                };
                let cmp = $func(to_compare, other.0.unwrapped_cast(), abs_den.unwrapped_cast());
                if neg_den {
                    Some(cmp.reverse())
                } else {
                    Some(cmp)
                }
            }
        }
        cmp_common!{ ($Num, $Den) }
    )* };
}

macro_rules! cmp_num_uden {
    ($func:path; $Num:ty; $($Den:ty)*) => { $(
        impl PartialOrd<($Num, $Den)> for Rational {
            #[inline]
            fn partial_cmp(&self, other: &($Num, $Den)) -> Option<Ordering> {
                assert_ne!(other.1, 0, "division by zero");
                Some($func(self, other.0.unwrapped_cast(), other.1.unwrapped_cast()))
            }
        }
        cmp_common!{ ($Num, $Den) }
    )* };
}

macro_rules! cmp_inum_32 {
    ($($Num:ty)*) => { $(
        cmp_num_iden! { xmpq::cmp_i32; $Num; i8 i16 i32 }
        cmp_num_iden! { xmpq::cmp_i64; $Num; i64 }
        cmp_num_iden! { xmpq::cmp_i128; $Num; i128 }
        #[cfg(target_pointer_width = "32")]
        cmp_num_iden! { xmpq::cmp_i32; $Num; isize }
        #[cfg(target_pointer_width = "64")]
        cmp_num_iden! { xmpq::cmp_i64; $Num; isize }

        cmp_num_uden! { xmpq::cmp_i32; $Num; u8 u16 u32 }
        cmp_num_uden! { xmpq::cmp_i64; $Num; u64 }
        cmp_num_uden! { xmpq::cmp_i128; $Num; u128 }
        #[cfg(target_pointer_width = "32")]
        cmp_num_uden! { xmpq::cmp_i32; $Num; usize }
        #[cfg(target_pointer_width = "64")]
        cmp_num_uden! { xmpq::cmp_i64; $Num; usize }
    )* };
}

macro_rules! cmp_inum_64 {
    ($($Num:ty)*) => { $(
        cmp_num_iden! { xmpq::cmp_i64; $Num; i8 i16 i32 i64 }
        cmp_num_iden! { xmpq::cmp_i128; $Num; i128 }
        cmp_num_iden! { xmpq::cmp_i64; $Num; isize }
        cmp_num_uden! { xmpq::cmp_i64; $Num; u8 u16 u32 u64 }
        cmp_num_uden! { xmpq::cmp_i128; $Num; u128 }
        cmp_num_uden! { xmpq::cmp_i64; $Num; usize }
    )* };
}

macro_rules! cmp_inum_128 {
    ($($Num:ty)*) => { $(
        cmp_num_iden! { xmpq::cmp_i128; $Num; i8 i16 i32 i64 i128 isize }
        cmp_num_uden! { xmpq::cmp_i128; $Num; u8 u16 u32 u64 u128 usize }
    )* };
}

macro_rules! cmp_unum_32 {
    ($($Num:ty)*) => { $(
        cmp_num_iden! { xmpq::cmp_u32; $Num; i8 i16 i32 }
        cmp_num_iden! { xmpq::cmp_u64; $Num; i64 }
        cmp_num_iden! { xmpq::cmp_u128; $Num; i128 }
        #[cfg(target_pointer_width = "32")]
        cmp_num_iden! { xmpq::cmp_u32; $Num; isize }
        #[cfg(target_pointer_width = "64")]
        cmp_num_iden! { xmpq::cmp_u64; $Num; isize }

        cmp_num_uden! { xmpq::cmp_u32; $Num; u8 u16 u32 }
        cmp_num_uden! { xmpq::cmp_u64; $Num; u64 }
        cmp_num_uden! { xmpq::cmp_u128; $Num; u128 }
        #[cfg(target_pointer_width = "32")]
        cmp_num_uden! { xmpq::cmp_u32; $Num; usize }
        #[cfg(target_pointer_width = "64")]
        cmp_num_uden! { xmpq::cmp_u64; $Num; usize }
    )* };
}

macro_rules! cmp_unum_64 {
    ($($Num:ty)*) => { $(
        cmp_num_iden! { xmpq::cmp_u64; $Num; i8 i16 i32 i64 }
        cmp_num_iden! { xmpq::cmp_u128; $Num; i128 }
        cmp_num_iden! { xmpq::cmp_u64; $Num; isize }
        cmp_num_uden! { xmpq::cmp_u64; $Num; u8 u16 u32 u64 }
        cmp_num_uden! { xmpq::cmp_u128; $Num; u128 }
        cmp_num_uden! { xmpq::cmp_u64; $Num; usize }
    )* };
}

macro_rules! cmp_unum_128 {
    ($($Num:ty)*) => { $(
        cmp_num_iden! { xmpq::cmp_u128; $Num; i8 i16 i32 i64 i128 isize }
        cmp_num_uden! { xmpq::cmp_u128; $Num; u8 u16 u32 u64 u128 usize }
    )* };
}

cmp_inum_32! { i8 i16 i32 }
cmp_inum_64! { i64 }
cmp_inum_128! { i128 }
#[cfg(target_pointer_width = "32")]
cmp_inum_32! { isize }
#[cfg(target_pointer_width = "64")]
cmp_inum_64! { isize }

cmp_unum_32! { u8 u16 u32 }
cmp_unum_64! { u64 }
cmp_unum_128! { u128 }
#[cfg(target_pointer_width = "32")]
cmp_unum_32! { usize }
#[cfg(target_pointer_width = "64")]
cmp_unum_64! { usize }

macro_rules! cmp_f {
    ($($T:ty)*) => { $(
        impl PartialOrd<$T> for Rational {
            #[inline]
            fn partial_cmp(&self, other: &$T) -> Option<Ordering> {
                if other.is_finite() {
                    Some(xmpq::cmp_finite_d(self, (*other).unwrapped_cast()))
                } else if other.is_nan() {
                    None
                } else if other.is_sign_negative() {
                    Some(Ordering::Greater)
                } else {
                    Some(Ordering::Less)
                }
            }
        }
        cmp_common! { $T }
    )* };
}

cmp_f! { f32 f64 }

#[cfg(test)]
mod tests {
    use crate::{
        tests::{I128, I32, I64, U128, U32, U64},
        Rational,
    };
    use az::{Az, Cast};
    use core::{cmp::Ordering, f32, f64, ops::Neg};

    fn check_cmp_prim<T>(s: &[T], against: &[Rational])
    where
        Rational: From<T> + PartialEq<T> + PartialOrd<T>,
        T: Copy + PartialEq<Rational> + PartialOrd<Rational>,
    {
        for op in s {
            let iop = Rational::from(*op);
            for b in against {
                assert_eq!(b.eq(op), PartialEq::<Rational>::eq(b, &iop));
                assert_eq!(op.eq(b), PartialEq::<Rational>::eq(&iop, b));
                assert_eq!(b.eq(op), op.eq(b));
                assert_eq!(
                    b.partial_cmp(op),
                    PartialOrd::<Rational>::partial_cmp(b, &iop)
                );
                assert_eq!(
                    op.partial_cmp(b),
                    PartialOrd::<Rational>::partial_cmp(&iop, b)
                );
                assert_eq!(
                    b.partial_cmp(op).unwrap(),
                    op.partial_cmp(b).unwrap().reverse()
                );
            }
        }
    }

    #[test]
    fn check_cmp_u_s() {
        let large = [(5, 17, 100), (-11, 3, 200), (33, 777, -150)];
        let against = large
            .iter()
            .map(|&(n, d, s)| Rational::from((n, d)) << s)
            .chain(U32.iter().map(|&x| Rational::from(x)))
            .chain(I32.iter().map(|&x| Rational::from(x)))
            .chain(U64.iter().map(|&x| Rational::from(x)))
            .chain(I64.iter().map(|&x| Rational::from(x)))
            .chain(U128.iter().map(|&x| Rational::from(x)))
            .chain(I128.iter().map(|&x| Rational::from(x)))
            .collect::<Vec<Rational>>();
        check_cmp_prim(U32, &against);
        check_cmp_prim(I32, &against);
        check_cmp_prim(U64, &against);
        check_cmp_prim(I64, &against);
        check_cmp_prim(U128, &against);
        check_cmp_prim(I128, &against);
    }

    fn check_cmp_prim_tuple<N, D>(num: &[N], den: &[D], against: &[Rational])
    where
        Rational: From<(N, D)> + PartialEq<(N, D)> + PartialOrd<(N, D)>,
        N: Copy,
        D: Copy + Eq,
        (N, D): PartialEq<Rational> + PartialOrd<Rational>,
        u8: Cast<D>,
    {
        for n in num {
            for d in den {
                if *d == 0.az() {
                    continue;
                }
                let op = (*n, *d);
                let iop = Rational::from(op);
                for b in against {
                    assert_eq!(b.eq(&op), PartialEq::<Rational>::eq(b, &iop));
                    assert_eq!(op.eq(b), PartialEq::<Rational>::eq(&iop, b));
                    assert_eq!(b.eq(&op), op.eq(b));
                    assert_eq!(
                        b.partial_cmp(&op),
                        PartialOrd::<Rational>::partial_cmp(b, &iop)
                    );
                    assert_eq!(
                        op.partial_cmp(b),
                        PartialOrd::<Rational>::partial_cmp(&iop, b)
                    );
                    assert_eq!(
                        b.partial_cmp(&op).unwrap(),
                        op.partial_cmp(b).unwrap().reverse()
                    );
                }
            }
        }
    }

    #[test]
    fn check_cmp_tuple() {
        let large = [(5, 17, 100), (-11, 3, 200), (33, 777, -150)];
        let against = large
            .iter()
            .map(|&(n, d, s)| Rational::from((n, d)) << s)
            .chain(U32.iter().map(|&x| Rational::from(x)))
            .chain(I32.iter().map(|&x| Rational::from(x)))
            .chain(U64.iter().map(|&x| Rational::from(x)))
            .chain(I64.iter().map(|&x| Rational::from(x)))
            .chain(U128.iter().map(|&x| Rational::from(x)))
            .chain(I128.iter().map(|&x| Rational::from(x)))
            .collect::<Vec<Rational>>();
        check_cmp_prim_tuple(U32, U32, &against);
        check_cmp_prim_tuple(U32, I32, &against);
        check_cmp_prim_tuple(U32, U64, &against);
        check_cmp_prim_tuple(U32, I64, &against);
        check_cmp_prim_tuple(I32, U32, &against);
        check_cmp_prim_tuple(I32, I32, &against);
        check_cmp_prim_tuple(I32, U64, &against);
        check_cmp_prim_tuple(I32, I64, &against);
        check_cmp_prim_tuple(U64, U32, &against);
        check_cmp_prim_tuple(U64, I32, &against);
        check_cmp_prim_tuple(U64, U64, &against);
        check_cmp_prim_tuple(U64, I64, &against);
        check_cmp_prim_tuple(I64, U32, &against);
        check_cmp_prim_tuple(I64, I32, &against);
        check_cmp_prim_tuple(I64, U64, &against);
        check_cmp_prim_tuple(I64, I64, &against);
        check_cmp_prim_tuple(U128, U128, &against);
        check_cmp_prim_tuple(U128, I128, &against);
        check_cmp_prim_tuple(I128, U128, &against);
        check_cmp_prim_tuple(I128, I128, &against);
    }

    fn check_known_cmp<T>(t: T, against: &Rational, ord: Ordering)
    where
        Rational: PartialOrd<T> + PartialOrd<<T as Neg>::Output>,
        T: Copy + Neg + PartialEq<Rational> + PartialOrd<Rational>,
        <T as Neg>::Output: PartialEq<Rational> + PartialOrd<Rational>,
    {
        let neg = against.as_neg();
        assert_eq!(t.eq(against), ord == Ordering::Equal);
        assert_eq!((-t).eq(&*neg), ord == Ordering::Equal);
        assert_eq!(against.eq(&t), ord == Ordering::Equal);
        assert_eq!(neg.eq(&-t), ord == Ordering::Equal);
        assert_eq!(t.partial_cmp(against), Some(ord));
        assert_eq!((-t).partial_cmp(&*neg), Some(ord.reverse()));
        assert_eq!(against.partial_cmp(&t), Some(ord.reverse()));
        assert_eq!(neg.partial_cmp(&-t), Some(ord));
    }

    fn check_nan_cmp<T>(t: T, against: &Rational)
    where
        Rational: PartialOrd<T> + PartialOrd<<T as Neg>::Output>,
        T: Copy + Neg + PartialEq<Rational> + PartialOrd<Rational>,
        <T as Neg>::Output: PartialEq<Rational> + PartialOrd<Rational>,
    {
        let neg = against.as_neg();
        assert!(t.ne(against));
        assert!((-t).ne(&*neg));
        assert!(against.ne(&t));
        assert!(neg.ne(&-t));
        assert!(t.partial_cmp(against).is_none());
        assert!((-t).partial_cmp(&*neg).is_none());
        assert!(against.partial_cmp(&t).is_none());
        assert!(neg.partial_cmp(&-t).is_none());
    }

    #[test]
    fn check_cmp_f() {
        let large = [(5, 2, 0), (5, 17, 100), (-11, 3, 200), (33, 777, -150)];
        let against = large
            .iter()
            .map(|&(n, d, s)| Rational::from((n, d)) << s)
            .chain(U32.iter().map(|&x| Rational::from(x)))
            .chain(I32.iter().map(|&x| Rational::from(x)))
            .chain(U64.iter().map(|&x| Rational::from(x)))
            .chain(I64.iter().map(|&x| Rational::from(x)))
            .chain(U128.iter().map(|&x| Rational::from(x)))
            .chain(I128.iter().map(|&x| Rational::from(x)))
            .collect::<Vec<Rational>>();
        for b in &against {
            check_known_cmp(0.0f32, b, b.cmp0().reverse());
            check_known_cmp(0.0f64, b, b.cmp0().reverse());
            let ord = 5.partial_cmp(&(b.clone() << 1)).unwrap();
            check_known_cmp(2.5f32, b, ord);
            check_known_cmp(2.5f64, b, ord);
            check_known_cmp(f32::INFINITY, b, Ordering::Greater);
            check_known_cmp(f64::INFINITY, b, Ordering::Greater);
            check_nan_cmp(f32::NAN, b);
            check_nan_cmp(f64::NAN, b);
        }
    }
}
