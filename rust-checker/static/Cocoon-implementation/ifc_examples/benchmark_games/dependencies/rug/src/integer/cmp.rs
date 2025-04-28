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

use crate::{ext::xmpz, Integer};
use az::UnwrappedAs;
use core::cmp::Ordering;

impl Eq for Integer {}

impl Ord for Integer {
    #[inline]
    fn cmp(&self, other: &Integer) -> Ordering {
        xmpz::cmp(self, other)
    }
}

impl PartialEq for Integer {
    #[inline]
    fn eq(&self, other: &Integer) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for Integer {
    #[inline]
    fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

macro_rules! cmp {
    ($T:ty, $func:path) => {
        impl PartialEq<$T> for Integer {
            #[inline]
            fn eq(&self, other: &$T) -> bool {
                self.partial_cmp(other) == Some(Ordering::Equal)
            }
        }

        impl PartialEq<Integer> for $T {
            #[inline]
            fn eq(&self, other: &Integer) -> bool {
                other.partial_cmp(self) == Some(Ordering::Equal)
            }
        }

        impl PartialOrd<$T> for Integer {
            #[inline]
            fn partial_cmp(&self, other: &$T) -> Option<Ordering> {
                Some($func(self, *other))
            }
        }

        impl PartialOrd<Integer> for $T {
            #[inline]
            fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
                other.partial_cmp(self).map(Ordering::reverse)
            }
        }
    };
}

macro_rules! cmp_cast {
    ($New:ty, $Existing:ty) => {
        impl PartialEq<$New> for Integer {
            #[inline]
            fn eq(&self, other: &$New) -> bool {
                self.partial_cmp(&(*other).unwrapped_as::<$Existing>()) == Some(Ordering::Equal)
            }
        }

        impl PartialEq<Integer> for $New {
            #[inline]
            fn eq(&self, other: &Integer) -> bool {
                other.partial_cmp(&(*self).unwrapped_as::<$Existing>()) == Some(Ordering::Equal)
            }
        }

        impl PartialOrd<$New> for Integer {
            #[inline]
            fn partial_cmp(&self, other: &$New) -> Option<Ordering> {
                self.partial_cmp(&(*other).unwrapped_as::<$Existing>())
            }
        }

        impl PartialOrd<Integer> for $New {
            #[inline]
            fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
                other
                    .partial_cmp(&(*self).unwrapped_as::<$Existing>())
                    .map(Ordering::reverse)
            }
        }
    };
}

cmp_cast! { i8, i32 }
cmp_cast! { i16, i32 }
cmp! { i32, xmpz::cmp_i32 }
cmp! { i64, xmpz::cmp_i64 }
cmp! { i128, xmpz::cmp_i128 }
#[cfg(target_pointer_width = "32")]
cmp_cast! { isize, i32 }
#[cfg(target_pointer_width = "64")]
cmp_cast! { isize, i64 }

cmp_cast! { u8, u32 }
cmp_cast! { u16, u32 }
cmp! { u32, xmpz::cmp_u32 }
cmp! { u64, xmpz::cmp_u64 }
cmp! { u128, xmpz::cmp_u128 }
#[cfg(target_pointer_width = "32")]
cmp_cast! { usize, u32 }
#[cfg(target_pointer_width = "64")]
cmp_cast! { usize, u64 }

cmp_cast! { f32, f64 }

impl PartialEq<f64> for Integer {
    #[inline]
    fn eq(&self, other: &f64) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl PartialEq<Integer> for f64 {
    #[inline]
    fn eq(&self, other: &Integer) -> bool {
        other.partial_cmp(self) == Some(Ordering::Equal)
    }
}

impl PartialOrd<f64> for Integer {
    #[inline]
    fn partial_cmp(&self, other: &f64) -> Option<Ordering> {
        xmpz::cmp_f64(self, *other)
    }
}

impl PartialOrd<Integer> for f64 {
    #[inline]
    fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
        other.partial_cmp(self).map(Ordering::reverse)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        tests::{I128, I32, I64, U128, U32, U64},
        Integer,
    };
    use core::{cmp::Ordering, f32, f64, ops::Neg};

    fn check_cmp_prim<T>(s: &[T], against: &[Integer])
    where
        Integer: From<T> + PartialEq<T> + PartialOrd<T>,
        T: Copy + PartialEq<Integer> + PartialOrd<Integer>,
    {
        for op in s {
            let iop = Integer::from(*op);
            for b in against {
                assert_eq!(b.eq(op), PartialEq::<Integer>::eq(b, &iop));
                assert_eq!(op.eq(b), PartialEq::<Integer>::eq(&iop, b));
                assert_eq!(b.eq(op), op.eq(b));
                assert_eq!(
                    b.partial_cmp(op),
                    PartialOrd::<Integer>::partial_cmp(b, &iop)
                );
                assert_eq!(
                    op.partial_cmp(b),
                    PartialOrd::<Integer>::partial_cmp(&iop, b)
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
        let large = [(1, 100), (-11, 200), (33, 150)];
        let against = large
            .iter()
            .map(|&(n, s)| Integer::from(n) << s)
            .chain(U32.iter().map(|&x| Integer::from(x)))
            .chain(I32.iter().map(|&x| Integer::from(x)))
            .chain(U64.iter().map(|&x| Integer::from(x)))
            .chain(I64.iter().map(|&x| Integer::from(x)))
            .chain(U128.iter().map(|&x| Integer::from(x)))
            .chain(I128.iter().map(|&x| Integer::from(x)))
            .collect::<Vec<Integer>>();
        check_cmp_prim(U32, &against);
        check_cmp_prim(I32, &against);
        check_cmp_prim(U64, &against);
        check_cmp_prim(I64, &against);
        check_cmp_prim(U128, &against);
        check_cmp_prim(I128, &against);
    }

    fn check_known_cmp<T>(t: T, against: &Integer, ord: Ordering)
    where
        Integer: PartialOrd<T> + PartialOrd<<T as Neg>::Output>,
        T: Copy + Neg + PartialEq<Integer> + PartialOrd<Integer>,
        <T as Neg>::Output: PartialEq<Integer> + PartialOrd<Integer>,
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

    fn check_nan_cmp<T>(t: T, against: &Integer)
    where
        Integer: PartialOrd<T> + PartialOrd<<T as Neg>::Output>,
        T: Copy + Neg + PartialEq<Integer> + PartialOrd<Integer>,
        <T as Neg>::Output: PartialEq<Integer> + PartialOrd<Integer>,
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
        let large = [(1, 100), (-11, 200), (33, 150)];
        let against = large
            .iter()
            .map(|&(n, s)| Integer::from(n) << s)
            .chain(U32.iter().map(|&x| Integer::from(x)))
            .chain(I32.iter().map(|&x| Integer::from(x)))
            .chain(U64.iter().map(|&x| Integer::from(x)))
            .chain(I64.iter().map(|&x| Integer::from(x)))
            .chain(U128.iter().map(|&x| Integer::from(x)))
            .chain(I128.iter().map(|&x| Integer::from(x)))
            .collect::<Vec<Integer>>();
        for b in &against {
            check_known_cmp(0.0f32, b, b.cmp0().reverse());
            check_known_cmp(0.0f64, b, b.cmp0().reverse());
            let ord = if *b <= 2 {
                Ordering::Greater
            } else {
                Ordering::Less
            };
            check_known_cmp(2.5f32, b, ord);
            check_known_cmp(2.5f64, b, ord);
            check_known_cmp(f32::INFINITY, b, Ordering::Greater);
            check_known_cmp(f64::INFINITY, b, Ordering::Greater);
            check_nan_cmp(f32::NAN, b);
            check_nan_cmp(f64::NAN, b);
        }
    }
}
