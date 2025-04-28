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
    ext::xmpfr,
    float::{
        big::{IExpIncomplete, UExpIncomplete},
        Special,
    },
    Float,
};
use az::Cast;
use core::cmp::Ordering;

impl PartialEq for Float {
    #[inline]
    fn eq(&self, other: &Float) -> bool {
        xmpfr::equal_p(self, other)
    }
}

impl PartialOrd for Float {
    #[inline]
    fn partial_cmp(&self, other: &Float) -> Option<Ordering> {
        if xmpfr::unordered_p(self, other) {
            None
        } else {
            Some(xmpfr::cmp(self, other))
        }
    }

    #[inline]
    fn lt(&self, other: &Float) -> bool {
        xmpfr::less_p(self, other)
    }

    #[inline]
    fn le(&self, other: &Float) -> bool {
        xmpfr::lessequal_p(self, other)
    }

    #[inline]
    fn gt(&self, other: &Float) -> bool {
        xmpfr::greater_p(self, other)
    }

    #[inline]
    fn ge(&self, other: &Float) -> bool {
        xmpfr::greaterequal_p(self, other)
    }
}

macro_rules! cmp {
    ($T:ty) => {
        impl PartialEq<$T> for Float {
            #[inline]
            fn eq(&self, other: &$T) -> bool {
                self.partial_cmp(other) == Some(Ordering::Equal)
            }
        }

        impl PartialEq<Float> for $T {
            #[inline]
            fn eq(&self, other: &Float) -> bool {
                other.partial_cmp(self) == Some(Ordering::Equal)
            }
        }

        impl PartialOrd<Float> for $T {
            #[inline]
            fn partial_cmp(&self, other: &Float) -> Option<Ordering> {
                other.partial_cmp(self).map(Ordering::reverse)
            }
        }
    };
}

macro_rules! cmp_i {
    ($T:ty, |$f:ident, $o:ident| $eval:expr) => {
        cmp! { $T }

        impl PartialOrd<$T> for Float {
            #[inline]
            fn partial_cmp(&self, $o: &$T) -> Option<Ordering> {
                if self.is_nan() {
                    None
                } else {
                    let $f = self;
                    Some($eval)
                }
            }
        }
    };
}

macro_rules! cmp_f {
    ($T:ty, |$f:ident, $o:ident| $eval:expr) => {
        cmp! { $T }

        impl PartialOrd<$T> for Float {
            #[inline]
            fn partial_cmp(&self, $o: &$T) -> Option<Ordering> {
                if self.is_nan() || $o.is_nan() {
                    None
                } else {
                    let $f = self;
                    Some($eval)
                }
            }
        }
    };
}

#[cfg(feature = "integer")]
cmp_i! { Integer, |f, z| xmpfr::cmp_z(f, z) }
#[cfg(feature = "rational")]
cmp_i! { Rational, |f, q| xmpfr::cmp_q(f, q) }

cmp_i! { i8, |f, t| xmpfr::cmp_si(f, (*t).into()) }
cmp_i! { i16, |f, t| xmpfr::cmp_si(f, (*t).into()) }
cmp_i! { i32, |f, t| xmpfr::cmp_si(f, (*t).into()) }
cmp_i! { i64, |f, t| xmpfr::cmp_i64(f, *t) }
cmp_i! { i128, |f, t| xmpfr::cmp_i128(f, *t) }
#[cfg(target_pointer_width = "32")]
cmp_i! { isize, |f, t| xmpfr::cmp_si(f, (*t).cast()) }
#[cfg(target_pointer_width = "64")]
cmp_i! { isize, |f, t| xmpfr::cmp_i64(f, (*t).cast()) }

cmp_i! { u8, |f, t| xmpfr::cmp_ui(f, (*t).into()) }
cmp_i! { u16, |f, t| xmpfr::cmp_ui(f, (*t).into()) }
cmp_i! { u32, |f, t| xmpfr::cmp_ui(f, (*t).into()) }
cmp_i! { u64, |f, t| xmpfr::cmp_u64(f, *t) }
cmp_i! { u128, |f, t| xmpfr::cmp_u128(f, *t) }
#[cfg(target_pointer_width = "32")]
cmp_i! { usize, |f, t| xmpfr::cmp_ui(f, (*t).cast()) }
#[cfg(target_pointer_width = "64")]
cmp_i! { usize, |f, t| xmpfr::cmp_u64(f, (*t).cast()) }

cmp_f! { f32, |f, t| xmpfr::cmp_f64(f, (*t).into()) }
cmp_f! { f64, |f, t| xmpfr::cmp_f64(f, *t) }

cmp! { Special }

impl PartialOrd<Special> for Float {
    #[inline]
    fn partial_cmp(&self, other: &Special) -> Option<Ordering> {
        if self.is_nan() {
            return None;
        }
        match *other {
            Special::Zero | Special::NegZero => self.cmp0(),
            Special::Infinity => {
                if self.is_sign_positive() && self.is_infinite() {
                    Some(Ordering::Equal)
                } else {
                    Some(Ordering::Less)
                }
            }
            Special::NegInfinity => {
                if self.is_sign_negative() && self.is_infinite() {
                    Some(Ordering::Equal)
                } else {
                    Some(Ordering::Greater)
                }
            }
            Special::Nan => None,
            _ => unreachable!(),
        }
    }
}

cmp! { UExpIncomplete }
cmp! { IExpIncomplete }

#[cfg(test)]
mod tests {
    #[cfg(feature = "rational")]
    use crate::Rational;
    use crate::{
        float::{self, FreeCache, Special},
        Assign, Float,
    };
    use core::cmp::Ordering;
    #[cfg(feature = "integer")]
    use {crate::Integer, core::str::FromStr};

    fn check_cmp_prim<T>(s: &[T], against: &[Float])
    where
        Float: Assign<T> + PartialEq<T> + PartialOrd<T>,
        T: Copy + PartialEq<Float> + PartialOrd<Float>,
    {
        for op in s {
            let fop = Float::with_val(150, *op);
            for b in against {
                assert_eq!(b.eq(op), PartialEq::<Float>::eq(b, &fop));
                assert_eq!(op.eq(b), PartialEq::<Float>::eq(&fop, b));
                assert_eq!(b.eq(op), op.eq(b));
                assert_eq!(b.partial_cmp(op), PartialOrd::<Float>::partial_cmp(b, &fop));
                assert_eq!(op.partial_cmp(b), PartialOrd::<Float>::partial_cmp(&fop, b));
                assert_eq!(b.partial_cmp(op), op.partial_cmp(b).map(Ordering::reverse));
            }
        }
    }

    #[cfg(feature = "integer")]
    fn check_cmp_big<'a, T>(s: &'a [T], against: &[Float])
    where
        Float: Assign<&'a T> + PartialEq<T> + PartialOrd<T>,
        T: PartialEq<Float> + PartialOrd<Float>,
    {
        for op in s {
            let fop = Float::with_val(150, op);
            for b in against {
                assert_eq!(b.eq(op), PartialEq::<Float>::eq(b, &fop));
                assert_eq!(op.eq(b), PartialEq::<Float>::eq(&fop, b));
                assert_eq!(b.eq(op), op.eq(b));
                assert_eq!(b.partial_cmp(op), PartialOrd::<Float>::partial_cmp(b, &fop));
                assert_eq!(op.partial_cmp(b), PartialOrd::<Float>::partial_cmp(&fop, b));
                assert_eq!(b.partial_cmp(op), op.partial_cmp(b).map(Ordering::reverse));
            }
        }
    }

    #[test]
    fn check_cmp_others() {
        use crate::tests::{F32, F64, I128, I32, I64, U128, U32, U64};
        let large = [
            Float::with_val(20, Special::Zero),
            Float::with_val(20, Special::NegZero),
            Float::with_val(20, Special::Infinity),
            Float::with_val(20, Special::NegInfinity),
            Float::with_val(20, Special::Nan),
            Float::with_val(20, 1),
            Float::with_val(20, -1),
            Float::with_val(20, 999_999e100),
            Float::with_val(20, 999_999e-100),
            Float::with_val(20, -999_999e100),
            Float::with_val(20, -999_999e-100),
        ];
        #[cfg(feature = "integer")]
        let z = &[
            Integer::from(0),
            Integer::from(1),
            Integer::from(-1),
            Integer::from_str("-1000000000000").unwrap(),
            Integer::from_str("1000000000000").unwrap(),
        ];
        #[cfg(feature = "rational")]
        let q = &[
            Rational::from(0),
            Rational::from(1),
            Rational::from(-1),
            Rational::from_str("-1000000000000/33333333333").unwrap(),
            Rational::from_str("1000000000000/33333333333").unwrap(),
        ];

        let against = large
            .iter()
            .cloned()
            .chain(U32.iter().map(|&x| Float::with_val(20, x)))
            .chain(I32.iter().map(|&x| Float::with_val(20, x)))
            .chain(U64.iter().map(|&x| Float::with_val(20, x)))
            .chain(I64.iter().map(|&x| Float::with_val(20, x)))
            .chain(U128.iter().map(|&x| Float::with_val(20, x)))
            .chain(I128.iter().map(|&x| Float::with_val(20, x)))
            .chain(F32.iter().map(|&x| Float::with_val(20, x)))
            .chain(F64.iter().map(|&x| Float::with_val(20, x)))
            .collect::<Vec<Float>>();
        #[cfg(feature = "integer")]
        let mut against = against;
        #[cfg(feature = "integer")]
        against.extend(z.iter().map(|x| Float::with_val(20, x)));
        #[cfg(feature = "rational")]
        against.extend(q.iter().map(|x| Float::with_val(20, x)));
        check_cmp_prim(U32, &against);
        check_cmp_prim(I32, &against);
        check_cmp_prim(U64, &against);
        check_cmp_prim(I64, &against);
        check_cmp_prim(U128, &against);
        check_cmp_prim(I128, &against);
        check_cmp_prim(F32, &against);
        check_cmp_prim(F64, &against);
        #[cfg(feature = "integer")]
        check_cmp_big(z, &against);
        #[cfg(feature = "rational")]
        check_cmp_big(q, &against);

        float::free_cache(FreeCache::All);
    }
}
