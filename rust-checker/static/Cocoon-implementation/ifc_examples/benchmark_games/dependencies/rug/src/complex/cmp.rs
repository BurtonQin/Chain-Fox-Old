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
use crate::{float::Special, Complex, Float};

impl PartialEq for Complex {
    #[inline]
    fn eq(&self, other: &Complex) -> bool {
        self.real().eq(other.real()) && self.imag().eq(other.imag())
    }
}

macro_rules! eq_re_im {
    ($Re:ty; $($Im:ty)*) => { $(
        impl PartialEq<($Re, $Im)> for Complex {
            #[inline]
            fn eq(&self, other: &($Re, $Im)) -> bool {
                self.real().eq(&other.0) && self.imag().eq(&other.1)
            }
        }

        impl PartialEq<Complex> for ($Re, $Im) {
            #[inline]
            fn eq(&self, other: &Complex) -> bool {
                other.real().eq(&self.0) && other.imag().eq(&self.1)
            }
        }
    )* };
}

macro_rules! eq_re {
    ($($Re:ty)*) => { $(
        impl PartialEq<$Re> for Complex {
            #[inline]
            fn eq(&self, other: &$Re) -> bool {
                self.imag().is_zero() && self.real().eq(other)
            }
        }

        impl PartialEq<Complex> for $Re {
            #[inline]
            fn eq(&self, other: &Complex) -> bool {
                other.imag().is_zero() && other.real().eq(self)
            }
        }

        #[cfg(feature = "integer")]
        eq_re_im! { $Re; Integer }
        #[cfg(feature = "rational")]
        eq_re_im! { $Re; Rational }
        eq_re_im! { $Re; Float Special }
        eq_re_im! { $Re; i8 i16 i32 i64 i128 isize }
        eq_re_im! { $Re; u8 u16 u32 u64 u128 usize }
        eq_re_im! { $Re; f32 f64 }
    )* };
}

#[cfg(feature = "integer")]
eq_re! { Integer }
#[cfg(feature = "rational")]
eq_re! { Rational }
eq_re! { Float Special }
eq_re! { i8 i16 i32 i64 i128 isize }
eq_re! { u8 u16 u32 u64 u128 usize }
eq_re! { f32 f64 }

#[cfg(test)]
mod tests {
    #[cfg(feature = "rational")]
    use crate::Rational;
    use crate::{
        float::{self, FreeCache, Special},
        Assign, Complex, Float,
    };
    #[cfg(feature = "integer")]
    use {crate::Integer, core::str::FromStr};

    fn check_eq_prim<T>(s: &[T], against: &[Complex])
    where
        Complex: Assign<T> + Assign<(T, T)> + PartialEq<T> + PartialEq<(T, T)>,
        T: Copy + PartialEq<Complex>,
        (T, T): Copy + PartialEq<Complex>,
    {
        for op in s {
            let fop = Complex::with_val(150, *op);
            for b in against {
                assert_eq!(b.eq(op), b.eq(&fop));
                assert_eq!(op.eq(b), fop.eq(b));
                assert_eq!(b.eq(op), op.eq(b));
            }
        }
        for op in combinations(s) {
            let fop = Complex::with_val(150, op);
            for b in against {
                assert_eq!(b.eq(&op), b.eq(&fop));
                assert_eq!(op.eq(b), fop.eq(b));
                assert_eq!(b.eq(&op), op.eq(b));
            }
        }
    }

    fn check_eq_big<'a, T>(s: &'a [T], against: &[Complex])
    where
        Complex:
            for<'b> Assign<&'b T> + for<'b> Assign<&'b (T, T)> + PartialEq<T> + PartialEq<(T, T)>,
        T: Clone + PartialEq<Complex>,
        (T, T): Clone + PartialEq<Complex>,
    {
        for op in s {
            let fop = Complex::with_val(150, op);
            for b in against {
                assert_eq!(b.eq(op), b.eq(&fop));
                assert_eq!(op.eq(b), fop.eq(b));
                assert_eq!(b.eq(op), op.eq(b));
            }
        }
        for op in combinations(s) {
            let fop = Complex::with_val(150, &op);
            for b in against {
                assert_eq!(b.eq(&op), b.eq(&fop));
                assert_eq!(op.eq(b), fop.eq(b));
                assert_eq!(b.eq(&op), op.eq(b));
            }
        }
    }

    fn combinations<T: Clone>(t: &[T]) -> Vec<(T, T)> {
        let mut ret = Vec::with_capacity(t.len() * t.len());
        for re in t {
            for im in t {
                ret.push((re.clone(), im.clone()));
            }
        }
        ret
    }

    fn to_complex<T>(t: T) -> Complex
    where
        Complex: Assign<T>,
    {
        Complex::with_val(20, t)
    }

    #[test]
    fn check_eq_others() {
        use crate::tests::{F32, F64, I128, I32, I64, U128, U32, U64};
        #[cfg(feature = "integer")]
        let z = [
            Integer::from(0),
            Integer::from(1),
            Integer::from(-1),
            Integer::from_str("-1000000000000").unwrap(),
            Integer::from_str("1000000000000").unwrap(),
        ];
        #[cfg(feature = "rational")]
        let q = [
            Rational::from(0),
            Rational::from(1),
            Rational::from(-1),
            Rational::from_str("-1000000000000/33333333333").unwrap(),
            Rational::from_str("1000000000000/33333333333").unwrap(),
        ];
        let f = [
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

        let against = combinations(&f)
            .iter()
            .map(to_complex)
            .chain(combinations(U32).iter().map(to_complex))
            .chain(combinations(I32).iter().map(to_complex))
            .chain(combinations(U64).iter().map(to_complex))
            .chain(combinations(I64).iter().map(to_complex))
            .chain(combinations(U128).iter().map(to_complex))
            .chain(combinations(I128).iter().map(to_complex))
            .chain(combinations(F32).iter().map(to_complex))
            .chain(combinations(F64).iter().map(to_complex))
            .collect::<Vec<Complex>>();
        #[cfg(feature = "integer")]
        let mut against = against;
        #[cfg(feature = "integer")]
        against.extend(combinations(&z).iter().map(to_complex));
        #[cfg(feature = "rational")]
        against.extend(combinations(&q).iter().map(to_complex));
        check_eq_prim(U32, &against);
        check_eq_prim(I32, &against);
        check_eq_prim(U64, &against);
        check_eq_prim(I64, &against);
        check_eq_prim(U128, &against);
        check_eq_prim(I128, &against);
        check_eq_prim(F32, &against);
        check_eq_prim(F64, &against);
        #[cfg(feature = "integer")]
        check_eq_big(&z, &against);
        #[cfg(feature = "rational")]
        check_eq_big(&q, &against);
        check_eq_big(&f, &against);

        float::free_cache(FreeCache::All);
    }
}
