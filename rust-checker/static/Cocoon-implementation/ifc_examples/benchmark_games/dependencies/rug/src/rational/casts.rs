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

use crate::{ext::xmpq, misc, Integer, Rational};
use az::{Az, Cast, CheckedCast, UnwrappedCast};

macro_rules! cast_int {
    ($Prim:ty) => {
        impl Cast<Rational> for $Prim {
            #[inline]
            fn cast(self) -> Rational {
                Rational::from(self)
            }
        }
    };
}

impl Cast<Rational> for bool {
    #[inline]
    fn cast(self) -> Rational {
        if self {
            Rational::from(1u32)
        } else {
            Rational::new()
        }
    }
}

cast_int! { i8 }
cast_int! { i16 }
cast_int! { i32 }
cast_int! { i64 }
cast_int! { i128 }
cast_int! { isize }
cast_int! { u8 }
cast_int! { u16 }
cast_int! { u32 }
cast_int! { u64 }
cast_int! { u128 }
cast_int! { usize }

impl Cast<Rational> for f32 {
    #[inline]
    fn cast(self) -> Rational {
        self.checked_cast().expect("not finite")
    }
}

impl CheckedCast<Rational> for f32 {
    #[inline]
    fn checked_cast(self) -> Option<Rational> {
        self.az::<f64>().checked_cast()
    }
}

impl UnwrappedCast<Rational> for f32 {
    #[inline]
    fn unwrapped_cast(self) -> Rational {
        self.checked_cast().expect("not finite")
    }
}

impl Cast<f32> for Rational {
    #[inline]
    fn cast(self) -> f32 {
        (&self).cast()
    }
}

impl Cast<f32> for &'_ Rational {
    #[inline]
    fn cast(self) -> f32 {
        misc::trunc_f64_to_f32(self.cast())
    }
}

impl Cast<Rational> for f64 {
    #[inline]
    fn cast(self) -> Rational {
        self.checked_cast().expect("not finite")
    }
}

impl CheckedCast<Rational> for f64 {
    #[inline]
    fn checked_cast(self) -> Option<Rational> {
        if self.is_finite() {
            let mut r = Rational::new();
            xmpq::set_f64(&mut r, self);
            Some(r)
        } else {
            None
        }
    }
}

impl UnwrappedCast<Rational> for f64 {
    #[inline]
    fn unwrapped_cast(self) -> Rational {
        self.checked_cast().expect("not finite")
    }
}

impl Cast<f64> for Rational {
    #[inline]
    fn cast(self) -> f64 {
        (&self).cast()
    }
}

impl Cast<f64> for &'_ Rational {
    #[inline]
    fn cast(self) -> f64 {
        xmpq::get_f64(self)
    }
}

impl Cast<Rational> for Integer {
    #[inline]
    fn cast(self) -> Rational {
        Rational::from(self)
    }
}

impl Cast<Rational> for &'_ Integer {
    #[inline]
    fn cast(self) -> Rational {
        Rational::from(self)
    }
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity, clippy::float_cmp)]
mod tests {
    use crate::{Integer, Rational};
    use az::{
        Az, Cast, CheckedAs, CheckedCast, OverflowingAs, OverflowingCast, SaturatingAs,
        SaturatingCast, UnwrappedAs, UnwrappedCast, WrappingAs, WrappingCast,
    };
    use core::{borrow::Borrow, f32, f64, fmt::Debug};
    use std::panic;

    #[test]
    fn check_bool() {
        let zero = Rational::new();
        let one = Rational::from(1);
        assert_eq!(false.az::<Rational>(), zero);
        assert_eq!(true.az::<Rational>(), one);
    }

    fn check_there_and_back<T>(min: T, max: T)
    where
        T: Copy + Debug + Eq + Cast<Rational>,
        for<'a> &'a Integer: Cast<T>
            + CheckedCast<T>
            + SaturatingCast<T>
            + WrappingCast<T>
            + OverflowingCast<T>
            + UnwrappedCast<T>,
    {
        let (min_int, denom) = min.az::<Rational>().into_numer_denom();
        assert_eq!(denom, 1);
        let (max_int, denom) = max.az::<Rational>().into_numer_denom();
        assert_eq!(denom, 1);

        assert_eq!(min_int.borrow().az::<T>(), min);
        assert_eq!(max_int.borrow().az::<T>(), max);
        assert_eq!(min_int.borrow().checked_as::<T>(), Some(min));
        assert_eq!(max_int.borrow().checked_as::<T>(), Some(max));
        assert_eq!(min_int.borrow().saturating_as::<T>(), min);
        assert_eq!(max_int.borrow().saturating_as::<T>(), max);
        assert_eq!(min_int.borrow().wrapping_as::<T>(), min);
        assert_eq!(max_int.borrow().wrapping_as::<T>(), max);
        assert_eq!(min_int.borrow().overflowing_as::<T>(), (min, false));
        assert_eq!(max_int.borrow().overflowing_as::<T>(), (max, false));
        assert_eq!(min_int.borrow().unwrapped_as::<T>(), min);
        assert_eq!(max_int.borrow().unwrapped_as::<T>(), max);
    }

    #[test]
    fn check_integers() {
        check_there_and_back(i8::min_value(), i8::max_value());
        check_there_and_back(i16::min_value(), i16::max_value());
        check_there_and_back(i32::min_value(), i32::max_value());
        check_there_and_back(i64::min_value(), i64::max_value());
        check_there_and_back(i128::min_value(), i128::max_value());
        check_there_and_back(isize::min_value(), isize::max_value());
        check_there_and_back(u8::min_value(), u8::max_value());
        check_there_and_back(u16::min_value(), u16::max_value());
        check_there_and_back(u32::min_value(), u32::max_value());
        check_there_and_back(u64::min_value(), u64::max_value());
        check_there_and_back(u128::min_value(), u128::max_value());
        check_there_and_back(usize::min_value(), usize::max_value());
    }

    #[test]
    fn check_floats() {
        let f32_min_pos_subnormal: Rational = Rational::from(1u32) >> (126 + 23);
        let f32_min_pos_normal: Rational = Rational::from(1u32) >> 126;
        let f32_max: Rational = Rational::from((1u32 << 24) - 1) << (127 - 23);
        let f64_min_pos_subnormal: Rational = Rational::from(1u32) >> (1022 + 52);
        let f64_min_pos_normal: Rational = Rational::from(1u32) >> 1022;
        let f64_max: Rational = Rational::from((1u64 << 53) - 1) << (1023 - 52);

        assert_eq!(f32::NAN.checked_as::<Rational>(), None);
        assert!(panic::catch_unwind(|| f32::NAN.unwrapped_as::<Rational>()).is_err());
        assert_eq!(f32::NEG_INFINITY.checked_as::<Rational>(), None);
        assert!(panic::catch_unwind(|| f32::NEG_INFINITY.unwrapped_as::<Rational>()).is_err());
        assert_eq!((-f32::MAX).az::<Rational>(), *f32_max.as_neg());
        assert_eq!((-2f32).az::<Rational>(), -2);
        assert_eq!((-1.75f32).az::<Rational>(), (-7, 4));
        assert_eq!((-1f32).az::<Rational>(), -1);
        assert_eq!((-0.125f32).az::<Rational>(), (-1, 8));
        assert_eq!(
            (-f32::MIN_POSITIVE).az::<Rational>(),
            *f32_min_pos_normal.as_neg()
        );
        assert_eq!(
            (-f32::from_bits(1)).az::<Rational>(),
            *f32_min_pos_subnormal.as_neg()
        );
        assert_eq!(f32::from_bits(1).az::<Rational>(), f32_min_pos_subnormal);
        assert_eq!(f32::MIN_POSITIVE.az::<Rational>(), f32_min_pos_normal);
        assert_eq!(0.125f32.az::<Rational>(), (1, 8));
        assert_eq!(1f32.az::<Rational>(), 1);
        assert_eq!(1.75f32.az::<Rational>(), (7, 4));
        assert_eq!(2f32.az::<Rational>(), 2);
        assert_eq!(f32::MAX.az::<Rational>(), f32_max);
        assert_eq!(f32::INFINITY.checked_as::<Rational>(), None);
        assert!(panic::catch_unwind(|| f32::INFINITY.unwrapped_as::<Rational>()).is_err());

        assert_eq!(f64::NAN.checked_as::<Rational>(), None);
        assert!(panic::catch_unwind(|| f64::NAN.unwrapped_as::<Rational>()).is_err());
        assert_eq!(f64::NEG_INFINITY.checked_as::<Rational>(), None);
        assert!(panic::catch_unwind(|| f64::NEG_INFINITY.unwrapped_as::<Rational>()).is_err());
        assert_eq!((-f64::MAX).az::<Rational>(), *f64_max.as_neg());
        assert_eq!((-2f64).az::<Rational>(), -2);
        assert_eq!((-1.75f64).az::<Rational>(), (-7, 4));
        assert_eq!((-1f64).az::<Rational>(), -1);
        assert_eq!((-0.125f64).az::<Rational>(), (-1, 8));
        assert_eq!(
            (-f64::MIN_POSITIVE).az::<Rational>(),
            *f64_min_pos_normal.as_neg()
        );
        assert_eq!(
            (-f64::from_bits(1)).az::<Rational>(),
            *f64_min_pos_subnormal.as_neg()
        );
        assert_eq!(f64::from_bits(1).az::<Rational>(), f64_min_pos_subnormal);
        assert_eq!(f64::MIN_POSITIVE.az::<Rational>(), f64_min_pos_normal);
        assert_eq!(0.125f64.az::<Rational>(), (1, 8));
        assert_eq!(1f64.az::<Rational>(), 1);
        assert_eq!(1.75f64.az::<Rational>(), (7, 4));
        assert_eq!(2f64.az::<Rational>(), 2);
        assert_eq!(f64::MAX.az::<Rational>(), f64_max);
        assert_eq!(f64::INFINITY.checked_as::<Rational>(), None);
        assert!(panic::catch_unwind(|| f64::INFINITY.unwrapped_as::<Rational>()).is_err());

        let zero: Rational = Rational::new();
        let one: Rational = Rational::from(1);
        let two_point5: Rational = Rational::from((5, 2));
        let f32_overflow: Rational = Rational::from(1) << 128;
        let f64_overflow: Rational = Rational::from(1) << 1024;
        let still_f32_max: Rational = f32_overflow.clone() - (Rational::from(1) >> 1000);
        let still_f64_max: Rational = f64_overflow.clone() - (Rational::from(1) >> 1000);

        assert_eq!(
            (*f32_overflow.as_neg()).borrow().az::<f32>(),
            f32::NEG_INFINITY
        );
        assert_eq!((*still_f32_max.as_neg()).borrow().az::<f32>(), -f32::MAX);
        assert_eq!((*f32_max.as_neg()).borrow().az::<f32>(), -f32::MAX);
        assert_eq!((*two_point5.as_neg()).borrow().az::<f32>(), -2.5f32);
        assert_eq!((*one.as_neg()).borrow().az::<f32>(), -1f32);
        assert_eq!(zero.borrow().az::<f32>(), 0f32);
        assert_eq!(one.borrow().az::<f32>(), 1f32);
        assert_eq!(two_point5.borrow().az::<f32>(), 2.5f32);
        assert_eq!(f32_max.borrow().az::<f32>(), f32::MAX);
        assert_eq!(still_f32_max.borrow().az::<f32>(), f32::MAX);
        assert_eq!(f32_overflow.borrow().az::<f32>(), f32::INFINITY);

        assert_eq!(
            (*f64_overflow.as_neg()).borrow().az::<f64>(),
            f64::NEG_INFINITY
        );
        assert_eq!((*still_f64_max.as_neg()).borrow().az::<f64>(), -f64::MAX);
        assert_eq!((*f64_max.as_neg()).borrow().az::<f64>(), -f64::MAX);
        assert_eq!((*two_point5.as_neg()).borrow().az::<f64>(), -2.5f64);
        assert_eq!((*one.as_neg()).borrow().az::<f64>(), -1f64);
        assert_eq!(zero.borrow().az::<f64>(), 0f64);
        assert_eq!(one.borrow().az::<f64>(), 1f64);
        assert_eq!(two_point5.borrow().az::<f64>(), 2.5f64);
        assert_eq!(f64_max.borrow().az::<f64>(), f64::MAX);
        assert_eq!(f64_overflow.borrow().az::<f64>(), f64::INFINITY);
    }
}
