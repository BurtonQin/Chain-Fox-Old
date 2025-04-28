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

use crate::{ext::xmpz, misc, ops::NegAssign, Integer};
use az::{
    Az, Cast, CheckedCast, OverflowingCast, Round, SaturatingCast, UnwrappedCast, WrappingCast,
};
use core::cmp::Ordering;

macro_rules! cast_int {
    ($Prim:ty, $fits:path, $get_abs:path) => {
        impl Cast<Integer> for $Prim {
            #[inline]
            fn cast(self) -> Integer {
                Integer::from(self)
            }
        }

        impl Cast<$Prim> for Integer {
            #[inline]
            fn cast(self) -> $Prim {
                (&self).cast()
            }
        }
        impl Cast<$Prim> for &'_ Integer {
            #[inline]
            fn cast(self) -> $Prim {
                let (wrapped, overflow) = self.overflowing_cast();
                debug_assert!(!overflow, "overflow");
                wrapped
            }
        }
        impl CheckedCast<$Prim> for Integer {
            #[inline]
            fn checked_cast(self) -> Option<$Prim> {
                (&self).checked_cast()
            }
        }
        impl CheckedCast<$Prim> for &'_ Integer {
            #[inline]
            fn checked_cast(self) -> Option<$Prim> {
                if $fits(self) {
                    Some(self.wrapping_cast())
                } else {
                    None
                }
            }
        }
        impl SaturatingCast<$Prim> for Integer {
            #[inline]
            fn saturating_cast(self) -> $Prim {
                (&self).saturating_cast()
            }
        }
        impl SaturatingCast<$Prim> for &'_ Integer {
            #[inline]
            fn saturating_cast(self) -> $Prim {
                if $fits(self) {
                    self.wrapping_cast()
                } else if self.cmp0() == Ordering::Less {
                    <$Prim>::min_value()
                } else {
                    <$Prim>::max_value()
                }
            }
        }
        impl WrappingCast<$Prim> for Integer {
            #[inline]
            fn wrapping_cast(self) -> $Prim {
                (&self).wrapping_cast()
            }
        }
        impl WrappingCast<$Prim> for &'_ Integer {
            #[inline]
            fn wrapping_cast(self) -> $Prim {
                let val = $get_abs(self);
                if self.cmp0() == Ordering::Less {
                    val.wrapping_neg()
                } else {
                    val
                }
                .wrapping_cast()
            }
        }
        impl OverflowingCast<$Prim> for Integer {
            #[inline]
            fn overflowing_cast(self) -> ($Prim, bool) {
                (&self).overflowing_cast()
            }
        }
        impl OverflowingCast<$Prim> for &'_ Integer {
            #[inline]
            fn overflowing_cast(self) -> ($Prim, bool) {
                (self.wrapping_cast(), !$fits(self))
            }
        }
        impl UnwrappedCast<$Prim> for Integer {
            #[inline]
            fn unwrapped_cast(self) -> $Prim {
                (&self).unwrapped_cast()
            }
        }
        impl UnwrappedCast<$Prim> for &'_ Integer {
            #[inline]
            fn unwrapped_cast(self) -> $Prim {
                if $fits(self) {
                    self.wrapping_cast()
                } else {
                    panic!("overflow")
                }
            }
        }
    };
}

impl Cast<Integer> for bool {
    #[inline]
    fn cast(self) -> Integer {
        if self {
            Integer::from(1u32)
        } else {
            Integer::new()
        }
    }
}

cast_int! { i8, xmpz::fits_i8, xmpz::get_abs_u8 }
cast_int! { i16, xmpz::fits_i16, xmpz::get_abs_u16 }
cast_int! { i32, xmpz::fits_i32, xmpz::get_abs_u32 }
cast_int! { i64, xmpz::fits_i64, xmpz::get_abs_u64 }
cast_int! { i128, xmpz::fits_i128, xmpz::get_abs_u128 }
#[cfg(target_pointer_width = "32")]
cast_int! { isize, xmpz::fits_i32, xmpz::get_abs_u32 }
#[cfg(target_pointer_width = "64")]
cast_int! { isize, xmpz::fits_i64, xmpz::get_abs_u64 }
cast_int! { u8, xmpz::fits_u8, xmpz::get_abs_u8 }
cast_int! { u16, xmpz::fits_u16, xmpz::get_abs_u16 }
cast_int! { u32, xmpz::fits_u32, xmpz::get_abs_u32 }
cast_int! { u64, xmpz::fits_u64, xmpz::get_abs_u64 }
cast_int! { u128, xmpz::fits_u128, xmpz::get_abs_u128 }
#[cfg(target_pointer_width = "32")]
cast_int! { usize, xmpz::fits_u32, xmpz::get_abs_u32 }
#[cfg(target_pointer_width = "64")]
cast_int! { usize, xmpz::fits_u64, xmpz::get_abs_u64 }

impl Cast<Integer> for f32 {
    #[inline]
    fn cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

impl CheckedCast<Integer> for f32 {
    #[inline]
    fn checked_cast(self) -> Option<Integer> {
        let bits = self.to_bits();
        let biased_exp = (bits >> 23) & 0xFF;
        // biased_exp:
        //     0x00 => subnormal, 1
        //     0x01..=0x7E => finite < 1.0
        //     0x7F..=0xFE finite >= 1.0
        //     0xFF => not finite 1
        if biased_exp < 0x7F {
            Some(Integer::new())
        } else if biased_exp == 0xFF {
            None
        } else {
            // 1.0 has biased_exp == 127 and would need >> 23.
            // 2.0 has biased_exp == 128 and would need >> 22.
            // 2.0^23 has biased_exp == 150 and would need >> 0.
            // So, we need >> 150 - biased_exp
            let mantissa_with_one = 0x0080_0000 | (bits & 0x007F_FFFF);
            let mut val = if biased_exp <= 150 {
                Integer::from(mantissa_with_one >> (150 - biased_exp))
            } else {
                Integer::from(mantissa_with_one) << (biased_exp - 150)
            };
            if bits & 0x8000_0000 != 0 {
                val.neg_assign();
            }
            Some(val)
        }
    }
}

impl UnwrappedCast<Integer> for f32 {
    #[inline]
    fn unwrapped_cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

impl Cast<f32> for Integer {
    #[inline]
    fn cast(self) -> f32 {
        (&self).cast()
    }
}

impl Cast<f32> for &'_ Integer {
    #[inline]
    fn cast(self) -> f32 {
        misc::trunc_f64_to_f32(self.cast())
    }
}

impl Cast<Integer> for f64 {
    #[inline]
    fn cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

impl CheckedCast<Integer> for f64 {
    #[inline]
    fn checked_cast(self) -> Option<Integer> {
        let bits = self.to_bits();
        let biased_exp = (bits >> 52) & 0x7FF;
        // biased_exp:
        //     0x000 => subnormal,
        //     0x001..=0x3FE => finite < 1.0,
        //     0x3FF..=0x7FE finite >= 1.0,
        //     0x7FF => not finite
        if biased_exp < 0x3FF {
            Some(Integer::new())
        } else if biased_exp == 0x7FF {
            None
        } else {
            // 1.0 has biased_exp == 1023 and would need >> 52.
            // 2.0 has biased_exp == 1024 and would need >> 51.
            // 2.0^52 has biased_exp == 1075 and would need >> 0.
            // So, we need >> 1075 - biased_exp
            let mantissa_with_one = 0x0010_0000_0000_0000 | (bits & 0x000F_FFFF_FFFF_FFFF);
            let mut val = if biased_exp <= 1075 {
                Integer::from(mantissa_with_one >> (1075 - biased_exp).az::<u32>())
            } else {
                Integer::from(mantissa_with_one) << (biased_exp - 1075).az::<u32>()
            };
            if bits & 0x8000_0000_0000_0000 != 0 {
                val.neg_assign();
            }
            Some(val)
        }
    }
}

impl UnwrappedCast<Integer> for f64 {
    #[inline]
    fn unwrapped_cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

impl Cast<f64> for Integer {
    #[inline]
    fn cast(self) -> f64 {
        (&self).cast()
    }
}

impl Cast<f64> for &'_ Integer {
    #[inline]
    fn cast(self) -> f64 {
        xmpz::get_f64(self)
    }
}

impl Cast<Integer> for Round<f32> {
    #[inline]
    fn cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

impl CheckedCast<Integer> for Round<f32> {
    #[inline]
    fn checked_cast(self) -> Option<Integer> {
        let bits = self.0.to_bits();
        let biased_exp = (bits >> 23) & 0xFF;
        // biased_exp:
        //     0x00 => subnormal, 1
        //     0x01..=0x7E => finite < 1.0
        //     0x7F..=0xFE finite >= 1.0
        //     0xFF => not finite 1
        if biased_exp < 0x7F {
            Some(Integer::new())
        } else if biased_exp == 0xFF {
            None
        } else {
            // 1.0 has biased_exp == 127 and would need >> 23.
            // 2.0 has biased_exp == 128 and would need >> 22.
            // 2.0^23 has biased_exp == 150 and would need >> 0.
            // So, we need >> 150 - biased_exp
            let mantissa_with_one = 0x0080_0000 | (bits & 0x007F_FFFF);
            let mut val = if biased_exp <= 150 {
                let mut round = 1u32 << (150 - biased_exp) >> 1;
                // Round away from zero if val & round != 0 and either
                //   * odd, that is val & (round << 1) != 0
                //   * greater than tie, that is val & (round - 1) != 0
                // The two conditions can be simplified to
                //     val & ((2 * round) | (round - 1))
                //   = val & (3 * round - 1)
                if mantissa_with_one & round == 0 || mantissa_with_one & (3 * round - 1) == 0 {
                    round = 0;
                }
                Integer::from((mantissa_with_one + round) >> (150 - biased_exp))
            } else {
                Integer::from(mantissa_with_one) << (biased_exp - 150)
            };
            if bits & 0x8000_0000 != 0 {
                val.neg_assign();
            }
            Some(val)
        }
    }
}

impl UnwrappedCast<Integer> for Round<f32> {
    #[inline]
    fn unwrapped_cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

impl Cast<Integer> for Round<f64> {
    #[inline]
    fn cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

impl CheckedCast<Integer> for Round<f64> {
    #[inline]
    fn checked_cast(self) -> Option<Integer> {
        let bits = self.0.to_bits();
        let biased_exp = (bits >> 52) & 0x7FF;
        // biased_exp:
        //     0x000 => subnormal,
        //     0x001..=0x3FE => finite < 1.0,
        //     0x3FF..=0x7FE finite >= 1.0,
        //     0x7FF => not finite
        if biased_exp < 0x3FF {
            Some(Integer::new())
        } else if biased_exp == 0x7FF {
            None
        } else {
            // 1.0 has biased_exp == 1023 and would need >> 52.
            // 2.0 has biased_exp == 1024 and would need >> 51.
            // 2.0^52 has biased_exp == 1075 and would need >> 0.
            // So, we need >> 1075 - biased_exp
            let mantissa_with_one = 0x0010_0000_0000_0000 | (bits & 0x000F_FFFF_FFFF_FFFF);
            let mut val = if biased_exp <= 1075 {
                let mut round = 1u64 << (1075 - biased_exp) >> 1;
                // Round away from zero if val & round != 0 and either
                //   * odd, that is val & (round << 1) != 0
                //   * greater than tie, that is val & (round - 1) != 0
                // The two conditions can be simplified to
                //     val & ((2 * round) | (round - 1))
                //   = val & (3 * round - 1)
                if mantissa_with_one & round == 0 || mantissa_with_one & (3 * round - 1) == 0 {
                    round = 0;
                }
                Integer::from((mantissa_with_one + round) >> (1075 - biased_exp).az::<u32>())
            } else {
                Integer::from(mantissa_with_one) << (biased_exp - 1075).az::<u32>()
            };
            if bits & 0x8000_0000_0000_0000 != 0 {
                val.neg_assign();
            }
            Some(val)
        }
    }
}

impl UnwrappedCast<Integer> for Round<f64> {
    #[inline]
    fn unwrapped_cast(self) -> Integer {
        self.checked_cast().expect("not finite")
    }
}

#[cfg(test)]
#[allow(clippy::cognitive_complexity, clippy::float_cmp)]
mod tests {
    use crate::Integer;
    use az::{
        Az, Cast, CheckedAs, CheckedCast, OverflowingAs, OverflowingCast, Round, SaturatingAs,
        SaturatingCast, UnwrappedAs, UnwrappedCast, WrappingAs, WrappingCast,
    };
    use core::{borrow::Borrow, f32, f64, fmt::Debug};
    use std::panic;

    #[test]
    fn check_bool() {
        let zero = Integer::new();
        let one = Integer::from(1);
        assert_eq!(false.az::<Integer>(), zero);
        assert_eq!(true.az::<Integer>(), one);
    }

    fn check_there_and_back<T>(min: T, max: T)
    where
        T: Copy + Debug + Eq + Cast<Integer>,
        for<'a> &'a Integer: Cast<T>
            + CheckedCast<T>
            + SaturatingCast<T>
            + WrappingCast<T>
            + OverflowingCast<T>
            + UnwrappedCast<T>,
    {
        let min_int: Integer = min.az::<Integer>();
        let max_int: Integer = max.az::<Integer>();
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

        let too_small: Integer = min_int - 1;
        let too_large: Integer = max_int + 1;
        assert_eq!(too_small.borrow().checked_as::<T>(), None);
        assert_eq!(too_large.borrow().checked_as::<T>(), None);
        assert_eq!(too_small.borrow().saturating_as::<T>(), min);
        assert_eq!(too_large.borrow().saturating_as::<T>(), max);
        assert_eq!(too_small.borrow().wrapping_as::<T>(), max);
        assert_eq!(too_large.borrow().wrapping_as::<T>(), min);
        assert_eq!(too_small.borrow().overflowing_as::<T>(), (max, true));
        assert_eq!(too_large.borrow().overflowing_as::<T>(), (min, true));
        assert!(panic::catch_unwind(|| too_small.borrow().unwrapped_as::<T>()).is_err());
        assert!(panic::catch_unwind(|| too_large.borrow().unwrapped_as::<T>()).is_err());
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
        let f32_max: Integer = Integer::from((1u32 << 24) - 1) << (127 - 23);
        let f64_max: Integer = Integer::from((1u64 << 53) - 1) << (1023 - 52);

        assert_eq!(f32::NAN.checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| f32::NAN.unwrapped_as::<Integer>()).is_err());
        assert_eq!(f32::NEG_INFINITY.checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| f32::NEG_INFINITY.unwrapped_as::<Integer>()).is_err());
        assert_eq!((-f32::MAX).az::<Integer>(), *f32_max.as_neg());
        assert_eq!((-2f32).az::<Integer>(), -2);
        assert_eq!((-1.99f32).az::<Integer>(), -1);
        assert_eq!((-1f32).az::<Integer>(), -1);
        assert_eq!((-0.99f32).az::<Integer>(), 0);
        assert_eq!(0.99f32.az::<Integer>(), 0);
        assert_eq!(1f32.az::<Integer>(), 1);
        assert_eq!(1.99f32.az::<Integer>(), 1);
        assert_eq!(2f32.az::<Integer>(), 2);
        assert_eq!(f32::MAX.az::<Integer>(), f32_max);
        assert_eq!(f32::INFINITY.checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| f32::INFINITY.unwrapped_as::<Integer>()).is_err());

        assert_eq!(f64::NAN.checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| f64::NAN.unwrapped_as::<Integer>()).is_err());
        assert_eq!(f64::NEG_INFINITY.checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| f64::NEG_INFINITY.unwrapped_as::<Integer>()).is_err());
        assert_eq!((-f64::MAX).az::<Integer>(), *f64_max.as_neg());
        assert_eq!((-2f64).az::<Integer>(), -2);
        assert_eq!((-1.99f64).az::<Integer>(), -1);
        assert_eq!((-1f64).az::<Integer>(), -1);
        assert_eq!((-0.99f64).az::<Integer>(), 0);
        assert_eq!(0.99f64.az::<Integer>(), 0);
        assert_eq!(1f64.az::<Integer>(), 1);
        assert_eq!(1.99f64.az::<Integer>(), 1);
        assert_eq!(2f64.az::<Integer>(), 2);
        assert_eq!(f64::MAX.az::<Integer>(), f64_max);
        assert_eq!(f64::INFINITY.checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| f64::INFINITY.unwrapped_as::<Integer>()).is_err());

        let zero: Integer = Integer::new();
        let one: Integer = Integer::from(1);
        let two: Integer = Integer::from(2);
        let f32_overflow: Integer = Integer::from(1) << 128;
        let f64_overflow: Integer = Integer::from(1) << 1024;
        let still_f32_max: Integer = f32_overflow.clone() - 1;
        let still_f64_max: Integer = f64_overflow.clone() - 1;

        assert_eq!(
            (*f32_overflow.as_neg()).borrow().az::<f32>(),
            f32::NEG_INFINITY
        );
        assert_eq!((*still_f32_max.as_neg()).borrow().az::<f32>(), -f32::MAX);
        assert_eq!((*f32_max.as_neg()).borrow().az::<f32>(), -f32::MAX);
        assert_eq!((*two.as_neg()).borrow().az::<f32>(), -2f32);
        assert_eq!((*one.as_neg()).borrow().az::<f32>(), -1f32);
        assert_eq!(zero.borrow().az::<f32>(), 0f32);
        assert_eq!(one.borrow().az::<f32>(), 1f32);
        assert_eq!(two.borrow().az::<f32>(), 2f32);
        assert_eq!(f32_max.borrow().az::<f32>(), f32::MAX);
        assert_eq!(still_f32_max.borrow().az::<f32>(), f32::MAX);
        assert_eq!(f32_overflow.borrow().az::<f32>(), f32::INFINITY);

        assert_eq!(
            (*f64_overflow.as_neg()).borrow().az::<f64>(),
            f64::NEG_INFINITY
        );
        assert_eq!((*still_f64_max.as_neg()).borrow().az::<f64>(), -f64::MAX);
        assert_eq!((*f64_max.as_neg()).borrow().az::<f64>(), -f64::MAX);
        assert_eq!((*two.as_neg()).borrow().az::<f64>(), -2f64);
        assert_eq!((*one.as_neg()).borrow().az::<f64>(), -1f64);
        assert_eq!(zero.borrow().az::<f64>(), 0f64);
        assert_eq!(one.borrow().az::<f64>(), 1f64);
        assert_eq!(two.borrow().az::<f64>(), 2f64);
        assert_eq!(f64_max.borrow().az::<f64>(), f64::MAX);
        assert_eq!(f64_overflow.borrow().az::<f64>(), f64::INFINITY);
    }

    #[test]
    fn check_round_floats() {
        let f32_max: Integer = Integer::from((1u32 << 24) - 1) << (127 - 23);
        let f64_max: Integer = Integer::from((1u64 << 53) - 1) << (1023 - 52);

        assert_eq!(Round(f32::NAN).checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| Round(f32::NAN).unwrapped_as::<Integer>()).is_err());
        assert_eq!(Round(f32::NEG_INFINITY).checked_as::<Integer>(), None);
        assert!(
            panic::catch_unwind(|| Round(f32::NEG_INFINITY).unwrapped_as::<Integer>()).is_err()
        );
        assert_eq!(Round(-f32::MAX).az::<Integer>(), *f32_max.as_neg());
        assert_eq!(Round(-4f32).az::<Integer>(), -4);
        assert_eq!(Round(-3.5f32).az::<Integer>(), -4);
        assert_eq!(Round(-3.49f32).az::<Integer>(), -3);
        assert_eq!(Round(-2.51f32).az::<Integer>(), -3);
        assert_eq!(Round(-2.5f32).az::<Integer>(), -2);
        assert_eq!(Round(-2f32).az::<Integer>(), -2);
        assert_eq!(Round(-1.5f32).az::<Integer>(), -2);
        assert_eq!(Round(-1.49f32).az::<Integer>(), -1);
        assert_eq!(Round(-1f32).az::<Integer>(), -1);
        assert_eq!(Round(-0.5f32).az::<Integer>(), 0);
        assert_eq!(Round(0.5f32).az::<Integer>(), 0);
        assert_eq!(Round(1f32).az::<Integer>(), 1);
        assert_eq!(Round(1.49f32).az::<Integer>(), 1);
        assert_eq!(Round(1.5f32).az::<Integer>(), 2);
        assert_eq!(Round(2f32).az::<Integer>(), 2);
        assert_eq!(Round(2.5f32).az::<Integer>(), 2);
        assert_eq!(Round(2.51f32).az::<Integer>(), 3);
        assert_eq!(Round(3.49f32).az::<Integer>(), 3);
        assert_eq!(Round(3.5f32).az::<Integer>(), 4);
        assert_eq!(Round(4f32).az::<Integer>(), 4);
        assert_eq!(Round(f32::MAX).az::<Integer>(), f32_max);
        assert_eq!(Round(f32::INFINITY).checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| Round(f32::INFINITY).unwrapped_as::<Integer>()).is_err());

        assert_eq!(Round(f64::NAN).checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| Round(f64::NAN).unwrapped_as::<Integer>()).is_err());
        assert_eq!(Round(f64::NEG_INFINITY).checked_as::<Integer>(), None);
        assert!(
            panic::catch_unwind(|| Round(f64::NEG_INFINITY).unwrapped_as::<Integer>()).is_err()
        );
        assert_eq!(Round(-f64::MAX).az::<Integer>(), *f64_max.as_neg());
        assert_eq!(Round(-4f64).az::<Integer>(), -4);
        assert_eq!(Round(-3.5f64).az::<Integer>(), -4);
        assert_eq!(Round(-3.49f64).az::<Integer>(), -3);
        assert_eq!(Round(-2.51f64).az::<Integer>(), -3);
        assert_eq!(Round(-2.5f64).az::<Integer>(), -2);
        assert_eq!(Round(-2f64).az::<Integer>(), -2);
        assert_eq!(Round(-1.5f64).az::<Integer>(), -2);
        assert_eq!(Round(-1.49f64).az::<Integer>(), -1);
        assert_eq!(Round(-1f64).az::<Integer>(), -1);
        assert_eq!(Round(-0.5f64).az::<Integer>(), 0);
        assert_eq!(Round(0.5f64).az::<Integer>(), 0);
        assert_eq!(Round(1f64).az::<Integer>(), 1);
        assert_eq!(Round(1.49f64).az::<Integer>(), 1);
        assert_eq!(Round(1.5f64).az::<Integer>(), 2);
        assert_eq!(Round(2f64).az::<Integer>(), 2);
        assert_eq!(Round(2.5f64).az::<Integer>(), 2);
        assert_eq!(Round(2.51f64).az::<Integer>(), 3);
        assert_eq!(Round(3.49f64).az::<Integer>(), 3);
        assert_eq!(Round(3.5f64).az::<Integer>(), 4);
        assert_eq!(Round(4f64).az::<Integer>(), 4);
        assert_eq!(Round(f64::MAX).az::<Integer>(), f64_max);
        assert_eq!(Round(f64::INFINITY).checked_as::<Integer>(), None);
        assert!(panic::catch_unwind(|| Round(f64::INFINITY).unwrapped_as::<Integer>()).is_err());
    }
}
