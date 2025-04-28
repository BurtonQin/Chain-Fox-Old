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
use crate::{
    ext::xmpfr,
    float::{
        big::{self, ExpFormat, Format},
        Constant, OrdFloat, Round, Special,
    },
    ops::AssignRound,
    Assign, Float,
};
use az::{UnwrappedAs, UnwrappedCast};
use core::{
    cmp::Ordering,
    fmt::{
        Binary, Debug, Display, Formatter, LowerExp, LowerHex, Octal, Result as FmtResult,
        UpperExp, UpperHex,
    },
};
use gmp_mpfr_sys::mpfr;
#[cfg(feature = "rational")]
use {
    crate::{rational::TryFromFloatError, Rational},
    az::CheckedCast,
    core::convert::TryFrom,
};

impl Clone for Float {
    #[inline]
    fn clone(&self) -> Float {
        let mut ret = Float::new_nan(self.prec());
        if !self.is_nan() {
            ret.assign(self);
        }
        ret
    }

    #[inline]
    fn clone_from(&mut self, source: &Float) {
        xmpfr::set_prec_nan(self, source.prec().unwrapped_cast());
        if !source.is_nan() {
            self.assign(source);
        }
    }
}

impl Drop for Float {
    #[inline]
    fn drop(&mut self) {
        // Safety: we are freeing memory. This is sound as self must be initialized.
        unsafe {
            mpfr::clear(self.as_raw_mut());
        }
    }
}

impl Display for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            exp: ExpFormat::Point,
            ..Format::default()
        };
        fmt_radix(self, f, format, "")
    }
}

impl Debug for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            exp: ExpFormat::Point,
            ..Format::default()
        };
        fmt_radix(self, f, format, "")
    }
}

impl LowerExp for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            exp: ExpFormat::Exp,
            ..Format::default()
        };
        fmt_radix(self, f, format, "")
    }
}

impl UpperExp for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            to_upper: true,
            exp: ExpFormat::Exp,
            ..Format::default()
        };
        fmt_radix(self, f, format, "")
    }
}

impl Binary for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            radix: 2,
            exp: ExpFormat::Point,
            ..Format::default()
        };
        fmt_radix(self, f, format, "0b")
    }
}

impl Octal for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            radix: 8,
            exp: ExpFormat::Point,
            ..Format::default()
        };
        fmt_radix(self, f, format, "0o")
    }
}

impl LowerHex for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            radix: 16,
            exp: ExpFormat::Point,
            ..Format::default()
        };
        fmt_radix(self, f, format, "0x")
    }
}

impl UpperHex for Float {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let format = Format {
            radix: 16,
            to_upper: true,
            exp: ExpFormat::Point,
            ..Format::default()
        };
        fmt_radix(self, f, format, "0x")
    }
}

impl AsRef<OrdFloat> for Float {
    #[inline]
    fn as_ref(&self) -> &OrdFloat {
        self.as_ord()
    }
}

impl<T> Assign<T> for Float
where
    Self: AssignRound<T, Round = Round, Ordering = Ordering>,
{
    #[inline]
    fn assign(&mut self, src: T) {
        self.assign_round(src, Round::Nearest);
    }
}

impl AssignRound<Constant> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: Constant, round: Round) -> Ordering {
        match src {
            Constant::Log2 => xmpfr::const_log2(self, round),
            Constant::Pi => xmpfr::const_pi(self, round),
            Constant::Euler => xmpfr::const_euler(self, round),
            Constant::Catalan => xmpfr::const_catalan(self, round),
            _ => unreachable!(),
        }
    }
}

assign_round_deref! { Constant => Float }

impl AssignRound<Special> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: Special, _round: Round) -> Ordering {
        xmpfr::set_special(self, src);
        Ordering::Equal
    }
}

assign_round_deref! { Special => Float }

impl AssignRound for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: Float, round: Round) -> Ordering {
        if self.prec() == src.prec() {
            *self = src;
            if self.is_nan() {
                xmpfr::set_nanflag();
            }
            Ordering::Equal
        } else {
            self.assign_round(&src, round)
        }
    }
}

impl AssignRound<&Float> for Float {
    type Round = Round;
    type Ordering = Ordering;
    #[inline]
    fn assign_round(&mut self, src: &Float, round: Round) -> Ordering {
        xmpfr::set(self, src, round)
    }
}

#[cfg(feature = "integer")]
macro_rules! assign {
    ($T:ty, $func:path) => {
        impl AssignRound<&$T> for Float {
            type Round = Round;
            type Ordering = Ordering;
            #[inline]
            fn assign_round(&mut self, src: &$T, round: Round) -> Ordering {
                $func(self, src, round)
            }
        }

        impl AssignRound<$T> for Float {
            type Round = Round;
            type Ordering = Ordering;
            #[inline]
            fn assign_round(&mut self, src: $T, round: Round) -> Ordering {
                self.assign_round(&src, round)
            }
        }
    };
}

#[cfg(feature = "integer")]
assign! { Integer, xmpfr::set_z }
#[cfg(feature = "rational")]
assign! { Rational, xmpfr::set_q }

macro_rules! conv_ops {
    ($T:ty, $set:path) => {
        impl AssignRound<$T> for Float {
            type Round = Round;
            type Ordering = Ordering;
            #[inline]
            fn assign_round(&mut self, src: $T, round: Round) -> Ordering {
                $set(self, src.into(), round)
            }
        }

        assign_round_deref! { $T => Float }
    };
}

macro_rules! conv_ops_cast {
    ($New:ty, $Existing:ty) => {
        impl AssignRound<$New> for Float {
            type Round = Round;
            type Ordering = Ordering;
            #[inline]
            fn assign_round(&mut self, src: $New, round: Round) -> Ordering {
                self.assign_round(src.unwrapped_as::<$Existing>(), round)
            }
        }

        assign_round_deref! { $New => Float }
    };
}

conv_ops! { i8, xmpfr::set_si }
conv_ops! { i16, xmpfr::set_si }
conv_ops! { i32, xmpfr::set_si }
conv_ops! { i64, xmpfr::set_sj }
conv_ops! { i128, xmpfr::set_i128 }
#[cfg(target_pointer_width = "32")]
conv_ops_cast! { isize, i32 }
#[cfg(target_pointer_width = "64")]
conv_ops_cast! { isize, i64 }

conv_ops! { u8, xmpfr::set_ui }
conv_ops! { u16, xmpfr::set_ui }
conv_ops! { u32, xmpfr::set_ui }
conv_ops! { u64, xmpfr::set_uj }
conv_ops! { u128, xmpfr::set_u128 }
#[cfg(target_pointer_width = "32")]
conv_ops_cast! { usize, u32 }
#[cfg(target_pointer_width = "64")]
conv_ops_cast! { usize, u64 }

conv_ops! { f32, xmpfr::set_f32 }
conv_ops! { f64, xmpfr::set_f64 }

#[cfg(feature = "rational")]
impl TryFrom<Float> for Rational {
    type Error = TryFromFloatError;
    #[inline]
    fn try_from(value: Float) -> Result<Self, TryFromFloatError> {
        TryFrom::try_from(&value)
    }
}

#[cfg(feature = "rational")]
impl TryFrom<&Float> for Rational {
    type Error = TryFromFloatError;
    #[inline]
    fn try_from(value: &Float) -> Result<Self, TryFromFloatError> {
        value
            .checked_cast()
            .ok_or(TryFromFloatError { _unused: () })
    }
}

#[allow(clippy::manual_strip)]
// overwrites format.precision
fn fmt_radix(flt: &Float, fmt: &mut Formatter<'_>, format: Format, prefix: &str) -> FmtResult {
    let format = Format {
        precision: fmt.precision(),
        ..format
    };
    let mut s = String::new();
    big::append_to_string(&mut s, flt, format);
    let (neg, buf) = if s.starts_with('-') {
        (true, &s[1..])
    } else {
        (false, &s[..])
    };
    let prefix = if flt.is_finite() { prefix } else { "" };
    fmt.pad_integral(!neg, prefix, buf)
}

// Safety: mpfr_t is thread safe as guaranteed by the MPFR library.
unsafe impl Send for Float {}
unsafe impl Sync for Float {}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use crate::{
        float::{self, FreeCache, Round},
        ops::AssignRound,
        Assign, Float,
    };
    use core::cmp::Ordering;

    #[test]
    fn check_assign() {
        let mut f = Float::with_val(4, 1.0);
        assert_eq!(f, 1.0);

        let other = Float::with_val(53, 14.75);
        let mut dir = f.assign_round(&other, Round::Nearest);
        assert_eq!(f, 15.0);
        assert_eq!(dir, Ordering::Greater);

        dir = f.assign_round(14.25, Round::Nearest);
        assert_eq!(f, 14.0);
        assert_eq!(dir, Ordering::Less);

        f.assign(other);
        assert_eq!(f, 15.0);

        float::free_cache(FreeCache::All);
    }

    #[cfg(feature = "rational")]
    #[test]
    fn check_fallible_conversions() {
        use crate::{float::Special, Float, Rational};
        use core::convert::TryFrom;
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
        for f in &large {
            let r = Rational::try_from(f);
            assert_eq!(r.is_ok(), f.is_finite());
            if let Ok(r) = r {
                assert_eq!(r, *f);
            }
        }

        float::free_cache(FreeCache::All);
    }
}
