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
    complex::OrdComplex,
    ext::xmpfr,
    float,
    serdeize::{self, Data, PrecReq, PrecVal},
    Assign, Complex,
};
use az::UnwrappedCast;
use serde::{
    de::{Deserialize, Deserializer, Error as DeError},
    ser::{Serialize, Serializer},
};

impl Serialize for Complex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let prec = self.prec();
        let radix = if (prec.0 <= 32 || !self.real().is_normal())
            && (prec.1 <= 32 || !self.imag().is_normal())
        {
            10
        } else {
            16
        };
        let prec = PrecVal::Two(prec);
        let value = self.to_string_radix(radix, None);
        let data = Data { prec, radix, value };
        serdeize::serialize("Complex", &data, serializer)
    }
}

impl<'de> Deserialize<'de> for Complex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Complex, D::Error> {
        let (prec, radix, value) = de_data(deserializer)?;
        let p = Complex::parse_radix(&value, radix).map_err(DeError::custom)?;
        Ok(Complex::with_val(prec, p))
    }

    fn deserialize_in_place<D: Deserializer<'de>>(
        deserializer: D,
        place: &mut Complex,
    ) -> Result<(), D::Error> {
        let (prec, radix, value) = de_data(deserializer)?;
        let p = Complex::parse_radix(&value, radix).map_err(DeError::custom)?;
        xmpfr::set_prec_nan(place.mut_real(), prec.0.unwrapped_cast());
        xmpfr::set_prec_nan(place.mut_imag(), prec.1.unwrapped_cast());
        place.assign(p);
        Ok(())
    }
}

fn de_data<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<((u32, u32), i32, String), D::Error> {
    let Data { prec, radix, value } = serdeize::deserialize("Complex", PrecReq::Two, deserializer)?;
    let prec = match prec {
        PrecVal::Two(two) => two,
        _ => unreachable!(),
    };
    serdeize::check_range(
        "real precision",
        prec.0,
        float::prec_min(),
        float::prec_max(),
    )?;
    serdeize::check_range(
        "imaginary precision",
        prec.1,
        float::prec_min(),
        float::prec_max(),
    )?;
    serdeize::check_range("radix", radix, 2, 36)?;
    Ok((prec, radix, value))
}

impl Serialize for OrdComplex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_complex().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OrdComplex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<OrdComplex, D::Error> {
        Complex::deserialize(deserializer).map(From::from)
    }

    fn deserialize_in_place<D: Deserializer<'de>>(
        deserializer: D,
        place: &mut OrdComplex,
    ) -> Result<(), D::Error> {
        Complex::deserialize_in_place(deserializer, place.as_complex_mut())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        float::{self, FreeCache, Special},
        Assign, Complex,
    };
    use az::UnwrappedCast;
    use serde_json::json;

    fn assert(a: &Complex, b: &Complex) {
        assert_eq!(a.prec(), b.prec());
        assert_eq!(a.as_ord(), b.as_ord());
    }

    enum Check<'a> {
        SerDe(&'a Complex),
        De(&'a Complex),
        DeError((u32, u32), &'a str),
    }

    impl Check<'_> {
        fn check(self, radix: i32, value: &'static str) {
            use crate::serdeize::test::*;
            use byteorder::{LittleEndian, WriteBytesExt};
            use serde_test::Token;
            use std::io::Write;
            let prec = match self {
                Check::SerDe(c) | Check::De(c) => c.prec(),
                Check::DeError(p, _) => p,
            };
            let tokens = [
                Token::Struct {
                    name: "Complex",
                    len: 3,
                },
                Token::Str("prec"),
                Token::Tuple { len: 2 },
                Token::U32(prec.0),
                Token::U32(prec.1),
                Token::TupleEnd,
                Token::Str("radix"),
                Token::I32(radix),
                Token::Str("value"),
                Token::Str(value),
                Token::StructEnd,
            ];
            let json = json!({
                "prec": [prec.0, prec.1],
                "radix": radix,
                "value": value,
            });
            let mut bincode = Vec::<u8>::new();
            bincode.write_u32::<LittleEndian>(prec.0).unwrap();
            bincode.write_u32::<LittleEndian>(prec.1).unwrap();
            bincode.write_i32::<LittleEndian>(radix).unwrap();
            bincode
                .write_u64::<LittleEndian>(value.len().unwrapped_cast())
                .unwrap();
            bincode.write_all(value.as_bytes()).unwrap();
            match self {
                Check::SerDe(c) => {
                    serde_test::assert_tokens(c.as_ord(), &tokens);
                    json_assert_value(c, &json, assert);
                    bincode_assert_value(c, &bincode, assert, Complex::new(1));
                }
                Check::De(c) => {
                    serde_test::assert_de_tokens(c.as_ord(), &tokens);
                    json_assert_de_value(c, json, assert);
                    bincode_assert_de_value(c, &bincode, assert);
                }
                Check::DeError(_, msg) => {
                    serde_test::assert_de_tokens_error::<Complex>(&tokens, msg);
                }
            }
        }
    }

    #[test]
    fn check() {
        let prec_min = float::prec_min();
        let real_prec_err = format!("real precision 0 less than minimum {}", prec_min);
        let imag_prec_err = format!("imaginary precision 0 less than minimum {}", prec_min);
        Check::DeError((0, 32), &real_prec_err).check(10, "0");
        Check::DeError((40, 0), &imag_prec_err).check(10, "0");
        Check::DeError((40, 32), "radix 1 less than minimum 2").check(1, "0");
        Check::DeError((40, 32), "radix 37 greater than maximum 36").check(37, "0");

        let mut c = Complex::new((40, 32));
        Check::SerDe(&c).check(10, "(0 0)");
        Check::De(&c).check(10, "0");

        c = -c;
        Check::SerDe(&c).check(10, "(-0 -0)");
        Check::De(&c).check(16, "(-0 -0)");

        c.assign((Special::Nan, 15.0));
        Check::SerDe(&c).check(10, "(NaN 15.000000000)");
        Check::De(&c).check(10, "(+@nan@ 15)");
        c = -c;
        Check::SerDe(&c).check(10, "(-NaN -15.000000000)");

        c.assign((15.0, Special::Nan));
        Check::SerDe(&c).check(16, "(f.0000000000 @NaN@)");
        Check::De(&c).check(10, "(1.5e1 nan)");
        Check::De(&c).check(15, "(0.10@2 @nan@)");

        c <<= 100;
        Check::SerDe(&c).check(16, "(f.0000000000@25 @NaN@)");

        float::free_cache(FreeCache::All);
    }
}
