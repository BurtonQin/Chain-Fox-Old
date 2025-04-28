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
    ext::xmpfr,
    float::{self, OrdFloat},
    serdeize::{self, Data, PrecReq, PrecVal},
    Assign, Float,
};
use az::UnwrappedCast;
use serde::{
    de::{Deserialize, Deserializer, Error as DeError},
    ser::{Serialize, Serializer},
};

impl Serialize for Float {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let prec = self.prec();
        let radix = if prec <= 32 || !self.is_normal() {
            10
        } else {
            16
        };
        let prec = PrecVal::One(prec);
        let value = self.to_string_radix(radix, None);
        let data = Data { prec, radix, value };
        serdeize::serialize("Float", &data, serializer)
    }
}

impl<'de> Deserialize<'de> for Float {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Float, D::Error> {
        let (prec, radix, value) = de_data(deserializer)?;
        let p = Float::parse_radix(&value, radix).map_err(DeError::custom)?;
        Ok(Float::with_val(prec, p))
    }

    fn deserialize_in_place<D: Deserializer<'de>>(
        deserializer: D,
        place: &mut Float,
    ) -> Result<(), D::Error> {
        let (prec, radix, value) = de_data(deserializer)?;
        let p = Float::parse_radix(&value, radix).map_err(DeError::custom)?;
        xmpfr::set_prec_nan(place, prec.unwrapped_cast());
        place.assign(p);
        Ok(())
    }
}

fn de_data<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(u32, i32, String), D::Error> {
    let Data { prec, radix, value } = serdeize::deserialize("Float", PrecReq::One, deserializer)?;
    let prec = match prec {
        PrecVal::One(one) => one,
        _ => unreachable!(),
    };
    serdeize::check_range("precision", prec, float::prec_min(), float::prec_max())?;
    serdeize::check_range("radix", radix, 2, 36)?;
    Ok((prec, radix, value))
}

impl Serialize for OrdFloat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_float().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OrdFloat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<OrdFloat, D::Error> {
        Float::deserialize(deserializer).map(From::from)
    }

    fn deserialize_in_place<D: Deserializer<'de>>(
        deserializer: D,
        place: &mut OrdFloat,
    ) -> Result<(), D::Error> {
        Float::deserialize_in_place(deserializer, place.as_float_mut())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        float::{self, FreeCache, Special},
        Assign, Float,
    };
    use az::UnwrappedCast;
    use serde_json::json;

    fn assert(a: &Float, b: &Float) {
        assert_eq!(a.prec(), b.prec());
        assert_eq!(a.as_ord(), b.as_ord());
    }

    enum Check<'a> {
        SerDe(&'a Float),
        De(&'a Float),
        DeError(u32, &'a str),
    }

    impl Check<'_> {
        fn check(self, radix: i32, value: &'static str) {
            use crate::serdeize::test::*;
            use byteorder::{LittleEndian, WriteBytesExt};
            use serde_test::Token;
            use std::io::Write;
            let prec = match self {
                Check::SerDe(f) | Check::De(f) => f.prec(),
                Check::DeError(p, _) => p,
            };
            let tokens = [
                Token::Struct {
                    name: "Float",
                    len: 3,
                },
                Token::Str("prec"),
                Token::U32(prec),
                Token::Str("radix"),
                Token::I32(radix),
                Token::Str("value"),
                Token::Str(value),
                Token::StructEnd,
            ];
            let json = json!({
                "prec": prec,
                "radix": radix,
                "value": value,
            });
            let mut bincode = Vec::<u8>::new();
            bincode.write_u32::<LittleEndian>(prec).unwrap();
            bincode.write_i32::<LittleEndian>(radix).unwrap();
            bincode
                .write_u64::<LittleEndian>(value.len().unwrapped_cast())
                .unwrap();
            bincode.write_all(value.as_bytes()).unwrap();
            match self {
                Check::SerDe(f) => {
                    serde_test::assert_tokens(f.as_ord(), &tokens);
                    json_assert_value(f, &json, assert);
                    bincode_assert_value(f, &bincode, assert, Float::new(1));
                }
                Check::De(f) => {
                    serde_test::assert_de_tokens(f.as_ord(), &tokens);
                    json_assert_de_value(f, json, assert);
                    bincode_assert_de_value(f, &bincode, assert);
                }
                Check::DeError(_, msg) => {
                    serde_test::assert_de_tokens_error::<Float>(&tokens, msg);
                }
            }
        }
    }

    #[test]
    fn check() {
        let prec_err = format!("precision 0 less than minimum {}", float::prec_min());
        Check::DeError(0, &prec_err).check(10, "0");
        Check::DeError(40, "radix 1 less than minimum 2").check(1, "0");
        Check::DeError(40, "radix 37 greater than maximum 36").check(37, "0");

        let mut f = Float::new(40);
        Check::SerDe(&f).check(10, "0");
        Check::De(&f).check(10, "+0.0e5");

        f = -f;
        Check::SerDe(&f).check(10, "-0");
        Check::De(&f).check(16, "-0");

        f.assign(Special::Nan);
        Check::SerDe(&f).check(10, "NaN");
        Check::De(&f).check(10, "+@nan@");
        f = -f;
        Check::SerDe(&f).check(10, "-NaN");

        f.assign(15.0);
        Check::SerDe(&f).check(16, "f.0000000000");
        Check::De(&f).check(10, "15");
        Check::De(&f).check(15, "10");

        f.set_prec(32);
        Check::SerDe(&f).check(10, "15.000000000");
        Check::De(&f).check(16, "f");
        Check::De(&f).check(16, "0.f@1");
        Check::De(&f).check(15, "1.0@1");

        float::free_cache(FreeCache::All);
    }
}
