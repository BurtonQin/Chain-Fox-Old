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
    serdeize::{self, Data, PrecReq, PrecVal},
    Assign, Integer,
};
use serde::{
    de::{Deserialize, Deserializer, Error as DeError},
    ser::{Serialize, Serializer},
};

impl Serialize for Integer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let prec = PrecVal::Zero;
        let radix = if self.significant_bits() <= 32 {
            10
        } else {
            16
        };
        let value = self.to_string_radix(radix);
        let data = Data { prec, radix, value };
        serdeize::serialize("Integer", &data, serializer)
    }
}

impl<'de> Deserialize<'de> for Integer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Integer, D::Error> {
        let (radix, value) = de_data(deserializer)?;
        let p = Integer::parse_radix(&value, radix).map_err(DeError::custom)?;
        Ok(Integer::from(p))
    }

    fn deserialize_in_place<D: Deserializer<'de>>(
        deserializer: D,
        place: &mut Integer,
    ) -> Result<(), D::Error> {
        let (radix, value) = de_data(deserializer)?;
        let p = Integer::parse_radix(&value, radix).map_err(DeError::custom)?;
        place.assign(p);
        Ok(())
    }
}

fn de_data<'de, D: Deserializer<'de>>(deserializer: D) -> Result<(i32, String), D::Error> {
    let Data { prec, radix, value } =
        serdeize::deserialize("Integer", PrecReq::Zero, deserializer)?;
    match prec {
        PrecVal::Zero => {}
        _ => unreachable!(),
    }
    serdeize::check_range("radix", radix, 2, 36)?;
    Ok((radix, value))
}

#[cfg(test)]
mod tests {
    use crate::{Assign, Integer};
    use az::UnwrappedCast;
    use serde_json::json;

    fn assert(a: &Integer, b: &Integer) {
        assert_eq!(a, b);
    }

    enum Check<'a> {
        SerDe(&'a Integer),
        De(&'a Integer),
        DeError(&'a str),
    }

    impl Check<'_> {
        fn check(self, radix: i32, value: &'static str) {
            use crate::serdeize::test::*;
            use byteorder::{LittleEndian, WriteBytesExt};
            use serde_test::Token;
            use std::io::Write;
            let tokens = [
                Token::Struct {
                    name: "Integer",
                    len: 2,
                },
                Token::Str("radix"),
                Token::I32(radix),
                Token::Str("value"),
                Token::Str(value),
                Token::StructEnd,
            ];
            let json = json!({
                "radix": radix,
                "value": value,
            });
            let mut bincode = Vec::<u8>::new();
            bincode.write_i32::<LittleEndian>(radix).unwrap();
            bincode
                .write_u64::<LittleEndian>(value.len().unwrapped_cast())
                .unwrap();
            bincode.write_all(value.as_bytes()).unwrap();
            match self {
                Check::SerDe(i) => {
                    serde_test::assert_tokens(i, &tokens);
                    json_assert_value(i, &json, assert);
                    let in_place = Integer::from(0xbad);
                    bincode_assert_value(i, &bincode, assert, in_place);
                }
                Check::De(i) => {
                    serde_test::assert_de_tokens(i, &tokens);
                    json_assert_de_value(i, json, assert);
                    bincode_assert_de_value(i, &bincode, assert);
                }
                Check::DeError(msg) => {
                    serde_test::assert_de_tokens_error::<Integer>(&tokens, msg);
                }
            }
        }
    }

    #[test]
    fn check() {
        Check::DeError("radix 1 less than minimum 2").check(1, "0");
        Check::DeError("radix 37 greater than maximum 36").check(37, "0");

        let mut i = Integer::new();
        Check::SerDe(&i).check(10, "0");
        Check::De(&i).check(10, "+0");
        Check::De(&i).check(10, "-00");

        i.assign(-0xffff_ffff_i64);
        Check::SerDe(&i).check(10, "-4294967295");
        Check::De(&i).check(16, "-ffffffff");

        i = i.abs() + 1;
        Check::SerDe(&i).check(16, "100000000");
        Check::De(&i).check(10, "4294967296");
    }
}
