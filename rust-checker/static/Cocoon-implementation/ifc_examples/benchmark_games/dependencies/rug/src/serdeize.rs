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

use core::fmt::{Display, Formatter, Result as FmtResult};
use serde::{
    de::{Deserialize, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor},
    ser::{SerializeStruct, Serializer},
};

#[allow(dead_code)]
pub enum PrecReq {
    Zero,
    One,
    Two,
}

pub enum PrecVal {
    Zero,
    One(u32),
    Two((u32, u32)),
}

pub struct Data {
    pub prec: PrecVal,
    pub radix: i32,
    pub value: String,
}

pub fn serialize<S: Serializer>(
    name: &'static str,
    data: &Data,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut state = match data.prec {
        PrecVal::Zero => serializer.serialize_struct(name, 2)?,
        PrecVal::One(one) => {
            let mut state = serializer.serialize_struct(name, 3)?;
            state.serialize_field("prec", &one)?;
            state
        }
        PrecVal::Two(two) => {
            let mut state = serializer.serialize_struct(name, 3)?;
            state.serialize_field("prec", &two)?;
            state
        }
    };
    state.serialize_field("radix", &data.radix)?;
    state.serialize_field("value", &data.value)?;
    state.end()
}

const FIELDS: &[&str] = &["radix", "value"];

enum Field {
    Radix,
    Value,
}

struct FieldVisitor;

impl<'de> Visitor<'de> for FieldVisitor {
    type Value = Field;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("`radix` or `value`")
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<Field, E> {
        match value {
            "radix" => Ok(Field::Radix),
            "value" => Ok(Field::Value),
            _ => Err(DeError::unknown_field(value, FIELDS)),
        }
    }
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Field, D::Error> {
        deserializer.deserialize_identifier(FieldVisitor)
    }
}

const PREC_FIELDS: &[&str] = &["prec", "radix", "value"];

enum PrecField {
    Prec,
    Field(Field),
}

struct PrecFieldVisitor;

impl<'de> Visitor<'de> for PrecFieldVisitor {
    type Value = PrecField;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("`prec`, `radix` or `value`")
    }

    fn visit_str<E: DeError>(self, value: &str) -> Result<PrecField, E> {
        match value {
            "prec" => Ok(PrecField::Prec),
            "radix" => Ok(PrecField::Field(Field::Radix)),
            "value" => Ok(PrecField::Field(Field::Value)),
            _ => Err(DeError::unknown_field(value, PREC_FIELDS)),
        }
    }
}

impl<'de> Deserialize<'de> for PrecField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<PrecField, D::Error> {
        deserializer.deserialize_identifier(PrecFieldVisitor)
    }
}

struct BigVisitor(&'static str, PrecReq);

impl<'de> Visitor<'de> for BigVisitor {
    type Value = Data;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str(self.0)
    }

    fn visit_seq<V: SeqAccess<'de>>(self, mut seq: V) -> Result<Data, V::Error> {
        let prec = match self.1 {
            PrecReq::Zero => PrecVal::Zero,
            PrecReq::One => PrecVal::One(
                seq.next_element()?
                    .ok_or_else(|| DeError::invalid_length(0, &self))?,
            ),
            PrecReq::Two => PrecVal::Two(
                seq.next_element()?
                    .ok_or_else(|| DeError::invalid_length(0, &self))?,
            ),
        };
        let prec_count = match self.1 {
            PrecReq::Zero => 0,
            PrecReq::One | PrecReq::Two => 1,
        };
        let radix = seq
            .next_element()?
            .ok_or_else(|| DeError::invalid_length(prec_count, &self))?;
        let value = seq
            .next_element()?
            .ok_or_else(|| DeError::invalid_length(prec_count + 1, &self))?;
        Ok(Data { prec, radix, value })
    }

    fn visit_map<V: MapAccess<'de>>(self, mut map: V) -> Result<Data, V::Error> {
        let mut prec = match self.1 {
            PrecReq::Zero => Some(PrecVal::Zero),
            PrecReq::One | PrecReq::Two => None,
        };
        let mut radix = None;
        let mut value = None;
        while let Some(key) = match self.1 {
            PrecReq::Zero => map.next_key()?.map(PrecField::Field),
            PrecReq::One | PrecReq::Two => map.next_key()?,
        } {
            match key {
                PrecField::Prec => {
                    if prec.is_some() {
                        return Err(DeError::duplicate_field("prec"));
                    }
                    prec = match self.1 {
                        PrecReq::Zero => unreachable!(),
                        PrecReq::One => Some(PrecVal::One(map.next_value()?)),
                        PrecReq::Two => Some(PrecVal::Two(map.next_value()?)),
                    }
                }
                PrecField::Field(Field::Radix) => {
                    if radix.is_some() {
                        return Err(DeError::duplicate_field("radix"));
                    }
                    radix = Some(map.next_value()?);
                }
                PrecField::Field(Field::Value) => {
                    if value.is_some() {
                        return Err(DeError::duplicate_field("value"));
                    }
                    value = Some(map.next_value()?);
                }
            }
        }
        let prec = prec.ok_or_else(|| DeError::missing_field("prec"))?;
        let radix = radix.ok_or_else(|| DeError::missing_field("radix"))?;
        let value = value.ok_or_else(|| DeError::missing_field("value"))?;
        Ok(Data { prec, radix, value })
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(
    name: &'static str,
    prec_req: PrecReq,
    deserializer: D,
) -> Result<Data, D::Error> {
    let fields = match prec_req {
        PrecReq::Zero => FIELDS,
        PrecReq::One | PrecReq::Two => PREC_FIELDS,
    };
    deserializer.deserialize_struct(name, fields, BigVisitor(name, prec_req))
}

pub fn check_range<T, D>(name: &'static str, val: T, min: T, max: T) -> Result<(), D>
where
    T: Copy + Display + Ord,
    D: DeError,
{
    if val < min {
        Err(DeError::custom(format_args!(
            "{} {} less than minimum {}",
            name, val, min,
        )))
    } else if val > max {
        Err(DeError::custom(format_args!(
            "{} {} greater than maximum {}",
            name, val, max,
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use serde::{Deserialize, Serialize};

    pub fn json_assert_value<T, F>(t: &T, val: &serde_json::Value, test: F)
    where
        T: Serialize + for<'de> Deserialize<'de>,
        F: Fn(&T, &T),
    {
        let enc = serde_json::to_string(t).unwrap();
        let dec: T = serde_json::from_str(&enc).unwrap();
        test(t, &dec);
        let dec_v: serde_json::Value = serde_json::from_str(&enc).unwrap();
        assert_eq!(val, &dec_v);
    }

    pub fn json_assert_de_value<T, F>(t: &T, val: serde_json::Value, test: F)
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&T, &T),
    {
        let dec: T = serde_json::from_value(val).unwrap();
        test(t, &dec);
    }

    pub fn bincode_assert_value<T, F>(t: &T, val: &[u8], test: F, in_place: T)
    where
        T: Serialize + for<'de> Deserialize<'de>,
        F: Fn(&T, &T),
    {
        let enc = bincode::serialize(&t).unwrap();
        let dec: T = bincode::deserialize(&enc).unwrap();
        test(t, &dec);

        assert_eq!(enc, val);

        let mut in_place: T = in_place;
        let reader = quick_and_dirty::SliceReader::new(&enc);
        bincode::deserialize_in_place(reader, &mut in_place).unwrap();
        test(t, &in_place);
    }

    pub fn bincode_assert_de_value<T, F>(t: &T, val: &[u8], test: F)
    where
        T: for<'de> Deserialize<'de>,
        F: Fn(&T, &T),
    {
        let dec: T = bincode::deserialize(&val).unwrap();
        test(t, &dec);
    }

    mod quick_and_dirty {
        use bincode::{BincodeRead, Result as BincodeResult};
        use serde::de::Visitor;
        use std::io::{Read, Result as IoResult};

        // this is just to test deserialize_in_place, so only
        // BincodeRead::get_byte_buffer is implemented
        pub struct SliceReader<'a>(&'a [u8]);

        impl SliceReader<'_> {
            pub fn new(slice: &[u8]) -> SliceReader<'_> {
                SliceReader(slice)
            }
        }

        impl Read for SliceReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
                (self.0).read(buf)
            }
        }

        impl<'a> BincodeRead<'a> for SliceReader<'a> {
            fn forward_read_str<V: Visitor<'a>>(
                &mut self,
                _length: usize,
                _visitor: V,
            ) -> BincodeResult<V::Value> {
                unimplemented!()
            }

            fn get_byte_buffer(&mut self, length: usize) -> BincodeResult<Vec<u8>> {
                let ret = self.0[..length].to_vec();
                self.0 = &self.0[length..];
                Ok(ret)
            }

            fn forward_read_bytes<V: Visitor<'a>>(
                &mut self,
                _length: usize,
                _visitor: V,
            ) -> BincodeResult<V::Value> {
                unimplemented!()
            }
        }
    }
}
