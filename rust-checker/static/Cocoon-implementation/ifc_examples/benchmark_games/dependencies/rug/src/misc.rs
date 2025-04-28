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

#![allow(dead_code)]

use az::WrappingCast;

pub trait NegAbs {
    type Abs;
    fn neg_abs(self) -> (bool, Self::Abs);
}

macro_rules! neg_abs {
    ($I:ty; $U:ty) => {
        impl NegAbs for $I {
            type Abs = $U;
            #[inline]
            fn neg_abs(self) -> (bool, $U) {
                if self < 0 {
                    (true, self.wrapping_neg().wrapping_cast())
                } else {
                    (false, self.wrapping_cast())
                }
            }
        }

        impl NegAbs for $U {
            type Abs = $U;
            #[inline]
            fn neg_abs(self) -> (bool, $U) {
                (false, self)
            }
        }
    };
}

neg_abs! { i8; u8 }
neg_abs! { i16; u16 }
neg_abs! { i32; u32 }
neg_abs! { i64; u64 }
neg_abs! { i128; u128 }
neg_abs! { isize; usize }

#[inline]
pub fn trunc_f64_to_f32(f: f64) -> f32 {
    // f as f32 might round away from zero, so we need to clear
    // the least significant bits of f.
    //   * If f is a nan, we do NOT want to clear any mantissa bits,
    //     as this may change f into +/- infinity.
    //   * If f is +/- infinity, the bits are already zero, so the
    //     masking has no effect.
    //   * If f is subnormal, f as f32 will be zero anyway.
    if !f.is_nan() {
        let u = f.to_bits();
        // f64 has 29 more significant bits than f32.
        let trunc_u = u & (!0 << 29);
        let trunc_f = f64::from_bits(trunc_u);
        trunc_f as f32
    } else {
        f as f32
    }
}

fn lcase(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A' + b'a',
        _ => byte,
    }
}

pub fn trim_start(bytes: &[u8]) -> &[u8] {
    for (start, &b) in bytes.iter().enumerate() {
        match b {
            b' ' | b'\t' | b'\n' | 0x0b | 0x0c | 0x0d => {}
            _ => return &bytes[start..],
        }
    }
    &[]
}

pub fn trim_end(bytes: &[u8]) -> &[u8] {
    for (end, &b) in bytes.iter().enumerate().rev() {
        match b {
            b' ' | b'\t' | b'\n' | 0x0b | 0x0c | 0x0d => {}
            _ => return &bytes[..=end],
        }
    }
    &[]
}

// If bytes starts with a match to one of patterns, return bytes with
// the match skipped. Only bytes is converted to lcase.
pub fn skip_lcase_match<'a>(bytes: &'a [u8], patterns: &[&[u8]]) -> Option<&'a [u8]> {
    'next_pattern: for pattern in patterns {
        if bytes.len() < pattern.len() {
            continue 'next_pattern;
        }
        for (&b, &p) in bytes.iter().zip(pattern.iter()) {
            if lcase(b) != p {
                continue 'next_pattern;
            }
        }
        return Some(&bytes[pattern.len()..]);
    }
    None
}

// If bytes starts with '(' and has a matching ')', returns the
// contents and the remainder.
pub fn matched_brackets(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut iter = bytes.iter().enumerate();
    match iter.next() {
        Some((_, &b'(')) => {}
        _ => return None,
    }
    let mut level = 1;
    for (i, &b) in iter {
        match b {
            b'(' => level += 1,
            b')' => {
                level -= 1;
                if level == 0 {
                    return Some((&bytes[1..i], &bytes[i + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

pub fn find_outside_brackets(bytes: &[u8], pattern: u8) -> Option<usize> {
    let mut level = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => level += 1,
            b')' if level > 0 => level -= 1,
            _ if level == 0 && b == pattern => return Some(i),
            _ => {}
        }
    }
    None
}

pub fn find_space_outside_brackets(bytes: &[u8]) -> Option<usize> {
    let mut level = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => level += 1,
            b')' if level > 0 => level -= 1,
            b' ' | b'\t' | b'\n' | 0x0b | 0x0c | 0x0d if level == 0 => {
                return Some(i);
            }
            _ => {}
        }
    }
    None
}
