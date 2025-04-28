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

use crate::{ext::xmpz::*, misc::NegAbs, Integer};
use az::{WrappingAs, WrappingCast};
use core::{cmp::Ordering, i32, i64, u32, u64};
use gmp_mpfr_sys::gmp::{self, mpz_t};

#[inline]
pub fn set_u128(rop: &mut Integer, u: u128) {
    if u <= u128::from(u64::MAX) {
        set_u64(rop, u.wrapping_cast());
    } else if u <= !(!0u128 << 96) {
        if rop.inner().alloc < 3 {
            cold_realloc(rop, 3);
        }
        unsafe {
            rop.inner_mut().size = 3;
            *limb_mut(rop, 0) = u.wrapping_cast();
            *limb_mut(rop, 1) = (u >> 32).wrapping_cast();
            *limb_mut(rop, 2) = (u >> 64).wrapping_cast();
        }
    } else {
        if rop.inner().alloc < 4 {
            cold_realloc(rop, 4);
        }
        unsafe {
            rop.inner_mut().size = 4;
            *limb_mut(rop, 0) = u.wrapping_cast();
            *limb_mut(rop, 1) = (u >> 32).wrapping_cast();
            *limb_mut(rop, 2) = (u >> 64).wrapping_cast();
            *limb_mut(rop, 3) = (u >> 96).wrapping_cast();
        }
    }
}

#[inline]
pub fn set_u64(rop: &mut Integer, u: u64) {
    if u <= u64::from(u32::MAX) {
        set_u32(rop, u.wrapping_cast());
    } else {
        if rop.inner().alloc < 2 {
            cold_realloc(rop, 2);
        }
        unsafe {
            rop.inner_mut().size = 2;
            *limb_mut(rop, 0) = u.wrapping_cast();
            *limb_mut(rop, 1) = (u >> 32).wrapping_cast();
        }
    }
}

#[inline]
pub fn set_u32(rop: &mut Integer, u: u32) {
    set_limb(rop, u);
}

#[inline]
pub unsafe fn init_set_u128(rop: *mut Integer, u: u128) {
    if u <= u128::from(u64::MAX) {
        init_set_u64(rop, u.wrapping_cast());
    } else if u <= !(!0u128 << 96) {
        gmp::mpz_init2(cast_ptr_mut!(rop, mpz_t), 96);
        let rop = &mut *rop;
        rop.inner_mut().size = 3;
        *limb_mut(rop, 0) = u.wrapping_cast();
        *limb_mut(rop, 1) = (u >> 32).wrapping_cast();
        *limb_mut(rop, 2) = (u >> 64).wrapping_cast();
    } else {
        gmp::mpz_init2(cast_ptr_mut!(rop, mpz_t), 128);
        let rop = &mut *rop;
        rop.inner_mut().size = 4;
        *limb_mut(rop, 0) = u.wrapping_cast();
        *limb_mut(rop, 1) = (u >> 32).wrapping_cast();
        *limb_mut(rop, 2) = (u >> 64).wrapping_cast();
        *limb_mut(rop, 3) = (u >> 96).wrapping_cast();
    }
}

#[inline]
pub unsafe fn init_set_u64(rop: *mut Integer, u: u64) {
    if u <= u64::from(u32::MAX) {
        init_set_u32(rop, u.wrapping_cast());
    } else {
        gmp::mpz_init2(cast_ptr_mut!(rop, mpz_t), 64);
        let rop = &mut *rop;
        rop.inner_mut().size = 2;
        *limb_mut(rop, 0) = u.wrapping_cast();
        *limb_mut(rop, 1) = (u >> 32).wrapping_cast();
    }
}

#[inline]
pub unsafe fn init_set_u32(rop: *mut Integer, u: u32) {
    if u == 0 {
        gmp::mpz_init(cast_ptr_mut!(rop, mpz_t));
    } else {
        gmp::mpz_init2(cast_ptr_mut!(rop, mpz_t), 32);
        let rop = &mut *rop;
        rop.inner_mut().size = 1;
        *limb_mut(rop, 0) = u;
    }
}

#[inline]
pub fn get_abs_u128(op: &Integer) -> u128 {
    unsafe {
        match op.inner().size {
            0 => 0,
            -1 | 1 => u128::from(limb(op, 0)),
            -2 | 2 => u128::from(limb(op, 1)) << 32 | u128::from(limb(op, 0)),
            -3 | 3 => {
                u128::from(limb(op, 2)) << 64
                    | u128::from(limb(op, 1)) << 32
                    | u128::from(limb(op, 0))
            }
            _ => {
                u128::from(limb(op, 3)) << 96
                    | u128::from(limb(op, 2)) << 64
                    | u128::from(limb(op, 1)) << 32
                    | u128::from(limb(op, 0))
            }
        }
    }
}

#[inline]
pub fn get_abs_u64(op: &Integer) -> u64 {
    unsafe {
        match op.inner().size {
            0 => 0,
            -1 | 1 => u64::from(limb(op, 0)),
            _ => u64::from(limb(op, 1)) << 32 | u64::from(limb(op, 0)),
        }
    }
}

#[inline]
pub fn cmp_u128(op1: &Integer, op2: u128) -> Ordering {
    let size = op1.inner().size;
    if size > 4 {
        Ordering::Greater
    } else if size < 0 {
        Ordering::Less
    } else {
        get_abs_u128(op1).cmp(&op2)
    }
}

#[inline]
pub fn cmp_i128(op1: &Integer, op2: i128) -> Ordering {
    let size = op1.inner().size;
    if size > 4 {
        Ordering::Greater
    } else if size < -4 {
        Ordering::Less
    } else {
        let neg1 = size < 0;
        let abs1 = get_abs_u128(op1);
        let (neg2, abs2) = op2.neg_abs();
        match (neg1, neg2) {
            (false, false) => abs1.cmp(&abs2),
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (true, true) => abs2.cmp(&abs1),
        }
    }
}

#[inline]
pub fn cmp_u64(op1: &Integer, op2: u64) -> Ordering {
    let size = op1.inner().size;
    if size > 2 {
        Ordering::Greater
    } else if size < 0 {
        Ordering::Less
    } else {
        get_abs_u64(op1).cmp(&op2)
    }
}

#[inline]
pub fn cmp_i64(op1: &Integer, op2: i64) -> Ordering {
    let size = op1.inner().size;
    if size > 2 {
        Ordering::Greater
    } else if size < -2 {
        Ordering::Less
    } else {
        let neg1 = size < 0;
        let abs1 = get_abs_u64(op1);
        let (neg2, abs2) = op2.neg_abs();
        match (neg1, neg2) {
            (false, false) => abs1.cmp(&abs2),
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (true, true) => abs2.cmp(&abs1),
        }
    }
}

#[inline]
pub fn cmp_u32(op1: &Integer, op2: u32) -> Ordering {
    let size = op1.inner().size;
    if size > 1 {
        Ordering::Greater
    } else if size < 0 {
        Ordering::Less
    } else {
        get_abs_u32(op1).cmp(&op2)
    }
}

#[inline]
pub fn cmp_i32(op1: &Integer, op2: i32) -> Ordering {
    let size = op1.inner().size;
    if size > 1 {
        Ordering::Greater
    } else if size < -1 {
        Ordering::Less
    } else {
        let neg1 = size < 0;
        let abs1 = get_abs_u32(op1);
        let (neg2, abs2) = op2.neg_abs();
        match (neg1, neg2) {
            (false, false) => abs1.cmp(&abs2),
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (true, true) => abs2.cmp(&abs1),
        }
    }
}

#[inline]
pub fn fits_u32(op: &Integer) -> bool {
    match op.inner().size {
        0 | 1 => true,
        _ => false,
    }
}

#[inline]
pub fn fits_i32(op: &Integer) -> bool {
    match op.inner().size {
        0 => true,
        1 => (unsafe { limb(op, 0) }) <= i32::MAX.wrapping_as::<u32>(),
        -1 => (unsafe { limb(op, 0) }) <= i32::MIN.wrapping_as::<u32>(),
        _ => false,
    }
}

#[inline]
pub fn fits_u64(op: &Integer) -> bool {
    match op.inner().size {
        0 | 1 | 2 => true,
        _ => false,
    }
}

#[inline]
pub fn fits_i64(op: &Integer) -> bool {
    match op.inner().size {
        0 | 1 | -1 => true,
        2 => (unsafe { limb(op, 1) }) <= i32::MAX.wrapping_as::<u32>(),
        -2 => {
            (unsafe { limb(op, 1) }) < i32::MIN.wrapping_as::<u32>()
                || ((unsafe { limb(op, 1) }) == i32::MIN.wrapping_as::<u32>()
                    && (unsafe { limb(op, 0) }) == 0)
        }
        _ => false,
    }
}

#[inline]
pub fn fits_u128(op: &Integer) -> bool {
    match op.inner().size {
        0 | 1 | 2 | 3 | 4 => true,
        _ => false,
    }
}

#[inline]
pub fn fits_i128(op: &Integer) -> bool {
    match op.inner().size {
        0 | 1 | -1 | 2 | -2 | 3 | -3 => true,
        4 => (unsafe { limb(op, 3) }) <= i32::MAX.wrapping_as::<u32>(),
        -4 => {
            (unsafe { limb(op, 3) }) < i32::MIN.wrapping_as::<u32>()
                || ((unsafe { limb(op, 3) }) == i32::MIN.wrapping_as::<u32>()
                    && (unsafe { limb(op, 2) }) == 0
                    && (unsafe { limb(op, 1) }) == 0
                    && (unsafe { limb(op, 0) }) == 0)
        }
        _ => false,
    }
}
