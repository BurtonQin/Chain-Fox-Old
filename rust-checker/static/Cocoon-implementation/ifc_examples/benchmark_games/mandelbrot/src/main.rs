#![feature(negative_impls)]
// The Computer Language Benchmarks Game
// https://salsa.debian.org/benchmarksgame-team/benchmarksgame/
//
// Contributed by Kevin Miller
// Converted from C to Rust by Tung Duong

extern crate rayon;

use std::io::Write;
use rayon::prelude::*;
use secret_macros::InvisibleSideEffectFreeDerive;
use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, InvisibleSideEffectFreeDerive)]
struct f64x2 {f0: f64, f1: f64}

const ZEROS: [f64x2;4] = [f64x2{f0: 0.0, f1: 0.0}; 4];

#[inline(always)]
#[side_effect_free_attr]
fn vec_nle(v : &[f64x2;4], f : f64) -> bool {
    return if v[0].f0 <= f ||
        v[0].f1 <= f ||
        v[1].f0 <= f ||
        v[1].f1 <= f ||
        v[2].f0 <= f ||
        v[2].f1 <= f ||
        v[3].f0 <= f ||
        v[3].f1 <= f {false} else {true};
}

#[inline(always)]
#[side_effect_free_attr]
fn clr_pixels_nle(v : &[f64x2;4], f: f64, pix8 : &mut u8) {
    if !(v[0].f0 <= f) { *pix8 = *pix8 & 0x7f;}
    if !(v[0].f1 <= f) {*pix8 = *pix8 & 0xbf;}
    if !(v[1].f0 <= f) {*pix8 = *pix8 & 0xdf;}
    if !(v[1].f1 <= f) {*pix8 = *pix8 & 0xef;}
    if !(v[2].f0 <= f) {*pix8 = *pix8 & 0xf7;}
    if !(v[2].f1 <= f) {*pix8 = *pix8 & 0xfb;}
    if !(v[3].f0 <= f) {*pix8 = *pix8 & 0xfd;}
    if !(v[3].f1 <= f) {*pix8 = *pix8 & 0xfe;}
}

#[inline(always)]
#[side_effect_free_attr]
fn calc_sum(r: &mut [f64x2;4], i : &mut[f64x2;4], sum : &mut[f64x2;4], init_r: &[f64x2;4], init_i : f64x2) {
	for j in 0..4 {
        let r2 = f64x2{f0: (&*r)[j].f0 * (&*r)[j].f0, f1: (&*r)[j].f1 * (&*r)[j].f1};
        let i2 = f64x2{f0: (&*i)[j].f0 * (&*i)[j].f0, f1: (&*i)[j].f1 * (&*i)[j].f1};
        let ri = f64x2{f0: (&*r)[j].f0 * (&*i)[j].f0, f1: (&*r)[j].f1 * (&*i)[j].f1};
        (&mut *sum)[j] = f64x2{f0: r2.f0 + i2.f0, f1: r2.f1 + i2.f1};
        (&mut *r)[j] = f64x2{f0: r2.f0 - i2.f0 + init_r[j].f0, f1: r2.f1 - i2.f1 + init_r[j].f1};
        (&mut *i)[j] = f64x2{f0: ri.f0 + ri.f0 + init_i.f0, f1: ri.f1 + ri.f1 + init_i.f1};
	}
}

#[inline(always)]
#[side_effect_free_attr]
fn mand8(init_r: &[f64x2;4], init_i : f64x2) -> u8 {
    // TODO
	let mut r = ZEROS;
	let mut i = ZEROS;
	let mut sum = ZEROS;

	for j in 0..4 {
		r[j] = init_r[j];
		i[j] = init_i;
	}

    let mut pix8 : u8 = 0xff;

    for _ in 0..6 {
        for _ in 0..8 {
            calc_sum(&mut r, &mut i, &mut sum, &init_r, init_i);
        }

        if vec_nle(&sum, 4.0) {
            pix8 = 0x00;
            break;
        }
    }
    if pix8 != 0 {
        calc_sum(&mut r, &mut i, &mut sum, &init_r, init_i);
        calc_sum(&mut r, &mut i, &mut sum, &init_r, init_i);
        clr_pixels_nle(&sum, 4.0, &mut pix8);
    }

    pix8
}

#[side_effect_free_attr]
fn mand64(init_r: &[f64x2;32], init_i : f64x2, out : &mut [u8]) {
    let mut tmp_init_r = ZEROS;

    for i in 0..8 {
        <[_]>::copy_from_slice(&mut tmp_init_r, &init_r[4*i..4*i+4]);
        (&mut *out)[i] = mand8(&tmp_init_r, init_i);
    }
}


fn main(){
	let mut width = std::env::args_os().nth(1)
        .and_then(|s| s.into_string().ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or(16000);
    width = (width+7) & !7;
    
    println!("P4\n{} {}", width, width);

    let secret_rows: st::Secret<Vec<Vec<u8>>, lat::Label_A> = secret_structs::secret_block!(
        lat::Label_A {
            let mut r0: std::vec::Vec<f64x2> = std::vec::Vec::new();
            for _ in 0..width/2 {
                std::vec::Vec::push(&mut r0, f64x2{f0: 0.0, f1: 0.0});
            }

            let mut i0: std::vec::Vec<f64> = std::vec::Vec::new();
            for _ in 0..width {
                std::vec::Vec::push(&mut i0, 0.0);
            }

            for i in 0..width/2 {
                let x1 = (2*i) as f64;
                let x2 = (2*i+1) as f64;
                let k = 2.0 / (width as f64);
                (&mut *r0)[i] = f64x2{f0: k * x1 - 1.5, f1: k * x2 - 1.5};
                (&mut *i0)[2*i] = k*x1 - 1.0;
                (&mut *i0)[2*i+1] = k*x2 - 1.0;
            }

            // TODO: get remainder operator working.
            let rows: Vec<_>  = if unchecked_operation(width%64 == 0) {
                let f = |y: usize| {
                    let mut row: std::vec::Vec<u8> = std::vec::Vec::new();
                    for _ in 0..width/8 {
                        std::vec::Vec::push(&mut row, 0);
                    }
                    let mut tmp_r0 = [f64x2{f0: 0.0, f1: 0.0}; 32];
                    let init_i = f64x2{f0: (&i0)[y], f1: (&i0)[y]};

                    for x in 0..width/64 {
                        <[_]>::copy_from_slice(&mut tmp_r0, &(&*r0)[32*x..32*x+32]);
                        mand64(&tmp_r0, init_i, &mut (&mut *row)[8*x..8*x + 8]);
                    }
                    row
                };

                // process 64 pixels (8 bytes) at a time
                unchecked_operation((0..width).into_par_iter().map(f).collect())
            } else {
                // process 8 pixels (1 byte) at a time
                let f = |y: usize| {
                    let mut row: std::vec::Vec<u8> = std::vec::Vec::new();
                    for _ in 0..width/8 {
                        std::vec::Vec::push(&mut row, 0);
                    }

                    let mut tmp_r0 = ZEROS;
                    let init_i = f64x2{f0: (&i0)[y], f1: (&i0)[y]};

                    for x in 0..width/8 {
                        <[_]>::copy_from_slice(&mut tmp_r0, &(&*r0)[4*x..4*x+4]);
                        (&mut *row)[x] = mand8(&tmp_r0, init_i);
                    }

                    row
                };
                unchecked_operation((0..width).into_par_iter().map(f).collect())
            };

            wrap_secret(rows)
        }
    );
    let stdout_unlocked = std::io::stdout();
    let mut stdout = stdout_unlocked.lock();
    for row in secret_rows.declassify().get_value_consume() {
        stdout.write_all(&row).unwrap();
    }
    stdout.flush().unwrap();
}