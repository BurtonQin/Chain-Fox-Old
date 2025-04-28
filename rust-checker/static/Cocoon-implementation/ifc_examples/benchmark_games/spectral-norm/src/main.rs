#![feature(negative_impls)]
// The Computer Language Benchmarks Game
// http://benchmarksgame.alioth.debian.org/
//
// contributed by the Rust Project Developers
// contributed by Matt Brubeck
// contributed by TeXitoi
// modified by Tung Duong
// contributed by Cristi Cobzarenco (@cristicbz)
// contributed by Andre Bogus

extern crate rayon;
use rayon::prelude::*;
use std::ops::*;
use secret_macros::InvisibleSideEffectFreeDerive;
use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

#[derive(Clone, Copy, InvisibleSideEffectFreeDerive)]
struct F64x2{f0: f64, f1: f64}

#[side_effect_free_attr]
fn splat(x: f64) -> F64x2 { F64x2{f0: x, f1: x} }

fn main() {
    let n = std::env::args().nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(100);
    let answer: st::Secret<f64, lat::Label_A> = secret_structs::secret_block!(
        lat::Label_A {
            wrap_secret(spectralnorm(n))
        }
    );
    println!("{:.9}", answer.declassify().get_value_consume());
}

#[side_effect_free_attr]
fn spectralnorm(n: usize) -> f64 {
    // Group all vectors in pairs of two for SIMD convenience.
    let mut u: std::vec::Vec<F64x2> = std::vec::Vec::new();
    let mut i = 0usize;
    let limit = n / 2;
    while i < limit {
        std::vec::Vec::push(&mut u, splat(1.0));
        i += 1;
    }

    let mut v: std::vec::Vec<F64x2> = std::vec::Vec::new();
    let mut i = 0;
    while i < limit {
        std::vec::Vec::push(&mut v, splat(1.0));
        i += 1;
    }

    let mut tmp: std::vec::Vec<F64x2> = std::vec::Vec::new();
    let mut i = 0;
    while i < limit {
        std::vec::Vec::push(&mut tmp, splat(0.0));
        i += 1;
    }

    let mut i = 0;
    while i < 10 {
        // Another pain point is slice decay.
        let u_ref: &[F64x2] = &u;
        let v_ref: &mut[F64x2] = &mut v;
        let mut_tmp_ref: &mut[F64x2] = &mut tmp;
        mult_at_av(u_ref, v_ref, mut_tmp_ref);

        let u_mut_ref: &mut[F64x2] = &mut u;
        let v_ref: &[F64x2] = &v;
        mult_at_av(v_ref, u_mut_ref, mut_tmp_ref);

        i += 1;
    }

    let uref: &[F64x2] = &u;
    let vref: &[F64x2] = &v;
    std::primitive::f64::sqrt(dot(uref, vref) / dot(vref, vref))
}

#[side_effect_free_attr]
fn mult_at_av(v: &[F64x2], out: &mut [F64x2], tmp: &mut [F64x2]) {
    // These are unchecked for two reasons.
    // First, we need a way to refer to functions that have been marked side_effect_free_attr.
    // Without this mechanism, referring to a is impossible.
    // Second, mult contains mostly unchecked operations from Rayon.
    unchecked_operation(mult(v, tmp, a));
    unchecked_operation(mult(tmp, out, |i, j| a(j, i)));
}

// I left this alone because of the heavy use of Rayon.
fn mult<F>(v: &[F64x2], out: &mut [F64x2], a: F)
           where F: Fn([usize; 2], [usize; 2]) -> F64x2 + Sync {
    // Parallelize along the output vector, with each pair of slots as a parallelism unit.
    out.par_iter_mut().enumerate().for_each(|(i, slot)| {
        // We're computing everything in chunks of two so the indces of slot[0] and slot[1] are 2*i
        // and 2*i + 1.
        let i = 2 * i;
        let (i0, i1) = ([i; 2], [i + 1; 2]);

        // Each slot in the pair gets its own sum, which is further computed in two f64 lanes (which
        // are summed at the end.
        let (mut sum0, mut sum1) = (F64x2{f0: 0.0, f1: 0.0}, F64x2{f0: 0.0, f1: 0.0});
        for (j, x) in v.iter().enumerate() {
            let j = [2 * j, 2 * j  + 1];
            div_and_add(*x, a(i0, j), a(i1, j), &mut sum0, &mut sum1);
        }

        // Sum the two lanes for each slot.
        *slot = F64x2{f0: sum0.f0 + sum0.f1, f1: sum1.f0 + sum1.f1};
    });
}

fn a(i: [usize; 2], j: [usize; 2]) -> F64x2 {
   F64x2{f0: ((i[0] + j[0]) * (i[0] + j[0] + 1) / 2 + i[0] + 1) as f64,
         f1: ((i[1] + j[1]) * (i[1] + j[1] + 1) / 2 + i[1] + 1) as f64}
}

#[side_effect_free_attr]
fn dot(v: &[F64x2], u: &[F64x2]) -> f64 {
    let r = unchecked_operation(
        u.iter()
             .zip(v)
             .map(|(&x, &y)| F64x2 {f0: x.f0 * y.f0, f1: x.f1 * y.f1})
             .fold(F64x2{f0: 0.0, f1: 0.0}, |s, x| F64x2 {f0: s.f0 + x.f0, f1: s.f1 + x.f1})
    );
    r.f0 + r.f1
}

#[side_effect_free_attr]
fn multiply_pair(pair: &(F64x2, F64x2)) -> F64x2 {
    F64x2 {
        f0: pair.0.f0 * pair.1.f0,
        f1: pair.0.f1 * pair.1.f1
    }
}

// Hint that this function should not be inlined. Keep the parallelised code tight, and vectorize
// better.
#[inline(never)]
fn div_and_add(x: F64x2,
               a0: F64x2,
               a1: F64x2,
               s0: &mut F64x2,
               s1: &mut F64x2) {
    *s0 = F64x2{f0: s0.f0 + x.f0 / a0.f0, f1: s0.f1 + x.f1 / a0.f1};
    *s1 = F64x2{f0: s1.f0 + x.f0 / a1.f0, f1: s1.f1 + x.f1 / a1.f1};
}