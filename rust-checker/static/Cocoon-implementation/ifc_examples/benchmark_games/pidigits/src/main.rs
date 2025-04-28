#![feature(negative_impls)]
//! The Computer Language Benchmarks Game
//! https://salsa.debian.org/benchmarksgame-team/benchmarksgame/
//!
//! Contributed by TeXitoi
//! Contributed by Ryohei Machida
//!
//! ```cargo
//! [dependencies]
//! rug = { version = "1.12.0", default-features = false, features = ["integer"] }
//! ```

extern crate rug;

use rug::{Assign};
use secret_structs::secret::InvisibleSideEffectFree;
use std::io::Write;

use secret_macros::InvisibleSideEffectFreeDerive;
use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

struct Integer(rug::Integer);
unsafe impl InvisibleSideEffectFree for Integer {}

#[derive(InvisibleSideEffectFreeDerive)]
pub struct Context {
    q: Integer,
    r: Integer,
    t: Integer,
    tmp1: Integer,
    tmp2: Integer,
    k: u32,
}

impl Context {
    pub fn new() -> Context {
        Context {
            q: Integer(rug::Integer::from(1)),
            r: Integer(rug::Integer::from(0)),
            t: Integer(rug::Integer::from(1)),
            tmp1: Integer(rug::Integer::from(0)),
            tmp2: Integer(rug::Integer::from(0)),
            k: 0,
         }
    }
}

#[side_effect_free_attr]
fn next(ctx: &mut Context) -> u8 {
    while true {
        next_term(ctx);
        if unchecked_operation(ctx.q.0 > ctx.r.0) {
            continue;
        }

        let d = extract(ctx, 3);
        if d != extract(ctx, 4) {
            continue;
        }

        produce(ctx, d);
        return d;
    }
    0
}

#[side_effect_free_attr]
fn assign(i1: &mut Integer, i2: &Integer) {
    unchecked_operation(i1.0.assign(&i2.0));
}

#[side_effect_free_attr]
fn mult_by_u32(i: &mut Integer, scalar: u32) {
    unchecked_operation(i.0 *= scalar);
}

#[side_effect_free_attr]
fn mult_by_u8(i: &mut Integer, scalar: u8) {
    unchecked_operation(i.0 *= scalar);
}

#[side_effect_free_attr]
fn next_term(ctx: &mut Context) {
    ctx.k += 1;
    let k2 = ctx.k * 2 + 1;
    unchecked_operation(ctx.tmp1.0.assign(&ctx.q.0 << 1));
    unchecked_operation(ctx.r.0 += &ctx.tmp1.0);
    mult_by_u32(&mut ctx.r, k2);
    mult_by_u32(&mut ctx.t, k2);
    mult_by_u32(&mut ctx.q, ctx.k);
}

#[inline]
#[side_effect_free_attr]
fn extract(ctx: &mut Context, nth: u32) -> u8 {
    if core::primitive::u32::is_power_of_two(nth) {
        unchecked_operation(ctx.tmp1.0.assign(&ctx.q.0 << nth.trailing_zeros()));
    } else {
        unchecked_operation(ctx.tmp1.0.assign(&ctx.q.0 * nth));
    }

    unchecked_operation(ctx.tmp2.0.assign(&ctx.tmp1.0 + &ctx.r.0));
    unchecked_operation(ctx.tmp1.0.assign(&ctx.tmp2.0 / &ctx.t.0));
    unchecked_operation(ctx.tmp1.0.to_u8().unwrap())
}

#[side_effect_free_attr]
fn produce(ctx: &mut Context, n: u8) {
    mult_by_u8(&mut ctx.q, 10u8);
    unchecked_operation(ctx.r.0 -= &ctx.t.0 * n);
    mult_by_u8(&mut ctx.r, 10u8);
}

fn main() {
    let n: usize = std::env::args_os()
        .nth(1)
        .and_then(|s| s.into_string().ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or(27);

    let secret_output: st::Secret<Vec<u8>, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
        let mut ctx = unchecked_operation(Context::new());
        let mut line_buf = [0u8; 12];
        line_buf[10] = b'\t';
        line_buf[11] = b':';

        // output buffer
        let mut output = std::vec::Vec::with_capacity(n * 2);
        let mut d = 0;
        while d < n {
            let count = std::cmp::min(10, n - d);

            let mut i = 0;
            while i < count {
                line_buf[i] = b'0' + next(&mut ctx);
                i += 1;
            }

            let mut i = count;
            while i < 10 {
                line_buf[i] = b' ';
                i += 1;
            }

            std::vec::Vec::extend_from_slice(&mut output, &line_buf);
            unchecked_operation(writeln!(output, "{}", d + count));
            d += 10;
        }

        wrap_secret(output)
    });


    let _ = std::io::stdout().write_all(&secret_output.declassify().get_value_consume());
}
