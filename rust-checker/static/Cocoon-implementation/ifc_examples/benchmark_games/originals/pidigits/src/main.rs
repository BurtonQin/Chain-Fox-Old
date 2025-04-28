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

use rug::{Assign, Integer};
use std::cmp;
use std::io::Write;

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
            q: Integer::from(1),
            r: Integer::from(0),
            t: Integer::from(1),
            tmp1: Integer::from(0),
            tmp2: Integer::from(0),
            k: 0,
        }
    }

    pub fn next(&mut self) -> u8 {
        loop {
            self.next_term();
            if self.q > self.r {
                continue;
            }
            let d = self.extract(3);
            if d != self.extract(4) {
                continue;
            }

            self.produce(d);
            return d;
        }
    }

    fn next_term(&mut self) {
        self.k += 1;
        let k2 = self.k * 2 + 1;

        self.tmp1.assign(&self.q << 1);
        self.r += &self.tmp1;
        self.r *= k2;
        self.t *= k2;
        self.q *= self.k;
    }

    #[inline]
    fn extract(&mut self, nth: u32) -> u8 {
        if nth.is_power_of_two() {
            // use shift operation if possible
            self.tmp1.assign(&self.q << nth.trailing_zeros());
        } else {
            self.tmp1.assign(&self.q * nth);
        };

        self.tmp2.assign(&self.tmp1 + &self.r);
        self.tmp1.assign(&self.tmp2 / &self.t);
        self.tmp1.to_u8().unwrap()
    }

    fn produce(&mut self, n: u8) {
        self.q *= 10u8;
        self.r -= &self.t * n;
        self.r *= 10u8;
    }
}

fn main() {
    let n: usize = std::env::args_os()
        .nth(1)
        .and_then(|s| s.into_string().ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or(27);

    let mut ctx = Context::new();

    // line buffer
    let mut line_buf = [0u8; 12];
    line_buf[10] = b'\t';
    line_buf[11] = b':';

    // output buffer
    let mut output = Vec::with_capacity(n * 2);

    for d in (0..n).step_by(10) {
        let count = cmp::min(10, n - d);

        for i in 0..count {
            line_buf[i] = b'0' + ctx.next();
        }

        for i in count..10 {
            line_buf[i] = b' ';
        }

        output.extend_from_slice(&line_buf);
        let _ = writeln!(output, "{}", d + count);
    }

    let _ = std::io::stdout().write_all(&*output);
}