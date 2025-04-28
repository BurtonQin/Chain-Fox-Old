/// The Computer Language Benchmarks Game
/// https://salsa.debian.org/benchmarksgame-team/benchmarksgame/
///
/// contributed by Miles
/// converted from C to Rust, by Henry Jayakusuma
///
/// As the code of `gcc #9` this code requires hardware supporting
/// the CPU feature SSE, AVX, implementing SIMD operations.
///

const N: usize = 5;
const PI: f64 = 3.141592653589793;
const SOLAR_MASS: f64 = 4.0 * PI * PI;
const DAYS_PER_YEAR: f64 = 365.24;
const PAIRS: usize = N * (N - 1) / 2;

use std::arch::x86_64::*;
use std::mem::{MaybeUninit, transmute};

#[repr(align(32))]
struct AlignedW([f64; PAIRS + 6]);

#[inline(always)]
unsafe fn _mm256_rsqrt_pd(
    s: __m256d
) -> __m256d {
    let q = _mm256_cvtpd_ps(s);
    let q = _mm_rsqrt_ps(q);
    let x = _mm256_cvtps_pd(q);
    let y = _mm256_mul_pd(_mm256_mul_pd(s, x), x);
    let a = _mm256_mul_pd(y, _mm256_set1_pd(0.375));
    let a = _mm256_mul_pd(a, y);
    let b = _mm256_mul_pd(y, _mm256_set1_pd(1.25));
    let b = _mm256_sub_pd(b, _mm256_set1_pd(1.875));
    let y = _mm256_sub_pd(a, b);
    _mm256_mul_pd(x, y)
}

// The type for w is [f64; PAIRS + 6] here because rust complains about
// transmuting to struct of different size.
#[inline(always)]
unsafe fn kernel(
    r: &mut [__m256d; PAIRS + 3],
    w: &mut [f64; PAIRS + 6],
    p: &[__m256d; N],
) {
    let mut k: usize = 0;
    for i in 1..N {
        for j in 0..i {
            r[k] = _mm256_sub_pd(p[i], p[j]);
            k = k + 1;
        }
    }

    for k in (0..PAIRS).step_by(4) {
        let x0 = _mm256_mul_pd(r[k], r[k]);
        let x1 = _mm256_mul_pd(r[k + 1], r[k + 1]);
        let x2 = _mm256_mul_pd(r[k + 2], r[k + 2]);
        let x3 = _mm256_mul_pd(r[k + 3], r[k + 3]);

        let t0 = _mm256_hadd_pd(x0, x1);
        let t1 = _mm256_hadd_pd(x2, x3);
        let y0 = _mm256_permute2f128_pd::<0x21>(t0, t1);
        let y1 = _mm256_blend_pd::<0b1100>(t0, t1);

        let z = _mm256_add_pd(y0, y1);
        let z = _mm256_rsqrt_pd(z);
        _mm256_store_pd(w.as_mut_ptr().offset(k as isize), z);
    }
}

unsafe fn energy(
    m: &[f64; N],
    p: &[__m256d; N],
    v: &[__m256d; N],
) -> f64 {
    let mut e: f64 = 0.0;
    let mut r: [__m256d; PAIRS + 3] = MaybeUninit::uninit().assume_init();
    let w: AlignedW = MaybeUninit::uninit().assume_init();
    let mut w = transmute::<AlignedW, [f64; PAIRS + 6]>(w);

    r[N] = _mm256_set1_pd(0.0);
    r[N + 1] = _mm256_set1_pd(0.0);
    r[N + 2] = _mm256_set1_pd(0.0);

    for k in 0..N { r[k] = _mm256_mul_pd(v[k], v[k]); }

    for k in (0..N).step_by(4) {
        let t0 = _mm256_hadd_pd(r[k], r[k + 1]);
        let t1 = _mm256_hadd_pd(r[k + 2], r[k + 3]);
        let y0 = _mm256_permute2f128_pd::<0x21>(t0, t1);
        let y1 = _mm256_blend_pd::<0b1100>(t0, t1);

        let z = _mm256_add_pd(y0, y1);
        _mm256_store_pd(w.as_mut_ptr().offset(k as isize), z);
    }

    for k in 0..N { e += 0.5 * m[k] * w[k] }

    r[PAIRS] = _mm256_set1_pd(1.0);
    r[PAIRS + 1] = _mm256_set1_pd(1.0);
    r[PAIRS + 2] = _mm256_set1_pd(1.0);

    kernel(&mut r, &mut w, &p);

    let mut k = 0;
    for i in 1..N {
        for j in 0..i {
            e -= m[i] * m[j] * w[k];
            k = k + 1;
        }
    }

    e
}

unsafe fn advance(
    n: i32,
    dt: f64,
    m: &[f64; N],
    p: &mut [__m256d; N],
    v: &mut [__m256d; N],
) {
    let mut r: [__m256d; PAIRS + 3] = MaybeUninit::uninit().assume_init();
    let w: AlignedW = MaybeUninit::uninit().assume_init();
    let mut w = transmute::<AlignedW, [f64; PAIRS + 6]>(w);
    r[PAIRS] = _mm256_set1_pd(1.0);
    r[PAIRS + 1] = _mm256_set1_pd(1.0);
    r[PAIRS + 2] = _mm256_set1_pd(1.0);

    let rt = _mm256_set1_pd(dt);

    let mut rm: [__m256d; N] = MaybeUninit::uninit().assume_init();
    for i in 0..N { rm[i] = _mm256_set1_pd(m[i]); }
    for _s in 0..n {
        kernel(&mut r, &mut w, &p);

        for k in (0..PAIRS).step_by(4) {
            let x = _mm256_load_pd(w.as_mut_ptr().offset(k as isize));
            let y = _mm256_mul_pd(x, x);
            let z = _mm256_mul_pd(x, rt);
            let x = _mm256_mul_pd(y, z);
            _mm256_store_pd(w.as_mut_ptr().offset(k as isize), x);
        }

        let mut k: usize = 0;
        for i in 1..N {
            for j in 0..i {
                let t = _mm256_set1_pd(w[k]);
                let t = _mm256_mul_pd(r[k], t);
                let x = _mm256_mul_pd(t, rm[j]);
                let y = _mm256_mul_pd(t, rm[i]);

                v[i] = _mm256_sub_pd(v[i], x);
                v[j] = _mm256_add_pd(v[j], y);
                k = k + 1;
            }
        }

        for i in 0..N {
            let t = _mm256_mul_pd(v[i], rt);
            p[i] = _mm256_add_pd(p[i], t);
        }
    }
}

fn main() {
    let n = std::env::args_os()
        .nth(1)
        .and_then(|s| s.into_string().ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or(1000);

    unsafe {
        let mut m: [f64; N] = MaybeUninit::uninit().assume_init();
        let mut p: [__m256d; N] = MaybeUninit::uninit().assume_init();
        let mut v: [__m256d; N] = MaybeUninit::uninit().assume_init();

        // sun
        m[0] = SOLAR_MASS;
        p[0] = _mm256_set1_pd(0.0);
        v[0] = _mm256_set1_pd(0.0);

        // jupiter
        m[1] = 9.54791938424326609e-04 * SOLAR_MASS;
        p[1] = _mm256_setr_pd(0.0,
                              4.84143144246472090e+00,
                              -1.16032004402742839e+00,
                              -1.03622044471123109e-01);
        v[1] = _mm256_setr_pd(0.0,
                              1.66007664274403694e-03 * DAYS_PER_YEAR,
                              7.69901118419740425e-03 * DAYS_PER_YEAR,
                              -6.90460016972063023e-05 * DAYS_PER_YEAR);

        // saturn
        m[2] = 2.85885980666130812e-04 * SOLAR_MASS;
        p[2] = _mm256_setr_pd(0.0,
                              8.34336671824457987e+00,
                              4.12479856412430479e+00,
                              -4.03523417114321381e-01);
        v[2] = _mm256_setr_pd(0.0,
                              -2.76742510726862411e-03 * DAYS_PER_YEAR,
                              4.99852801234917238e-03 * DAYS_PER_YEAR,
                              2.30417297573763929e-05 * DAYS_PER_YEAR);

        // uranus
        m[3] = 4.36624404335156298e-05 * SOLAR_MASS;
        p[3] = _mm256_setr_pd(0.0,
                              1.28943695621391310e+01,
                              -1.51111514016986312e+01,
                              -2.23307578892655734e-01);
        v[3] = _mm256_setr_pd(0.0,
                              2.96460137564761618e-03 * DAYS_PER_YEAR,
                              2.37847173959480950e-03 * DAYS_PER_YEAR,
                              -2.96589568540237556e-05 * DAYS_PER_YEAR);

        // neptune
        m[4] = 5.15138902046611451e-05 * SOLAR_MASS;
        p[4] = _mm256_setr_pd(0.0,
                              1.53796971148509165e+01,
                              -2.59193146099879641e+01,
                              1.79258772950371181e-01);
        v[4] = _mm256_setr_pd(0.0,
                              2.68067772490389322e-03 * DAYS_PER_YEAR,
                              1.62824170038242295e-03 * DAYS_PER_YEAR,
                              -9.51592254519715870e-05 * DAYS_PER_YEAR);

        // offset momentum
        let mut o = _mm256_set1_pd(0.0);
        for i in 0..N {
            let t = _mm256_mul_pd(_mm256_set1_pd(m[i]), v[i]);
            o = _mm256_add_pd(o, t);
        }

        v[0] = _mm256_mul_pd(o, _mm256_set1_pd(-1.0 / SOLAR_MASS));
        println!("{:.9}", energy(&m, &p, &v));
        advance(n, 0.01, &mut m, &mut p, &mut v);
        println!("{:.9}", energy(&m, &p, &v));
    }
}
