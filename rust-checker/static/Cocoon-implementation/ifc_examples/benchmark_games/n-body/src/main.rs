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

use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;
use std::arch::x86_64::*;
use std::mem::{MaybeUninit};

#[repr(align(32))]
struct AlignedW([f64; PAIRS + 6]);

unsafe impl st::InvisibleSideEffectFree for AlignedW {}

#[inline(always)]
#[side_effect_free_attr]
unsafe fn _mm256_rsqrt_pd(s: __m256d) -> __m256d {
    let q = std::arch::x86_64::_mm256_cvtpd_ps(s);
    let q = std::arch::x86_64::_mm_rsqrt_ps(q);
    let x = std::arch::x86_64::_mm256_cvtps_pd(q);
    let y = std::arch::x86_64::_mm256_mul_pd(std::arch::x86_64::_mm256_mul_pd(s, x), x);
    let a = std::arch::x86_64::_mm256_mul_pd(y, std::arch::x86_64::_mm256_set1_pd(0.375));
    let a = std::arch::x86_64::_mm256_mul_pd(a, y);
    let b = std::arch::x86_64::_mm256_mul_pd(y, std::arch::x86_64::_mm256_set1_pd(1.25));
    let b = std::arch::x86_64::_mm256_sub_pd(b, std::arch::x86_64::_mm256_set1_pd(1.875));
    let y = std::arch::x86_64::_mm256_sub_pd(a, b);
    std::arch::x86_64::_mm256_mul_pd(x, y)
}

// The type for w is [f64; PAIRS + 6] here because rust complains about
// transmuting to struct of different size.
#[inline(always)]
#[side_effect_free_attr]
unsafe fn kernel(r: &mut [__m256d; PAIRS + 3], w: &mut [f64; PAIRS + 6], p: &[__m256d; N]) {
    let mut k: usize = 0;
    let mut i = 1;
    while i < N {
        let mut j = 0;
        while j < i {
            (*r)[k] = std::arch::x86_64::_mm256_sub_pd(p[i], p[j]);
            k = k + 1;
            j += 1;
        }
        i += 1;
    }

    k = 0;
    while k < PAIRS {
        let x0 = std::arch::x86_64::_mm256_mul_pd((&*r)[k], (&*r)[k]);
        let x1 = std::arch::x86_64::_mm256_mul_pd((&*r)[k + 1], (&*r)[k + 1]);
        let x2 = std::arch::x86_64::_mm256_mul_pd((&*r)[k + 2], (&*r)[k + 2]);
        let x3 = std::arch::x86_64::_mm256_mul_pd((&*r)[k + 3], (&*r)[k + 3]);
        let t0 = std::arch::x86_64::_mm256_hadd_pd(x0, x1);
        let t1 = std::arch::x86_64::_mm256_hadd_pd(x2, x3);
        let y0 = unchecked_operation(_mm256_permute2f128_pd::<0x21>(t0, t1));
        let y1 = unchecked_operation(_mm256_blend_pd::<0b1100>(t0, t1));
        let z = std::arch::x86_64::_mm256_add_pd(y0, y1);
        let z = _mm256_rsqrt_pd(z);
        unchecked_operation(_mm256_store_pd(w.as_mut_ptr().offset(k as isize), z));
        k += 4;
    }
}

#[side_effect_free_attr]
unsafe fn energy(m: &[f64; N], p: &[__m256d; N], v: &[__m256d; N]) -> f64 {
    let mut e: f64 = 0.0;
    let r: std::mem::MaybeUninit<[__m256d; PAIRS + 3]> = std::mem::MaybeUninit::uninit();
    let mut r: [__m256d; PAIRS + 3] = std::mem::MaybeUninit::assume_init(r);
    let w: std::mem::MaybeUninit<AlignedW> = std::mem::MaybeUninit::uninit();
    let w: AlignedW = std::mem::MaybeUninit::assume_init(w);
    let mut w: [f64; PAIRS + 6] = std::mem::transmute(w);

    r[N] = std::arch::x86_64::_mm256_set1_pd(0.0);
    r[N + 1] = std::arch::x86_64::_mm256_set1_pd(0.0);
    r[N + 2] = std::arch::x86_64::_mm256_set1_pd(0.0);

    let mut k = 0;
    while k < N {
        r[k] = std::arch::x86_64::_mm256_mul_pd(v[k], v[k]);
        k += 1;
    }

    k = 0;
    while k < N {
        let t0 = std::arch::x86_64::_mm256_hadd_pd((&r)[k], (&r)[k+1]);
        let t1 = std::arch::x86_64::_mm256_hadd_pd((&r)[k + 2], (&r)[k + 3]);
        // Has to be unchecked due to generic.
        let y0 = unchecked_operation(std::arch::x86_64::_mm256_permute2f128_pd::<0x21>(t0, t1));
        let y1 = unchecked_operation(std::arch::x86_64::_mm256_blend_pd::<0b1100>(t0, t1));
        let z = std::arch::x86_64::_mm256_add_pd(y0, y1);
        std::arch::x86_64::_mm256_store_pd(unchecked_operation(w.as_mut_ptr().offset(k as isize)), z);
        k += 4;
    }

    k = 0;
    while k < N {
        e += 0.5 * m[k] * (&w)[k];
        k += 1;
    }

    r[PAIRS] = std::arch::x86_64::_mm256_set1_pd(1.0);
    r[PAIRS+1] = std::arch::x86_64::_mm256_set1_pd(1.0);
    r[PAIRS+2] = std::arch::x86_64::_mm256_set1_pd(1.0);

    kernel(&mut r, &mut w, &p);

    let mut k = 0;
    let mut i = 1;
    while i < N {
        let mut j = 0;
        while j < i {
            e -= m[i] * m[j] * (&w)[k];
            k = k + 1;
            j = j + 1;
        }
        i += 1;
    }

    e
}

#[side_effect_free_attr]
unsafe fn advance(n: i32, dt: f64, m: &[f64; N], p: &mut [__m256d; N], v: &mut [__m256d; N]) {
    let r: std::mem::MaybeUninit<[__m256d; PAIRS + 3]> = std::mem::MaybeUninit::uninit();
    let mut r: [__m256d; PAIRS + 3] = std::mem::MaybeUninit::assume_init(r);

    let w: std::mem::MaybeUninit<AlignedW> = std::mem::MaybeUninit::uninit();
    let w: AlignedW = std::mem::MaybeUninit::assume_init(w);
    let mut w: [f64; PAIRS + 6] = std::mem::transmute(w);

    r[PAIRS] = std::arch::x86_64::_mm256_set1_pd(1.0);
    r[PAIRS + 1] = std::arch::x86_64::_mm256_set1_pd(1.0);
    r[PAIRS + 2] = std::arch::x86_64::_mm256_set1_pd(1.0);

    let rt = std::arch::x86_64::_mm256_set1_pd(dt);

    let rm: std::mem::MaybeUninit<[__m256d; N]> = std::mem::MaybeUninit::uninit();
    let mut rm: [__m256d; N] = std::mem::MaybeUninit::assume_init(rm);

    let mut i = 0;
    while i < N {
        rm[i] = std::arch::x86_64::_mm256_set1_pd(m[i]);
        i += 1;
    }

    let mut _s = 0;
    while _s < n {
        {
            let p: &[__m256d; N] = p as &_; // Explicit cast to immutable ref needed because of macro weirdness
            kernel(&mut r, &mut w, p);
        }

        let mut k = 0;
        while k < PAIRS {
            let x = unchecked_operation(_mm256_load_pd(w.as_mut_ptr().offset(k as isize)));
            let y = std::arch::x86_64::_mm256_mul_pd(x, x);
            let z = std::arch::x86_64::_mm256_mul_pd(x, rt);
            let x = std::arch::x86_64::_mm256_mul_pd(y, z);
            std::arch::x86_64::_mm256_store_pd(unchecked_operation(w.as_mut_ptr().offset(k as isize)), x);
            k += 4;
        }

        let mut k: usize = 0;
        let mut i = 1;
        while i < N {
            let mut j = 0;
            while j < i {
                let t = std::arch::x86_64::_mm256_set1_pd((&w)[k]);
                let t = std::arch::x86_64::_mm256_mul_pd((&r)[k], t);
                let x = std::arch::x86_64::_mm256_mul_pd(t, (&rm)[j]);
                let y = std::arch::x86_64::_mm256_mul_pd(t, (&rm)[i]);

                (*v)[i] = std::arch::x86_64::_mm256_sub_pd((&*v)[i], x);
                (*v)[j] = std::arch::x86_64::_mm256_add_pd((&*v)[j], y);
                k = k + 1;
                j += 1;
            }
            i += 1;
        }

        let mut i = 0;
        while i < N {
            let t = std::arch::x86_64::_mm256_mul_pd((&*v)[i], rt);
            (*p)[i] = std::arch::x86_64::_mm256_add_pd((&*p)[i], t);
            i += 1;

        }
        _s += 1;
    }
}

fn main() {
    let start_time = std::time::SystemTime::now();

    let n = std::env::args_os()
        .nth(1)
        .and_then(|s| s.into_string().ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or(1000);

    unsafe {
        let mut m: st::Secret<[f64; N], lat::Label_A> = st::Secret::new(MaybeUninit::uninit().assume_init());
        let mut p: st::Secret<[__m256d; N], lat::Label_A> = st::Secret::new(MaybeUninit::uninit().assume_init());
        let mut v: st::Secret<[__m256d; N], lat::Label_A> = st::Secret::new(MaybeUninit::uninit().assume_init());

        secret_structs::secret_block!(
            lat::Label_A {
                // sun
                let m = unwrap_secret_mut_ref(&mut m);
                (&mut *m)[0] = SOLAR_MASS;
                let p = unwrap_secret_mut_ref(&mut p);
                (&mut *p)[0] = std::arch::x86_64::_mm256_set1_pd(0.0);
                let v = unwrap_secret_mut_ref(&mut v);
                (&mut *v)[0] = std::arch::x86_64::_mm256_set1_pd(0.0);

                // jupiter
                (&mut *m)[1] = 9.54791938424326609e-04 * SOLAR_MASS;
                (&mut *p)[1] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    4.84143144246472090e+00,
                    -1.16032004402742839e+00,
                    -1.03622044471123109e-01,
                );
                (&mut *v)[1] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    1.66007664274403694e-03 * DAYS_PER_YEAR,
                    7.69901118419740425e-03 * DAYS_PER_YEAR,
                    -6.90460016972063023e-05 * DAYS_PER_YEAR,
                );

                // saturn
                (&mut *m)[2] = 2.85885980666130812e-04 * SOLAR_MASS;
                (&mut *p)[2] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    8.34336671824457987e+00,
                    4.12479856412430479e+00,
                    -4.03523417114321381e-01,
                );
                (&mut *v)[2] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    -2.76742510726862411e-03 * DAYS_PER_YEAR,
                    4.99852801234917238e-03 * DAYS_PER_YEAR,
                    2.30417297573763929e-05 * DAYS_PER_YEAR,
                );

                // uranus
                (&mut *m)[3] = 4.36624404335156298e-05 * SOLAR_MASS;
                (&mut *p)[3] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    1.28943695621391310e+01,
                    -1.51111514016986312e+01,
                    -2.23307578892655734e-01,
                );
                (&mut *v)[3] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    2.96460137564761618e-03 * DAYS_PER_YEAR,
                    2.37847173959480950e-03 * DAYS_PER_YEAR,
                    -2.96589568540237556e-05 * DAYS_PER_YEAR,
                );

                // neptune
                (&mut *m)[4] = 5.15138902046611451e-05 * SOLAR_MASS;
                (&mut *p)[4] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    1.53796971148509165e+01,
                    -2.59193146099879641e+01,
                    1.79258772950371181e-01,
                );
                (&mut *v)[4] = std::arch::x86_64::_mm256_setr_pd(
                    0.0,
                    2.68067772490389322e-03 * DAYS_PER_YEAR,
                    1.62824170038242295e-03 * DAYS_PER_YEAR,
                    -9.51592254519715870e-05 * DAYS_PER_YEAR,
                );

                // offset momentum
                let mut o = std::arch::x86_64::_mm256_set1_pd(0.0);
                let mut i = 0;
                while i < N {
                    let t = std::arch::x86_64::_mm256_mul_pd(std::arch::x86_64::_mm256_set1_pd((&*m)[i]), (&*v)[i]);
                    o = std::arch::x86_64::_mm256_add_pd(o, t);
                    i += 1;
                }

                v[0] = std::arch::x86_64::_mm256_mul_pd(o, std::arch::x86_64::_mm256_set1_pd(-1.0 / SOLAR_MASS));
            }
        );

        let energy_result: st::Secret<f64, lat::Label_A> = secret_structs::secret_block!(
            lat::Label_A {
                wrap_secret(energy(unwrap_secret_ref(&m), unwrap_secret_ref(&p), unwrap_secret_ref(&v)))
            }
        );
        println!("{:.9}", energy_result.declassify().get_value_consume());

        secret_structs::secret_block!(
            lat::Label_A {
                let m = unwrap_secret_ref(&m);
                let p = unwrap_secret_mut_ref(&mut p);
                let v = unwrap_secret_mut_ref(&mut v);
                advance(n, 0.01, m, p, v);
            }
        );

        let energy_result: st::Secret<f64, lat::Label_A> = secret_structs::secret_block!(
            lat::Label_A {
                wrap_secret(energy(unwrap_secret_ref(&m), unwrap_secret_ref(&p), unwrap_secret_ref(&v)))
            }
        );
        println!("{:.9}", energy_result.declassify().get_value_consume());
    }

    let end_time = std::time::SystemTime::now();
    eprintln!("{:?}", end_time.duration_since(start_time).unwrap());
}
