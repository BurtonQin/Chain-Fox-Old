// The Computer Language Benchmarks Game
// https://salsa.debian.org/benchmarksgame-team/benchmarksgame/
//
// contributed by the Rust Project Developers
// contributed by TeXitoi
// contributed by Alisdair Owens
// contributed by Ryohei Machida

extern crate core;
extern crate num_cpus;
extern crate spin;

use spin::Mutex;
use std::cmp;
use std::io::{self, ErrorKind, Write};
use std::sync::Arc;
use std::thread;

const LINE_LENGTH: usize = 60;
const IM: u32 = 139968;
const LINES: usize = 1024;
const BLKLEN: usize = LINE_LENGTH * LINES;

#[repr(align(32))]
#[derive(Clone)]
struct Aligned<T>(T);

#[derive(Clone)]
struct WeightedRandom<T> {
    cumprob: Aligned<[u32; 16]>,
    elements: [T; 16],
}

impl<T: Copy + Default> WeightedRandom<T> {
    fn from_slice(mapping: &[(T, f32)]) -> Self {
        assert!(0 < mapping.len());
        assert!(mapping.len() <= 16);
        let mut elements = [T::default(); 16];
        let mut cumprob = Aligned([i32::MAX as u32; 16]);
        let mut acc = 0.;

        for (i, map) in mapping.iter().enumerate() {
            elements[i] = map.0;
            acc += map.1;
            cumprob.0[i] = (acc * IM as f32).floor() as u32;
        }

        Self { elements, cumprob }
    }

    #[cfg(target_feature = "sse2")]
    fn gen_from_u32(&self, prob: u32) -> T {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        // count elements in cumprob which satisfy `cumprob[i] < prob`
        unsafe {
            let needle = _mm_set1_epi32(prob as i32);
            let ptr = self.cumprob.0.as_ptr();

            let vcp1 = _mm_load_si128(ptr as _);
            let vcp2 = _mm_load_si128(ptr.add(4) as _);
            let vcp3 = _mm_load_si128(ptr.add(8) as _);
            let vcp4 = _mm_load_si128(ptr.add(12) as _);

            let mut count = _mm_setzero_si128();
            count = _mm_sub_epi32(count, _mm_cmplt_epi32(vcp1, needle));
            count = _mm_sub_epi32(count, _mm_cmplt_epi32(vcp2, needle));
            count = _mm_sub_epi32(count, _mm_cmplt_epi32(vcp3, needle));
            count = _mm_sub_epi32(count, _mm_cmplt_epi32(vcp4, needle));

            let idx = _mm_extract_epi32(count, 0)
                + _mm_extract_epi32(count, 1)
                + _mm_extract_epi32(count, 2)
                + _mm_extract_epi32(count, 3);
            *self.elements.get_unchecked(idx as usize)
        }
    }

    #[cfg(not(target_feature = "sse2"))]
    fn gen_from_u32(&self, prob: u32) -> T {
        let mut cnt = 0;

        for i in 0..16 {
            if self.cumprob.0[i] < prob {
                cnt += 1;
            }
        }

        self.elements[cnt]
    }
}

struct MyRandom {
    seed: u32,
    count: usize,
    thread_count: u16,
    next_thread_id: u16,
}

impl MyRandom {
    fn new(count: usize, thread_count: u16) -> MyRandom {
        MyRandom {
            seed: 42,
            count,
            thread_count,
            next_thread_id: 0,
        }
    }

    fn reset(&mut self, count: usize) {
        self.next_thread_id = 0;
        self.count = count;
    }

    // performance bottleneck
    fn gen(&mut self, buf: &mut [u32], cur_thread: u16) -> Result<usize, ()> {
        if self.next_thread_id != cur_thread {
            return Err(());
        }
        self.next_thread_id = (self.next_thread_id + 1) % self.thread_count;

        let to_gen = cmp::min(buf.len(), self.count);
        for i in 0..to_gen {
            self.seed = (self.seed * 3877 + 29573) % IM;
            buf[i] = self.seed;
        }
        self.count -= to_gen;
        Ok(to_gen)
    }
}

struct MyStdOut {
    thread_count: u16,
    next_thread_id: u16,
    stdout: io::Stdout,
}

impl MyStdOut {
    fn new(thread_count: u16) -> MyStdOut {
        MyStdOut {
            thread_count,
            next_thread_id: 0,
            stdout: io::stdout(),
        }
    }

    fn write(&mut self, data: &[u8], cur_thread: u16) -> io::Result<()> {
        if self.next_thread_id != cur_thread {
            return Err(io::Error::new(ErrorKind::Other, ""));
        }
        self.next_thread_id = (self.next_thread_id + 1) % self.thread_count;
        self.stdout.write_all(data)
    }
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

fn fasta_repeat(seq: &[u8], n: usize) -> io::Result<()> {
    let num_lines_per_buf = seq.len() / gcd(seq.len(), LINE_LENGTH);
    let buf_size = num_lines_per_buf * (LINE_LENGTH + 1);
    let mut buf = vec![0u8; buf_size];
    let mut n2 = n + n / LINE_LENGTH;

    // fill buf
    let mut it = seq.iter().copied().cycle();
    for i in 0..num_lines_per_buf {
        for j in 0..LINE_LENGTH {
            buf[i * (LINE_LENGTH + 1) + j] = it.next().unwrap();
        }
        buf[i * (LINE_LENGTH + 1) + LINE_LENGTH] = b'\n';
    }

    // write to stdout
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    while n2 >= buf_size {
        stdout.write_all(buf.as_slice())?;
        n2 -= buf_size;
    }

    // trailing line feed
    if n % LINE_LENGTH != 0 {
        buf[n2] = b'\n';
        n2 += 1;
    }

    stdout.write_all(&buf[..n2])?;
    Ok(())
}

fn fasta_random(
    thread_id: u16,
    rng: Arc<Mutex<MyRandom>>,
    writer: Arc<Mutex<MyStdOut>>,
    wr: WeightedRandom<u8>,
) {
    let mut rng_buf = [0u32; BLKLEN];
    let mut out_buf = [0u8; BLKLEN + LINES];
    loop {
        let count = loop {
            if let Ok(x) = rng.lock().gen(&mut rng_buf, thread_id) {
                break x;
            }
        };

        if count == 0 {
            break;
        }

        let rng_buf = &rng_buf[..count];

        let mut line_count = 0;
        for begin in (0..rng_buf.len()).step_by(LINE_LENGTH) {
            let end = cmp::min(begin + LINE_LENGTH, rng_buf.len());

            for j in begin..end {
                let rn = rng_buf[j];
                out_buf[j + line_count] = wr.gen_from_u32(rn);
            }

            out_buf[end + line_count] = b'\n';
            line_count += 1;
        }

        while let Err(_) = writer
            .lock()
            .write(&out_buf[..(rng_buf.len() + line_count)], thread_id)
        {}
    }
}

fn fasta_random_par(
    rng: Arc<Mutex<MyRandom>>,
    wr: WeightedRandom<u8>,
    num_threads: u16,
) -> io::Result<()> {
    let stdout = Arc::new(Mutex::new(MyStdOut::new(num_threads)));
    let mut threads = Vec::new();
    for thread in 0..num_threads {
        let wr = wr.clone();
        let rng_clone = rng.clone();
        let stdout_clone = stdout.clone();
        threads.push(thread::spawn(move || {
            fasta_random(thread, rng_clone, stdout_clone, wr);
        }));
    }
    for thread_guard in threads {
        thread_guard.join().unwrap();
    }
    Ok(())
}

fn main() {
    let n = std::env::args_os()
        .nth(1)
        .and_then(|s| s.into_string().ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or(1000);
    let num_threads: u16 = cmp::min(num_cpus::get() as u16, 2);

    // Homo sapiens alu
    {
        let alu: [u8; 287] = *b"GGCCGGGCGCGGTGGCTCACGCCTGTAATCCCAGCACTTT\
                                GGGAGGCCGAGGCGGGCGGATCACCTGAGGTCAGGAGTTC\
                                GAGACCAGCCTGGCCAACATGGTGAAACCCCGTCTCTACT\
                                AAAAATACAAAAATTAGCCGGGCGTGGTGGCGCGCGCCTG\
                                TAATCCCAGCTACTCGGGAGGCTGAGGCAGGAGAATCGCT\
                                TGAACCCGGGAGGCGGAGGTTGCAGTGAGCCGAGATCGCG\
                                CCACTGCACTCCAGCCTGGGCGACAGAGCGAGACTCCGTC\
                                TCAAAAA";

        println!(">ONE Homo sapiens alu");
        fasta_repeat(&alu, n * 2).unwrap();
    }

    let rng = Arc::new(Mutex::new(MyRandom::new(n * 3, num_threads)));

    // IUB ambiguity codes
    {
        let iub = WeightedRandom::from_slice(&[
            (b'a', 0.27),
            (b'c', 0.12),
            (b'g', 0.12),
            (b't', 0.27),
            (b'B', 0.02),
            (b'D', 0.02),
            (b'H', 0.02),
            (b'K', 0.02),
            (b'M', 0.02),
            (b'N', 0.02),
            (b'R', 0.02),
            (b'S', 0.02),
            (b'V', 0.02),
            (b'W', 0.02),
            (b'Y', 0.02),
        ]);

        println!(">TWO IUB ambiguity codes");
        fasta_random_par(rng.clone(), iub, num_threads).unwrap();
    }

    rng.lock().reset(n * 5);

    // Homo sapience frequency
    {
        let homosapiens = WeightedRandom::from_slice(&[
            (b'a', 0.3029549426680),
            (b'c', 0.1979883004921),
            (b'g', 0.1975473066391),
            (b't', 0.3015094502008),
        ]);

        println!(">THREE Homo sapiens frequency");
        fasta_random_par(rng, homosapiens, num_threads).unwrap();
    }
}
