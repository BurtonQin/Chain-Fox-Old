// The Computer Language Benchmarks Game
// https://salsa.debian.org/benchmarksgame-team/benchmarksgame/
//
// contributed by Tom Kaitchuck

// Based on k-nucleotide Rust #7
// Switched to used Hashbrown and removed custom hash code.
// Removed rayon and use threads directly
// Copied the read_input function from k-nucleotide Rust #4
#![feature(negative_impls)]
use secret_macros::side_effect_free_attr;
use secret_macros::InvisibleSideEffectFreeDerive;
use secret_structs::lattice as lat;
use secret_structs::secret as st;
use secret_structs::secret::InvisibleSideEffectFree;

extern crate hashbrown;

use std::io::BufRead;
use std::sync::Arc;
use hashbrown::HashMap;
use std::thread;

struct Map {v: HashMap<Code, u32>}
unsafe impl st::InvisibleSideEffectFree for Map {}

impl Default for Map {
    fn default() -> Self {
        Self { v: Default::default() }
    }
}

#[derive(Hash, PartialEq, PartialOrd, Ord, Eq, Clone, Copy, InvisibleSideEffectFreeDerive)]
struct Code{ v: u64}

#[side_effect_free_attr]
fn make_mask(frame: usize) -> u64 {
    unchecked_operation((1u64 << (2 * frame)) - 1)
}

#[side_effect_free_attr]
fn code_push(code: &mut Code, c: u8, mask: u64) {
    unchecked_operation(code.v <<= 2);
    unchecked_operation(code.v |= c as u64);
    unchecked_operation(code.v &= mask);
}

impl Code {
    fn push(&mut self, c: u8, mask: u64) {
        self.v <<= 2;
        self.v |= c as u64;
        self.v &= mask;
    }
    fn from_str(s: &str) -> Code {
        let mask = Code::make_mask(s.len());
        let mut res = Code{v: 0};
        for c in s.as_bytes() {
            res.push(Code::encode_byte(*c), mask);
        }
        res
    }
    fn to_string(&self, frame: usize) -> String {
        let mut res = vec![];
        let mut code = self.v;
        for _ in 0..frame {
            let c = match code as u8 & 0b11 {
                c if c == Code::encode_byte(b'A') => b'A',
                c if c == Code::encode_byte(b'T') => b'T',
                c if c == Code::encode_byte(b'G') => b'G',
                c if c == Code::encode_byte(b'C') => b'C',
                _ => unreachable!(),
            };
            res.push(c);
            code >>= 2;
        }
        res.reverse();
        String::from_utf8(res).unwrap()
    }
    fn make_mask(frame: usize) -> u64 {
        (1u64 << (2 * frame)) - 1
    }
    #[inline(always)]
    fn encode_byte(c: u8) -> u8 {
        (c & 0b110) >> 1
    }
}

struct Iter<'a> {
    iter: std::slice::Iter<'a, u8>,
    code: Code,
    mask: u64,
}
unsafe impl<'a> InvisibleSideEffectFree for Iter<'a> {}

#[side_effect_free_attr]
fn new_iter(input: &[u8], frame: usize) -> Iter {
    let mut iter = <[_]>::iter(input);
    let mut code: Code = Code{v: 0};
    let mask = make_mask(frame);
    for c in std::iter::Iterator::take(std::iter::Iterator::by_ref(&mut iter), frame-1) {
        code_push(&mut code, *c, mask);
    }
    Iter {
        iter: iter,
        code: code,
        mask: mask,
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Code;
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|&c| {
            self.code.push(c, self.mask);
            self.code
        })
    }
}

#[side_effect_free_attr]
fn gen_freq(input: &[u8], frame: usize) -> Map {
    let mut freq = Map{v: unchecked_operation(HashMap::default())};
    for code in new_iter(input, frame) {
        unchecked_operation(*freq.v.entry(code).or_insert(0) += 1);
    }
    freq
}

#[derive(Clone, Copy)]
struct Freq(usize);
#[derive(Clone, Copy, Default)]
struct Occ { v: &'static str}
unsafe impl st::InvisibleSideEffectFree for Occ {}
unsafe impl st::Immutable for Occ {}


impl Freq {
    fn print(&self, freq: &Map) {
        let mut v: Vec<_> = freq.v.iter()
                                .map(|(&code, &count)| (count, code))
                                .collect();
        v.sort();
        let total = v.iter().map(|&(count, _)| count).sum::<u32>() as f32;
        for &(count, key) in v.iter().rev() {
            println!("{} {:.3}", 
            key.to_string(self.0), (count as f32 * 100.) / total);
        }
        println!("");
    }
}
impl Occ {
    fn print(&self, freq: &Map) {
        let count = if freq.v.contains_key(&Code::from_str(self.v)) {
            freq.v[&Code::from_str(self.v)]
        } else {
            0
        };
        println!("{}\t{}", count, self.v);
    }
}

fn read_input() -> Vec<u8> {
    let stdin = std::io::stdin();
    let mut r = stdin.lock();
    let key = b">THREE";
    let mut res = Vec::with_capacity(65536);
    let mut line = Vec::with_capacity(64);

    loop {
        match r.read_until(b'\n', &mut line) {
            Ok(b) if b > 0 => if line.starts_with(key) { break },
            _ => break,
        }
        line.clear();
    }

    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(b) if b > 0 => 
                res.extend(line[..line.len()-1].iter()
                   .cloned().map(Code::encode_byte)),
            _ => break,
        }
    }
    res
}

fn main() {
    let occs = vec![
        Occ{v: "GGTATTTTAATTTATAGT"},
        Occ{v: "GGTATTTTAATT"},
        Occ{v: "GGTATT"},
        Occ{v: "GGTA"},
        Occ{v: "GGT"},
    ];
    let input = Arc::new(read_input());

    // In reverse to spawn big tasks first
    let results: Vec<_> = occs.into_iter().map(|item| {
        let input = input.clone();
        thread::spawn(
            move || {
                let input_slice: &[u8] = &input;
                secret_structs::secret_block!(lat::Label_A { wrap_secret((item, gen_freq(&input_slice, core::primitive::str::len(&item.v)))) }).declassify().get_value_consume()
            }
        )}).collect();

    {let input_slice: &[u8] = &input;
    Freq(1).print(&secret_structs::secret_block!(lat::Label_A {wrap_secret(gen_freq(input_slice, 1))}).declassify().get_value_consume());
    Freq(2).print(&secret_structs::secret_block!(lat::Label_A {wrap_secret(gen_freq(input_slice, 1))}).declassify().get_value_consume());}

    for t in results.into_iter().rev() {
        let (item, freq) = t.join().unwrap();
        item.print(&freq);
    }
}
