// The Computer Language Benchmarks Game
// https://salsa.debian.org/benchmarksgame-team/benchmarksgame/
//
// contributed by Tom Kaitchuck

extern crate rayon;
extern crate regex;

use std::io::{self, Read};
use rayon::prelude::*;
use std::mem;
use secret_macros::InvisibleSideEffectFreeDerive;
use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

struct Regex {
    string: &'static str,
    regex: ::regex::bytes::Regex,
}
unsafe impl st::InvisibleSideEffectFree for Regex {}

impl Regex {
    fn new(string: &'static str) -> Regex {
        Regex {
            string: string,
            regex: ::regex::bytes::Regex::new(string).unwrap(),
        }
    }

    fn replace_all<'t>(&self, text: &'t [u8], rep: &[u8], out: &mut Vec<u8>) {
        let mut last_match = 0;
        for m in self.regex.find_iter(text) {
            out.extend_from_slice(&text[last_match..m.start()]);
            out.extend_from_slice(&rep);
            last_match = m.end();
        }
        out.extend_from_slice(&text[last_match..]);
    }
}

#[side_effect_free_attr]
fn new_regex(string: &'static str) -> Regex {
    Regex { string: string, regex: unchecked_operation(regex::bytes::Regex::new(string).unwrap()) }
}

#[side_effect_free_attr]
fn count_reverse_complements(sequence : &Vec<u8>) -> Vec<String> {
    // Search for occurrences of the following patterns:
    let mut variants: std::vec::Vec<Regex> = std::vec::Vec::new();
    std::vec::Vec::push(&mut variants, new_regex("agggtaaa|tttaccct"));
    std::vec::Vec::push(&mut variants, new_regex("[cgt]gggtaaa|tttaccc[acg]"));
    std::vec::Vec::push(&mut variants, new_regex("a[act]ggtaaa|tttacc[agt]t"));
    std::vec::Vec::push(&mut variants, new_regex("ag[act]gtaaa|tttac[agt]ct"));
    std::vec::Vec::push(&mut variants, new_regex("agg[act]taaa|ttta[agt]cct"));
    std::vec::Vec::push(&mut variants, new_regex("aggg[acg]aaa|ttt[cgt]ccct"));
    std::vec::Vec::push(&mut variants, new_regex("agggt[cgt]aa|tt[acg]accct"));
    std::vec::Vec::push(&mut variants, new_regex("agggta[cgt]a|t[acg]taccct"));
    std::vec::Vec::push(&mut variants, new_regex("agggtaa[cgt]|[acg]ttaccct"));
    unchecked_operation(
        variants.par_iter().map(|ref variant| {
            format!("{} {}",
                    variant.string,
                    variant.regex.find_iter(sequence).count()) }).collect()
    )
}

#[side_effect_free_attr]
fn find_replaced_sequence_length(sequence: Vec<u8>, scratch_buff: Vec<u8>) -> usize {
    // Replace the following patterns, one at a time:
    let mut substs: std::vec::Vec<(Regex, &[u8])> = std::vec::Vec::new();
    std::vec::Vec::push(&mut substs, (new_regex("tHa[Nt]"), &b"<4>"[..]));
    std::vec::Vec::push(&mut substs, (new_regex("aND|caN|Ha[DS]|WaS"), &b"<3>"[..]));
    std::vec::Vec::push(&mut substs, (new_regex("a[NSt]|BY"), &b"<2>"[..]));
    std::vec::Vec::push(&mut substs, (new_regex("<[^>]*>"), &b"|"[..]));
    std::vec::Vec::push(&mut substs, (new_regex("\\|[^|][^|]*\\|"),  &b"-"[..]));

    let mut current = sequence;
    let mut next = scratch_buff;
    // Perform the replacements in sequence:
    for (re, replacement) in substs {
        unchecked_operation(re.replace_all(&current, replacement, &mut next));
        unchecked_operation(mem::swap(&mut current, &mut next));
        std::vec::Vec::clear(&mut next);
    }
    std::vec::Vec::len(&current)
}

fn main() {
    let mut input = Vec::with_capacity(51 * (1 << 20));
    io::stdin().read_to_end(&mut input).unwrap();
    let input_len = input.len();
    let mut sequence: Vec<u8> = Vec::with_capacity(input.len());
    Regex::new(">[^\n]*\n|\n").replace_all(&input, &b""[..], &mut sequence);
    let sequence_len = sequence.len();
    input.clear();
    let (result, counts) = rayon::join(
        || secret_structs::secret_block!(lat::Label_A { wrap_secret(find_replaced_sequence_length(std::vec::Vec::clone(&sequence), input)) }).declassify().get_value_consume(),
        || secret_structs::secret_block!(lat::Label_A { wrap_secret(count_reverse_complements(&sequence)) }).declassify().get_value_consume(),
    );
    for variant in counts {
	    println!("{}", variant)
    }
    println!("\n{}\n{}\n{:?}", input_len, sequence_len, result);
}
