// The Computer Language Benchmarks Game
// http://benchmarksgame.alioth.debian.org/
//
// contributed by the Rust Project Developers
// contributed by TeXitoi
// contributed by Cristi Cobzarenco
// contributed by Matt Brubeck
// modified by Tom Kaitchuck
// modified by Volodymyr M. Lisivka
// modified by Ryohei Machida

extern crate bumpalo;
extern crate rayon;

use bumpalo::Bump;
use rayon::prelude::*;

use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

struct WrappedBump { v: Bump }
unsafe impl st::InvisibleSideEffectFree for WrappedBump {}

impl WrappedBump {
    fn alloc<T>(&self, obj: T) -> &mut T {
        self.v.alloc(obj)
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
struct Tree<'a> {
    left: Option<&'a Tree<'a>>,
    right: Option<&'a Tree<'a>>,
}
// Needed because InvisibleSideEffectFreeDerive cannot handle lifetime parameters.
unsafe impl<'a> st::InvisibleSideEffectFree for Tree<'a> {}
//unsafe impl<'a> st::SecretValueSafe for &Tree<'a> {} // not needed

// Needed for Secret<&Tree<'a>,L>:
impl<'a> Default for &Tree<'a> {
    fn default() -> Self {
        &DEFAULT_TREE
    }
}
const DEFAULT_TREE: Tree = Tree {left: Option::None, right: Option::None};

#[side_effect_free_attr]
fn item_check(tree: &Tree) -> i32 {
    match tree.left {
        Some(left) => {
            match tree.right {
                Some(right) => 1 + item_check(right) + item_check(left),
                None => 1,
            }
        },
        None => 1,
    }
}

#[side_effect_free_attr]
fn bottom_up_tree<'r>(arena: &'r WrappedBump, depth: i32) -> &'r Tree<'r> {
    // Since we can't return an &mut from an side_effect_free_attr function, this must be unchecked.
    // Note that we still need the WrappedBump since Bump is not InvisibleSideEffectFree.
    let tree = unchecked_operation(WrappedBump::alloc(arena, Tree { left: None, right: None }));
    if depth > 0 {
        tree.right = std::option::Option::Some(bottom_up_tree(arena, depth - 1));
        tree.left = std::option::Option::Some(bottom_up_tree(arena, depth - 1));
    }
    tree as &_ // Explicit cast to immutable ref needed because of macro weirdness
}

/*
    I left this not side_effect_free_attr due to the heavy use of Rayon
    and the format! macro. Internally, it does its work in a side-effect-free
    block, so it's still a valuable benchmark.
*/
fn inner(depth: i32, iterations: i32) -> String {
    let chk: i32 = (0..iterations)
        .into_par_iter()
        .map(|_| {
            let arena = WrappedBump{v: Bump::new()};
            let a: i32 = secret_structs::secret_block!(lat::Label_A {
                let a = bottom_up_tree(&arena, depth);
                wrap_secret(item_check(a))
            }).declassify().get_value_consume();
            a
        })
        .sum();
    format!("{}\t trees of depth {}\t check: {}", iterations, depth, chk)
}

fn main() {
    let n = std::env::args().nth(1).and_then(|n| n.parse().ok()).unwrap_or(10);
    let min_depth = 4;
    let max_depth = if min_depth + 2 > n { min_depth + 2 } else { n };

    {
        let arena = WrappedBump { v: Bump::new() };
        let secret_result: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
            let depth = max_depth + 1;
            let tree = bottom_up_tree(&arena, depth);
            wrap_secret((depth, item_check(tree)))
        });

        let result = secret_result.declassify().get_value_consume();
        println!(
            "stretch tree of depth {}\t check: {}",
            result.0,
            result.1,
        );
    }

    let long_lived_arena = WrappedBump{v: Bump::new()};
    let long_lived_tree = secret_structs::secret_block!(
        lat::Label_A {
            wrap_secret(bottom_up_tree(&long_lived_arena, max_depth))
        }
    ).declassify().get_value_consume();

    let messages = (min_depth / 2..=max_depth / 2)
        .into_par_iter()
        .map(|half_depth| {
            let depth = half_depth * 2;
            let iterations = 1 << ((max_depth - depth + min_depth) as u32);
            let res = inner(depth, iterations);
            res
        })
        .collect::<Vec<_>>();

    for message in messages {
        println!("{}", message);
    }

    let check = secret_structs::secret_block!(lat::Label_A {
        wrap_secret(item_check(long_lived_tree))
    }).declassify().get_value_consume();

    println!(
        "long lived tree of depth {}\t check: {}",
        max_depth,
        check,
    );
}