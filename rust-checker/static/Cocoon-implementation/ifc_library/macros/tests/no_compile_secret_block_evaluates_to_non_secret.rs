extern crate secret_macros;
extern crate secret_structs;

use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

#[side_effect_free_attr]
pub fn subtract_secret(a: i32, b: i32) -> i32 {
  a - b
}

pub fn main() {
  let t: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 84)) });
  let result: i32 = secret_structs::secret_block!(lat::Label_A {
    let q: &(i32, i32) = unwrap_secret_ref(&t);
    subtract_secret(*q.0, *q.1)
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );
}
