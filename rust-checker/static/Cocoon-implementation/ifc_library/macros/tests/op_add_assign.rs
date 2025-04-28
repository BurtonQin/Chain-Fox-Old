extern crate secret_macros;
extern crate secret_structs;

use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

#[side_effect_free_attr]
pub fn add_secrets(a: i32, b: i32) -> i32 {
  a + b
}

pub fn main() {
  let t: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 84)) });
  let result: st::Secret::<i32, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
    let q: &(i32, i32) = unwrap_secret_ref(&t);
    let mut z = 2;
    z += 3;
    wrap_secret(add_secrets(q.0, z))
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );
}
