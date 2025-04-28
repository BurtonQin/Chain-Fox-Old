extern crate secret_macros;
extern crate secret_structs;

use secret_macros::{side_effect_free_attr};
use secret_structs::lattice as lat;
use secret_structs::secret as st;

pub fn main() {
  let t: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 2)) });
  let result: st::Secret::<i32, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
    let q: &(i32, i32) = unwrap_secret_ref(&t);
    let mut z = 42;
    z *= q.0;
    wrap_secret(z)
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );
}
