extern crate secret_macros;
extern crate secret_structs;

use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

#[side_effect_free_attr]
pub fn repeat_secrets(a: i32, b: i32) -> i32 {
  let x = [1; 16];
  42
}

pub fn main() {
  println!("This is an important program.");
  let int_tuple = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 84)) });
  let result: st::Secret::<i32, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
      let x: i32 = unwrap_secret_ref(&int_tuple).0;
      wrap_secret(x)
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );

  let t: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 84)) });
  let result: st::Secret::<i32, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
    let q: &(i32, i32) = unwrap_secret_ref(&t);
    wrap_secret(repeat_secrets(q.0, q.1))
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );
}
