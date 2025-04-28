#![feature(fn_traits, unboxed_closures)]
extern crate secret_macros;
extern crate secret_structs;

use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

struct MyType {}

impl std::ops::Drop for MyType {
  fn drop(&mut self) {
    println!("Is 42!");
  }
}

pub fn main() {
  let t: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 84)) });
  let result: st::Secret::<i32, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
    let q: &(i32, i32) = unwrap_secret_ref(&t);
    if q.0 == 42 {
      let _: MyType = MyType{};
    }

    wrap_secret(q.0 + q.1)
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );
}
