#![feature(fn_traits, unboxed_closures)]
extern crate secret_macros;
extern crate secret_structs;

use secret_macros::side_effect_free_attr;
use secret_structs::lattice as lat;
use secret_structs::secret as st;

struct MyType {}

impl std::ops::FnOnce<()> for MyType {
  type Output = ();
  extern "rust-call" fn call_once(self, args: ()) -> Self::Output {
    ()
  }
}

impl std::ops::FnMut<()> for MyType {
  extern "rust-call" fn call_mut(&mut self, args: ()) -> Self::Output {
    println!("We are leaking!");
    ()
  }
}

pub fn main() {
  let t: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 84)) });
  let result: st::Secret::<i32, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
    let q: &(i32, i32) = unwrap_secret_ref(&t);
    let m: MyType = MyType{};
    m();
    wrap_secret(q.0 + q.1)
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );
}
