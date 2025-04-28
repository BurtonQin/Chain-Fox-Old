#![feature(fn_traits, step_trait, unboxed_closures)]
extern crate secret_macros;
extern crate secret_structs;

use secret_structs::lattice as lat;
use secret_structs::secret as st;

#[derive(Clone, PartialEq, PartialOrd)]
struct MyType {
  x: i32,
}
unsafe impl st::InvisibleSideEffectFree for MyType {}

impl std::ops::RangeBounds<i32> for MyType {
  fn start_bound(&self) -> std::ops::Bound<&i32> {
    println!("I see {}", self.x);
    std::ops::Bound::Included(&self.x)
  }

  fn end_bound(&self) -> std::ops::Bound<&i32> {
    println!("I see {}", self.x);
    std::ops::Bound::Included(&self.x)
  }

  fn contains<U>(&self, item: &U) -> bool
    where U: PartialOrd<i32> + ?Sized {
      false
  }
}

impl std::iter::Step for MyType {
  fn steps_between(start: &Self, end: &Self) -> Option<usize> {
    println!("I am: {}", start.x);
    Some((end.x as usize) - (start.x as usize))
  }

  fn forward_checked(start: Self, count: usize) -> Option<Self> {
    println!("I am: {}", start.x);
    Some(MyType{x: ((start.x as usize) + count) as i32})
  }

  fn backward_checked(start: Self, count: usize) -> Option<Self> {
    println!("I am: {}", start.x);
    if (start.x as usize) > count {
      Some(MyType{x: ((start.x as usize) - count) as i32})
    } else {
      None
    }
  }
}

pub fn main() {
  let t: st::Secret<(i32, i32), lat::Label_A> = secret_structs::secret_block!(lat::Label_A { wrap_secret((42, 84)) });
  let result: st::Secret::<i32, lat::Label_A> = secret_structs::secret_block!(lat::Label_A {
    let q: &(i32, i32) = unwrap_secret_ref(&t);
    let s = MyType{x: q.0};
    let e = MyType{x: q.1};
    for _ in 0..4 {
      // Do nothing.
    }
    wrap_secret(q.0 + q.1)
  });
  println!(
    "Result: {}",
    result.declassify().get_value_consume(),
  );
}
