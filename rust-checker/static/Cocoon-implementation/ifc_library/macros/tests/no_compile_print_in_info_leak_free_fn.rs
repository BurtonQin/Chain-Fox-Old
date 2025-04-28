extern crate secret_macros;
extern crate secret_structs;

#[side_effect_free_attr]
pub fn do_nothing() {
  println!("Leaking a secret...");
}

pub fn main() {
  println!("Hello world!");
}
