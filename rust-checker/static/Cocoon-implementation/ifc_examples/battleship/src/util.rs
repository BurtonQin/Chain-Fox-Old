use rand::Rng;
use secret_macros::side_effect_free_attr;

#[side_effect_free_attr]
pub fn random(limit: usize) -> usize {
    unchecked_operation(rand::thread_rng().gen_range(0..limit))
}
