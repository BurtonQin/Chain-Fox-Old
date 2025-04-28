use rand::Rng;

pub fn random(limit: usize) -> usize {
    rand::thread_rng().gen_range(0..limit)
}
