use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

struct CountingResource {
    counter: AtomicUsize,  
    name: String,          
    data: usize,          
}

impl CountingResource {
    fn new(name: &str, data: usize) -> Self {
        CountingResource {
            counter: AtomicUsize::new(0),
            name: name.to_string(),
            data,
        }
    }

    fn increment(&self) -> usize {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }
}

fn main() {
    let resource = Arc::new(CountingResource::new("Resource", 42));

    let handles: Vec<_> = (0..10).map(|_| {
        let res_clone = Arc::clone(&resource);
        thread::spawn(move || {
            for _ in 0..10 {
                res_clone.increment();
            }
        })
    }).collect();

    for handle in handles {
        handle.join().unwrap();
    }

    println!("Final count: {}", resource.counter.load(Ordering::Relaxed));
    println!("Resource name: {}", resource.name);
    println!("Resource data: {}", resource.data);
}
