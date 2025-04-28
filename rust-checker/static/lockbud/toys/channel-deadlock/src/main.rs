// A bug that will be checked today
use std::sync::mpsc::channel; 
use std::thread;

fn main() {
    let (tx, rx) = channel();
    let (tx2, rx2) = channel();
    let th = thread::spawn(move || {
        let _ = rx2.recv().unwrap();  // 1. wait for tx2.send
        let _ = tx.send(1).unwrap();  // 2. tx.send
    });
    let _ = tx2.send(2).unwrap();     // 4. tx2.send
    let _ = rx.recv().unwrap();       // 3. wait for tx.send
    th.join().unwrap();
}
