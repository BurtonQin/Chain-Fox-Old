#![feature(
    allocator_api,
    auto_traits,
    negative_impls,
    fn_traits,
    slice_index_methods,
    unboxed_closures,
    const_trait_impl
)]
use std::ops::Deref;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;

mod lattice;
mod secret;

use secret_structs::lattice as lat3;
use secret_structs::secret as st;

pub struct Example<T, L>
where
    T: st::SecretValueSafe,
{
    val: T,
    secret_val: st::Secret<T, L>,
}

pub struct MyDerefable<T> {
    pub x: T,
}
impl<T> Deref for MyDerefable<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        todo!()
    }
}

// Two (currently unused) examples of accessing mutable secrets:
pub fn inc<L, T>(x: &mut st::Secret<i32, L>, q: &MyDerefable<i32>) {
    let mut a = 5;
    let _b = &mut a;
    let z = Box::<i32>::n32(5);
    let _j = Box::new(_b);
    secret_structs::secret_block!(L {
        //**b = 2;
        //let z = *j;
        //let r = q;
        let y: i32 = *z;
        //let q2 = q;
        let y = unwrap_secret_mut_ref(x);
        *y = 1;
    });
}

pub fn sort<T: st::SecretValueSafe + Ord, L>(myvec: &mut st::Secret<Vec<T>, L>) {
    secret_structs::secret_block!(L {
        let x = unwrap_secret_mut_ref(myvec);
        <[T]>::sort(x);
    });
}

struct CustomDeref<T> {
    x: T,
}
impl<T> CustomDeref<T> {
    fn new(val: T) -> CustomDeref<T> {
        CustomDeref { x: val }
    }
}
impl<T> Deref for CustomDeref<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        println!("Leak"); //bad
        &self.x
    }
}

fn main() {
    /* deref_pure() stuff:
    let a = Box::new(Box::new(5i32));
    let b = a.deref_pure();
    println!("a.deref_pure(): {:?}", *b);
    let i = 5;
    let j = i.deref_pure();
    println!("i.deref_pure() = {:?}", *j);
    struct MyType {f: i32}
    let m = Box::new(MyType{f: 5});
    let x = m.deref_pure();
    println!("m.deref_pure().f = {:?}", x.f);
    struct MyDerefable {f: i32}
    impl Deref for MyDerefable {
        type Target = i32;
        fn deref(&self) -> &Self::Target {
            todo!()
        }
    }
    let bmd = Box::new(MyDerefable{f: 5});
    let z = bmd.deref_pure();
    println!("bmd.deref_pure() = {:?}", z.f);
    */
    /* i64s */
    println!("Secret i64s:");

    // define secrets
    let sec = st::Secret::<i64, lat3::ABC>::new(42);
    let med = st::Secret::<i64, lat3::AB>::new(25);
    let not_sec = st::Secret::<i64, lat3::None>::new(3);

    // Example with Display trait
    println!("Non-secret value: {}", not_sec);
    println!("Secret value: {}", sec);

    // Example with Debug trait
    println!("Debug trait for non-secret value: {:?}", not_sec);
    println!("Debug trait for secret value: {:?}", sec);

    // closure to perform binary operations
    let add_closure =
        secret_macros::secret_closure!(|op: (&i64, &i64)| -> i64 { (*op.0) + (*op.1) });

    let _unsafe_add_closure = |op: (&i64, &i64)| -> i64 { op.0 + op.1 };

    // add ABC secrecy to AB for result of ABC. Can't be printed unless declassified
    let x: st::Secret<i64, lat3::ABC> = st::apply_binary_ref(add_closure, &sec, &med);
    //println!("x = {}", x.get_value());
    println!("x = {}", x.declassify_ref());

    // results must have higher of two operands' secrecy levels. Otherwise won't compile
    // Cannot use add_closure more than once since move occurs
    // let y1 : st::Secret::<i64, lat3::AB> = st::apply_binary_ref(add_closure, &not_sec, &med);
    // let y2 : st::Secret::<i64, lat3::AB> = st::apply_binary_ref(add_closure, &not_sec, &med);
    // println!("y1 = {}", y1.declassify_ref());
    // println!("y2 = {}", y2.declassify_ref());

    // don't need to declassify non-secret values
    println!("p = {}", not_sec.get_value_ref());

    /* bools */
    println!("Secret bools:");

    // define secrets
    let sec_bool = st::Secret::<bool, lat3::ABC>::new(true);
    let _med_bool = st::Secret::<bool, lat3::A>::new(false);
    let not_sec_bool = st::Secret::<bool, lat3::None>::new(true);

    // define and closure
    let and_closure =
        secret_macros::secret_closure!(|op: (&bool, &bool)| -> bool { *op.0 && *op.1 });

    let xx: st::Secret<bool, lat3::ABC> =
        st::apply_binary_ref(and_closure, &sec_bool, &not_sec_bool);
    //println!("xx = {}", xx.get_value());
    println!("xx = {}", xx.declassify_ref());
    println!("not_sec_bool = {}", not_sec_bool.get_value_ref());
    println!();

    /* Strings */
    println!("Secret Strings:");
    // define secrets
    let _sec_string = st::Secret::<String, lat3::ABC>::new(String::from("Hello, world! "));
    let med_string = st::Secret::<String, lat3::A>::new(String::from("Goodbye, cruel world. "));
    let not_sec_string = st::Secret::<String, lat3::None>::new(String::from(
        "So long and thanks for all the fish. ",
    ));
    // Doesn't compile - maybe because push_str and to_string aren't safe
    //let push_closure = secret_macros::secret_closure!(|op: (&mut String, &mut String)| -> String {
    //    op.0.push_str(op.1);
    //    op.0.to_string()
    //});
    // Does not compile since we are pushing a top level secret onto a mid level secret
    // st::apply_binary(push_closure, med_string, sec_string);
    //med_string = st::apply_mut_binary_ref(push_closure, &mut med_string, &mut not_sec_string);
    println!("med_string = {}", med_string.declassify_ref());
    println!("not_sec_bool = {}", not_sec_string.get_value_ref());
    println!();

    /* Vectors */
    println!("Secret vectors:");
    let sec_vec = st::Secret::<Vec<i32>, lat3::ABC>::new(vec![1, 2, 3]);
    let med_vec = st::Secret::<Vec<i32>, lat3::AB>::new(vec![4, 5, 6]);
    let not_sec_vec = st::Secret::<Vec<i32>, lat3::None>::new(vec![7, 8, 9]);
    // Only mutable because we currently don't have an apply() which takes (&mut, &)
    let _secret_val = st::Secret::<i32, lat3::AB>::new(5);
    // Doesn't compile - maybe because push and to_vec aren't safe
    //let push_closure = secret_macros::secret_closure!(|op: (&mut Vec<i32>, &mut i32)| -> Vec<i32> {
    //    op.0.push(*op.1);
    //    op.0.to_vec()
    //});
    // Doesn't compile - cannot add more secret data to less secret data
    //not_sec_vec = st::apply_binary_ref(push_closure, &mut not_sec_vec, &secret_val);
    //med_vec = st::apply_mut_binary_ref(push_closure, &mut med_vec, &mut secret_val);
    println!("med_vec = {:?}", med_vec.declassify_ref());
    println!("not_sec_vec = {:?}", not_sec_vec.get_value_ref());
    println!("sec_vec = {:?}", sec_vec.declassify_ref());
    println!();

    /* Generic - structs */
    println!("Generic secrets (structs):");
    let struct1 = Example {
        val: 5,
        secret_val: st::Secret::<i64, lat3::ABC>::new(10),
    };
    let struct2 = Example {
        val: 2,
        secret_val: st::Secret::<i64, lat3::AB>::new(4),
    };
    let struct3 = Example {
        val: 1,
        secret_val: st::Secret::<i64, lat3::AB>::new(2),
    };
    let _sec_struct = st::Secret::<Example<i64, lat3::ABC>, lat3::ABC>::new(struct1);
    let med_struct = st::Secret::<Example<i64, lat3::AB>, lat3::AB>::new(struct2);
    let not_sec_struct = st::Secret::<Example<i64, lat3::AB>, lat3::None>::new(struct3);

    //println!("sec_struct = {:?}", sec_struct.get_value());                      // Doesn't compile
    let med_struct_declassified = med_struct.declassify_ref(); // declassify() takes ownership and secret version no longer exists
    println!("med_struct val = {:?}", med_struct_declassified.val);
    //println!("med struct secret val = {:?}", med_struct_declassified.get_value_ref().secret_val.get_value_ref());     // Doesn't compile
    println!(
        "med struct secret val = {:?}",
        med_struct_declassified.secret_val.declassify_ref()
    );
    println!("not_sec_struct = {:?}", not_sec_struct.get_value_ref().val);
    println!(
        "not_sec_struct secret val = {:?}",
        not_sec_struct.get_value_ref().secret_val.declassify_ref()
    );
    println!();

    /* Shared Pointers - No Mutex */
    //let my_arc = st::Secret::<Rc<i64>, lat3::AB>::new(Rc::<i64>::new(5));  // doesn't compile - fails SecretValueSafe
    println!("Rc leak example:");
    let public_rc1 = Rc::new(5);
    let mut private_rc2 = public_rc1.clone(); // Make one reference of public variable private
    *Rc::make_mut(&mut private_rc2) = 6; // Clones private_rc2 so this does not affect public_rc1
                                         //*Rc::get_mut(&mut private_rc2).unwrap() = 6;      // Returns None since there is another Rc pointing to same data
    println!("public Rc: {:?}", public_rc1); // No leak - private and public print different values
    println!("private Rc: {:?}", private_rc2);

    /* Shared Pointers - Mutex */
    let public_mutex1 = Arc::new(Mutex::new(1));
    let private_mutex1 = Arc::clone(&public_mutex1);
    let _ = thread::spawn(move || {
        let mut data = private_mutex1.lock().unwrap();
        *data += 1;
    })
    .join();
    println!("public Arc<Mutex>: {:?}", public_mutex1); // Expect it to have value 1 from line 145 but it shows 2 (from updating private_mutex)
                                                        // println!("private Arc<Mutex>: {:?}", private_mutex1);      // Doesn't compile beause the thread took ownership of private_mutex
    println!();

    // Doesn't work with just Mutex's (no Arc) either
    // let private_mutex = st::Secret::<Mutex<i64>, lat3::AB>::new(public_mutex.clone());    // Doesn't compile since Mutex uses UnsafeCell

    // let private_mutex_wrapped = st::Secret::<Arc<Mutex<i64>>, lat3::AB>::new(Arc::<Mutex<i64>>::new(Mutex::new(1)));  // Doesn't compile - fails SecretValueSafe
}
