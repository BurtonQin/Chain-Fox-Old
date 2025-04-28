#![allow(dead_code)]
#![feature(negative_impls)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use secret_structs::secret::{self as sec,Secret,*};
use secret_structs::lattice as lat;
use secret_macros::{self,side_effect_free_attr,*};
use std::ops::Add;
//use std::rc::Rc;
use std::ops::Deref;
use std::cell::RefCell; 

struct MyContainer {
    val: RefCell<i32>
}
//Theoretical overload-using code post-macro-transformation shown on lines 43-54, 147, and 150.
//Proof that &T types can't custom-implement Deref lines 63-69
//Problems with deref coercion/auto-derefing from lines 82-85, and 105-151

//Need to somehow reserve function names so other people can't use it.

struct BadI32 {
    pub data: i32,
}

struct BadI32Wrapper {
    pub data2: BadI32,
}

pub trait MyAddTrait<Rhs = Self> {
    type Output;
    #[allow(non_snake_case)]
    fn myAdd(self, rhs: Rhs) -> Self::Output;
}

trait DerefedTrait {
    fn method(&self, rhs: i32) -> Self;
}
//SOLUTION
impl DerefedTrait for BadI32 {
    fn method(&self, rhs: i32) -> Self {
        BadI32 {data: self.data + rhs}
    }
}

impl MyAddTrait for BadI32 {
    type Output = Self;
    fn myAdd(self, other: Self) -> Self {
        Self {data: self.data + other.data}
    }/*
    fn func(&self) -> &Self {
        *self.myAdd(BadI32{data: 1})
    }*/
}
impl MyAddTrait for i32 {
    type Output = Self;
    fn myAdd(self, other: Self) -> Self {
        self + other
    }
}


impl Deref for BadI32Wrapper {
    type Target = BadI32;
    fn deref(&self) -> &Self::Target {
        &self.data2
    }
}

//SOLUTION
#[side_effect_free_attr]
fn add(n: &i32, m: &i32) -> i32 {
    n + *m
}

//This demonstrates calling of a macro-built function, which I don't see causing any errors, 
//but which may not be behavior we want to allow.
fn add_2(n: &i32, m: &i32) -> i32 {
    __add_secret_trampoline_unchecked(n, m)
}

//SOLUTION
//#[side_effect_free_attr]
fn _x(x: i32) -> i32 { x.add(1) } //Need to figure out how to add i32 methods to the allowlist, otherwise should work.


fn _print_type<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}


pub fn test<L: lat::Label>(x: Secret<i32,L>) -> (Secret<String,L>,Secret<i32,L>) {
    secret_structs::secret_block!(L {
        let y = unwrap_secret(x) + 1i32;
        (wrap_secret(std::string::String::from("asdf")), wrap_secret(y+1))
    })
}

pub fn example(x: Secret<i64, lat::Label_A>, y: Secret<i64, lat::Label_B>) {
    let compare = secret_structs::secret_block!(lat::Label_AB {
      let diff = calc_diff(unwrap_secret(x), unwrap_secret(y));
      if diff > 0i64 {
        wrap_secret("x wins!")
      } else {
        wrap_secret("x loses!")
      }
    });
    println!("Result: {:}", compare.declassify());
  }
  
#[side_effect_free_attr]
fn calc_diff(op1: i64, op2: i64) -> i64 {
  op1 - op2
}

#[derive(InvisibleSideEffectFreeDerive)]
struct Container {
    a: i32
}

fn main() {

//Test Code START
/*
    let x: i32 = 3;
    let result = secret_structs::secret_block_deref!(lat::Label_ABC {
        //wrap_secret(x)
    });*/
//Test Code END

    // From 02/15/2023 meeting
	let mut sec_val = secret_structs::secret_block!(lat::Label_A { wrap_secret(5) });
	let secreter_val = secret_structs::secret_block!(lat::Label_B { wrap_secret(7) });
    let sec_val2 = secret_structs::secret_block!(lat::Label_A { wrap_secret(9) });
    let a: Container = Container{a: 3};

    /* Following code shouldn't compile.
    secret_structs::secret_block!(lat::Label_B {
        let unwrapped_secreter_val = unwrap_secret(secreter_val);
        let b = {println!("{}", unwrapped_secreter_val); a}.a;
    });*/


	let secreter_val = secret_structs::secret_block!(lat::Label_B { wrap_secret(7) });
	secret_structs::secret_block!(lat::Label_B {
	    let unwrapped_secreter_val = unwrap_secret(secreter_val);
	    if unwrapped_secreter_val > 0 {
	        unchecked_operation(sec_val = sec_val2); // Operation not allowed without unchecked_operation(...)
	    }
    });
    // Now sec_val has a value dependent on secreter_val (which has label B), but only has label A

    let mut secret_val = secret_structs::secret_block!(lat::Label_A { wrap_secret(5i32) }); 
    let modified_secret = secret_structs::secret_block!(lat::Label_A {
        let mut unwrapped_secret = unwrap_secret(secret_val);
        // modify unwrapped_secret in some way:
        unwrapped_secret = unwrapped_secret + 1;
        wrap_secret(unwrapped_secret)
    });
    secret_val = modified_secret;
    println!("secret_val = {}", secret_val);
    
    struct MyStruct { data: i32 }
    let x = MyStruct { data: 3 };
    secret_structs::secret_block!(lat::Label_A {
        // Is correctly disallowed:
        //let y = x;
        wrap_secret(5)
    });

    let mut secret_val = secret_structs::secret_block!(lat::Label_A { wrap_secret(5) });
    secret_structs::secret_block!(lat::Label_A {
        let unwrapped_secret: &mut i32 = unwrap_secret_mut_ref(&mut secret_val);
        // modify *unwrapped_secret in some way:
        *unwrapped_secret = 7;
        wrap_secret(()) // Or we could make a secret_block_returns_nothing!() macro
    });

    let a: i32 = 5;
    let b: i32 = 6; 
    let mut c = (a, b);
    let _d = &mut c;

    secret_structs::secret_block!(lat::Label_ABC { wrap_secret(5i32) });
    let tmp_sec = Box::new(6i32);
    secret_structs::secret_block!(lat::Label_ABC { wrap_secret(tmp_sec)});

    /* Commented this out because it leads to double frees:
    let pair = (String::from("hi"), String::from("bye"));
    let x = check_ISEF(&pair).0;
    let y = check_ISEF(&pair).1;
    let z = pair.0; // this is allowed because check_ISEF violates ownership rules, but that's okay because we're planning to put check_ISEF() calls only in the dupliate closure/function that never runs
    */

    // #[derive(InvisibleSideEffectFreeDerive)] /* disallowed (and should be) */
    struct MyDroppable<T /*: InvisibleSideEffectFree <- would try as part of deriving InvisibleSideEffectFreeDerive*/> {
        #[allow(dead_code)]
        f: T
    }
    impl<T /*: InvisibleSideEffectFree*/> Drop for MyDroppable<T> {
        fn drop(&mut self) {
            panic!(); // shouldn't get called if put inside Secret
        }
    }

    #[derive(InvisibleSideEffectFreeDerive)]
    struct MySafeStruct<T: InvisibleSideEffectFree> {
        #[allow(dead_code)]
        f: T
    }

    #[allow(dead_code)]
    struct MyDerefable<T>(T);
    impl<T> Deref for MyDroppable<T> {
        type Target = i32;
        fn deref(&self) -> &Self::Target {
            &0i32
        }
    }

    // Disallowed (and should be):
    /*
    Secret::<_,lat::Label_ABC>::new(MyDroppable { f: 8i32 } );
    Secret::<_,lat::Label_ABC>::new(&MyDroppable { f: 8i32 });
    Secret::<_,lat::Label_ABC>::new(MyDroppable { f: MyDroppable { f: 8i32 } } );
    */

    let _spy: Secret<i32, lat::Label_Empty> = secret_structs::secret_block!(lat::Label_Empty {
        wrap_secret(5)
    });
    let secret: Secret<i32, lat::Label_ABC> = secret_structs::secret_block!(lat::Label_ABC {
        wrap_secret(13)
    });
    let y = 42;
    #[allow(unused_mut)]
    let mut z = 0;

    let result = secret_structs::secret_block!(lat::Label_ABC {
        let x: i32 = add(unwrap_secret_ref(&secret), &y); /*z = 2;*/ wrap_secret(*&x)//wrap_secret(x + *unwrap_secret_ref(&spy))
    });

    let _a: i32 = 5;
    let b: i64 = 10;
    let _c: i32 = b as i32;
    

    println!("{}", z);

    println!("{:?}", result.declassify_ref());

    /*
    let clos = secret_macros::secret_closure!(
        |op: (&i32, &i32)| -> i32 {
            let (target, spy) = op; 
            // *spy = *target; 
            *target + *spy
        }
    );
    let _secret: sec::Secret<i32, lat::Label_ABC> = sec::apply_binary_ref(clos, 
        &secret, &spy);
    */


    // Original example (won't compile now):
    /*
    let spy: sec::Secret<RefCell<i32>, lat::Label_Empty> = 
        sec::Secret::new(RefCell::new(0));
    let secret: sec::Secret<i32, lat::Label_ABC> = sec::Secret::new(13);
    let clos = secret_macros::secret_closure!(
        |op: (&i32, &RefCell<i32>)| -> i32 {
            let (target, spy) = op; 
            *spy.borrow_mut() = *target; 
            *target
        }
    );
    let _secret: sec::Secret<i32, lat::Label_ABC> = sec::apply_binary_ref(clos,
        &secret, &spy);
    println!("{:?}", spy.get_value_ref());
    */

    // Unnamed structure containing a RefCell also isn't allowed:
    /*
    let spy: sec::Secret<(RefCell<i32>, i32), lat::Label_Empty> = 
        sec::Secret::new((RefCell::new(0), 1));
    let secret: sec::Secret<i32, lat::Label_ABC> = sec::Secret::new(13);
    let clos = secret_macros::secret_closure!(
        |op: (&i32, &(RefCell<i32>, i32))| -> i32 {
            let (target, spy) = op; 
            *spy.0.borrow_mut() = *target;
            *target
        }
    );
    let _secret: sec::Secret<i32, lat::Label_ABC> = sec::apply_binary_ref(clos,
        &secret, &spy);
    println!("{:?}", spy.get_value_ref());
    */

    // Named structure containing a RefCell also isn't allowed:
    /*
    let spy: sec::Secret<MyContainer, lat::Label_Empty> = 
        sec::Secret::new(MyContainer { val: RefCell::new(0) });
    let secret: sec::Secret<i32, lat::Label_ABC> = sec::Secret::new(13);
    let clos = secret_macros::secret_closure!(
        |op: (&i32, &MyContainer)| -> i32 {
            let (target, spy) = op; 
            *spy.val.borrow_mut() = *target;
            *target
        }
    );
    let _secret: sec::Secret<i32, lat::Label_ABC> = sec::apply_binary_ref(clos, 
        &secret, &spy);
    println!("{:?}", spy.get_value_ref().val);
    */

    // Trying to leak into a RefCell<i32> from outside the params or is also disallowed:
    /*
    let spy: sec::Secret<i32, lat::Label_Empty> = 
        sec::Secret::new(0);
    let secret: sec::Secret<i32, lat::Label_ABC> = sec::Secret::new(13);
    let mut spy2: sec::Secret<i32, lat::Label_Empty> = 
        sec::Secret::new(0);
    let mut spy3 = 0;
    let spy4 = RefCell::<i32>::new(0);
    let spy5 = (0, RefCell::<i32>::new(0));
    let clos = secret_macros::secret_closure!(
        |op: (&i32, &i32)| -> i32 {
            let (target, spy) = op;
            *spy = *target;
            spy2 = sec::Secret::new(*spy);
            spy3 = *spy;
            *spy4.borrow_mut() = *target;
            *spy5.1.borrow_mut() = *target;
            *target
        }
    );
    let _secret: sec::Secret<i32, lat::Label_ABC> = sec::apply_binary_ref(clos, 
        &secret, &spy);
    println!("{:?}", spy4);
    */

    // Included this non-leaking code just so there's something uncommented here:
    let _spy: sec::Secret<i32, lat::Label_Empty> =  secret_structs::secret_block!(lat::Label_Empty {
        wrap_secret(0)
    });
    let _secret: sec::Secret<i32, lat::Label_ABC> = secret_structs::secret_block!(lat::Label_ABC {
        wrap_secret(13)
    });

    /*let _clos = secret_macros::secret_closure!(
        |op: (&i32, &i32)| -> i32 {
            let (target, _spy) = op;
            // *spy = *target;
            *target
        }
    );*/
    /*let _secret: sec::Secret<i32, lat::Label_ABC> = sec::apply_binary_ref(clos, 
        &secret, &spy);
    println!("{:?}", spy.get_value_ref());*/

}