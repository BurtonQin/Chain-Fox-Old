#![allow(unused_parens, unused_imports)]

use secret_structs::secret as ss;
use secret_structs::lattice as lat;
use secret_structs::secret::SafeAdd;
use std::ops::Add;
use secret_macros::{self,side_effect_free_attr,*};

#[derive(Copy, Clone)]
pub struct NonSafeAddI32 {
    pub val: i32,
}

// Doesn't matter if NonSafeAddI32 implements std::ops::Add, if the user calls +, the macro will call safe_add() instead of add()
impl Add for NonSafeAddI32 {
    type Output = NonSafeAddI32;

    // redefine + to leak self and rhs so that we know in main() that + is being rewritten to not call this
    fn add(self, rhs: Self) -> Self::Output {
        println!("{}", self.val);
        println!("{}", rhs.val);
        NonSafeAddI32 { val: self.val + rhs.val }
    }
}

// Uncomment to test SafeDeref for NonSafeAddI32 instead of SafeAdd
// unsafe impl SafeAdd for NonSafeAddI32 {
//    type Output = NonSafeAddI32;

//    fn safe_add(self, rhs: Self) -> Self::Output {
//        NonSafeAddI32 { val: self.val + rhs.val }
//    }
// }

// unsafe impl SafeAdd<&NonSafeAddI32> for &NonSafeAddI32 {
//     type Output = <NonSafeAddI32 as SafeAdd<NonSafeAddI32>>::Output;

//     #[inline]
//     fn safe_add(self, other: &NonSafeAddI32) -> <NonSafeAddI32 as SafeAdd<NonSafeAddI32>>::Output {
//         SafeAdd::safe_add(*self, *other)
//     }
// }

fn main() {
    // Example with Secret<I32> using the library's safe_add() implementation
    let x1 = secret_structs::secret_block!(lat::Label_AB { wrap_secret(5) });
    let y1 = secret_structs::secret_block!(lat::Label_AB { wrap_secret(7) });
    let x2 = secret_structs::secret_block!(lat::Label_AB { wrap_secret(6) });
    let y2 = secret_structs::secret_block!(lat::Label_AB { wrap_secret(8) });

    let add_sec_block = secret_structs::secret_block!(lat::Label_AB {
        let x = unwrap_secret_ref(&x1) + unwrap_secret_ref(&y1);
        wrap_secret(x)
    });

    let sub_sec_block = secret_structs::secret_block!(lat::Label_AB {
        let x = unwrap_secret_ref(&x2) - unwrap_secret_ref(&y2);
        wrap_secret(x)
    });

    println!("{:?}", add_sec_block.declassify().get_value_consume());
    println!("{:?}", sub_sec_block.declassify().get_value_consume());

    // Example with NonSafeAddI32 Deref
    // Does not compile because NonSafeAddI32 does not implement SafeAdd or SafeDeref
    // let b_nsa1 = ss::Secret::<NonSafeAddI32, lat::Label_ABC>::new(NonSafeAddI32{ val: 3 });
    // let b_nsa2 = ss::Secret::<NonSafeAddI32, lat::Label_ABC>::new(NonSafeAddI32{ val: 9 });

    // let deref_clos = secret_macros::secret_closure!(
    //     |op: (&NonSafeAddI32, &NonSafeAddI32)| -> NonSafeAddI32 {
    //         *&op.0 + *&op.1
    //     }
    // );

    // let nsa1: ss::Secret<NonSafeAddI32, lat::Label_ABC> = ss::apply_binary_ref(deref_clos, &b_nsa1, &b_nsa2);
    // println!("{:?}", nsa1.declassify().get_value_consume().val);

    // test !=
    let x3 = secret_structs::secret_block!(lat::Label_B { wrap_secret(4) });
    let y3 = secret_structs::secret_block!(lat::Label_B { wrap_secret(4) });
    //let z3 = ss::Secret::<u8, lat::Label_B>::new(10);

    let ans1 = secret_structs::secret_block!(lat::Label_B {
        wrap_secret(unwrap_secret(x3) != unwrap_secret(y3))
    });

    // No longer valid: Standard Rust doesn't support != for & types
    // so we need to use unwrap_secret which means we can't use x3 in
    // a second closure.
    // let ans2 = secret_structs::secret_block!(lat::Label_B {
    //     wrap_secret(unwrap_secret_ref(&x3) != unwrap_secret_ref(&z3))
    // });

    println!("{}", ans1.declassify().get_value_consume());
    //println!("{}", ans2.declassify().get_value_consume());
}