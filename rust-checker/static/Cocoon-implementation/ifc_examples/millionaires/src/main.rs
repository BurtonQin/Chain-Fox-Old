#![feature(negative_impls)] // Needed because of #[derive(InvisibleSideEffectFreeDerive)]

mod millionaire;

use secret_structs::lattice as lat;
use millionaire::millionaire as mil;
use secret_macros::secret_block;

fn main() {
    let alice = mil::Millionaire::<lat::Label_Empty, lat::Label_A>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Alice")) }), 
        secret_block!(lat::Label_A { wrap_secret(10) })
    );
    let bob = mil::Millionaire::<lat::Label_Empty, lat::Label_B>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Bob")) }), 
        secret_block!(lat::Label_B { wrap_secret(50) })
    );
    let charlie = mil::Millionaire::<lat::Label_Empty, lat::Label_C>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Charlie")) }), 
        secret_block!(lat::Label_C { wrap_secret(100) })
    );

    // answer should be 100
    // using secrecy of millionaires problem here
    let result_alice_bob : mil::Millionaire<lat::Label_AB, lat::Label_AB> = alice.compare(bob);
    let result_alice_bob_charlie : mil::Millionaire<lat::Label_ABC, lat::Label_ABC> = charlie.compare(result_alice_bob);
    
    let ret = result_alice_bob_charlie.unwrap_ref();
    println!("Largest net worth is: {} with net worth {}", ret.0.declassify_ref(), ret.1.declassify_ref());

    // Now try it with a vector of millionaires:
    let mut mil_vec = Vec::<mil::Millionaire<lat::Label_Empty, lat::Label_ABC>>::new();
    mil_vec.push(mil::Millionaire::<lat::Label_Empty, lat::Label_ABC>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Alice")) }), 
        secret_block!(lat::Label_ABC { wrap_secret(200) })
    ));
    mil_vec.push(mil::Millionaire::<lat::Label_Empty, lat::Label_ABC>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Bob")) }), 
        secret_block!(lat::Label_ABC { wrap_secret(50) })
    ));
    mil_vec.push(mil::Millionaire::<lat::Label_Empty, lat::Label_ABC>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Charlie")) }), 
        secret_block!(lat::Label_ABC { wrap_secret(100) })
    ));
    mil_vec.push(mil::Millionaire::<lat::Label_Empty, lat::Label_ABC>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Darlene")) }), 
        secret_block!(lat::Label_ABC { wrap_secret(250) })
    ));
    mil_vec.push(mil::Millionaire::<lat::Label_Empty, lat::Label_ABC>::new(
        secret_block!(lat::Label_Empty { wrap_secret(std::string::String::from("Edith")) }), 
        secret_block!(lat::Label_ABC { wrap_secret(60) })
    ));

    let ret: mil::Millionaire::<lat::Label_ABC, lat::Label_ABC> = mil::compare_vec(&mil_vec);
    println!("Largest net worth is: {} with net worth {}", ret.unwrap_ref().0.declassify_ref(), ret.unwrap_ref().1.declassify_ref());
}
