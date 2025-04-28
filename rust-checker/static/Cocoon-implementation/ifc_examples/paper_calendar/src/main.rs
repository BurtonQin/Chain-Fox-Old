use std::collections::HashMap;

use secret_structs::secret::*;
use secret_structs::lattice as lat;
use secret_macros::*;

fn main() {
    // Insecure
    example_insecure();
    /*let alice_cal =
    HashMap::from([ (String::from("Monday"), true),
                    (String::from("Tuesday"), false),
                    (String::from("Wednesday"), true),
                    (String::from("Thursday"), false) ]);
    let bob_cal =
    HashMap::from([ (String::from("Monday"), true),
                    (String::from("Tuesday"), true),
                    (String::from("Wednesday"), true),
                    (String::from("Thursday"), false) ]);
    let count = overlap_insecure(&alice_cal, &bob_cal);
    println!("Available days: {}", count);*/

    // Secure
    example_secure();
    /*let alice_cal =
    HashMap::from([ (String::from("Monday"), Secret::<_, lat::Label_A>::new(true)),
                    (String::from("Tuesday"), Secret::<_, lat::Label_A>::new(false)),
                    (String::from("Wednesday"), Secret::<_, lat::Label_A>::new(true)),
                    (String::from("Thursday"), Secret::<_, lat::Label_A>::new(false)) ]);
    let bob_cal =
    HashMap::from([ (String::from("Monday"), Secret::<_, lat::Label_B>::new(true)),
                    (String::from("Tuesday"), Secret::<_, lat::Label_B>::new(true)),
                    (String::from("Wednesday"), Secret::<_, lat::Label_B>::new(true)),
                    (String::from("Thursday"), Secret::<_, lat::Label_B>::new(false)) ]);
    let count: Secret<_, lat::Label_AB> = overlap_secure(&alice_cal, &bob_cal);
    println!("Available days: {}", count.declassify_ref());
    let count: Secret<_, lat::Label_AB> = overlap_secure(&alice_cal, &bob_cal);
    println!("Available days: {}", count.declassify_ref());*/
}

fn overlap_insecure
(map1: &HashMap<String, bool>, map2: &HashMap<String, bool>) -> i32 {
    let mut count = 0;
    for (day, available) in map1 {
        if *available && *map2.get(day).unwrap() {
            count += 1;
        }
    }
    count
}

fn overlap_secure<Label1: lat::Label, Label2: lat::Label, RetLabel: lat::Label>
(cal1: &HashMap<String, Secret<bool, Label1>>, cal2: &HashMap<String, Secret<bool, Label2>>)
-> Secret<i32, RetLabel>
where RetLabel: lat::MoreSecretThan<Label1> + lat::MoreSecretThan<Label2> {
    let mut count = secret_block!(RetLabel { wrap_secret(0) });
    for (day, available) in cal1 {
        secret_block!(RetLabel {
            if *unwrap_secret_ref(available) &&
               *unwrap_secret_ref(std::option::Option::unwrap(std::collections::HashMap::get(cal2, day))) {
                *unwrap_secret_mut_ref(&mut count) += 1;
            }
        });
    }
    count
}

fn overlap_secure_alt<Label1: lat::Label, Label2: lat::Label, RetLabel: lat::Label>
(cal1: &HashMap<String, Secret<bool, Label1>>, cal2: &HashMap<String, Secret<bool, Label2>>)
-> Secret<i32, RetLabel>
where RetLabel: lat::MoreSecretThan<Label1> + lat::MoreSecretThan<Label2> {
    secret_block!(RetLabel {
        let mut count = 0;
        for (day, available) in cal1 {
            if *unwrap_secret_ref(&available) && std::collections::HashMap::contains_key(cal2, day) &&
               *unwrap_secret_ref(std::option::Option::unwrap(std::collections::HashMap::get(cal2, day))) {
                count += 1;
            }
        }
        wrap_secret(count)
    })
}

fn example_insecure() {
    let alice_cal =
    HashMap::from([ (String::from("Monday"), true),
                    (String::from("Tuesday"), false),
                    (String::from("Wednesday"), true),
                    (String::from("Thursday"), false) ]);
    let bob_cal =
    HashMap::from([ (String::from("Monday"), true),
                    (String::from("Tuesday"), true),
                    (String::from("Wednesday"), true),
                    (String::from("Thursday"), false) ]);
    let mut count = 0;
    for (day, available) in alice_cal {
        if available && *bob_cal.get(&day).unwrap() {
            count += 1;
        }
    }
    println!("Overlapping days: {}", count);
}

fn example_secure() {
    let alice_cal =
    HashMap::from([ (String::from("Monday"),  secret_structs::secret_block!(lat::Label_A { wrap_secret(true) })),
                    (String::from("Tuesday"),  secret_structs::secret_block!(lat::Label_A { wrap_secret(false) })),
                    (String::from("Wednesday"), secret_structs::secret_block!(lat::Label_A { wrap_secret(true) })),
                    (String::from("Thursday"), secret_structs::secret_block!(lat::Label_A { wrap_secret(false) }))]);
    let bob_cal =
    HashMap::from([ (String::from("Monday"), secret_structs::secret_block!(lat::Label_B { wrap_secret(true) })),
                    (String::from("Tuesday"), secret_structs::secret_block!(lat::Label_B { wrap_secret(true) })),
                    (String::from("Wednesday"), secret_structs::secret_block!(lat::Label_B { wrap_secret(true) })),
                    (String::from("Thursday"), secret_structs::secret_block!(lat::Label_B { wrap_secret(false) }))]);
    let mut count = secret_block!(lat::Label_AB { wrap_secret(0) });
    for (day, available) in alice_cal {
        secret_block!(lat::Label_AB {
            if unwrap_secret(available) &&
               *unwrap_secret_ref(std::option::Option::unwrap(std::collections::HashMap::get(&bob_cal, &day))) {
                *unwrap_secret_mut_ref(&mut count) += 1;
            }
        });
    }
    println!("Overlapping days: {}", count);
    println!("Overlapping days (declassified): {}", count.declassify().get_value_consume());
}

/*
let alice_guess1 = Secret::<(i32, i32), lat::Label_A>::new((1, 0));
let alice_guess2 = Secret::<(i32, i32), lat::Label_A>::new((2, 3));
let mut bob_board = HashMap::<(i32,i32), Secret<bool, lat::Label_B>>::new();
bob_board.insert((2, 3), Secret::<bool, lat::Label_B>::new(true));

let is_hit: Secret<_, lat::Label_AB> = play(&alice_guess1, &bob_board);
println!("Is hit? {}", is_hit.declassify_ref());
let is_hit: Secret<_, lat::Label_AB> = play(&alice_guess2, &bob_board);
println!("Is hit? {}", is_hit.declassify_ref());
let is_hit: Secret<_, lat::Label_AB> = play2(&alice_guess1, &bob_board);
println!("Is hit? {}", is_hit.declassify_ref());
let is_hit: Secret<_, lat::Label_AB> = play2(&alice_guess2, &bob_board);
println!("Is hit? {}", is_hit.declassify_ref());

let alice_map = HashMap::from([ (1, Secret::<_, lat::Label_A>::new(12)), (3, Secret::<_, lat::Label_A>::new(5)), (7, Secret::<_, lat::Label_A>::new(32)) ]);
let bob_map = HashMap::from([ (1, Secret::<_, lat::Label_B>::new(5)), (3, Secret::<_, lat::Label_B>::new(5)), (6, Secret::<_, lat::Label_B>::new(32)) ]);
let overlap: Secret<_, lat::Label_AB> = overlap(&alice_map, &bob_map);
println!("Overlap: {:?}", overlap.declassify_ref());

fn play<PlayerLabel: lat::Label, BoardLabel: lat::Label, CombinedLabel: lat::Label>
(guess: &Secret<(i32, i32), PlayerLabel>, board: &HashMap<(i32, i32), Secret<bool, BoardLabel>>) -> Secret<bool, CombinedLabel>
where CombinedLabel: lat::MoreSecretThan<PlayerLabel> + lat::MoreSecretThan<BoardLabel> {
    let mut is_hit = Secret::<bool, CombinedLabel>::new(false);
    for (pos, has_ship) in board {
        secret_block!(CombinedLabel {
            let is_match = unwrap_secret_ref(guess).0 == pos.0 && unwrap_secret_ref(guess).1 == pos.1 && *unwrap_secret_ref(has_ship);
            if is_match {
                *unwrap_secret_mut_ref(&mut is_hit) = true;
            }
        });
    }
    is_hit
}

fn play2<PlayerLabel: lat::Label, BoardLabel: lat::Label, CombinedLabel: lat::Label>
(guess: &Secret<(i32, i32), PlayerLabel>, board: &HashMap<(i32, i32), Secret<bool, BoardLabel>>) -> Secret<bool, CombinedLabel>
where CombinedLabel: lat::MoreSecretThan<PlayerLabel> + lat::MoreSecretThan<BoardLabel> {
    let mut is_hit = Secret::<bool, CombinedLabel>::new(false);
    secret_block!(CombinedLabel {
        let result = std::option::Option::unwrap(std::collections::HashMap::get(board, unwrap_secret_ref(guess)));
        if *unwrap_secret_ref(result) {
            *unwrap_secret_mut_ref(&mut is_hit) = true;
        }
    });
    is_hit
}

fn overlap<Label1: lat::Label, Label2: lat::Label, RetLabel: lat::Label>
(map1: &HashMap<i32, Secret<i32, Label1>>, map2: &HashMap<i32, Secret<i32, Label2>>) -> Secret<HashMap<i32, i32>, RetLabel>
where RetLabel: lat::MoreSecretThan<Label1> + lat::MoreSecretThan<Label2> {
    let mut result = Secret::<HashMap<i32, i32>, RetLabel>::new(HashMap::<i32, i32>::new());
    for (k, v) in map1 {
        secret_block!(RetLabel {
            if std::collections::HashMap::contains_key(map2, k) && *unwrap_secret_ref(std::option::Option::unwrap(std::collections::HashMap::get(map2, k))) == *unwrap_secret_ref(v) {
                let r = unwrap_secret_mut_ref(&mut result);
                std::collections::HashMap::insert(r, *k, *unwrap_secret_ref(v));
            }
        });
    }
    result
}
*/