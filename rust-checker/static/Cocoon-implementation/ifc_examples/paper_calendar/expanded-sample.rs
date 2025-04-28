#![feature(prelude_import)]
#[prelude_import]
use ::std::prelude::rust_2018::*;
#[macro_use]
extern crate std;
use ::std::collections::HashMap;

use cocoon::*;
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

fn overlap_insecure(map1: &HashMap<String, bool>,
    map2: &HashMap<String, bool>) -> i32 {
    let mut count = 0;
    for (day, available) in map1 {
        if *available && *map2.get(day).unwrap() { count += 1; }
    }
    count
}

fn overlap_secure<Label1: lat::Label, Label2: lat::Label,
    RetLabel: lat::Label>(cal1: &HashMap<String, Secret<bool, Label1>>,
    cal2: &HashMap<String, Secret<bool, Label2>>) -> Secret<i32, RetLabel>
    where RetLabel: lat::MoreSecretThan<Label1> +
    lat::MoreSecretThan<Label2> {
    let mut count =
        if true {
                ::cocoon::call_closure::<RetLabel, _,
                        _>((|| -> _
                            {
                                let result =
                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                    {
                                                        {
                                                            {
                                                                {
                                                                    let tmp = 0;
                                                                    unsafe {
                                                                        ::cocoon::Secret::<_, RetLabel>::new(tmp)
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    })).unwrap_or_default();
                                result
                            }))
            } else {
               ::cocoon::call_closure::<RetLabel, _,
                       _>((|| -> _
                           {
                               {
                                   {
                                       unsafe {
                                           ::cocoon::Secret::<_, RetLabel>::new(0)
                                       }
                                   }
                               }
                           }))
           };
    for (day, available) in cal1 {
        if true {
                ::cocoon::call_closure::<RetLabel, _,
                        _>((|| -> _
                            {
                                let result =
                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                    {
                                                        {
                                                            {
                                                                if *{
                                                                                    let tmp = available;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::unwrap_ref::<RetLabel>(tmp)
                                                                                    }
                                                                                } &&
                                                                            *{
                                                                                    let tmp =
                                                                                        ::std::option::Option::unwrap(::std::collections::HashMap::get(cal2,
                                                                                                day));
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::unwrap_ref::<RetLabel>(tmp)
                                                                                    }
                                                                                } {
                                                                        {
                                                                            (*{
                                                                                            let tmp = &mut count;
                                                                                            unsafe {
                                                                                                ::cocoon::Secret::unwrap_mut_ref::<RetLabel>(tmp)
                                                                                            }
                                                                                        } += 1);
                                                                        }
                                                                    } else {}
                                                            }
                                                        }
                                                    })).unwrap_or_default();
                                result
                            }))
            } else {
               ::cocoon::call_closure::<RetLabel, _,
                       _>((|| -> _
                           {
                               {
                                   {
                                       if (*(unsafe {
                                                                   ::cocoon::Secret::unwrap_ref::<RetLabel>({
                                                                           let tmp = &(available);
                                                                           unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                                       })
                                                               })) &&
                                                   (*(unsafe {
                                                                   ::cocoon::Secret::unwrap_ref::<RetLabel>({
                                                                           ::cocoon::check_ISEF(::std::option::Option::unwrap({
                                                                                       ::cocoon::check_ISEF(::std::collections::HashMap::get({
                                                                                                   let tmp = &(cal2);
                                                                                                   unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                                                               },
                                                                                               {
                                                                                                   let tmp = &(day);
                                                                                                   unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                                                               }))
                                                                                   }))
                                                                       })
                                                               })) {
                                               {
                                                   ::cocoon::SafeAddAssign::safe_add_assign(&mut *(unsafe
                                                                       {
                                                                       ::cocoon::Secret::unwrap_mut_ref::<RetLabel>({
                                                                               ::cocoon::check_ISEF((&mut count))
                                                                           })
                                                                   }), 1);
                                               }
                                           } else {}
                                   }
                               }
                           }))
           };
    }
    count
}

fn overlap_secure_alt<Label1: lat::Label, Label2: lat::Label,
    RetLabel: lat::Label>(cal1: &HashMap<String, Secret<bool, Label1>>,
    cal2: &HashMap<String, Secret<bool, Label2>>) -> Secret<i32, RetLabel>
    where RetLabel: lat::MoreSecretThan<Label1> +
    lat::MoreSecretThan<Label2> {
    if true {
            ::cocoon::call_closure::<RetLabel, _,
                    _>((|| -> _
                        {
                            let result =
                                ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                {
                                                    {
                                                        {
                                                            let mut count = 0;
                                                            for (day, available) in cal1 {
                                                                {
                                                                    if *{
                                                                                            let tmp = &available;
                                                                                            unsafe {
                                                                                                ::cocoon::Secret::unwrap_ref::<RetLabel>(tmp)
                                                                                            }
                                                                                        } && ::std::collections::HashMap::contains_key(cal2, day) &&
                                                                                *{
                                                                                        let tmp =
                                                                                            ::std::option::Option::unwrap(::std::collections::HashMap::get(cal2,
                                                                                                    day));
                                                                                        unsafe {
                                                                                            ::cocoon::Secret::unwrap_ref::<RetLabel>(tmp)
                                                                                        }
                                                                                    } {
                                                                            { (count += 1); }
                                                                        } else {}
                                                                }
                                                            }
                                                            {
                                                                let tmp = count;
                                                                unsafe {
                                                                    ::cocoon::Secret::<_, RetLabel>::new(tmp)
                                                                }
                                                            }
                                                        }
                                                    }
                                                })).unwrap_or_default();
                            result
                        }))
        } else {
           ::cocoon::call_closure::<RetLabel, _,
                   _>((|| -> _
                       {
                           {
                               {
                                   let mut count = 0;
                                   for (day, available) in
                                       {
                                           let tmp = &(cal1);
                                           unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                       } {
                                       {
                                           if ((*(unsafe {
                                                                               ::cocoon::Secret::unwrap_ref::<RetLabel>({
                                                                                       ::cocoon::check_expr_secret_block_safe_ref((&available))
                                                                                   })
                                                                           })) &&
                                                               (::std::collections::HashMap::contains_key({
                                                                           let tmp = &(cal2);
                                                                           unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                                       },
                                                                       {
                                                                           let tmp = &(day);
                                                                           unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                                       }))) &&
                                                       (*(unsafe {
                                                                       ::cocoon::Secret::unwrap_ref::<RetLabel>({
                                                                               ::cocoon::check_ISEF(::std::option::Option::unwrap({
                                                                                           ::cocoon::check_ISEF(::std::collections::HashMap::get({
                                                                                                       let tmp = &(cal2);
                                                                                                       unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                                                                   },
                                                                                                   {
                                                                                                       let tmp = &(day);
                                                                                                       unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                                                                   }))
                                                                                       }))
                                                                           })
                                                                   })) {
                                                   {
                                                       ::cocoon::SafeAddAssign::safe_add_assign(&mut count,
                                                           1);
                                                   }
                                               } else {}
                                       }
                                   }
                                   unsafe {
                                       ::cocoon::Secret::<_,
                                               RetLabel>::new({
                                               let tmp = &(count);
                                               unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                           })
                                   }
                               }
                           }
                       }))
       }
}

fn example_insecure() {
    let alice_cal =
        HashMap::from([(String::from("Monday"), true),
                    (String::from("Tuesday"), false),
                    (String::from("Wednesday"), true),
                    (String::from("Thursday"), false)]);
    let bob_cal =
        HashMap::from([(String::from("Monday"), true),
                    (String::from("Tuesday"), true),
                    (String::from("Wednesday"), true),
                    (String::from("Thursday"), false)]);
    let mut count = 0;
    for (day, available) in alice_cal {
        if available && *bob_cal.get(&day).unwrap() { count += 1; }
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
            let result = ::std::option::Option::unwrap(::std::collections::HashMap::get(board, unwrap_secret_ref(guess)));
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
                if ::std::collections::HashMap::contains_key(map2, k) && *unwrap_secret_ref(::std::option::Option::unwrap(std::collections::HashMap::get(map2, k))) == *unwrap_secret_ref(v) {
                    let r = unwrap_secret_mut_ref(&mut result);
                    ::std::collections::HashMap::insert(r, *k, *unwrap_secret_ref(v));
                }
            });
        }
        result
    }
    */

    { ::std::io::_print(format_args!("Overlapping days: {0}\n", count)); };
}
fn example_secure() {
    let alice_cal =
        HashMap::from([(String::from("Monday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_A, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = true;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_A>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_A, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_A>::new(true)
                                                       }
                                                   }
                                               }
                                           }))
                           }),
                    (String::from("Tuesday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_A, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = false;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_A>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_A, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_A>::new(false)
                                                       }
                                                   }
                                               }
                                           }))
                           }),
                    (String::from("Wednesday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_A, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = true;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_A>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_A, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_A>::new(true)
                                                       }
                                                   }
                                               }
                                           }))
                           }),
                    (String::from("Thursday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_A, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = false;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_A>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_A, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_A>::new(false)
                                                       }
                                                   }
                                               }
                                           }))
                           })]);
    let bob_cal =
        HashMap::from([(String::from("Monday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_B, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = true;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_B>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_B, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_B>::new(true)
                                                       }
                                                   }
                                               }
                                           }))
                           }),
                    (String::from("Tuesday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_B, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = true;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_B>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_B, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_B>::new(true)
                                                       }
                                                   }
                                               }
                                           }))
                           }),
                    (String::from("Wednesday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_B, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = true;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_B>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_B, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_B>::new(true)
                                                       }
                                                   }
                                               }
                                           }))
                           }),
                    (String::from("Thursday"),
                        if true {
                                ::cocoon::call_closure::<lat::Label_B, _,
                                        _>((|| -> _
                                            {
                                                let result =
                                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                                    {
                                                                        {
                                                                            {
                                                                                {
                                                                                    let tmp = false;
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::<_,
                                                                                                lat::Label_B>::new(tmp)
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    })).unwrap_or_default();
                                                result
                                            }))
                            } else {
                               ::cocoon::call_closure::<lat::Label_B, _,
                                       _>((|| -> _
                                           {
                                               {
                                                   {
                                                       unsafe {
                                                           ::cocoon::Secret::<_,
                                                                   lat::Label_B>::new(false)
                                                       }
                                                   }
                                               }
                                           }))
                           })]);
    let mut count =
        if true {
                ::cocoon::call_closure::<lat::Label_AB, _,
                        _>((|| -> _
                            {
                                let result =
                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                    {
                                                        {
                                                            {
                                                                {
                                                                    let tmp = 0;
                                                                    unsafe {
                                                                        ::cocoon::Secret::<_,
                                                                                lat::Label_AB>::new(tmp)
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    })).unwrap_or_default();
                                result
                            }))
            } else {
               ::cocoon::call_closure::<lat::Label_AB, _,
                       _>((|| -> _
                           {
                               {
                                   {
                                       unsafe {
                                           ::cocoon::Secret::<_, lat::Label_AB>::new(0)
                                       }
                                   }
                               }
                           }))
           };
    for (day, available) in alice_cal {
        if true {
                ::cocoon::call_closure::<lat::Label_AB, _,
                        _>((|| -> _
                            {
                                let result =
                                    ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(||
                                                    {
                                                        {
                                                            {
                                                                if {
                                                                                let tmp = available;
                                                                                unsafe {
                                                                                    ::cocoon::Secret::unwrap::<lat::Label_AB>(tmp)
                                                                                }
                                                                            } &&
                                                                            *{
                                                                                    let tmp =
                                                                                        ::std::option::Option::unwrap(::std::collections::HashMap::get(&bob_cal,
                                                                                                &day));
                                                                                    unsafe {
                                                                                        ::cocoon::Secret::unwrap_ref::<lat::Label_AB>(tmp)
                                                                                    }
                                                                                } {
                                                                        {
                                                                            (*{
                                                                                            let tmp = &mut count;
                                                                                            unsafe {
                                                                                                ::cocoon::Secret::unwrap_mut_ref::<lat::Label_AB>(tmp)
                                                                                            }
                                                                                        } += 1);
                                                                        }
                                                                    } else {}
                                                            }
                                                        }
                                                    })).unwrap_or_default();
                                result
                            }))
            } else {
               ::cocoon::call_closure::<lat::Label_AB, _,
                       _>((|| -> _
                           {
                               {
                                   {
                                       if (unsafe {
                                                           ::cocoon::Secret::unwrap::<lat::Label_AB>({
                                                                   let tmp = &(available);
                                                                   unsafe { ::cocoon::check_ISEF_unsafe(tmp) }
                                                               })
                                                       }) &&
                                                   (*(unsafe {
                                                                   ::cocoon::Secret::unwrap_ref::<lat::Label_AB>({
                                                                           ::cocoon::check_ISEF(::std::option::Option::unwrap({
                                                                                       ::cocoon::check_ISEF(::std::collections::HashMap::get({
                                                                                                   ::cocoon::check_expr_secret_block_safe_ref((&bob_cal))
                                                                                               },
                                                                                               {
                                                                                                   ::cocoon::check_expr_secret_block_safe_ref((&day))
                                                                                               }))
                                                                                   }))
                                                                       })
                                                               })) {
                                               {
                                                   ::cocoon::SafeAddAssign::safe_add_assign(&mut *(unsafe
                                                                       {
                                                                       ::cocoon::Secret::unwrap_mut_ref::<lat::Label_AB>({
                                                                               ::cocoon::check_ISEF((&mut count))
                                                                           })
                                                                   }), 1);
                                               }
                                           } else {}
                                   }
                               }
                           }))
           };
    }
    {
        ::std::io::_print(format_args!("Overlapping days: {0}\n",
                count.declassify()));
    };
}
