pub mod millionaire {
    use secret_macros::InvisibleSideEffectFreeDerive;
    use secret_structs::lattice::{self as lat};
    use secret_structs::secret::{self as st};

    // L is secrecy of name
    // M is secrecy of net worth
    #[derive(InvisibleSideEffectFreeDerive)]
    pub struct Millionaire<L, M>
        where L: lat::MoreSecretThan<L>,
              M: lat::MoreSecretThan<M>{
        name: st::Secret<String, L>,
        net_worth: st::Secret<i64, M>,  
    }

    // Allows us to deconstruct millionaire and get the name/net_worth
    impl<L, M> Millionaire<L, M>
        where L: lat::MoreSecretThan<L>,
              M: lat::MoreSecretThan<M> {
        pub fn unwrap_ref(&self) -> (&st::Secret<String, L>, &st::Secret<i64,M>) {
            (&self.name, &self.net_worth)
        }

        pub fn new(name: st::Secret<String, L>, net_worth: st::Secret<i64, M>) -> Millionaire<L, M> {
            Millionaire {name, net_worth}
        }

        // Compares each millionaire and returns the highest net worth
        pub fn compare<R: lat::Label, S: lat::Label, T>(&self, other: Millionaire<R, S>) -> Millionaire<T, T> 
            where T: lat::MoreSecretThan<R> + lat::MoreSecretThan<L>, 
                  T: lat::MoreSecretThan<S> + lat::MoreSecretThan<M> {

            let (name, net_worth) = secret_structs::secret_block!(T {
                if *unwrap_secret_ref(&self.net_worth) >= *unwrap_secret_ref(&other.net_worth) {
                    (wrap_secret(std::string::String::clone(unwrap_secret_ref(&self.name))), wrap_secret(*unwrap_secret_ref(&self.net_worth)))
                } else {
                    (wrap_secret(std::string::String::clone(unwrap_secret_ref(&other.name))), wrap_secret(*unwrap_secret_ref(&other.net_worth)))
                }
            });
            Millionaire::<T, T>::new(name, net_worth)

            /*
            let secret_closure_compare = secret_macros::secret_closure!(|op: (&String, &i64, &String, &i64)| -> (String, i64) {
                if op.1 >= op.3 {
                    (op.0.clone(), *op.1)
                } else {
                    (op.2.clone(), *op.3)
                }
            });
            
            // ret has type Secret<(String, i64), _>
            // Should not *really* be secrecy level U since string and i64 have different secrecy values
            let ret : (st::Secret<String, T>, st::Secret<i64, T>) =
                st::apply_quaternary_ref_returns_pair(secret_closure_compare,
             self.unwrap_ref().0, self.unwrap_ref().1,
             other.unwrap_ref().0, other.unwrap_ref().1);
            
            Millionaire::<T, T>::new(ret.0, ret.1) 
            */
        }
    }

    pub fn compare_vec<L1: lat::Label, L2: lat::Label, L3>(mil_vec: &Vec::<Millionaire<L1, L2>>) -> Millionaire<L3, L3>
    where L3: lat::MoreSecretThan<L1> + lat::MoreSecretThan<L2> {
        let richest_mil: (st::Secret<_,L3>, st::Secret<_,L3>) = secret_structs::secret_block!(L3 {
            let mut richest_index = 0usize;
            for index in 0..std::vec::Vec::len(mil_vec) {
                if *unwrap_secret_ref(&mil_vec[index].net_worth) >= *unwrap_secret_ref(&mil_vec[richest_index].net_worth) {
                    richest_index = index;
                }
            }
            let richest_mil = &mil_vec[richest_index];
            (wrap_secret(std::string::String::clone(unwrap_secret_ref(&richest_mil.name))), wrap_secret(*unwrap_secret_ref(&richest_mil.net_worth)))
            /*let secret_closure_compare = secret_macros::secret_closure!(|op: (&String, &i64, &String, &i64)| -> (String, i64) {
                if op.1 >= op.3 {
                    (*op.0, *op.1)
                } else {
                    (*op.2, *op.3)
                }
            });
            let ret : (st::Secret<String, L3>, st::Secret<i64, L3>) =
                st::apply_quaternary_ref_returns_pair(secret_closure_compare,
                                                  mil.unwrap_ref().0, mil.unwrap_ref().1,
                                                  &richest_mil.0, &richest_mil.1);*/
        });
        Millionaire::<L3, L3>::new(richest_mil.0, richest_mil.1)
    }
    
}

