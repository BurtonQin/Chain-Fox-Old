use proc_macro::TokenStream;
use proc_macro2::{Ident};
use quote::{quote, ToTokens};
use std::collections::HashSet;
use std::{iter::FromIterator, str::FromStr};
use syn::{parse_macro_input, spanned::Spanned, Data, DataStruct, DeriveInput, Expr, Fields, Type, Block, FieldValue, ExprField};
use syn::parse::{Parse, ParseStream};
use syn::token::Comma;

struct LabeledBlock {
    ty: Type,
    blk: Block
}

impl Parse for LabeledBlock {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ty: Type = input.parse().unwrap_or_else(|_|{panic!("not a type")});
        let blk: Block = input.parse().unwrap();
        Ok(LabeledBlock {ty, blk})
    }
}

#[proc_macro]
pub fn secret_block(tokens: TokenStream) -> TokenStream {
    let LabeledBlock{ty, blk} = parse_macro_input!(tokens as LabeledBlock);
    let executed_code: proc_macro2::TokenStream = secret_block_backend_helper(
        quote::quote! {
            || -> #ty { #blk }
        }.into(), false
    ).into();
    let checking_code: proc_macro2::TokenStream = secret_block_backend_helper(
        quote::quote! {
            || -> #ty { #blk }
        }.into(), true
    ).into();
    quote::quote! {
        if true {
            ::secret_structs::secret::call_closure::<#ty, _, _>(
                #executed_code
            )
        } else {
            ::secret_structs::secret::call_closure::<#ty, _, _>(
                #checking_code
            )
        }
    }.into()
}

#[proc_macro]
pub fn secret_block_no_return(tokens: TokenStream) -> TokenStream {
    let LabeledBlock{ty, blk} = parse_macro_input!(tokens as LabeledBlock);
    let executed_code: proc_macro2::TokenStream = secret_block_backend_helper(
        quote::quote! {
            || -> #ty { #blk }
        }.into(), false
    ).into();
    let checking_code: proc_macro2::TokenStream = secret_block_backend_helper(
        quote::quote! {
            || -> #ty { #blk }
        }.into(), true
    ).into();
    quote::quote! {
        if true {
            ::secret_structs::secret::call_closure_no_return::<#ty, _>(
                #executed_code
            )
        } else {
            ::secret_structs::secret::call_closure_no_return::<#ty, _>(
                #checking_code
            )
        }
    }.into()
}

fn secret_block_backend_helper(input: TokenStream, is_duplicate: bool) -> TokenStream {
    //let ast_returned: syn::ExprClosure = syn::parse(input.clone()).unwrap();
    let ast: syn::ExprClosure = syn::parse(input).unwrap();
    let params = ast.inputs;
    assert!(params.is_empty());
    let ret = ast.output;
    let secrecy_label = match ret {
        syn::ReturnType::Default => panic!("Unsupported"), // Even if the secret block has no return type, the input closure still must have a return type to indicate the secrecy label
        syn::ReturnType::Type(_, t) => Option::Some(*t),
    };
    //let secrecy_label_returned = secrecy_label.clone();
    //let secrecy_label = Option::Some(ret_simple);
    let body: proc_macro2::TokenStream = if is_duplicate {
        match &*ast.body {
            syn::Expr::Block(b) => check_block(&b.block, &secrecy_label).into(),
            _ => check_expr(&*ast.body, &secrecy_label, true),
        }
    } else {
        match &*ast.body {
            syn::Expr::Block(b) => expand_block(&b.block, &secrecy_label).into(),
            _ => expand_expr(&*ast.body, &secrecy_label),
        }
    };

    let gen = if is_duplicate {
        quote::quote! {
            (|| -> _ { #body })
        }
    } else {
        if cfg!(debug_assertions) {
            quote::quote! {
                (|| -> _ {
                    let result = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| { #body })).unwrap_or_default();
                    result
                })
            }
        } else {
            quote::quote! {
                (|| -> _ {
                    let prev_hook = ::std::panic::take_hook();
                    ::std::panic::set_hook(Box::new(|_| {}));
                    let result = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| { #body })).unwrap_or_default();
                    ::std::panic::set_hook(prev_hook);
                    result
                })
            }
        }
    };
    gen.into()
}

// Returns if the function call is white-listed.
fn is_call_to_allowlisted_function(call: &syn::ExprCall) -> bool {
    let allowed_functions = HashSet::from([
        "char::is_digit".to_string(),
        "core::primitive::str::len".to_string(),
        "std::arch::x86_64::_mm256_add_pd".to_string(),
        "std::arch::x86_64::_mm256_cvtpd_ps".to_string(),
        "std::arch::x86_64::_mm256_cvtps_pd".to_string(),
        "std::arch::x86_64::_mm256_hadd_pd".to_string(),
        "std::arch::x86_64::_mm256_mul_pd".to_string(),
        "std::arch::x86_64::_mm256_permute2f128_pd".to_string(),
        "std::arch::x86_64::_mm_rsqrt_ps".to_string(),
        "std::arch::x86_64::_mm256_setr_pd".to_string(),
        "std::arch::x86_64::_mm256_set1_pd".to_string(),
        "std::arch::x86_64::_mm256_store_pd".to_string(),
        "std::arch::x86_64::_mm256_sub_pd".to_string(),
        "std::clone::Clone::clone".to_string(),
        "std::cmp::min".to_string(),
        "std::fs::File::open".to_string(),
        "std::iter::Copied::cycle".to_string(),
        "std::iter::Iterator::by_ref".to_string(),
        "std::iter::Iterator::next".to_string(),
        "std::iter::Iterator::take".to_string(),
        "std::iter::zip".to_string(),
        "std::mem::MaybeUninit::assume_init".to_string(),
        "std::mem::MaybeUninit::uninit".to_string(),
        "std::mem::transmute".to_string(),
        "std::primitive::f64::sqrt".to_string(),
        "core::primitive::u32::is_power_of_two".to_string(),
        "std::option::Option::Some".to_string(),
        "std::option::Option::unwrap".to_string(),
        "std::slice::Iter::copied".to_string(),
        "std::string::String::clear".to_string(),
        "std::string::String::from".to_string(),
        "std::string::String::len".to_string(),
        "std::string::String::clone".to_string(),
        "std::vec::Vec::clear".to_string(),
        "std::vec::Vec::clone".to_string(),
        "std::vec::Vec::extend_from_slice".to_string(),
        "std::vec::Vec::len".to_string(),
        "std::vec::Vec::new".to_string(),
        "std::vec::Vec::push".to_string(),
        "std::vec::Vec::with_capacity".to_string(),
        "std::collections::HashMap::get".to_string(),
        "std::collections::HashMap::insert".to_string(),
        "std::collections::HashMap::contains_key".to_string(),
        "std::collections::HashSet::insert".to_string(),
        "str::chars".to_string(),
        "str::to_string".to_string(),
        "str::trim".to_string(),
        "usize::to_string".to_string(),
        "<[T]>::sort".to_string(),
        "<[_]>::copy_from_slice".to_string(),
        "<[_]>::iter".to_string(),
        "<[_]>::len".to_string(),
        "secret_structs::secret::SafeAdd::safe_add".to_string(),
        "secret_structs::secret::SafeSub::safe_sub".to_string(),
        "secret_structs::secret::SafeNot::safe_not".to_string(),
        "secret_structs::secret::SafeNeg::safe_neg".to_string(),
        "secret_structs::secret::SafeMul::safe_mul".to_string(),
        "secret_structs::secret::SafePartialEq::safe_eq".to_string(),
        "secret_structs::secret::SafePartialEq::safe_ne".to_string(),
        "secret_structs::secret::SafeDiv::safe_div".to_string(),
        "secret_structs::secret::SafePartialOrd::safe_le".to_string(),
        "secret_structs::secret::SafePartialOrd::safe_lt".to_string(),
        "secret_structs::secret::SafePartialOrd::safe_ge".to_string(),
        "secret_structs::secret::SafePartialOrd::safe_gt".to_string(),
        "secret_structs::secret::SafeIndex::safe_index".to_string(),
        "secret_structs::secret::SafeIndexMut::safe_index_mut".to_string(),
        "secret_structs::secret::SafeAddAssign::safe_add_assign".to_string(),
        "secret_structs::secret::SafeSubAssign::safe_sub_assign".to_string(),
        "secret_structs::secret::SafeMulAssign::safe_mul_assign".to_string(),
        "secret_structs::secret::SafeDivAssign::safe_div_assign".to_string(),
        // Add other allowed functions here.
    ]);

    if let syn::Expr::Path(path_expr) = &*call.func {
        let mut path_str = quote::quote! {#path_expr}.to_string();
        path_str.retain(|c| !c.is_whitespace());
        allowed_functions.contains(&path_str)
    } else {
        false
    }
}

// Returns whether the function call is a specific function.
fn is_call_to(call: &syn::ExprCall, path: &str) -> bool {
    if let syn::Expr::Path(path_expr) = &*call.func {
        let mut path_str = quote::quote! {#path_expr}.to_string();
        path_str.retain(|c| !c.is_whitespace());
        return path_str == path;
    } else {
        false
    }
}

fn expand_expr(expr: &syn::Expr, secrecy_label: &Option<syn::Type>) -> proc_macro2::TokenStream {
    match expr {
        syn::Expr::Array(array_exp) => {
            let elements = comma_separate(
                array_exp.elems.iter().map(|expr| expand_expr(expr, secrecy_label))
            );
            quote::quote!{
                [#elements]
            }
        }
        syn::Expr::Break(expr_break) => expr_break.into_token_stream(),
        syn::Expr::Call(expr_call) => {
            let args = comma_separate(expr_call.args.iter().map(
                |arg: &syn::Expr| -> proc_macro2::TokenStream { expand_expr(arg, secrecy_label) },
            ));
            if is_call_to(expr_call, "unwrap_secret_ref") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    { let tmp = #args; unsafe { ::secret_structs::secret::Secret::unwrap_unsafe::<#label>(tmp) } }
                }
            } else if is_call_to(expr_call, "unwrap_secret_mut_ref") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    { let tmp = #args; unsafe { ::secret_structs::secret::Secret::unwrap_mut_unsafe::<#label>(tmp) } }
                }
            } else if is_call_to(expr_call, "unwrap_secret") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    { let tmp = #args; unsafe { ::secret_structs::secret::Secret::unwrap_consume_unsafe::<#label>(tmp) } }
                }
            } else if is_call_to(expr_call, "wrap_secret") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    { let tmp = #args; unsafe { ::secret_structs::secret::Secret::<_,#label>::new(tmp) } }
                }
            } else if is_call_to(expr_call, "unchecked_operation") {
                let expr = expr_call.args.iter().nth(0);
                if let Some(block) = expr {
                    quote::quote! {#block}
                } else {
                    quote::quote! {compile_error!("unchecked_operation needs an operation.");}
                }
            } else if is_call_to_allowlisted_function(expr_call) {
                let func = &*expr_call.func;
                quote::quote! {
                    #func(#args)
                }
            } else {
                let func = &*expr_call.func;
                // TODO: Shouldn't evaluate #args inside of unsafe block
                quote::quote! {
                    (unsafe { (#func(#args) as ::secret_structs::secret::Vetted<_>).unwrap() })
                }
            }
        }
        syn::Expr::Continue(continue_stmt) => continue_stmt.into_token_stream(),
        syn::Expr::Macro(_) => quote::quote! { compile_error!("Function calls & macros are not allowed in secret blocks.") },
        syn::Expr::Binary(expr_binary) => {
            // Check the left-hand side of the expression, and the right-hand side.
            let lhs = expand_expr(&*expr_binary.left, secrecy_label);
            let rhs = expand_expr(&*expr_binary.right, secrecy_label);
            let op = expr_binary.op;
            quote::quote! {
                #lhs #op #rhs
            }
        }
        syn::Expr::If(expr_if) => {
            let condition = expand_expr(&*expr_if.cond, secrecy_label);
            let then_block: proc_macro2::TokenStream =
                expand_block(&expr_if.then_branch, secrecy_label).into();
            let else_branch = match &expr_if.else_branch {
                Some(block) => expand_expr(&*block.1, secrecy_label),
                None => quote::quote! {},
            };
            quote::quote! {
                if #condition {
                    #then_block
                } else {
                    #else_branch
                }
            }
        }
        syn::Expr::Block(expr_block) => expand_block(&expr_block.block, secrecy_label).into(),
        syn::Expr::Closure(closure_expr) => {
            let mut new_closure = closure_expr.clone();
            new_closure.body =
                Box::new(syn::parse2(expand_expr(&new_closure.body, secrecy_label)).unwrap());
            new_closure.into_token_stream()
        }
        syn::Expr::Assign(assign_expr) => {
            let lhs: proc_macro2::TokenStream =
                expand_expr(&assign_expr.left, secrecy_label).into();
            let rhs: proc_macro2::TokenStream =
                expand_expr(&assign_expr.right, secrecy_label).into();
            // Don't need not_mut_secret here since it's already in the duplicate (i.e., check_expr) path
            quote::quote! {
                (#lhs = #rhs)
            }
        }
        syn::Expr::AssignOp(assign_op_expr) => {
            let lhs: proc_macro2::TokenStream =
                expand_expr(&assign_op_expr.left, secrecy_label).into();
            let rhs: proc_macro2::TokenStream =
                expand_expr(&assign_op_expr.right, secrecy_label).into();
            let op = assign_op_expr.op;
            // Don't need not_mut_secret here since the duplicate (i.e., check_expr) path ensures built-in numeric/string types
            quote::quote! {
                (#lhs #op #rhs)
            }
        }
        syn::Expr::MethodCall(method_call_expr) => {
            let receiver: proc_macro2::TokenStream =
                expand_expr(&method_call_expr.receiver, secrecy_label).into();
            let args = comma_separate(method_call_expr.args.iter().map(
                |arg: &syn::Expr| -> proc_macro2::TokenStream { expand_expr(arg, secrecy_label) },
            ));
            let method = &method_call_expr.method;
            let turbofish = &method_call_expr.turbofish;
            // TODO: Shouldn't evaluate #args inside of unsafe block
            quote::quote! {
                (unsafe { (#receiver.#method#turbofish(#args) as ::secret_structs::secret::Vetted<_>).unwrap() })
            }
        }
        syn::Expr::Lit(expr_lit) => expr_lit.into_token_stream(),
        syn::Expr::Field(field_access) => {
            let e: Expr  = syn::parse2(expand_expr(&(field_access.base), secrecy_label)).expect("ErrS");
            let e2: Expr = syn::parse2(quote::quote!{ (#e) }).expect("ErrS");
            let e3: Box<Expr> = Box::new(e2);
            let f_new = ExprField {
                attrs: field_access.attrs.clone(),
                base: e3,
                dot_token: field_access.dot_token.clone(),
                member: field_access.member.clone()
            };
            f_new.into_token_stream()
        }
        syn::Expr::Path(path_access) => path_access.into_token_stream(),
        syn::Expr::Paren(paren_expr) => {
            let interal_expr = expand_expr(&paren_expr.expr, secrecy_label);
            let mut new_paren_expr = paren_expr.clone();
            new_paren_expr.expr = Box::new(syn::parse2(interal_expr).unwrap());
            new_paren_expr.into_token_stream()
        }
        syn::Expr::Struct(struct_literal) => {
            let fields: syn::punctuated::Punctuated<FieldValue, Comma> = {
                let mut f = syn::punctuated::Punctuated::<FieldValue, Comma>::new();
                for field in struct_literal.clone().fields.iter() {
                    let e = syn::parse2(expand_expr(&field.expr, secrecy_label)).expect("ErrS");
                    let fv = syn::FieldValue {
                        attrs: field.attrs.clone(), 
                        member: field.member.clone(),
                        colon_token: field.colon_token.clone(),
                        expr: e
                    };
                    f.push(fv);
                }
                f
            };
            let struct_new = syn::ExprStruct {
                attrs: struct_literal.attrs.clone(),
                path: struct_literal.path.clone(),
                brace_token: struct_literal.brace_token.clone(),
                fields: fields,
                dot2_token: struct_literal.dot2_token.clone(),
                rest: struct_literal.rest.clone(),
            };
            struct_new.into_token_stream()
        }
        syn::Expr::ForLoop(for_loop) => {
            // TODO: Does #pat need expansion?
            let pat = for_loop.pat.clone().into_token_stream();
            let expr: proc_macro2::TokenStream = expand_expr(&*for_loop.expr, secrecy_label).into();
            let body: proc_macro2::TokenStream = expand_block(&for_loop.body, secrecy_label).into();
            quote::quote! {
                for #pat in #expr {
                    #body
                }
            }
        }
        syn::Expr::While(while_loop) => {
            let cond: proc_macro2::TokenStream =
                expand_expr(&*while_loop.cond, secrecy_label).into();
            let body: proc_macro2::TokenStream =
                expand_block(&while_loop.body, secrecy_label).into();
            quote::quote! {
                while #cond {
                    #body
                }
            }
        }
        syn::Expr::Match(expr_match) => {
            let mut expr_match_copy = expr_match.clone();
            expr_match_copy.expr =
                Box::new(syn::parse2(expand_expr(&*expr_match_copy.expr, secrecy_label)).unwrap());
            for arm in &mut expr_match_copy.arms {
                match &arm.guard {
                    Some((if_token, guard_expr_boxed)) => {
                        arm.guard = Some((
                            *if_token,
                            Box::new(
                                syn::parse2(expand_expr(&*guard_expr_boxed, secrecy_label))
                                    .unwrap(),
                            ),
                        ))
                    }
                    _ => {}
                }
                arm.body = Box::new(syn::parse2(expand_expr(&*arm.body, secrecy_label)).unwrap());
            }
            expr_match_copy.into_token_stream()
        }
        syn::Expr::Range(range) => {
            let mut range_copy = range.clone();
            match range_copy.from {
                Some(from) => {
                    range_copy.from = Some(syn::parse2(expand_expr(&*from, secrecy_label)).unwrap())
                }
                _ => {}
            };
            match range_copy.to {
                Some(to) => {
                    range_copy.to = Some(syn::parse2(expand_expr(&*to, secrecy_label)).unwrap())
                }
                _ => {}
            };
            quote::quote!{(#range_copy)}
        }
        syn::Expr::Repeat(repeat_expr) => {
            let expr = expand_expr(&repeat_expr.expr, secrecy_label);
            let len_expr = expand_expr(&repeat_expr.len, secrecy_label);
            let mut new_repeat_expr = repeat_expr.clone();
            new_repeat_expr.expr = Box::new(syn::parse2(expr).unwrap());
            new_repeat_expr.len = Box::new(syn::parse2(len_expr).unwrap());
            new_repeat_expr.into_token_stream()
        }
        syn::Expr::Return(return_expr) => {
            if let None = return_expr.expr {
                return return_expr.into_token_stream();
            }
            let mut new_return_expr = return_expr.clone();
            let expr = expand_expr(&new_return_expr.expr.unwrap(), secrecy_label);
            new_return_expr.expr = Some(Box::new(syn::parse2(expr).unwrap()));
            new_return_expr.into_token_stream()
        }
        syn::Expr::Index(idx) => {
            let expr: proc_macro2::TokenStream = expand_expr(&*idx.expr, secrecy_label).into();
            let index: proc_macro2::TokenStream = expand_expr(&*idx.index, secrecy_label).into();
            quote::quote! {
                #expr[#index]
            }
        }
        syn::Expr::Tuple(tuple) => {
            let args = comma_separate(tuple.elems.iter().map(
                |arg: &syn::Expr| -> proc_macro2::TokenStream { expand_expr(arg, secrecy_label) },
            ));
            quote::quote! {
                (#args)
            }
        }
        syn::Expr::Unary(unary) => {
            let operand = expand_expr(&*unary.expr, secrecy_label);
            let operator = unary.op;
            quote::quote! {
                #operator #operand
            }
        }
        syn::Expr::Unsafe(unsafe_expr) => {
            quote::quote! {#unsafe_expr}
        }
        syn::Expr::Reference(reference) => {
            let operand = expand_expr(&*reference.expr, secrecy_label);
            match reference.mutability {
                Some(_) => {
                    quote::quote! {
                        &mut #operand
                    }
                }
                _ => {
                    quote::quote! {
                        &#operand
                    }
                }
            }
        }
        syn::Expr::Cast(cast) => {
            let expr = expand_expr(&*cast.expr, secrecy_label);
            let ty = &cast.ty;
            quote::quote! {
                #expr as #ty
            }
        }
        // TODO: Handle the other kinds of expressions
        expr => {
            let expr_display = proc_macro2::TokenStream::to_string(&quote! {#expr});
            let ts = proc_macro2::TokenStream::from_str(&format!(
                "r#\"secret_macros: Unrecognized syntax: {:?}.\"#",
                expr_display
            ))
            .unwrap_or(
                proc_macro2::TokenStream::from_str("\"secret_macros: Unrecognized syntax.\"")
                    .unwrap(),
            );

            // Note: in some contexts you need a semicolon to terminate the compile_error! macro.
            // In other contexts you don't.
            // If you see a compiler error like `error: custom attribute panicked` then try adding a semicolon to the compile_error! macro here to get a better message.
            quote::quote! {
                { compile_error!(#ts); }
            }
        }
    }
}
// Only forbids function calls and macros.
fn check_expr(expr: &syn::Expr, secrecy_label: &Option<syn::Type>, do_sbs_check: bool) -> proc_macro2::TokenStream {
    match expr {
        syn::Expr::Array(array_exp) => {
            let elements = comma_separate(
                array_exp.elems.iter().map(|expr| check_expr(expr, secrecy_label, true))
            );
            quote::quote!{
                [#elements]
            }
        }
        syn::Expr::Break(expr_break) => expr_break.into_token_stream(),
        syn::Expr::Call(expr_call) => {
            let args = comma_separate(expr_call.args.iter().map(
                |arg: &syn::Expr| -> proc_macro2::TokenStream { check_expr(arg, secrecy_label, true) },
            ));
            let _unchecked_args = comma_separate(
                expr_call.args.iter().map(|arg: &syn::Expr| -> proc_macro2::TokenStream { check_expr(arg, secrecy_label, true)}),
            );
            // It's okay to include #args in the unsafe block, because it's outside the unsafe block in the executed path (i.e., expand_expr)
            if is_call_to(expr_call, "unwrap_secret_ref") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    unsafe { ::secret_structs::secret::Secret::unwrap_unsafe::<#label>(#args) }
                }
            } else if is_call_to(expr_call, "unwrap_secret_mut_ref") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    unsafe { ::secret_structs::secret::Secret::unwrap_mut_unsafe::<#label>(#args) }
                }
            } else if is_call_to(expr_call, "unwrap_secret") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    unsafe { ::secret_structs::secret::Secret::unwrap_consume_unsafe::<#label>(#args) }
                }
            } else if is_call_to(expr_call, "wrap_secret") && secrecy_label.is_some() {
                let label = Some(secrecy_label).unwrap();
                quote::quote! {
                    unsafe { ::secret_structs::secret::Secret::<_,#label>::new(#args) }
                }
            } else if is_call_to(expr_call, "unchecked_operation") {
                let expr = expr_call.args.iter().nth(0);
                if let Some(block) = expr {
                    quote::quote! {#block}
                } else {
                    quote::quote! {compile_error!("unchecked_operation needs an operation.");}
                }
            } else if is_call_to_allowlisted_function(expr_call) {
                let args = comma_separate(expr_call.args.iter().map(
                    |arg: &syn::Expr| -> proc_macro2::TokenStream {
                        check_expr(arg, secrecy_label, true)
                    },
                ));
                let func = &*expr_call.func;
                make_check_secret_block_safe(quote::quote! { #func(#args) }, do_sbs_check)
            } else {
                let args = comma_separate(expr_call.args.iter().map(
                    |arg: &syn::Expr| -> proc_macro2::TokenStream {
                        check_expr(arg, secrecy_label, true)
                    },
                ));
                let func = &*expr_call.func;
                // An side_effect_free_attr function must return a InvisibleSideEffectFree type
                // TODO: Shouldn't evaluate #args inside of unsafe block
                /*make_check_secret_block_safe(*/quote::quote! { unsafe {(#func(#args) as ::secret_structs::secret::Vetted<_>).unwrap() } }/*, do_sbs_check)*/
            }
        }
        syn::Expr::Continue(continue_stmt) => continue_stmt.into_token_stream(),
        // TODO: Handle macros better. I think you can look at their token stream to get their expansion?
        syn::Expr::Macro(_) => quote::quote! { compile_error!("Function calls & macros are not allowed in secret blocks.") },
        syn::Expr::Binary(expr_binary) => {
            let op = expr_binary.op;

            // Outer SBS checks not needed because expressions have built-in types
            let new_expr_left: proc_macro2::TokenStream = check_expr(&expr_binary.left, secrecy_label, false);
            let new_expr_right = check_expr(&expr_binary.right, secrecy_label, false);
            match op {
                syn::BinOp::Add(_) => {
                    quote::quote! { ::secret_structs::secret::SafeAdd::safe_add(#new_expr_left, #new_expr_right) }
                }
                syn::BinOp::Sub(_) => {
                    quote::quote! { ::secret_structs::secret::SafeSub::safe_sub(#new_expr_left, #new_expr_right) }
                }
                syn::BinOp::Mul(_) => {
                    quote::quote! { ::secret_structs::secret::SafeMul::safe_mul(#new_expr_left, #new_expr_right) }
                }
                syn::BinOp::Div(_) => {
                    quote::quote! { ::secret_structs::secret::SafeDiv::safe_div(#new_expr_left, #new_expr_right) }
                }
                syn::BinOp::Ne(_) => {
                    quote::quote! { ::secret_structs::secret::SafePartialEq::safe_ne(&(#new_expr_left), &(#new_expr_right)) }
                }
                syn::BinOp::Eq(_) => {
                    quote::quote! { ::secret_structs::secret::SafePartialEq::safe_eq(&(#new_expr_left), &(#new_expr_right)) }
                }
                syn::BinOp::Le(_) => {
                    quote::quote! { ::secret_structs::secret::SafePartialOrd::safe_le(&(#new_expr_left), &(#new_expr_right)) }
                }
                syn::BinOp::Ge(_) => {
                    quote::quote! { ::secret_structs::secret::SafePartialOrd::safe_ge(&(#new_expr_left), &(#new_expr_right)) }
                }
                syn::BinOp::Gt(_) => {
                    quote::quote! { ::secret_structs::secret::SafePartialOrd::safe_gt(&(#new_expr_left), &(#new_expr_right)) }
                }
                syn::BinOp::Lt(_) => {
                    quote::quote! { ::secret_structs::secret::SafePartialOrd::safe_lt(&(#new_expr_left), &(#new_expr_right)) }
                }

                // these are not overloadable (shortcircuiting logical or/and)
                // https://doc.rust-lang.org/book/appendix-02-operators.html
                syn::BinOp::Or(_) | syn::BinOp::And(_) => {
                    // Outer SBS checks not needed because expressions have built-in types
                    let lhs = check_expr(&*expr_binary.left, secrecy_label, false);
                    let rhs = check_expr(&*expr_binary.right, secrecy_label, false);
                    quote::quote! {(#lhs)#op(#rhs)}
                }

                syn::BinOp::BitXor(_) => {
                    // Outer SBS checks not needed because expressions have built-in types (well, once we disallow overloading)
                    let lhs = check_expr(&*expr_binary.left, secrecy_label, false);
                    let rhs = check_expr(&*expr_binary.right, secrecy_label, false);
                    quote::quote! { ::secret_structs::secret::SafeBitXor::safe_bitxor(#lhs, #rhs) }
                }

                syn::BinOp::BitAnd(_) => {
                    // Outer SBS checks not needed because expressions have built-in types (well, once we disallow overloading)
                    let lhs = check_expr(&*expr_binary.left, secrecy_label, false);
                    let rhs = check_expr(&*expr_binary.right, secrecy_label, false);
                    quote::quote! { ::secret_structs::secret::SafeBitAnd::safe_bitand(#lhs, #rhs) }
                }
                // Disallows all other binary operators
                _op => {
                    let expr_display = proc_macro2::TokenStream::to_string(&quote! {#expr_binary});
                    let ts = proc_macro2::TokenStream::from_str(&format!(
                        "r#\"secret_macros: Unsupported binary operator: {:?}.\"#",
                        expr_display
                    ))
                    .unwrap_or(
                        proc_macro2::TokenStream::from_str(
                            "\"secret_macros: Unsupported binary operator.\"",
                        )
                        .unwrap(),
                    );
                    // Note: in some contexts you need a semicolon to terminate the compile_error! macro.
                    // In other contexts you don't.
                    // If you see a compiler error like `error: custom attribute panicked` then try adding a semicolon to the compile_error! macro here to get a better message.
                    quote::quote! {
                        { compile_error!(#ts); }
                    }
                }
            }
        }
        syn::Expr::If(expr_if) => {
            let condition = check_expr(&*expr_if.cond, secrecy_label, true);
            let then_block: proc_macro2::TokenStream =
                check_block(&expr_if.then_branch, secrecy_label).into();
            let else_branch = match &expr_if.else_branch {
                Some(block) => check_expr(&*block.1, secrecy_label, true),
                None => quote::quote! {},
            };

            // Shouldn't need to check the type of the if-then-else, since the type of the then_block and else_branch is being checked
            /*make_check_secret_block_safe(*/quote::quote! {
                if #condition {
                    #then_block
                } else {
                    #else_branch
                }
            }/*, do_sbs_check)*/
        }
        syn::Expr::Block(expr_block) => check_block(&expr_block.block, secrecy_label).into(),
        syn::Expr::Closure(closure_expr) => {
            let mut new_closure = closure_expr.clone();
            new_closure.body =
                Box::new(syn::parse2(check_expr(&new_closure.body, secrecy_label, true)).unwrap());
            new_closure.into_token_stream()
        }
        syn::Expr::Assign(assign_expr) => {
            // Set do_sbs_check for LHS of assignments, since it's an lvalue, not an rvalue
            let lhs: proc_macro2::TokenStream = check_expr(&assign_expr.left, secrecy_label, false).into();
            let rhs: proc_macro2::TokenStream =
                check_expr(&assign_expr.right, secrecy_label, true).into();
            make_check_secret_block_safe(
                quote::quote!{
                    *::secret_structs::secret::not_mut_secret(&mut #lhs) = #rhs
                },
                do_sbs_check
            )
        }
        syn::Expr::AssignOp(assign_op_expr) => {
            let op = assign_op_expr.op;

            // Outer SBS checks not needed because expressions have built-in types
            let new_expr_left: proc_macro2::TokenStream = check_expr(&make_mut_ref(*assign_op_expr.left.clone()), secrecy_label, false);
            let new_expr_right = check_expr(&assign_op_expr.right, secrecy_label, false);

            match op {
                syn::BinOp::AddEq(_) => {
                    quote::quote! { ::secret_structs::secret::SafeAddAssign::safe_add_assign(#new_expr_left, #new_expr_right) }
                }
                syn::BinOp::SubEq(_) => {
                    quote::quote! { ::secret_structs::secret::SafeSubAssign::safe_sub_assign(#new_expr_left, #new_expr_right) }
                }
                syn::BinOp::MulEq(_) => {
                    quote::quote! { ::secret_structs::secret::SafeMulAssign::safe_mul_assign(#new_expr_left, #new_expr_right) }
                }
                syn::BinOp::DivEq(_) => {
                    quote::quote! { ::secret_structs::secret::SafeDivAssign::safe_div_assign(#new_expr_left, #new_expr_right) }
                }
                // Disallows all other assignment operators
                _op => {
                    let expr_display =
                        proc_macro2::TokenStream::to_string(&quote! {#assign_op_expr});
                    let ts = proc_macro2::TokenStream::from_str(&format!(
                        "r#\"secret_macros: Unsupported binary operator: {:?}.\"#",
                        expr_display
                    ))
                    .unwrap_or(
                        proc_macro2::TokenStream::from_str(
                            "\"secret_macros: Unsupported binary operator.\"",
                        )
                        .unwrap(),
                    );
                    // Note: in some contexts you need a semicolon to terminate the compile_error! macro.
                    // In other contexts you don't.
                    // If you see a compiler error like `error: custom attribute panicked` then try adding a semicolon to the compile_error! macro here to get a better message.
                    quote::quote! {
                        { compile_error!(#ts); }
                    }
                }
            }
        }
        syn::Expr::MethodCall(method_call_expr) => {
            let receiver: proc_macro2::TokenStream =
                check_expr(&method_call_expr.receiver, secrecy_label, true).into();
            let args = comma_separate(method_call_expr.args.iter().map(
                |arg: &syn::Expr| -> proc_macro2::TokenStream { check_expr(arg, secrecy_label, true) },
            ));
            let method = &method_call_expr.method;
            let turbofish = &method_call_expr.turbofish;

            // Don't need an outer check since side_effect_free_attr methods are guaranteed to be InvisibleSideEffectFree
            // TODO: Shouldn't evaluate #args inside of unsafe block
            /*make_check_secret_block_safe(*/quote::quote! {
                ((&#receiver).#method#turbofish(#args) as ::secret_structs::secret::Vetted<_>).unwrap()
            }/*, do_sbs_check)*/
        }
        // Literals don't need checks
        syn::Expr::Lit(expr_lit) =>  {
            let e = expr_lit.into_token_stream();
            //make_check_secret_block_safe(e, do_sbs_check);
            e
        }
        syn::Expr::Field(field_access) => {
            let e: Expr  = syn::parse2(check_expr(&*(field_access.base), secrecy_label, true)).expect("ErrS");
            let e2: Expr = syn::parse2(quote::quote!{ (#e) }).expect("ErrS");
            let e3: Box<Expr> = Box::new(e2);
            let f_new = ExprField {
                attrs: field_access.attrs.clone(),
                base: e3,
                dot_token: field_access.dot_token.clone(),
                member: field_access.member.clone()
            };
            // Don't need check around whole expression because e.f is InvisibleSideEffectFree if e is
            f_new.into_token_stream()
        }
        syn::Expr::Paren(paren_expr) => {
            let interal_expr = check_expr(&paren_expr.expr, secrecy_label, do_sbs_check);
            let mut new_paren_expr = paren_expr.clone();
            new_paren_expr.expr = Box::new(syn::parse2(interal_expr).unwrap());
            new_paren_expr.into_token_stream()
        }
        // fix_sbs_checking: Path (e.g., an identifier) needs a check because VisibleSideEffectFree doesn't exclude all non-InvisibleSideEffectFree types from being captured
        syn::Expr::Path(path_access) => {
            let p = path_access.into_token_stream();
            make_check_secret_block_safe_ptr_read(p, do_sbs_check)
            //p
        }
        // Duplicate - commenting out in favor of latter case
        //syn::Expr::Range(range_expr) => {
        //    let mut new_range = range_expr.clone();
        //    new_range.from = new_range.from.and_then(
        //        |from| Some(
        //            Box::new(syn::parse2(check_expr(&from, secrecy_label, do_sbs_check)).unwrap())
        //        )
        //    );
        //    new_range.to = new_range.to.and_then(
        //        |from| Some(
        //            Box::new(syn::parse2(check_expr(&from, secrecy_label, do_sbs_check)).unwrap())
        //        )
        //    );
        //    quote::quote!{(#new_range)}
        //}
        syn::Expr::Struct(struct_literal) => {
            // Struct initializer expressions need checks
            let fields: syn::punctuated::Punctuated<FieldValue, Comma> = {
                let mut f = syn::punctuated::Punctuated::<FieldValue, Comma>::new();

                for field in struct_literal.clone().fields.iter() {
                    // The inner types don't need an SBS check because they are guaranteed to be InvisibleSideEffectFree because the outer type is guaranteed to be (because of check inserted below)
                    let e = syn::parse2(check_expr(&field.expr, secrecy_label, false)).expect("ErrS");
                    let fv = syn::FieldValue {
                        attrs: field.attrs.clone(),
                        member: field.member.clone(),
                        colon_token: field.colon_token.clone(),
                        expr: e
                    };
                    f.push(fv);
                }
                f
            };
            let struct_new = syn::ExprStruct {
                attrs: struct_literal.attrs.clone(),
                path: struct_literal.path.clone(),
                brace_token: struct_literal.brace_token.clone(),
                fields: fields,
                dot2_token: struct_literal.dot2_token.clone(),
                rest: struct_literal.rest.clone(),
            };
            let s = struct_new.into_token_stream();
            make_check_secret_block_safe(s, do_sbs_check)
        }
        // Duplicate
        //syn::Expr::Paren(expr_paren) => {
        //    let expr: proc_macro2::TokenStream = check_expr(&expr_paren.expr, secrecy_label, true).into();
        //    make_check_secret_block_safe(expr, do_sbs_check)
        //}
        syn::Expr::ForLoop(for_loop) => {
            // TODO: Does #pat need expansion?
            let pat = for_loop.pat.clone().into_token_stream();
            let expr: proc_macro2::TokenStream = check_expr(&*for_loop.expr, secrecy_label, true).into();
            let body: proc_macro2::TokenStream = check_block(&for_loop.body, secrecy_label).into();
            // We don't need to check the for loop, since its body and sub-expressions are checked.
            // make_check_secret_block_safe(quote::quote! {
            //     for #pat in #expr {
            //         #body
            //     }
            // }, do_sbs_check)
            quote::quote! {
                for #pat in #expr {
                    #body
                }
            }
        }
        syn::Expr::While(while_loop) => {
            let cond: proc_macro2::TokenStream =
                check_expr(&*while_loop.cond, secrecy_label, true).into();
            let body: proc_macro2::TokenStream =
                check_block(&while_loop.body, secrecy_label).into();
            // We don't need to check the while loop, since its body and sub-expressions are checked.
            /*make_check_secret_block_safe(*/quote::quote! {
                while #cond {
                    #body
                }
            }/*, do_sbs_check)*/
        }
        // TODO: Need to implement check for match -- wait, what still needs to be implemented?
        syn::Expr::Match(expr_match) => {
            let mut expr_match_copy = expr_match.clone();
            expr_match_copy.expr =
                Box::new(syn::parse2(check_expr(&*expr_match_copy.expr, secrecy_label, true)).unwrap());
            for arm in &mut expr_match_copy.arms {
                match &arm.guard {
                    Some((if_token, guard_expr_boxed)) => {
                        arm.guard = Some((
                            *if_token,
                            Box::new(
                                syn::parse2(check_expr(&*guard_expr_boxed, secrecy_label, true)).unwrap(),
                            ),
                        ))
                    }
                    _ => {}
                }
                arm.body = Box::new(syn::parse2(check_expr(&*arm.body, secrecy_label, true)).unwrap());
            }
            expr_match_copy.into_token_stream()
        }
        syn::Expr::Range(range) => {
            // Not one simple function call. Idea: have it call safe_start_bound and safe_end_bound but then still use the .. operator
            let mut range_copy = range.clone();
            match range_copy.from {
                Some(from) => range_copy.from = Some(syn::parse2(check_expr(&*from, secrecy_label, true)).unwrap()),
                _ => {},
            };
            match range_copy.to {
                Some(to) => range_copy.to = Some(syn::parse2(check_expr(&*to, secrecy_label, true)).unwrap()),
                _ => {},
            };
            //range_copy.into_token_stream();
            //let expr_display = proc_macro2::TokenStream::to_string(&quote! {#range});
            quote::quote! {
                ::secret_structs::secret::check_safe_range_bounds(#range)
            }
            // let ts = proc_macro2::TokenStream::from_str(&format!(
            //     "r#\"secret_macros: Unsupported binary operator: {:?}.\"#",
            //     expr_display
            // ))
            // .unwrap_or(
            //     proc_macro2::TokenStream::from_str(
            //         "\"secret_macros: Unsupported binary operator.\"",
            //     )
            //     .unwrap(),
            // );

            // Note: in some contexts you need a semicolon to terminate the compile_error! macro.
            // In other contexts you don't.
            // If you see a compiler error like `error: custom attribute panicked` then try adding a semicolon to the compile_error! macro here to get a better message.
            // quote::quote! {
            //     { compile_error!(#ts); }
            // }
        }
        syn::Expr::Repeat(repeat_expr) => {
            // An expression of the form `[value; length]`.
            // We don't need to actually check the length, since it must be a constant expression.
            let expr = check_expr(&repeat_expr.expr, secrecy_label, true);
            let mut new_repeat_expr = repeat_expr.clone();
            new_repeat_expr.expr = Box::new(syn::parse2(expr).unwrap());
            new_repeat_expr.len = repeat_expr.len.clone();
            quote::quote! { #new_repeat_expr }
        }
        syn::Expr::Return(return_expr) => {
            if let None = return_expr.expr {
                return return_expr.into_token_stream();
            }
            let mut new_return_expr = return_expr.clone();
            let expr = check_expr(&new_return_expr.expr.unwrap(), secrecy_label, true);
            new_return_expr.expr = Some(Box::new(syn::parse2(expr).unwrap()));
            new_return_expr.into_token_stream()
        }
        syn::Expr::Index(idx) => {
            // Outer expressions don't need checks since the arguments of safe_index must be built-in types
            let new_idx_expr: proc_macro2::TokenStream = check_expr(&idx.expr, secrecy_label, false);
            let new_idx_index = check_expr(&idx.index, secrecy_label, false);
            quote::quote! {
                ::secret_structs::secret::check_safe_index_expr(#new_idx_expr)[::secret_structs::secret::check_safe_index(#new_idx_index)]
            }
        }
        syn::Expr::Tuple(tuple) => {
            let args = comma_separate(
                tuple
                    .elems
                    .iter()
                    .map(|arg: &syn::Expr| -> proc_macro2::TokenStream { check_expr(arg, secrecy_label, true) }),
            );
            // Outer expression doesn't need checks since elements must be InvisibleSideEffectFree
            /*make_check_secret_block_safe(*/quote::quote!{(#args)}/*, do_sbs_check*/
        }
        syn::Expr::Unary(unary) => {
            let operator = unary.op;

            match operator {
                syn::UnOp::Deref(_) => {
                    let new_operand_expr = check_expr(&*unary.expr, secrecy_label, true);
                    // Outer expression doesn't need a check since operand must be InvisibleSideEffectFree
                    // make_check_secret_block_safe(quote::quote! { #operator(#operand) }, do_sbs_check)
                    quote::quote! { #operator(#new_operand_expr) }
                }
                syn::UnOp::Not(_) => {
                    // Expressions don't need InvisibleSideEffectFree checks because they're built-in types
                    let new_operand_expr: proc_macro2::TokenStream = check_expr(&unary.expr, secrecy_label, false);
                    quote::quote! { ::secret_structs::secret::SafeNot::safe_not(#new_operand_expr) }
                }
                syn::UnOp::Neg(_) => {
                    // Expressions don't need InvisibleSideEffectFree checks because they're built-in types
                    let new_operand_expr: proc_macro2::TokenStream = check_expr(&unary.expr, secrecy_label, false);
                    quote::quote! { ::secret_structs::secret::SafeNeg::safe_neg(#new_operand_expr) }
                }
            }
        }
        syn::Expr::Unsafe(unsafe_expr) => quote::quote! {#unsafe_expr},
        syn::Expr::Reference(reference) => {
            // fix_sbs_checking: do_sbs_check: true -> false because reference.expr will be checked below
            // TODO: Why put the check around &e instead of putting it around e?
            let operand = check_expr(&*reference.expr, secrecy_label, false);
            match reference.mutability {
                Some(_) => {
                    // fix_sbs_checking: We need a check around this expression because VisibleSideEffectFree doesn't exclude all non-SBS types from being captured
                    make_check_secret_block_safe_mut_ref(quote::quote! { &mut #operand }, do_sbs_check)
                    //quote::quote! { &mut #operand }
                }
                _ => {
                    // fix_sbs_checking: We need a check around this expression because VisibleSideEffectFree doesn't exclude all non-SBS types from being captured
                    make_check_secret_block_safe_ref(quote::quote! { &#operand }, do_sbs_check)
                    //quote::quote! { &#operand }
                }
            }
        }
        syn::Expr::Cast(cast) => {
            let expr = check_expr(&*cast.expr, secrecy_label, true);
            let ty = &cast.ty;
            make_check_secret_block_safe(quote::quote! { #expr as #ty }, do_sbs_check)
        }
        // TODO: Handle the other kinds of expressions
        expr => {
            let expr_display = proc_macro2::TokenStream::to_string(&quote! {#expr});
            let ts = proc_macro2::TokenStream::from_str(&format!(
                "r#\"secret_macros: Unrecognized syntax: {:?}.\"#",
                expr_display
            ))
            .unwrap_or(
                proc_macro2::TokenStream::from_str("\"secret_macros: Unrecognized syntax.\"")
                    .unwrap(),
            );

            // Note: in some contexts you need a semicolon to terminate the compile_error! macro.
            // In other contexts you don't.
            // If you see a compiler error like `error: custom attribute panicked` then try adding a semicolon to the compile_error! macro here to get a better message.
            quote::quote! {
                unsafe { compile_error!(#ts); }
            }
        }
    }
}

fn make_check_secret_block_safe(e: proc_macro2::TokenStream, do_check: bool) -> proc_macro2::TokenStream {
    if do_check {
        // TODO: The outer { } are needed or there's an error in millionaires
        quote::quote! {
            { ::secret_structs::secret::check_ISEF(#e) }
        }
    } else {
        e
    }
}

fn make_check_secret_block_safe_ptr_read(e: proc_macro2::TokenStream, do_check: bool) -> proc_macro2::TokenStream {
    if do_check {
        quote::quote! {
            { let tmp = &(#e); unsafe { ::secret_structs::secret::check_ISEF_unsafe(tmp) } }
        }
    } else {
        e
    }
}

fn make_check_secret_block_safe_ref(e: proc_macro2::TokenStream, do_check: bool) -> proc_macro2::TokenStream {
    if do_check {
        quote::quote! {
            { ::secret_structs::secret::check_expr_secret_block_safe_ref((#e)) }
        }
    } else {
        e
    }
}

fn make_check_secret_block_safe_mut_ref(e: proc_macro2::TokenStream, do_check: bool) -> proc_macro2::TokenStream {
    if do_check {
        quote::quote! {
            { ::secret_structs::secret::check_ISEF_mut_ref((#e)) }
        }
    } else {
        e
    }
}

// Helper function to get "&e" from "e"
fn _make_ref(e: Expr) -> Expr {
    syn::parse((quote::quote! {& #e } as proc_macro2::TokenStream).into()).unwrap()
}

// Helper function to get "&mut e" from "e"
fn make_mut_ref(e: Expr) -> Expr {
    syn::parse((quote::quote! {&mut #e } as proc_macro2::TokenStream).into()).unwrap()
}

fn check_block(input: &syn::Block, secrecy_label: &Option<syn::Type>) -> TokenStream {
    // We have to use proc_macro2::TokenStream here because it has an implementation
    // for ToTokens, but TokenStream does not implement.
    let token_streams: Vec<proc_macro2::TokenStream> = input
        .stmts
        .iter()
        .map(|stmt: &syn::Stmt| -> proc_macro2::TokenStream {
            match stmt {
                syn::Stmt::Local(local_expr) => match &local_expr.init {
                    // Check the right-hand side of a store.
                    Some((_, expr)) => {
                        let mut new_expr = local_expr.clone();
                        let new_init: Expr =
                            syn::parse(check_expr(expr, secrecy_label, true).into()).unwrap();
                        new_expr.init = Some((syn::token::Eq(expr.span()), Box::new(new_init)));
                        quote! {
                            #new_expr
                        }
                    }
                    None => local_expr.into_token_stream().into(),
                },
                //Unsure of if need check for Item
                syn::Stmt::Item(item) => {
                    match item {
                        // Const items can never have side-effects, so leave them alone.
                        syn::Item::Const(const_item) => const_item.into_token_stream(),
                        _ => {
                            let i = item.into_token_stream();
                            make_check_secret_block_safe(i, true)
                        }
                    }
                }
                syn::Stmt::Expr(expr) => check_expr(expr, secrecy_label, true),
                syn::Stmt::Semi(expr, _) => {
                    let expr_tokens = check_expr(expr, secrecy_label, true);
                    quote::quote! {
                        #expr_tokens;
                    }
                }
            }
        })
        .collect();
    let stream: proc_macro2::TokenStream = proc_macro2::TokenStream::from_iter(token_streams);
    let gen = quote::quote! {
        {
            #stream
        }
    };
    gen.into()
}

fn expand_block(input: &syn::Block, secrecy_label: &Option<syn::Type>) -> TokenStream {
    let token_streams: Vec<proc_macro2::TokenStream> = input
        .stmts
        .iter()
        .map(|stmt: &syn::Stmt| -> proc_macro2::TokenStream {
            match stmt {
                syn::Stmt::Local(local_expr) => match &local_expr.init {
                    // Check the right-hand side of a store.
                    Some((_, expr)) => {
                        let mut new_expr = local_expr.clone();
                        let new_init: Expr =
                            syn::parse(expand_expr(expr, secrecy_label).into()).unwrap();
                        new_expr.init = Some((syn::token::Eq(expr.span()), Box::new(new_init)));
                        quote! {
                            #new_expr
                        }
                    }
                    None => local_expr.into_token_stream().into(),
                },
                syn::Stmt::Item(item) => {
                    // Looking at the definition of Item, any Item should be fine.
                    item.into_token_stream().into()
                }
                syn::Stmt::Expr(expr) => expand_expr(expr, secrecy_label),
                syn::Stmt::Semi(expr, _) => {
                    let expr_tokens = expand_expr(expr, secrecy_label);
                    quote::quote! {
                        #expr_tokens;
                    }
                }
            }
        })
        .collect();
    let stream: proc_macro2::TokenStream = proc_macro2::TokenStream::from_iter(token_streams);
    let gen = quote::quote! {
        {
            #stream
        }
    };
    gen.into()
}
// Comma separates each of the tokens in the iterator of TokenStreams ts.
fn comma_separate<T: Iterator<Item = proc_macro2::TokenStream>>(ts: T) -> proc_macro2::TokenStream {
    ts.fold(
        proc_macro2::TokenStream::new(),
        |acc: proc_macro2::TokenStream,
         token: proc_macro2::TokenStream|
         -> proc_macro2::TokenStream {
            if acc.is_empty() {
                token
            } else {
                let ba: proc_macro2::TokenStream = acc.into();
                let bt: proc_macro2::TokenStream = token.into();
                quote! {#ba, #bt}
            }
        },
    )
}

fn get_trampoline_fn_name(fn_name: &str, special: &str) -> String {
    "__".to_owned() + fn_name + "_secret_trampoline"  + special
}

#[proc_macro_attribute]
pub fn side_effect_free_attr(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let fn_definition: syn::ItemFn = syn::parse(item).unwrap();
    let new_fn_name_checked = get_trampoline_fn_name(&fn_definition.sig.ident.to_string(), &"_checked".to_string());
    let new_fn_name_unchecked = get_trampoline_fn_name(&fn_definition.sig.ident.to_string(), &"_unchecked".to_string());

    // Get the names of the formal parameters of the function.
    let mut is_method = false;
    let param_names_vec: Vec<_> = fn_definition
        .sig
        .inputs
        .clone()
        .iter()
        .map(|arg| -> proc_macro2::TokenStream {
            match arg {
                syn::FnArg::Receiver(_) => {
                    is_method = true;
                    quote! {self}
                }
                syn::FnArg::Typed(t) => {
                    let name = &t.pat;
                    quote! {#name}
                }
            }
        })
        .collect();

    let param_names = if is_method {
        comma_separate(
            param_names_vec
                .iter()
                .map(|x| x.clone())
                .skip(1)
                .into_iter(),
        )
    } else {
        comma_separate(
            param_names_vec
                .iter()
                .map(|x| x.clone())
                .skip(0)
                .into_iter(),
        )
    };

    // Make a new unsafe function with the same name as the function the user defined.
    let fn_access = fn_definition.vis.clone();
    let fn_sig = fn_definition.sig.clone();
    let fn_const = fn_definition.sig.constness;
    let fn_name = fn_sig.ident;
    let fn_args = fn_sig.inputs;
    let fn_return_type = match fn_sig.output {
        syn::ReturnType::Default => quote! {()},
        syn::ReturnType::Type(_, t) => {
            let t = *t;
            quote! { #t }
        }
    };
    let generic_params = fn_sig.generics.params;
    let where_clause = match fn_sig.generics.where_clause {
        Some(clause) => quote::quote! {#clause},
        _ => quote::quote! {}
    };

    let mut new_fn_definition_unchecked = fn_definition.clone();
    let new_fn_name_unchecked = Ident::new(&new_fn_name_unchecked, fn_definition.span());
    new_fn_definition_unchecked.sig.ident = new_fn_name_unchecked.clone();
    new_fn_definition_unchecked.block =
        Box::new(syn::parse(expand_block(&*(new_fn_definition_unchecked.block), &None)).unwrap());

    let mut new_fn_definition_checked = fn_definition.clone();
    let new_fn_name_checked = Ident::new(&new_fn_name_checked, fn_definition.span());
    new_fn_definition_checked.sig.ident = new_fn_name_checked.clone();
    new_fn_definition_checked.block = Box::new(syn::parse(check_block(&*(new_fn_definition_checked.block), &None)).unwrap());

    let self_block = if is_method {
        quote! {self.}
    } else {
        quote! {}
    };

    let gen = quote! {
        #new_fn_definition_unchecked
        
        #new_fn_definition_checked

        #[inline(always)]
        #fn_access #fn_const unsafe fn #fn_name<#generic_params>(#fn_args) -> ::secret_structs::secret::Vetted<#fn_return_type> #where_clause {
            //if true {
                ::secret_structs::secret::Vetted::<#fn_return_type>::wrap(#self_block#new_fn_name_unchecked(#param_names))
            //} else {
            //    ::secret_structs::secret::Vetted::<#fn_return_type>::wrap(#self_block#new_fn_name_checked(#param_names))
            //}
        }
    };

    gen.into()
}

// Based on https://blog.turbo.fish/proc-macro-simple-derive/
#[proc_macro_derive(InvisibleSideEffectFreeDerive)]
pub fn secret_block_safe_macro(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);

    let fields = match input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields.named,
        _ => panic!("this derive macro only works on structs with named fields"),
    };

    let st_name = input.ident;
    let st_generics = input.generics;
    let st_generics_params = st_generics.clone().params;
    let st_generics_names = st_generics_params
        .into_iter()
        .map(|p: syn::GenericParam| match p {
            syn::GenericParam::Type(y) => y.ident,
            _ => panic!("can only support GenericParam::Type, not other GenericParam::*"),
        });
    let st_generics_names: proc_macro2::TokenStream = quote! {
        <#(#st_generics_names,)*>
    };
    let st_where_clause = st_generics.clone().where_clause;

    let getters = fields.into_iter().map(|f| {
        // Interpolation only works for variables, not arbitrary expressions.
        // That's why we need to move these fields into local variables first
        // (borrowing would also work though).
        let _field_name = f.ident.unwrap();
        let field_ty = f.ty;
        quote! {
            ::secret_structs::secret::check_type_is_secret_block_safe::<#field_ty>();
        }
    });

    // Build the output, possibly using quasi-quotation
    let expanded: proc_macro2::TokenStream = quote! {
        #[automatically_derived]
        unsafe impl #st_generics ::secret_structs::secret::InvisibleSideEffectFree for #st_name #st_generics_names #st_where_clause {
            unsafe fn check_all_types() {
                #(#getters)*
            }
        }
        #[automatically_derived]
        impl #st_generics !::std::ops::Drop for #st_name #st_generics_names #st_where_clause {}
        #[automatically_derived]
        impl #st_generics !::std::ops::Deref for #st_name #st_generics_names #st_where_clause {}
        #[automatically_derived]
        impl #st_generics !::std::ops::DerefMut for #st_name #st_generics_names #st_where_clause {}
    };

    // Hand the output tokens back to the compiler
    TokenStream::from(expanded)
}
