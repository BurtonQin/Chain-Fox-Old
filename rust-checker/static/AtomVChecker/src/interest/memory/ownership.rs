extern crate rustc_hir;
extern crate rustc_middle;

use regex::Regex;
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{SubstsRef, TyCtxt};

/// y = Arc::clone(x)
pub fn is_arc_or_rc_clone<'tcx>(def_id: DefId, substs: SubstsRef<'tcx>, tcx: TyCtxt<'tcx>) -> bool {
    let fn_name = tcx.def_path_str(def_id);
    if fn_name != "std::clone::Clone::clone" {
        return false;
    }
    
    if let &[arg] = substs.as_ref() {
        let arg_ty_name = format!("{:?}", arg);
        if is_arc(&arg_ty_name) || is_rc(&arg_ty_name) {
            return true;
        }
    }
    false
}

#[inline]
pub fn is_arc(arg_ty_name: &str) -> bool {
    arg_ty_name.starts_with("std::sync::Arc<")
}

#[inline]
pub fn is_rc(arg_ty_name: &str) -> bool {
    arg_ty_name.starts_with("std::rc::Rc<")
}

#[inline]
pub fn is_get_unchecked(def_id: DefId, tcx: TyCtxt<'_>) -> bool {
    tcx.def_path_str(def_id).contains("get_unchecked")
}

#[inline]
pub fn is_atomic_operate(def_id: DefId, tcx: TyCtxt<'_>) -> bool {
    let re = Regex::new(r"^(std|core)::sync::atomic::((Atomic[A-Za-z]+(::<.*?>)?)(::)?(load|store|swap|compare_exchange(_weak)?|fetch_(add|sub|or|update|max|xor)|compare_and_swap))").unwrap(); //|atomic_
    let func_name = tcx.def_path_str(def_id);
    re.is_match(&func_name)
    
}

#[inline]
pub fn is_ptr_operate(def_id: DefId, tcx: TyCtxt<'_>) -> bool {
    let func = tcx.def_path_str(def_id);
    let re = Regex::new(r"^std::ptr::mut_ptr::<.*>::(add|offset)").unwrap();
    re.is_match(&func) || tcx.def_path_str(def_id).starts_with("std::ptr::read::<") 
}

#[inline]
pub fn is_addr(def_id: DefId, tcx: TyCtxt<'_>) -> bool {
    tcx.def_path_str(def_id).ends_with("addr")
}

#[inline]
pub fn is_null(def_id: DefId, tcx: TyCtxt<'_>) -> bool {
    tcx.def_path_str(def_id).ends_with("is_null")
}

#[inline]
pub fn is_smart_pointers(def_id: DefId, tcx: TyCtxt<'_>) -> bool {
    tcx.def_path_str(def_id).ends_with("from_raw") || tcx.def_path_str(def_id).ends_with("into_raw")
}