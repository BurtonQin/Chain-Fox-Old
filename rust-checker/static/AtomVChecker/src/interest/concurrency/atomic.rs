//! Find atomic functions and classify them into read, write, read-write.
extern crate rustc_hash;
extern crate rustc_middle;
extern crate rustc_hir;

use std::cmp::{Ordering, PartialOrd};
use std::collections::HashMap;
use crate::analysis::datadep;
use crate::detector::atomic;
use rustc_middle::mir::{Body, Local, Place, TerminatorKind, Operand, StatementKind, Rvalue, BasicBlockData, PlaceRef};
use crate::analysis::pointsto::{AliasAnalysis, AliasId, ConstraintNode};
use rustc_middle::ty::{Instance, TyCtxt, self};
use crate::analysis::callgraph::{CallGraph, InstanceId};
use petgraph::Direction::Incoming;


#[cfg(test)]
mod tests {
    #[test]
    fn test_atomic_api_regex() {
        use regex::Regex; 
        let line :usize = 177;
        let mut r = r"ident: (?P<title>[0-9a-zA-Z]*)[#0-9]*, hir_id:[\sA-Za-z0-9({:})~_]*\[[0-9a-zA-Z]*\][0-9a-zA-Z:),\s_)}(]*[{0-9a-zA-Z#}:), _()]*[\] }),]*span: [a-zA-Z/.:]*".to_string();
        let line = format!("{:?}", line);
        r = r + &line;
        let re: &str = &r[..];
        let re = Regex::new(re).unwrap();
        let haystack = "::{constructor#0})), segments: [PathSegment { ident: Relaxed#0, hir_id: Some(HirId { owner: DefId(0:58 ~ RUSTSEC_2022_0029[64b1]::{impl#3}::push), local_id: 205 }), res: Some(Err), args: None, infer_args: true }] })), span: src/main.rs:177:57:";
        match re.captures(haystack) {
            None =>{},
            Some(caps) => {
                let ordering = caps["title"].to_string();
                println!("result:{:?}", ordering);
            }
        }
    }
}

// #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AtomicOrd {
    SeqCst,
    AcqRel,
    Acquire,
    Release,
    Relaxed,
}

impl PartialOrd for AtomicOrd {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        use AtomicOrd::*;
        match (*self, *other) {
            (SeqCst, SeqCst)
            | (AcqRel, AcqRel)
            | (Acquire, Acquire)
            | (Acquire, Release)
            | (Release, Acquire)
            | (Release, Release) 
            | (Relaxed, Relaxed)=> Some(Ordering::Equal),
            (SeqCst, _) | (Acquire, Relaxed) | (Release, Relaxed) | (AcqRel, Relaxed) | (AcqRel, Acquire) | (AcqRel, Release)=> {
                Some(Ordering::Greater)
            }
            (_, SeqCst) | (Relaxed, Release) | (Relaxed, Acquire) | (Relaxed, AcqRel) | (Acquire, AcqRel) | (Release, AcqRel)=> {
                Some(Ordering::Less)
            }
        }
    }
}

impl Default for AtomicOrd {
    fn default() -> Self {
        AtomicOrd::SeqCst
    }
}

impl AtomicOrd {
    fn from_ordering<'a>(basic_block_data: &'a BasicBlockData<'a>, place: &Place) -> Option<Self> {
        for statement in &basic_block_data.statements {
            if let StatementKind::Assign(box (assigned_place, rvalue)) = &statement.kind {
                if assigned_place.local == place.local {
                    if let Rvalue::Use(operand) = rvalue {
                        if let Operand::Constant(_) = operand {
                            let ordering = format!("{:?}", operand);
                            if ordering.ends_with("Relaxed") {
                                return Some(AtomicOrd::Relaxed);
                            } else if ordering.ends_with("Acquire") {
                                return Some(AtomicOrd::Acquire);
                            } else if ordering.ends_with("Release") {
                                return Some(AtomicOrd::Release);
                            } else if ordering.ends_with("AcqRel") {
                                return Some(AtomicOrd::AcqRel);
                            } else if ordering.ends_with("SeqCst") {
                                return Some(AtomicOrd::SeqCst);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub enum AtomicInstructions {
    CompareExchange,
    Load,
    Store,
    ReadModifyWrite,
}

impl AtomicInstructions {
    pub fn from_instance<'tcx>(instance: Instance<'tcx>, tcx: TyCtxt<'tcx>) -> Option<Self> {
        let path = tcx.def_path_str_with_substs(instance.def_id(), instance.substs);
        let rmw_operations = ["swap", "fetch_add", "fetch_sub", "fetch_max", "fetch_or", "fetch_xor", "fetch_min", "compare_and_swap"];
        if path.ends_with("compare_exchange") || path.ends_with("compare_exchange_weak") || path.ends_with("fetch_update") {
            Some(AtomicInstructions::CompareExchange)
        } else if path.ends_with("load") {
            Some(AtomicInstructions::Load)
        } else if path.ends_with("store") {
            Some(AtomicInstructions::Store)
        } else if rmw_operations.iter().any(|op| path.ends_with(op)) {
            Some(AtomicInstructions::ReadModifyWrite)
        } else {
            None
        }
    }
}

pub struct AtomicCollector<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    instance_id: InstanceId,
    instance: &'a Instance<'tcx>,
    pub atomics: Vec<AtomicInfo<'tcx>>, //AtomicMap<'tcx>,
}

impl<'a, 'tcx> AtomicCollector<'a, 'tcx>{
    pub fn new(tcx: TyCtxt<'tcx>,
        instance_id: InstanceId,
        instance: &'a Instance<'tcx>,
    ) -> Self {
        Self {
            tcx,
            instance_id,
            instance,
            atomics: Vec::new(),//Default::default(),
        }
    }

    pub fn analyze(&mut self, callgraph: &CallGraph<'tcx>){
        let callers: Vec<InstanceId> = callgraph.graph.neighbors_directed(self.instance_id, Incoming).collect();
        for caller in callers {
            let instance_node = callgraph.index_to_instance(caller).unwrap();
            let caller_instance = instance_node.instance();           
            let body = self.tcx.instance_mir(caller_instance.def); 
            let callsites = atomic::callsite_locations(callgraph, caller, self.instance_id);
            for callsite in callsites.unwrap() {
                if let TerminatorKind::Call {
                    func: _func,
                    args,
                    destination,
                    fn_span,
                    ..
                } = &body[callsite.block].terminator().kind
                {   
                    let atomic_operate: Option<AtomicInstructions> = AtomicInstructions::from_instance(*self.instance, self.tcx);
                    let mut ordering_type = Vec::new();
                    let mut atomic_arg: Option<Place<'tcx>> = None;
                    let mut influence_value: Vec<Place<'tcx>> = Vec::new();
                    let source_info = self.tcx.sess.source_map().span_to_diagnostic_string(*fn_span);
                    if source_info.contains(".cargo") {
                        continue;
                    }
                    if let Some(operate) = atomic_operate {
                        match operate {
                            AtomicInstructions::CompareExchange => {
                                // _14 = AtomicPtr::<Waiter>::compare_exchange(move _15, move _16, move _17, move _20, move _21) -> bb7;
                                atomic_arg = args.get(0).unwrap().place();

                                influence_value.push(*destination);

                                let write_value = args.get(2).and_then(|arg1| arg1.place());
                                if let Some(place) = write_value {
                                    influence_value.push(place);
                                }

                                let succ_ordering_place = args.get(3).and_then(|arg1| arg1.place()).unwrap();
                                if let Some(succ_ordering) = AtomicOrd::from_ordering(&body[callsite.block], &succ_ordering_place) {
                                    ordering_type.push(succ_ordering);
                                }
                                // ordering_type.push(AtomicOrd::from_ordering(&body[callsite.block], &succ_ordering_place));
                                let fail_ordering_place = args.get(4).and_then(|arg1| arg1.place()).unwrap();
                                if let Some(fail_ordering) = AtomicOrd::from_ordering(&body[callsite.block], &fail_ordering_place) {
                                    ordering_type.push(fail_ordering);
                                }
                                
                                // ordering_type.push(AtomicOrd::from_ordering(&body[callsite.block], &fail_ordering_place));
                            },
                            AtomicInstructions::Load => {
                                // _3 = AtomicPtr::<Waiter>::load(move _4, move _5) -> bb1;
                                atomic_arg = args.get(0).unwrap().place();

                                influence_value.push(*destination);

                                let ordering_place = args.get(1).and_then(|arg1| arg1.place()).unwrap();
                                if let Some(ordering) = AtomicOrd::from_ordering(&body[callsite.block], &ordering_place) {
                                    ordering_type.push(ordering);
                                }
                                // ordering_type.push(AtomicOrd::from_ordering(&body[callsite.block], &ordering_place))
                            },
                            AtomicInstructions::Store => {
                                // _36 = AtomicBool::store(move _37, const true, move _38) -> [return: bb10, unwind: bb13];
                                atomic_arg = args.get(0).unwrap().place();

                                let write_place = args.get(1).and_then(|arg1| arg1.place());
                                if let Some(place) = write_place {
                                    influence_value.push(place);
                                }

                                let ordering_place = args.get(2).and_then(|arg1| arg1.place()).unwrap();
                                if let Some(ordering) = AtomicOrd::from_ordering(&body[callsite.block], &ordering_place) {
                                    ordering_type.push(ordering);
                                }
                                // ordering_type.push(AtomicOrd::from_ordering(&body[callsite.block], &ordering_place))
                            },
                            AtomicInstructions::ReadModifyWrite => {
                                // _2 = AtomicPtr::<Waiter>::swap(move _3, move _4, move _5) -> bb1;
                                let path = self.tcx.def_path_str_with_substs(self.instance.def_id(), self.instance.substs);
                                if path.ends_with("compare_and_swap") {
                                    atomic_arg = args.get(0).unwrap().place();

                                    influence_value.push(*destination);

                                    let write_value = args.get(2).and_then(|arg1| arg1.place());
                                    if let Some(place) = write_value {
                                        influence_value.push(place);
                                    }
                                    let ordering_place = args.get(3).and_then(|arg1| arg1.place()).unwrap();
                                    if let Some(ordering) = AtomicOrd::from_ordering(&body[callsite.block], &ordering_place) {
                                        ordering_type.push(ordering);
                                    }
                                    // ordering_type.push(AtomicOrd::from_ordering(&body[callsite.block], &ordering_place))
                                } else {
                                    atomic_arg = args.get(0).unwrap().place();

                                    influence_value.push(*destination);

                                    let write_value = args.get(1).and_then(|arg1| arg1.place());
                                    if let Some(place) = write_value {
                                        influence_value.push(place);
                                    }

                                    let ordering_place = args.get(2).and_then(|arg1| arg1.place()).unwrap();
                                    if let Some(ordering) = AtomicOrd::from_ordering(&body[callsite.block], &ordering_place) {
                                        ordering_type.push(ordering);
                                    }
                                    // ordering_type.push(AtomicOrd::from_ordering(&body[callsite.block], &ordering_place))
                                }
                            },
                        }
                    }
                    // If the ordering_type is null, the memory ordering of this atomic operation is specified by the user,
                    // ignoring the analysis of this atomic operation
                    if !ordering_type.is_empty() {
                        let atomic_collertor = 
                        AtomicInfo::new(atomic_arg
                            ,influence_value
                            ,atomic_operate
                            ,caller
                            ,ordering_type
                            ,source_info
                        );
                        self.atomics.push(atomic_collertor);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AtomicInfo<'tcx> {
    pub atomic_place: Option<Place<'tcx>>,
    pub atomic_value: Vec<Place<'tcx>>,
    pub atomic_operate: Option<AtomicInstructions>,
    pub caller_instance: InstanceId,
    pub ordering: Vec<AtomicOrd>,
    pub source_info: String,
}

impl<'tcx> AtomicInfo<'tcx> {
    pub fn new(
        atomic_place: Option<Place<'tcx>>, 
        atomic_value: Vec<Place<'tcx>>, 
        atomic_operate: Option<AtomicInstructions>, 
        caller_instance: InstanceId,
        ordering: Vec<AtomicOrd>,
        source_info: String
    ) -> Self {
        Self {
            atomic_place,
            atomic_value,
            atomic_operate,
            caller_instance,
            ordering,
            source_info,
        }
    }

   
}

#[derive(Clone)]
pub struct AtomPart<'tcx> {
    tcx: TyCtxt<'tcx>,
    pub atom_info: AtomicInfo<'tcx>,
    pub partner: Vec<(AtomicInfo<'tcx>, Vec<Local>)>,
    pub partner_atomptr: Vec<(AtomicInfo<'tcx>, Vec<Local>)>,
}

impl<'tcx> AtomPart<'tcx> {
    pub fn new(tcx: TyCtxt<'tcx>, atom_info: AtomicInfo<'tcx>) -> AtomPart<'tcx> {
        AtomPart {
            tcx,
            atom_info,
            partner: Vec::new(),
            partner_atomptr: Vec::new(),
        }
    }

    pub fn from_adt(body: &Body<'_>, place_ref: &PlaceRef<'_>) -> bool {
        match body.local_decls[place_ref.local].ty.kind() {
            ty::TyKind::Adt(_, _) => {
                return true;
            },
            ty::TyKind::Array(var_ty, _) |
            ty::TyKind::Slice(var_ty) |
            ty::TyKind::Ref(_, var_ty, _)  => {
                if let ty::TyKind::Adt(_, _) = var_ty.kind() {
                    return true;
                }
            },
            ty::TyKind::RawPtr(var_ty) => {
                if let ty::TyKind::Adt(_, _) = var_ty.ty.kind() {
                    return true;
                }
            },
            _ => {},
        }
        return false;
    }

    pub fn classify_atomic(&self, callgraph: &CallGraph<'tcx>) -> HashMap<String, Vec<(AtomicInfo<'tcx>, Vec<Local>)>> {
        let mut parts_map: HashMap<String, Vec<(AtomicInfo<'_>, Vec<Local>)>> = HashMap::new(); // rustc_middle::mir::ProjectionElem<Local, ty::Ty<'_>>  rustc_middle::mir::ProjectionElem<Local, ty::Ty<'tcx>>
    
        for (atomic, interival) in &self.partner {
            let inst = callgraph.index_to_instance(atomic.caller_instance);
            let body = self.tcx.instance_mir(inst.unwrap().instance().def); 
            let atomic_alias = AliasId {
                instance_id: self.atom_info.caller_instance,
                local: self.atom_info.atomic_place.unwrap().local,
            };
            let mut alias_analysis = AliasAnalysis::new(self.tcx); 
            let node = ConstraintNode::Place(Place::from(atomic_alias.local).as_ref());
            let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
            if let Some(ptses) = points_to_map.get(&node) {
                for pts_node in ptses {
                    if let ConstraintNode::Alloc(place_ref) | 
                        ConstraintNode::Place(place_ref) = pts_node {
                        if !place_ref.projection.is_empty() && Self::from_adt(body, place_ref){
                            let key = place_ref.projection[0].clone();
                            let atomic_clone = atomic.clone();  
                            let interival_clone = interival.clone();  
    
                            parts_map.entry(format!("{:?}", key))
                                .or_insert_with(Vec::new)
                                .push((atomic_clone, interival_clone));
                            break;
                        }
                    }
                    if let ConstraintNode::ConstantDeref(const_ref) = pts_node {
                        if let Some(alloc) = const_ref.try_to_value(self.tcx) {
                            let key = format!("{:?}", alloc);
                            let atomic_clone = atomic.clone();  
                            let interival_clone = interival.clone(); 
                            parts_map.entry(key)
                                .or_insert_with(Vec::new)
                                .push((atomic_clone, interival_clone));
                            break;
                        }
                    }

                }
            }
        }
    
        parts_map
    }

    // TODO
    // Correlated vars often appear near atomic operations, But sometimes here I want to get correlation vars, the
    // correlation variable may appear outside the function of the atomic operation (there are not many such scenarios), 
    // so when the local before and after the atomic operation is less than 30%, the heuristic thought that it may be 
    // associated with some local outside the function.
    pub fn infer_interival(&mut self, callgraph: &CallGraph<'tcx>) {
        let inst = callgraph.index_to_instance(self.atom_info.caller_instance);
        let body = self.tcx.instance_mir(inst.unwrap().instance().def); 
        let mut interim_val = Vec::new();
        let vars_and_temps = body.vars_and_temps_iter().collect::<Vec<_>>();
        let total = vars_and_temps.len(); 
        let atomic_place_local = self.atom_info.atomic_place.unwrap().local;
        let index = vars_and_temps.iter().position(|&x| x == atomic_place_local).unwrap_or(0); 
        let range = (total as f64 * 0.3).round() as usize;
        match self.atom_info.atomic_operate.unwrap() {
            AtomicInstructions::Store => {
                // 只保存 index 前 30% 的 local
                let start = if index >= range { index - range } else { 0 };
                interim_val.extend(vars_and_temps[start..index].iter().copied());
            },
            AtomicInstructions::Load => {
                // 只保存 index 后 30% 的 local
                let end = usize::min(index + range, total);
                if index == 0 {
                    interim_val.extend(vars_and_temps[index..end].iter().copied());
                } else {
                    interim_val.extend(vars_and_temps[index + 1..end].iter().copied());
                }
            },
            AtomicInstructions::ReadModifyWrite | AtomicInstructions::CompareExchange => {
                // 保存 index 前后 30% 的 local
                let start = if index >= range { index - range } else { 0 };
                let end = usize::min(index + range, total);
                interim_val.extend(vars_and_temps[start..end-1].iter().copied());
            },
        }
        self.partner.push((self.atom_info.clone(), interim_val));
    }


    pub fn infer_atomptr_interival(&mut self, callgraph: &CallGraph<'tcx>) {
        let inst = callgraph.index_to_instance(self.atom_info.caller_instance);
        let body = self.tcx.instance_mir(inst.unwrap().instance().def); 
        let mut interim_val = Vec::new();
    
        let mut alias_analysis = AliasAnalysis::new(self.tcx); 
        // Get data dependency
        let data_deps = datadep::data_deps(body);
        
        match self.atom_info.atomic_operate.unwrap() {
            AtomicInstructions::CompareExchange => {
                let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
                let atomic_node = ConstraintNode::Place(Place::from(self.atom_info.atomic_value[1].local).as_ref());
                let atomic_pts = points_to_map.get(&atomic_node).unwrap();
                interim_val = atomic_pts.iter().filter_map(|atomic_node| {
                    match atomic_node {
                        ConstraintNode::Alloc(place) | ConstraintNode::Place(place) 
                            if place.local.index() < self.atom_info.atomic_value[1].local.index()
                            && place.local != self.atom_info.atomic_value[0].local => {
                                Some(place.local)
                        },
                        _ => None,
                    }
                }).collect();
                interim_val.push(self.atom_info.atomic_value[1].local);
                
                // Collect the load semantic association variable of atomicptr
                let local = self.atom_info.atomic_value[0].local;
                interim_val.push(local.clone());
                // Obtain the data flow of a specific local
                let deps = datadep::all_data_dep_on(local, &data_deps, callgraph, self.atom_info.caller_instance, body, self.tcx);
                for dep in deps {
                    if dep.index() > self.atom_info.atomic_value[0].local.index() 
                        && dep != self.atom_info.atomic_value[1].local {
                        interim_val.push(dep);
                    }
                }
                
            },
            AtomicInstructions::Load => {
                let local = self.atom_info.atomic_value[0].local;
                // Obtain the data flow of a specific local
                let deps = datadep::all_data_dep_on(local, &data_deps, callgraph, self.atom_info.caller_instance, body, self.tcx);
                interim_val.push(self.atom_info.atomic_value[0].local);
                for dep in deps {
                    if dep.index() > self.atom_info.atomic_value[0].local.index() {
                        interim_val.push(dep);
                    }
                }
            },
            AtomicInstructions::Store => {
                let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
                let atomic_node = ConstraintNode::Place(Place::from(self.atom_info.atomic_value[0].local).as_ref());
                let atomic_pts = points_to_map.get(&atomic_node);
                if let Some(atomic_pts) = atomic_pts {
                    // Collect the store semantic association variable of atomicptr
                    interim_val = atomic_pts.iter().filter_map(|atomic_node| {
                        match atomic_node {
                            ConstraintNode::Alloc(place) | ConstraintNode::Place(place) 
                                if place.local.index() < self.atom_info.atomic_value[0].local.index() => {
                                    Some(place.local)
                            },
                            _ => None,
                        }
                    }).collect();
                }
                interim_val.push(self.atom_info.atomic_value[0].local);
            },
            AtomicInstructions::ReadModifyWrite => {
                let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
                let atomic_node = ConstraintNode::Place(Place::from(self.atom_info.atomic_value[1].local).as_ref());
                let atomic_pts = points_to_map.get(&atomic_node);
                if let Some(atomic_pts) = atomic_pts {                 
                    // Collect the store semantic association variable of atomicptr
                    interim_val = atomic_pts.iter().filter_map(|atomic_node| {
                        match atomic_node {
                            ConstraintNode::Alloc(place) | ConstraintNode::Place(place) 
                                if place.local.index() < self.atom_info.atomic_value[1].local.index()
                                    && place.local != self.atom_info.atomic_value[0].local => {
                                    Some(place.local)
                            },
                            _ => None,
                        }
                    }).collect();
                }
                interim_val.push(self.atom_info.atomic_value[1].local);

                // Collect the load semantic association variable of atomicptr

                let local = self.atom_info.atomic_value[0].local;

                interim_val.push(local.clone());
                // Obtain the data flow of a specific local
                let deps = datadep::all_data_dep_on(local, &data_deps, callgraph, self.atom_info.caller_instance, body, self.tcx);
                for dep in deps {
                    if dep.index() > self.atom_info.atomic_value[0].local.index() 
                        && dep != self.atom_info.atomic_value[1].local {
                        interim_val.push(dep);
                    }
                }
            },
        }
        self.partner.push((self.atom_info.clone(), interim_val));
    }

}