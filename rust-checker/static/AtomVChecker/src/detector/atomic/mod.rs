//! Detect atomicity violation caused by misuse of atomic variables.
//! Currently only support the following two patterns:
//! ```no_run
//! // atomic::store is control dep on atomic::load
//! if atomic.load(order) == v1 {
//!     atomic.store(v2, order);
//! }
//!
//! // atomic::store is data dep on atomic::load
//! let v1 = atomic_load(order);
//! let v2 = v1 + 1;
//! atomic.store(v2, order);
//! ```
extern crate rustc_data_structures;
extern crate rustc_hash;
extern crate rustc_middle;
extern crate rustc_codegen_ssa;
extern crate rustc_hir;
extern crate rustc_index;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use regex::Regex;
use rustc_middle::mir::{Body, Local, Location, Place, PlaceRef, ProjectionElem};
use rustc_middle::ty::TyCtxt;
use log::{debug, warn};


pub mod report;
use crate::analysis::callgraph::{CallGraph, InstanceId, CallGraphNode};
use crate::analysis::controldep;
use crate::analysis::datadep;
use crate::analysis::defuse;
use crate::analysis::pointsto::{AliasAnalysis, ConstraintNode};
use crate::detector::atomic::report::AtomicityViolationDiagnosis;
use crate::detector::report::{Report, ReportContent};
use crate::interest::concurrency::atomic::{AtomicCollector, AtomicInfo, AtomicInstructions, AtomicOrd, AtomPart};

use petgraph::visit::IntoNodeReferences;

pub struct CorrelationAnalyzer<'tcx> {
    tcx: TyCtxt<'tcx>,
    partner: (AtomicInfo<'tcx>, Vec<Local>),
    // interimval_map: HashMap<Local, Option<HashSet<ConstraintNode<'tcx>, BuildHasherDefault<FxHasher>>>>, // HashMap<Local, Option<&HashSet<ConstraintNode<'tcx>, BuildHasherDefault<FxHasher>>>>,
    correlations: HashSet<PlaceRef<'tcx>>,
}

impl<'tcx> CorrelationAnalyzer<'tcx> {
    pub fn new(
        tcx: TyCtxt<'tcx>,
        partner: (AtomicInfo<'tcx>, Vec<Local>),
    ) -> Self {
        Self { 
            tcx,
            partner,
            // interimval_map: HashMap::new(),
            correlations: HashSet::new(),
        }
    }

    pub fn resolve_load_collelation(&mut self, callgraph: &CallGraph<'tcx>) {
        let (atomic_info, interim_val) = self.partner.clone();
        let inst = callgraph.index_to_instance(atomic_info.caller_instance);
        let body = self.tcx.instance_mir(inst.unwrap().instance().def); 
        let mut corrlations = HashSet::new();
        let mut alias_analysis = AliasAnalysis::new(self.tcx); 
        let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
        if let Some(AtomicInstructions::CompareExchange) | Some(AtomicInstructions::ReadModifyWrite) = atomic_info.atomic_operate {
            if let Some(position) = interim_val.iter().position(|&x| x == atomic_info.atomic_place.unwrap().local) {
                let atomic_node = ConstraintNode::Place(Place::from(atomic_info.atomic_place.unwrap().local).as_ref());
                let atomic_pts = points_to_map.get(&atomic_node).unwrap();
                let atomic_field = atomic_pts.iter()
                    .find(|&pointee| {
                        if let ConstraintNode::Alloc(place) | ConstraintNode::Place(place) = pointee {
                            !place.projection.is_empty() && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref)
                        } else {
                            false
                        }
                    });
                // 处理后面的元素
                for interim in &interim_val[position + 1..] {
                    let node = ConstraintNode::Place(Place::from(*interim).as_ref());
                    if let Some(ptses) = points_to_map.get(&node) {
                        for pts in ptses {
                            match pts {
                                ConstraintNode::Alloc(place) => {
                                    if place.projection.is_empty() {
                                        continue;
                                    }
                                    if let Some(atomic_field) = atomic_field {
                                        if let ConstraintNode::Alloc(atomic) | ConstraintNode::Place(atomic) = atomic_field {
                                            if atomic.local == place.local 
                                                && atomic.projection != place.projection 
                                                && !place.projection.is_empty() 
                                                && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref) 
                                            {
                                                debug!("place.projection.iter().any(|elem| *elem != ProjectionElem::Deref):{:?}", place.projection.iter().any(|elem| *elem != ProjectionElem::Deref));
                                                corrlations.insert(place.clone());
                                            }
                                        }
                                    }
                                },
                                ConstraintNode::ConstantDeref(_) => {

                                },
                                _ => {},
                            }
                        }
                    } 
                }
            }
        } else {
            let atomic_node = ConstraintNode::Place(Place::from(atomic_info.atomic_place.unwrap().local).as_ref());
            let atomic_pts = points_to_map.get(&atomic_node).unwrap();
            let atomic_field = atomic_pts.iter()
                .find(|&pointee| {
                    if let ConstraintNode::Alloc(place) | ConstraintNode::Place(place) = pointee {
                        !place.projection.is_empty() && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref)
                    } else {
                        false
                    }
                });
            
            for interim in interim_val {
                let node = ConstraintNode::Place(Place::from(interim).as_ref());
                    if let Some(ptses) = points_to_map.get(&node) {
                        for pts in ptses {
                            match pts {
                                ConstraintNode::Alloc(place) => {
                                    if place.projection.is_empty() {
                                        continue;
                                    }
                                    if let Some(atomic_field) = atomic_field {
                                        if let ConstraintNode::Alloc(atomic) | ConstraintNode::Place(atomic) = atomic_field {
                                            if atomic.local == place.local 
                                                && atomic.projection != place.projection 
                                                && !place.projection.is_empty() 
                                                && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref) {
                                                corrlations.insert(place.clone());
                                            }
                                        }
                                    }
                                },
                                ConstraintNode::ConstantDeref(_) => {

                                },
                                _ => {},
                            }
                        }
                    } 
            }
        }

        self.correlations = corrlations;
    }

    /// 
    pub fn resolve_store_collelation(&mut self, callgraph: &CallGraph<'tcx>) {
        let (atomic_info, interim_val) = self.partner.clone();
        let inst = callgraph.index_to_instance(atomic_info.caller_instance);
        let body = self.tcx.instance_mir(inst.unwrap().instance().def); 
        let mut corrlations = HashSet::new();
        let mut alias_analysis = AliasAnalysis::new(self.tcx); 
        let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
        if let Some(AtomicInstructions::CompareExchange) | Some(AtomicInstructions::ReadModifyWrite) = atomic_info.atomic_operate {
            if let Some(position) = interim_val.iter().position(|&x| x == atomic_info.atomic_place.unwrap().local) {
                let atomic_node = ConstraintNode::Place(Place::from(atomic_info.atomic_place.unwrap().local).as_ref());
                let atomic_pts = points_to_map.get(&atomic_node).unwrap();
                let atomic_field = atomic_pts.iter()
                    .find(|&pointee| {
                        if let ConstraintNode::Alloc(place) | ConstraintNode::Place(place) = pointee {
                            !place.projection.is_empty() && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref)
                        } else {
                            false
                        }
                    });
                for interim in &interim_val[..position] {
                    let node = ConstraintNode::Place(Place::from(*interim).as_ref());
                    if let Some(ptses) = points_to_map.get(&node) {
                        for pts in ptses {
                            match pts {
                                ConstraintNode::Alloc(place) => {
                                    if place.projection.is_empty() {
                                        continue;
                                    }
                                    if let Some(atomic_field) = atomic_field {
                                        if let ConstraintNode::Alloc(atomic) | ConstraintNode::Place(atomic) = atomic_field {
                                            if atomic.local == place.local 
                                                && atomic.projection!= place.projection 
                                                && !place.projection.is_empty() 
                                                && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref) {
                                                corrlations.insert(place.clone());
                                            }
                                        }
                                    }
                                },
                                ConstraintNode::ConstantDeref(_) => {

                                },
                                _ => {},
                            }
                        }
                    } 
                }
            }
        } else {
            let atomic_node = ConstraintNode::Place(Place::from(atomic_info.atomic_place.unwrap().local).as_ref());
            let atomic_pts = points_to_map.get(&atomic_node).unwrap();
            let atomic_field = atomic_pts.iter()
                .find(|&pointee| {
                    if let ConstraintNode::Alloc(place) | ConstraintNode::Place(place) = pointee {
                        !place.projection.is_empty() && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref)
                    } else {
                        false
                    }
                });
            for interim in interim_val {
                let node = ConstraintNode::Place(Place::from(interim).as_ref());
                    if let Some(ptses) = points_to_map.get(&node) {
                        for pts in ptses {
                            match pts {
                                ConstraintNode::Alloc(place) => {
                                    if place.projection.is_empty() {
                                        continue;
                                    }
                                    if let Some(atomic_field) = atomic_field{
                                        if let ConstraintNode::Alloc(atomic) | ConstraintNode::Place(atomic) = atomic_field {
                                            if atomic.local == place.local && atomic.projection!= place.projection && !place.projection.is_empty() && place.projection.iter().any(|elem| *elem != ProjectionElem::Deref) {
                                                corrlations.insert(place.clone());
                                            }
                                        }
                                    }
                                    
                                },
                                ConstraintNode::ConstantDeref(_) => {

                                },
                                _ => {},
                            }
                        }
                    } 
            }
        }
        self.correlations = corrlations;
    }

    fn resolve_atomptr_load_collelation(&mut self) {
        let mut corrlations = HashSet::new();
        match self.partner.clone().0.atomic_operate.unwrap() {
            AtomicInstructions::CompareExchange | AtomicInstructions::ReadModifyWrite => {
                if let Some(index) = self.partner.clone().1.iter().position(|&x| x == self.partner.clone().0.atomic_value[0].local) {
                    corrlations = HashSet::from_iter(self.partner.clone().1[index..].iter().cloned().map(|local| Place::from(local).as_ref()));
                }
            },
            AtomicInstructions::Load => {
                corrlations = self.partner.clone().1.iter().map(|local| Place::from(*local).as_ref()).collect();
            },
            _ => {},
        }
        self.correlations = corrlations;
    }

    fn resolve_atomptr_store_collelation(&mut self) {
        let mut corrlations = HashSet::new();
        match self.partner.clone().0.atomic_operate.unwrap() {
            AtomicInstructions::CompareExchange | AtomicInstructions::ReadModifyWrite => {
                if let Some(index) = self.partner.clone().1.iter().position(|&x| x == self.partner.clone().0.atomic_value[1].local) {
                    corrlations = HashSet::from_iter(self.partner.clone().1[..index+1].iter().cloned().map(|local| Place::from(local).as_ref()));
                }
            },
            AtomicInstructions::Store => {
                corrlations = self.partner.clone().1.iter().map(|local| Place::from(*local).as_ref()).collect();
            },
            _ => {},
        }
        self.correlations = corrlations;
    }

}

pub struct AtomicityViolationDetector<'tcx> {
    tcx: TyCtxt<'tcx>,
}

impl<'tcx> AtomicityViolationDetector<'tcx> {
    pub fn new(tcx: TyCtxt<'tcx>) -> Self {
        Self { tcx }
    }

    pub fn gen_atomic_info(
        &self, 
        atomics: Vec<&CallGraphNode<'tcx>>, 
        atomics_atomptr: HashMap<String ,Vec<&CallGraphNode<'tcx>>>, 
        callgraph: &CallGraph<'tcx>
    ) -> (
        Vec<Vec<(AtomicInfo<'tcx>, Vec<Local>)>>, 
        HashMap<String, Vec<(AtomicInfo<'tcx>, Vec<Local>)>> 
    ) { 
        let mut atom_maps = HashMap::new();
        // let mut atom_ptr_infos: Vec<Vec<(AtomicInfo<'tcx>, Vec<Local>)>> = Vec::new();
        for atomic in &atomics {
            let atomic_instance = atomic.instance();
            let instance_id = callgraph.instance_to_index(atomic_instance).unwrap();
            let mut atomic_collector = AtomicCollector::new(self.tcx, instance_id, atomic_instance);
            atomic_collector.analyze(callgraph);
            if atomic_collector.atomics.len() != 0{
                for key in atomic_collector.atomics.into_iter() {
                    let mut atompart_collector = AtomPart::new(self.tcx, key);
                    atompart_collector.infer_interival(callgraph);

                    let atom_map = atompart_collector.classify_atomic(callgraph);
                    for (key, values) in atom_map {
                        let values_cloned = values.iter()
                          .map(|(info, locals)| (info.clone(), locals.clone()))
                          .collect::<Vec<_>>();
                        atom_maps.entry(key)
                            .and_modify(|e: &mut Vec<(AtomicInfo<'tcx>, Vec<Local>)>| e.extend(values_cloned.clone()))
                            .or_insert_with(|| values_cloned);
                    }
                }
            }
        }
        let atom_ptr_infos = atomics_atomptr.into_iter().map(|(_, atomics)| {
            let mut infos = Vec::new();
            for atomic in &*atomics {
                let atomic_instance = atomic.instance();
                let instance_id = callgraph.instance_to_index(atomic_instance).unwrap();
                let mut atomic_collector = AtomicCollector::new(self.tcx, instance_id, atomic_instance);
                atomic_collector.analyze(callgraph);
                if atomic_collector.atomics.len() != 0 {
                    for key in atomic_collector.atomics.into_iter() {
                        let mut atompart_collector = AtomPart::new(self.tcx, key);
                        atompart_collector.infer_atomptr_interival(callgraph);
                        infos.extend(atompart_collector.partner);
                    }
                }
            }
            infos
        }).collect();
        (atom_ptr_infos, atom_maps)
    }

    
    /// Collect atomic APIs.
    /// Rerturn the atomicInfos.
    fn collect_atomics(&self, callgraph: &CallGraph<'tcx>) -> (Vec<Vec<(AtomicInfo<'tcx>, Vec<Local>)>>, HashMap<String, Vec<(AtomicInfo<'tcx>, Vec<Local>)>>) { // ProjectionElem<Local, Ty<'tcx>>
        let mut atomics = Vec::new();
        let mut ptr_type = String::new();
        let mut atomics_atomptr = HashMap::new();
        for (index, node) in callgraph.graph.node_references() {
            let inst = match callgraph.index_to_instance(index).unwrap() {
                CallGraphNode::WithBody(instance) => instance,
                CallGraphNode::WithoutBody(instance) => instance,
            };
            let func_name = self.tcx.def_path_str_with_substs(inst.def_id(), inst.substs);
            let re = Regex::new(r"^(std|core)::sync::atomic::((AtomicPtr)(::<(.*?)>)?|(Atomic[A-Za-z]+)(::<(.*?)>)?)(::)?(load|store|swap|compare_exchange(_weak)?|fetch_(and|add|sub|or|update|max|xor)|compare_and_swap)").unwrap();
            
            // Identify atomic operations and distinguish between AtomicPtr and non-AtomicPtr
            if let Some(caps) = re.captures(&func_name) {
            if caps.get(3).is_some() { 
                // The operation is an AtomicPtr operation
                if let Some(specific_type) = caps.get(5) { 
                    ptr_type = specific_type.as_str().to_string();
                }
                atomics_atomptr.entry(ptr_type.clone()).or_insert_with(Vec::new).push(node);
            } else if caps.get(6).is_some() { 
                    // The operation is a non-AtomicPtr operation
                    atomics.push(node);
                }
            }
        }
        self.gen_atomic_info(atomics, atomics_atomptr, callgraph)
    }

    // pub fn is_unsafe_write(
    //     &mut self
    //     ,place_ref: PlaceRef
    //     ,callgraph: &CallGraph
    //     ,instance_id: InstanceId
    //     ,body: &Body<'tcx>) -> bool {
    //         let mut callsites = Vec::new();
    //         let call_targets:Vec<InstanceId> = callgraph.graph.neighbors_directed(instance_id, Outgoing).collect();
    //         for call_target in call_targets {
    //             let sites = callsite_locations(callgraph, instance_id, call_target).unwrap();
    //             for callsite in sites {
    //                 callsites.push(callsite);
    //             }
    //         }
    //         for location in callsites {
    //             if let TerminatorKind::Call {
    //                 func,
    //                 args,
    //                 ..
    //             } = &body[location.block].terminator().kind
    //             {   
    //                 let func_ty = func.ty(body, self.tcx);
    //                 match func_ty.kind() {
    //                     TyKind::FnDef(def_id, substs) =>
    //                     {
    //                         let path = self.tcx.def_path_str_with_substs(*def_id, substs);
    //                         if let Some(arg) = args.get(0) {
    //                             if  path.contains("write") | path.contains("replace") | path.contains("swap") | path.contains("set") {  // path.contains("std::ptr::mut_ptr::") &
    //                                 if let Operand::Move(arg) = arg {
    //                                     if arg.local == place_ref.local { 
    //                                         return true;
    //                                     }
    //                                 }
    //                             }
    //                         }                           
    //                     }
    //                     _ => {}
    //                 }
    //             }
    //         }
    //         return false;
    //     }

    pub fn get_factors(atomic_infos: Vec<(AtomicInfo<'tcx>, Vec<Local>)>) -> Vec<((AtomicInfo<'tcx>, Vec<rustc_middle::mir::Local>), (AtomicInfo<'tcx>, Vec<rustc_middle::mir::Local>))> {
        // Classify atomic operations
        let mut read_atomics = Vec::new();
        let mut write_atomics = Vec::new();
        let mut read_write_atomics = Vec::new();
        
        for (atomic_info, interimval) in atomic_infos.clone() {
            if let Some(operate) = atomic_info.atomic_operate {
                match operate {
                    AtomicInstructions::CompareExchange => {
                        read_write_atomics.push((atomic_info, interimval));
                    },
                    AtomicInstructions::Load => {
                        read_atomics.push((atomic_info, interimval));
                    },
                    AtomicInstructions::Store => {
                        write_atomics.push((atomic_info, interimval));
                    },
                    AtomicInstructions::ReadModifyWrite => {
                        read_write_atomics.push((atomic_info, interimval));
                    },
                }
            }
        }

        // if atomic_infos.len() > 1 && atomic_infos.iter().all(|x| x.0.caller_instance == atomic_infos[0].0.caller_instance) {
        //     for info in atomic_infos {
        //         let mut ordering = HashSet::new();
        //         ordering.insert(AtomicOrd::Relaxed);
        //         ordering_candidates.entry(info.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
        //             ordering_result.extend(ordering.iter().clone());
        //         }).or_insert(ordering);
        //     }
        // }

        // Generate atomic read-write pairs
        let mut factors = Vec::new();
        for read_atomic in read_atomics.clone() {
            for write_atomic in write_atomics.clone() {
                // if &read_atomic.0.caller_instance != &write_atomic.0.caller_instance {
                    factors.push((read_atomic.clone(), write_atomic.clone()));
                // }
            }
        }

        for read_atomic in read_atomics.clone() {
            for read_write_atomic in read_write_atomics.clone() {
                // if  &read_atomic.0.caller_instance != &read_write_atomic.0.caller_instance {
                    factors.push((read_atomic.clone(), read_write_atomic.clone()));
                // }
            }
        }

        for read_write_atomic in read_write_atomics.clone() {
            for write_atomic in write_atomics.clone() {
                // if &read_write_atomic.0.caller_instance != &write_atomic.0.caller_instance {
                    factors.push((read_write_atomic.clone(), write_atomic.clone()));
                // }
            }
        }

        for read_atomic in read_write_atomics.clone() {
            for write_atomic in read_write_atomics.clone() {
                // if read_atomic.0.caller_instance != write_atomic.0.caller_instance {
                    factors.push((read_atomic.clone(), write_atomic.clone()));
                // }
            }
        }
        return factors;
    }


    pub fn get_atomptr_factors(atomic_infos: Vec<(AtomicInfo<'tcx>, Vec<Local>)>) -> Vec<((AtomicInfo<'tcx>, Vec<rustc_middle::mir::Local>), (AtomicInfo<'tcx>, Vec<rustc_middle::mir::Local>))> {
        // Classify atomic operations
        let mut read_atomics = Vec::new();
        let mut write_atomics = Vec::new();
        let mut read_write_atomics = Vec::new();
        
        for (atomic_info, interimval) in atomic_infos.clone() {
            if let Some(operate) = atomic_info.atomic_operate {
                match operate {
                    AtomicInstructions::CompareExchange => {
                        read_write_atomics.push((atomic_info, interimval));
                    },
                    AtomicInstructions::Load => {
                        read_atomics.push((atomic_info, interimval));
                    },
                    AtomicInstructions::Store => {
                        write_atomics.push((atomic_info, interimval));
                    },
                    AtomicInstructions::ReadModifyWrite => {
                        read_write_atomics.push((atomic_info, interimval));
                    },
                }
            }
        }

        // Generate atomic read-write pairs
        let mut factors = Vec::new();
        for read_atomic in read_atomics.clone() {
            for write_atomic in write_atomics.clone() {
                // if &read_atomic.0.caller_instance != &write_atomic.0.caller_instance {
                    factors.push((read_atomic.clone(), write_atomic.clone()));
                // }
            }
        }

        for read_atomic in read_atomics.clone() {
            for read_write_atomic in read_write_atomics.clone() {
                // if  &read_atomic.0.caller_instance != &read_write_atomic.0.caller_instance {
                    factors.push((read_atomic.clone(), read_write_atomic.clone()));
                // }
            }
        }

        for read_write_atomic in read_write_atomics.clone() {
            for write_atomic in write_atomics.clone() {
                // if &read_write_atomic.0.caller_instance != &write_atomic.0.caller_instance {
                    factors.push((read_write_atomic.clone(), write_atomic.clone()));
                // }
            }
        }

        for read_atomic in read_write_atomics.clone() {
            for write_atomic in read_write_atomics.clone() {
                    factors.push((read_atomic.clone(), write_atomic.clone()));
            }
        }
        return factors;
    }


    /// Detect atomicity violation intra-procedurally and returns bug report.
    pub fn detect<'a>(
        &mut self,
        callgraph: &'a CallGraph<'tcx>,
    ) -> Vec<Report> {
        let mut reports = Vec::new();
        
        let (atomptr_infos, atom_infos) = self.collect_atomics(callgraph);
        // 1、Detect critial-state inconsistent update bug
        for (_, atom_infos) in atom_infos {
            // Analyze all atomic operations for each atomic variable
            let mut ordering_candidates = HashMap::new();
            let factors = Self::get_factors(atom_infos.clone());
            for (factor_load, factor_write) in factors {
                let instance = callgraph
                    .index_to_instance(factor_load.clone().0.caller_instance)
                    .map(CallGraphNode::instance).unwrap();
                let body = self.tcx.instance_mir(instance.def);

                // Get Control dependency graphs
                let control_deps = controldep::control_deps(body.basic_blocks.clone());

                // Get data dependency
                let data_deps = datadep::data_deps(body);
                let local = factor_load.0.atomic_value[0].local;
                // Obtain the data flow of a specific local
                let deps = datadep::all_data_dep_on(
                    local, 
                    &data_deps, 
                    callgraph, 
                    factor_load.0.caller_instance,body, 
                    self.tcx
                );
                let mut control_dep = Vec::new();
                for dep in deps {
                    let uses = defuse::find_uses(body, dep);
                    for atomic_use in uses {
                        if control_deps.banch_node.contains(&atomic_use.block) {
                            control_dep.push(atomic_use.block);
                            }
                        }
                }
                if !control_dep.is_empty() {
                    let mut analyzer_load = CorrelationAnalyzer::new(self.tcx, factor_load.clone());
                    analyzer_load.resolve_load_collelation(callgraph);
                    let mut analyzer_store = CorrelationAnalyzer::new(self.tcx, factor_write.clone());
                    analyzer_store.resolve_store_collelation(callgraph);
                    if analyzer_load.correlations.is_empty() && !analyzer_store.correlations.is_empty() {
                        // let mut load_ordering = HashSet::new();
                        // load_ordering.insert(AtomicOrd::Acquire);
                        // let mut store_ordering = HashSet::new();
                        // store_ordering.insert(AtomicOrd::Release);
                        
                        // ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                        //     ordering_result.extend(load_ordering.iter().clone());
                        // }).or_insert(load_ordering);

                        // ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                        //     ordering_result.extend(store_ordering.iter().clone());
                        // }).or_insert(store_ordering);
                    } else if !analyzer_load.correlations.is_empty() && !analyzer_store.correlations.is_empty() {
                        let common_field = analyzer_store.correlations.iter().any(|place_store| {
                            analyzer_load.correlations.iter().any(|place_load| {
                                place_store.projection == place_load.projection
                            })
                        });
                        if common_field == true {
                            let mut load_ordering = HashSet::new();
                            load_ordering.insert(AtomicOrd::Acquire);
                            let mut store_ordering = HashSet::new();
                            store_ordering.insert(AtomicOrd::Release);
                            ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                ordering_result.extend(load_ordering.iter().clone());
                            }).or_insert(load_ordering);

                            ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                ordering_result.extend(store_ordering.iter().clone());
                            }).or_insert(store_ordering);
                        } else {
                            let mut load_ordering = HashSet::new();
                            load_ordering.insert(AtomicOrd::Acquire);
                            let mut store_ordering = HashSet::new();
                            if factor_write.clone().0.ordering.contains(&AtomicOrd::AcqRel) {
                                store_ordering.insert(AtomicOrd::AcqRel);
                            } else if factor_write.clone().0.ordering.contains(&AtomicOrd::Release) {
                                store_ordering.insert(AtomicOrd::Release);
                            } else {
                                store_ordering.insert(AtomicOrd::Relaxed);
                            }
                            ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                ordering_result.extend(load_ordering.iter().clone());
                            }).or_insert(load_ordering);

                            ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                ordering_result.extend(store_ordering.iter().clone());
                            }).or_insert(store_ordering);
                        }
                    } else {
                        // let mut load_ordering = HashSet::new();
                        // load_ordering.insert(AtomicOrd::Relaxed);
                        // let mut store_ordering = HashSet::new();
                        // store_ordering.insert(AtomicOrd::Relaxed);
                        // ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                        //     ordering_result.extend(load_ordering.iter().clone());
                        // }).or_insert(load_ordering);

                        // ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                        //     ordering_result.extend(store_ordering.iter().clone());
                        // }).or_insert(store_ordering);
                    }
                } else {
                    let mut load_ordering = HashSet::new();
                    if factor_load.clone().0.ordering.contains(&AtomicOrd::AcqRel) || factor_load.clone().0.ordering.contains(&AtomicOrd::Acquire) || factor_load.clone().0.ordering.contains(&AtomicOrd::Release){
                        continue;
                    }
                    load_ordering.insert(AtomicOrd::Relaxed);
                    // let mut store_ordering = HashSet::new();
                    // store_ordering.insert(AtomicOrd::Relaxed);
                    ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                        ordering_result.extend(load_ordering.iter().clone());
                    }).or_insert(load_ordering);

                    // ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                    //     ordering_result.extend(store_ordering.iter().clone());
                    // }).or_insert(store_ordering);
                }   
            }
            let candidates = format!("{:?}", ordering_candidates);
            let num = format!("{:?}", ordering_candidates.len());
            debug!("atomic correlations: {}: {}", candidates, num);
            
            for (atomic, ordering_condidates) in ordering_candidates {
                let ordering = calculate_min_ordering(&ordering_condidates);
                if let Some(AtomicInstructions::Load) | Some(AtomicInstructions::Store) | Some(AtomicInstructions::ReadModifyWrite)= atomic.atomic_operate {
                    // e.g. fetch_add 
                    if ordering.len() == 2 {
                        if atomic.ordering[0] > AtomicOrd::AcqRel {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead. Using AcqRel is sufficient to ensure the correctness of the program."),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] < AtomicOrd::AcqRel {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using AcqRel is sufficient to ensure the program's correctness."),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    } else if ordering.len() == 1 { // e.g. store/load
                        if atomic.ordering[0] > ordering[0] {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead. Using {:?} is sufficient to ensure the correctness of the program", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] < ordering[0] {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using {:?} is sufficient to ensure the program's correctness.", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    }
                } else {
                    // ordering == Release & Acquire
                    if ordering.len() == 2 {
                        if atomic.ordering[0] < AtomicOrd::AcqRel || atomic.ordering[1] < AtomicOrd::Acquire {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                "Using an atomic compare_exchange operation with a weaker memory ordering than necessary can lead to an inconsistent memory state, Using AcqRel and Acquire is sufficient to ensure the correctness of the program"
                                    .to_owned(),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] > AtomicOrd::AcqRel || atomic.ordering[1] > AtomicOrd::Acquire{ // Compare_exchange can also use AcqRel if it fails
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                "Using an atomic compare_exchange operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead, Using AcqRel and Acquire is sufficient to ensure the correctness of the program"
                                    .to_owned(),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    } else if ordering.len() == 1 {
                         if atomic.ordering[0] < ordering[0]  { // || atomic.ordering[1] < ordering[0]
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using {:?} is sufficient to ensure the program's correctness.", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] > ordering[0]  { // Compare_exchange can also use AcqRel if it fails || atomic.ordering[1] > ordering[0]
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead. Using {:?} is sufficient to ensure the correctness of the program", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    }
                }
            }
        }

        // 2、Detect AtomicPtr related Concurrency bug
        for atomptr_info in atomptr_infos {
            // Analyze all atomic operations for each atomicptr variable
            let mut ordering_candidates = HashMap::new();
            let factors = Self::get_atomptr_factors(atomptr_info.clone());
            for (factor_load, factor_write) in factors {

                let mut analyzer_load = CorrelationAnalyzer::new(self.tcx, factor_load.clone());
                analyzer_load.resolve_atomptr_load_collelation();
                let mut analyzer_store = CorrelationAnalyzer::new(self.tcx, factor_write.clone());
                analyzer_store.resolve_atomptr_store_collelation();

                let inst = callgraph.index_to_instance(factor_write.0.caller_instance);
                let body = self.tcx.instance_mir(inst.unwrap().instance().def); 
                let mut alias_analysis = AliasAnalysis::new(self.tcx); 
                let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
                for correlation in analyzer_store.correlations {
                    let node = ConstraintNode::Place(correlation);
                    let pts = points_to_map.get(&node);
                    if let Some(pts) = pts {
                        for correlation_node in pts {
                            match correlation_node {
                                ConstraintNode::Alloc(_) | ConstraintNode::Place(_)=> {
                                    // The atomic pointer, as identified through data flow analysis, references a function parameter of 
                                    // an ADT (Abstract Data Type). It is posited that the atomic pointer might be assigned via other 
                                    // fields of the struct. Consequently, it is also contemplated that the use of 'Release' is necessary 
                                    // in this context.
                                    if points_to_map.keys().any(|node|    // is_parameter(place.local, body) &&
                                        if let ConstraintNode::Alloc(arg) | ConstraintNode::Place(arg) = node {
                                             return is_parameter(arg.local, body) && !arg.projection.is_empty() && arg.projection.iter().any(|elem| *elem != ProjectionElem::Deref);
                                        } else {
                                            return false;
                                        }
                                    ) {
                                        let mut store_ordering = HashSet::new();
                                        store_ordering.insert(AtomicOrd::Release);

                                        ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                            ordering_result.extend(store_ordering.iter().clone());
                                        }).or_insert(store_ordering);
                                    } else {
                                        let mut store_ordering = HashSet::new();
                                        store_ordering.insert(AtomicOrd::Relaxed);

                                        ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                            ordering_result.extend(store_ordering.iter().clone());
                                        }).or_insert(store_ordering);
                                    }
                                },
                                ConstraintNode::Construct(_) | ConstraintNode::FunctionRet(_) => {
                                    // the pointer's initialization originates either from the creation of a struct or from the return value of a function

                                    let mut store_ordering = HashSet::new();
                                    store_ordering.insert(AtomicOrd::Release);
    
                                    ordering_candidates.entry(factor_write.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                        ordering_result.extend(store_ordering.iter().clone());
                                    }).or_insert(store_ordering);
                                },
                                _ => {},
                            }
                        }
                    }
                }
                
                //  pointer is dereferenced in the current instance
                let inst = callgraph.index_to_instance(factor_load.0.caller_instance);
                let body = self.tcx.instance_mir(inst.unwrap().instance().def); 
                let points_to_map = alias_analysis.get_or_insert_pts(inst.unwrap().instance().def_id(), body).clone();
                if alias_analysis.load_corrlation(&body.clone(), &analyzer_load.correlations) { // factor_load.1.clone()
                    let mut load_ordering = HashSet::new();
                    load_ordering.insert(AtomicOrd::Acquire);
                    
                    ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                        ordering_result.extend(load_ordering.iter().clone());
                    }).or_insert(load_ordering);
                } else {
                    let mut load_ordering = HashSet::new();
                    load_ordering.insert(AtomicOrd::Relaxed);
                    
                    ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                        ordering_result.extend(load_ordering.iter().clone());
                    }).or_insert(load_ordering);
                }

                // pointer is converted to a smart pointer or passed as a parameter to another instance(Heuristically, there may be de-referencing behavior)
                for correlation in analyzer_load.correlations {
                    let node = ConstraintNode::Place(correlation);
                    let pts = points_to_map.get(&node);
                    if let Some(pts) = pts {
                        for correlation_node in pts {
                            match correlation_node {
                                ConstraintNode::SmartPointer(_) | ConstraintNode::ParameterInto(_) => {
                                    let mut load_ordering = HashSet::new();
                                    load_ordering.insert(AtomicOrd::Acquire);
                                    
                                    ordering_candidates.entry(factor_load.clone().0).and_modify(|ordering_result: &mut HashSet<AtomicOrd>| {
                                        ordering_result.extend(load_ordering.iter().clone());
                                    }).or_insert(load_ordering);
                                },
                                _ => {},
                            }
                        }
                    }
                }

            }

            let candidates = format!("{:?}", ordering_candidates);
            let num = format!("{:?}", ordering_candidates.len());
            debug!("atomic correlations: {}: {}", candidates, num);

            for (atomic, ordering_condidates) in &ordering_candidates{
                let ordering = calculate_min_ordering(&ordering_condidates);
                if let Some(AtomicInstructions::Load) 
                    | Some(AtomicInstructions::Store) 
                    | Some(AtomicInstructions::ReadModifyWrite) = atomic.atomic_operate {
                    if ordering.len() == 2 {
                        if atomic.ordering[0] > AtomicOrd::AcqRel {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead. Using AcqRel is sufficient to ensure the correctness of the program."),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] < AtomicOrd::AcqRel {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using AcqRel is sufficient to ensure the program's correctness."),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    } else if ordering.len() == 1 { // e.g. store/load
                        if atomic.ordering[0] > ordering[0] {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead. Using {:?} is sufficient to ensure the correctness of the program", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] < ordering[0] {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using {:?} is sufficient to ensure the program's correctness.", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    }
                } else {
                    // ordering == Release & Acquire
                    if ordering.len() == 2 {
                        if atomic.ordering[0] < AtomicOrd::AcqRel || atomic.ordering[1] < AtomicOrd::Acquire {
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                "Using an atomic compare_exchange operation with a weaker memory ordering than necessary can lead to an inconsistent memory state, Using AcqRel and Acquire is sufficient to ensure the correctness of the program"
                                    .to_owned(),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] > AtomicOrd::AcqRel || atomic.ordering[1] > AtomicOrd::Acquire{ // Compare_exchange can also use AcqRel if it fails
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                "Using an atomic compare_exchange operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead, Using AcqRel and Acquire is sufficient to ensure the correctness of the program"
                                    .to_owned(),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    } else if ordering.len() == 1 {
                         if atomic.ordering[0] < ordering[0] { //  || atomic.ordering[1] < ordering[0]
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a weaker memory ordering than necessary can lead to an inconsistent memory state. Using {:?} is sufficient to ensure the program's correctness.", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        } else if atomic.ordering[0] > ordering[0]  { // Compare_exchange can also use AcqRel if it fails || atomic.ordering[1] > ordering[0]
                            let diagnosis = AtomicityViolationDiagnosis {
                                atomic: atomic.source_info.clone(),
                            };
                            let report_content = ReportContent::new(
                                "AtimicCorrelationViolation".to_owned(),
                                "Possibly".to_owned(),
                                diagnosis,
                                format!("Using an atomic operation with a stronger memory ordering than necessary can lead to unnecessary performance overhead. Using {:?} is sufficient to ensure the correctness of the program", ordering[0]),
                            );
                            reports.push(Report::AtomicCorrelationViolation(report_content));
                        }
                    }
                }
            }
        }
        reports
    }
}

/// CallSite Locations from source to target
pub fn callsite_locations(
    callgraph: &CallGraph<'_>,
    source: InstanceId,
    target: InstanceId,
) -> Option<Vec<Location>> {
    Some(
        callgraph
            .callsites(source, target)?
            .into_iter()
            .filter_map(|callsite| callsite.location())
            .collect(),
    )
}

// fn is_adt_or_contains_adt(ty: &Ty) -> bool {
//     match ty.kind() {
//         ty::TyKind::Adt(_, _) => true,
//         ty::TyKind::Array(var_ty, _) | ty::TyKind::Slice(var_ty) | ty::TyKind::Ref(_, var_ty, _) => {
//             is_adt_or_contains_adt(var_ty)
//         }
//         ty::TyKind::RawPtr(var_ty) => is_adt_or_contains_adt(&var_ty.ty),
//         _ => false,
//     }
// }

fn is_parameter(local: Local, body: &Body<'_>) -> bool {
    body.args_iter().any(|arg| arg == local)
}

fn calculate_min_ordering(ord_set: &HashSet<AtomicOrd>) -> Vec<AtomicOrd> {
    let mut max_ord: Option<AtomicOrd> = None;

    for ord in ord_set {
        max_ord = match max_ord {
            Some(current_max) => {
                if ord > &current_max {
                    Some(ord.clone())
                } else {
                    Some(current_max)
                }
            },
            None => Some(ord.clone()),
        };
    }

    max_ord.map_or(Vec::new(), |max| {
        ord_set.iter().filter(|&ord| ord == &max || ord.partial_cmp(&max) == Some(Ordering::Equal)).cloned().collect()
    })
}