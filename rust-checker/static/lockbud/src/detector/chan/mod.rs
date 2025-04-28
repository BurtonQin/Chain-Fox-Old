extern crate rustc_data_structures;
extern crate rustc_hash;
extern crate rustc_span;

use std::collections::VecDeque;

use petgraph::visit::IntoNodeReferences;
use rustc_hash::{FxHashMap, FxHashSet};
use rustc_middle::{mir::Local, ty::{TyCtxt, TypingEnv}};

use crate::{analysis::{callgraph::{CallGraph, InstanceId}, pointsto::AliasAnalysis}, interest::concurrency::chan::ChanApi};

pub struct ChanDetector<'tcx> {
    tcx: TyCtxt<'tcx>,
    typing_env: TypingEnv<'tcx>,
    // ChanInfo
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverId {
    pub instance_id: InstanceId,
    pub local: Local,
}

pub struct SenderId {
    pub instance_id: InstanceId,
    pub local: Local,
}

#[derive(Clone, Debug, Default)]
struct LiveReceivers(FxHashSet<ReceiverId>);

impl LiveReceivers {
    fn insert(&mut self, recv_id: ReceiverId) -> bool {
        self.0.insert(recv_id)
    }
    fn raw_receiver_ids(&self) -> &FxHashSet<ReceiverId> {
        &self.0
    }
    // self = self \ other, if changed return true
    fn difference_in_place(&mut self, other: &Self) -> bool {
        let old_len = self.0.len();
        for id in &other.0 {
            self.0.remove(id);
        }
        old_len != self.0.len()
    }
    // self = self U other, if changed return true
    fn union_in_place(&mut self, other: Self) -> bool {
        let old_len = self.0.len();
        self.0.extend(other.0);
        old_len != self.0.len()
    }
}

impl<'tcx> ChanDetector<'tcx> {
    pub fn new(tcx: TyCtxt<'tcx>, typing_env: TypingEnv<'tcx>) -> Self {
        Self {
            tcx,
            typing_env,
            // lockguard_relations: Default::default(),
        }
    }

    /// Collect channel APIs.
    /// Return the channel API's InstanceId and kind.
    fn collect_chan(&self, callgraph: &CallGraph<'tcx>) -> FxHashMap<InstanceId, ChanApi> {
        callgraph
            .graph
            .node_references()
            .filter_map(|(instance_id, node)| {
                ChanApi::from_instance(node.instance(), self.tcx)
                    .map(|chan_api| (instance_id, chan_api))
            })
            .collect()
    }

    pub fn detect<'a>(&mut self,
        callgraph: &'a CallGraph<'tcx>,
        alias_analysis: &mut AliasAnalysis<'a, 'tcx>,) -> Vec<()> {
        let chan_apis = self.collect_chan(callgraph);
        println!("{:#?}", chan_apis);
        // Init `worklist` with all the `InstanceId`s
        let mut worklist = callgraph
            .graph
            .node_references()
            .map(|(instance_id, _)| instance_id)
            .collect::<VecDeque<_>>();
        while let Some(node) = worklist.pop_front() {
            // body = mir_body(node)
            // for term in body.term
            //   if term calls create
            //      record return value: rx, tx
            //   else if 
            //      record return value: rx, tx
            
        }
        vec![]
    }
}
