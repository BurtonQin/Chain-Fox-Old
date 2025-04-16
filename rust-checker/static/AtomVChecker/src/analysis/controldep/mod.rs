extern crate rustc_data_structures;
extern crate rustc_index;
extern crate rustc_middle;

use std::collections::HashSet;

use rustc_data_structures::fx::FxHashSet;
use rustc_index::vec::{Idx, IndexVec};
use crate::analysis::postdom::{post_dominators, EndsControlFlowGraph};


#[derive(Clone, Debug)]
pub struct ControlDeps<N: Idx> {
    pub parents: IndexVec<N, FxHashSet<N>>,
    pub banch_node: HashSet<N>,
}

pub fn control_deps<G: EndsControlFlowGraph>(graph: G) -> ControlDeps<G::Node> {
    let mut parents = IndexVec::from_elem_n(FxHashSet::default(), graph.num_nodes());

    let mut banch_node = HashSet::new();
    let pdt = post_dominators(&graph);
    let nodes = IndexVec::from_elem_n((), graph.num_nodes());
    for (a, _) in nodes.iter_enumerated() {
        for b in graph.successors(a) {
            if a != b && pdt.is_post_dominated_by(a, b) {
                continue;
            }
            if let Some(l) = pdt.find_nearest_common_dominator(a, b) {
                if a == l {
                    parents[a].insert(a);
                    banch_node.insert(a);
                }
                
                for c in pdt.post_dominators(b) {
                    if c == l {
                        break;
                    } else {
                        parents[c].insert(a);
                        banch_node.insert(a);
                    }
                }

            } else {
                // (fake) end node
                for c in pdt.post_dominators(b) {
                    parents[c].insert(a);
                    banch_node.insert(a);
                }
            }
        }
    }
    let root = graph.start_node();
    for c in pdt.post_dominators(root) {
        parents[c].insert(root);
    }
    ControlDeps { 
        parents,
        banch_node,
     }
}
