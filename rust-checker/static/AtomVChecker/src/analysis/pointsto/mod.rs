//! Points-to analysis.
//! It checks if two pointers may point to the same memory& cell.
//! It depends on `CallGraph` and provides support for detectors.
//! Currently I have implemented an Andersen-style pointer analysis.
//! It is basically a field-sensitive intra-procedural pointer analysis
//! with limited support for inter-procedural analysis
//! of methods and closures.
//! See `Andersen` for more details.
extern crate rustc_hash;
extern crate rustc_hir;
extern crate rustc_index;

use std::collections::{VecDeque, HashSet};

use rustc_hash::{FxHashMap, FxHashSet};

use rustc_hir::def_id::DefId;
use rustc_middle::mir::visit::Visitor;
use rustc_middle::mir::{
    Body, Constant, ConstantKind, Local, Location, Operand, Place, PlaceRef,
    ProjectionElem, Rvalue, Statement, StatementKind, Terminator, TerminatorKind,
};
use rustc_middle::ty::{TyCtxt, TyKind};

use petgraph::dot::{Config, Dot};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::{Directed, Direction, Graph};
use crate::analysis::callgraph::InstanceId;
use crate::interest::memory::ownership;

/// Field-sensitive intra-procedural Andersen pointer analysis.
/// <https://helloworld.pub/program-analysis-andersen-pointer-analysis-algorithm-based-on-svf.html>
/// 1. collect constraints from MIR to build a `ConstraintGraph`
/// 2. adopt a fixed-point algorithm to update `ConstraintGraph` and points-to info
///
/// There are several changes:
/// 1. Use a place to represent a memroy cell.
/// 2. Create an Alloc node for each place and let the place points to it.
/// 3. Distinguish local places with global ones (denoted as Constant).
/// 4. Treat special functions by names or signatures (e.g., Arc::clone).
/// 5. Interproc methods: Use parameters' type info to guide the analysis heuristically (simple but powerful).
/// 6. Interproc closures: Track the upvars of closures in the functions defining the closures (restricted).
pub struct Andersen<'a, 'tcx> {
    body: &'a Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    pts: PointsToMap<'tcx>,
}

pub type PointsToMap<'tcx> = FxHashMap<ConstraintNode<'tcx>, FxHashSet<ConstraintNode<'tcx>>>;

impl<'a, 'tcx> Andersen<'a, 'tcx> {
    pub fn new(body: &'a Body<'tcx>, tcx: TyCtxt<'tcx>) -> Self {
        Self {
            body,
            tcx,
            pts: Default::default(),
        }
    }

    pub fn analyze(&mut self) {
        let mut collector = ConstraintGraphCollector::new(self.body, self.tcx);
        collector.visit_body(self.body);
        let mut graph = collector.finish();
        let mut worklist = VecDeque::new();
        // 首先模拟编译器分配内存地址
        // alloc: place = alloc
        for node in graph.nodes() {
            match node {
                ConstraintNode::Place(place) => {
                    graph.add_alloc(place);
                }
                ConstraintNode::Constant(constant) => {
                    graph.add_constant(constant);
                    // For constant C, track *C.
                    worklist.push_back(ConstraintNode::ConstantDeref(constant));
                }
                _ => {}
            }
            worklist.push_back(node);
        }
        // address: target = &source
        for (source, target, weight) in graph.edges() {
            if weight == ConstraintEdge::Address {
                self.pts.entry(target).or_default().insert(source);
                
                worklist.push_back(target);
            }
        }

        while let Some(node) = worklist.pop_front() {
            if !self.pts.contains_key(&node) {
                continue;
            }
            for o in self.pts.get(&node).unwrap() {
                // store: *node = source
                for source in graph.store_sources(&node) {
                    if graph.insert_edge(source, *o, ConstraintEdge::Copy) {
                        worklist.push_back(source);
                    }
                }
                // load: target = *node
                for target in graph.load_targets(&node) {
                    if graph.insert_edge(*o, target, ConstraintEdge::Copy) {
                        worklist.push_back(*o);
                    }
                }
            }
            // alias_copy: target = &X; X = ptr::read(node)
            for target in graph.alias_copy_targets(&node) {
                if graph.insert_edge(node, target, ConstraintEdge::Copy) {
                    worklist.push_back(node);
                }
            }
            // copy: target = node
            for target in graph.copy_targets(&node) {
                if self.union_pts(&target, &node) {
                    worklist.push_back(target);
                }
            }

        }
    }

    /// pts(target) = pts(target) U pts(source), return true if pts(target) changed
    fn union_pts(&mut self, target: &ConstraintNode<'tcx>, source: &ConstraintNode<'tcx>) -> bool {
        // skip Alloc target
        if matches!(target, ConstraintNode::Alloc(_)) {
            return false;
        }
        if self.pts.get(target).is_none() {
            let source_pts = self.pts.get(source).unwrap().clone();      
            self.pts.insert(*target, source_pts);
            return true;
        } else {
            let old_len = self.pts.get(target).unwrap().len();
            let source_pts = self.pts.get(source).unwrap().clone();      
            let target_pts = self.pts.get_mut(target).unwrap();
            target_pts.extend(source_pts.into_iter());
            old_len != target_pts.len()
        }
        
    }

    pub fn finish(self) -> FxHashMap<ConstraintNode<'tcx>, FxHashSet<ConstraintNode<'tcx>>> {
        self.pts
    }
}

/// `ConstraintNode` represents a memory cell, denoted by `Place` in MIR.
/// A `Place` encompasses `Local` and `[ProjectionElem]`, `ProjectionElem`
/// can be a `Field`, `Index`, etc.
/// Since there is no `Alloc` in MIR, we cannot use locations of `Alloc`
/// to uniquely identify the allocation of a memory cell.
/// Instead, we use `Place` itself to represent its allocation,
/// namely, forall Place(p), Alloc(p)--|address|-->Place(p).
/// `Constant` appears on right-hand in assignments like `Place = Constant(c)`.
/// To enable the propagtion of points-to info for `Constant`,
/// we introduce `ConstantDeref` to denote the points-to node of `Constant`,
/// namely, forall Constant(c), Constant(c)--|address|-->ConstantDeref(c).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintNode<'tcx> {
    Alloc(PlaceRef<'tcx>),
    Place(PlaceRef<'tcx>),
    Constant(ConstantKind<'tcx>),
    ConstantDeref(ConstantKind<'tcx>),
    Construct(PlaceRef<'tcx>),
    FunctionRet(PlaceRef<'tcx>),
    ParameterInto(PlaceRef<'tcx>),
    SmartPointer(PlaceRef<'tcx>),
}

impl<'tcx> ConstraintNode<'tcx> {
    // pub fn place(&self) -> Option<&PlaceRef<'tcx>> {
    //     match self {
    //         ConstraintNode::Alloc(place) 
    //         | ConstraintNode::Place(place) 
    //         | ConstraintNode::Construct(place) 
    //         | ConstraintNode::FunctionRet(place) 
    //         | ConstraintNode::ParameterInto(place) 
    //         | ConstraintNode::SmartPointer(place) => Some(place),

    //         ConstraintNode::Constant(_)
    //         | ConstraintNode::ConstantDeref(_) => None,
    //     }
    // }
}

/// The assignments in MIR with default `mir-opt-level` (level 1) are simplified
/// to the following four kinds:
///
/// | Edge   | Assignment | Constraint |
/// | ------ | ---------- | ----------
/// | Address| a = &b     | pts(a)∋b
/// | Copy   | a = b      | pts(a)⊇pts(b)
/// | Load   | a = *b     | ∀o∈pts(b), pts(a)⊇pts(o)
/// | Store  | *a = b     | ∀o∈pts(a), pts(o)⊇pts(b)
///
/// Note that other forms like a = &((*b).0) exists but is uncommon.
/// This is the case when b is an arg. I just treat (*b).0
/// as the mem cell and do not further dereference it.
/// I also introduce `AliasCopy` edge to represent x->y
/// for y=Arc::clone(x) and y=ptr::read(x),
/// where x--|copy|-->pointers of y
/// and x--|load|-->y (y=*x)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConstraintEdge {
    Address,
    Copy,
    Load,
    Store,
    AliasCopy, // Special: y=Arc::clone(x) or y=ptr::read(x)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)] // , Copy, PartialEq, Eq
enum AccessPattern<'tcx> {
    Ref(PlaceRef<'tcx>),
    Indirect(PlaceRef<'tcx>),
    Direct(PlaceRef<'tcx>),
    Constant(ConstantKind<'tcx>),
    Initialize(PlaceRef<'tcx>), // imp::Waiter { thread: move _7, signaled: move _10, next: move _11 } 默认第一个参数和lvalue成为这种关系
}

#[derive(Default)]
struct ConstraintGraph<'tcx> {
    graph: Graph<ConstraintNode<'tcx>, ConstraintEdge, Directed>,
    node_map: FxHashMap<ConstraintNode<'tcx>, NodeIndex>,
}

impl<'tcx> ConstraintGraph<'tcx> {
    fn get_or_insert_node(&mut self, node: ConstraintNode<'tcx>) -> NodeIndex {
        if let Some(idx) = self.node_map.get(&node) {
            *idx
        } else {
            let idx = self.graph.add_node(node);
            self.node_map.insert(node, idx);
            idx
        }
    }

    fn get_node(&self, node: &ConstraintNode<'tcx>) -> Option<NodeIndex> {
        self.node_map.get(node).copied()
    }

    fn add_alloc(&mut self, place: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(place);
        let rhs = ConstraintNode::Alloc(place);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
    }

    fn add_constant(&mut self, constant: ConstantKind<'tcx>) {
        let lhs = ConstraintNode::Constant(constant);
        let rhs = ConstraintNode::ConstantDeref(constant);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
        // For a constant C, there may be deref like *C, **C, ***C, ... in a real program.
        // For simplicity, we only track *C, and treat **C, ***C, ... the same as *C.
        self.graph.add_edge(rhs, rhs, ConstraintEdge::Address);
    }

    fn add_address(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Place(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
    }

    fn add_copy(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Place(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);

        self.graph.add_edge(rhs, lhs, ConstraintEdge::Copy);
    }  

    fn add_func_ret(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::FunctionRet(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
    }

    fn add_smart_pointer(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lnode = ConstraintNode::Place(lhs);
        let rnode = ConstraintNode::SmartPointer(rhs);
        let lhs = self.get_or_insert_node(lnode);
        let rhs = self.get_or_insert_node(rnode);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
    }

    fn add_parameter_into(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lnode = ConstraintNode::Place(lhs);
        let rnode = ConstraintNode::ParameterInto(rhs);
        let lhs = self.get_or_insert_node(lnode);
        let rhs = self.get_or_insert_node(rnode);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
    }

    fn add_initialize_copy(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Construct(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        // It is heuristic to think that a struct is created and then the created address is given to lvaue
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
    }

    fn add_copy_constant(&mut self, lhs: PlaceRef<'tcx>, rhs: ConstantKind<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Constant(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Copy);
    }

    fn add_load(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Place(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Load);
    }

    fn add_store(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Place(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Store);
    }

    fn add_initialize_store(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Construct(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        // It is heuristic to think that a struct is created and then the created address is given to lvaue
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Address);
    }

    fn add_store_constant(&mut self, lhs: PlaceRef<'tcx>, rhs: ConstantKind<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Constant(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::Store);
    }

    fn add_alias_copy(&mut self, lhs: PlaceRef<'tcx>, rhs: PlaceRef<'tcx>) {
        let lhs = ConstraintNode::Place(lhs);
        let rhs = ConstraintNode::Place(rhs);
        let lhs = self.get_or_insert_node(lhs);
        let rhs = self.get_or_insert_node(rhs);
        self.graph.add_edge(rhs, lhs, ConstraintEdge::AliasCopy);
    }

    fn nodes(&self) -> Vec<ConstraintNode<'tcx>> {
        self.node_map.keys().copied().collect::<_>()
    }

    fn edges(&self) -> Vec<(ConstraintNode<'tcx>, ConstraintNode<'tcx>, ConstraintEdge)> {
        let mut v = Vec::new();
        for edge in self.graph.edge_references() {
            let source = self.graph.node_weight(edge.source()).copied().unwrap();
            let target = self.graph.node_weight(edge.target()).copied().unwrap();
            let weight = *edge.weight();
            v.push((source, target, weight));
        }
        v
    }

    /// *lhs = ?
    /// ?--|store|-->lhs
    fn store_sources(&self, lhs: &ConstraintNode<'tcx>) -> Vec<ConstraintNode<'tcx>> {
        let lhs1 = self.get_node(lhs).unwrap();
        let mut sources = Vec::new();
        for edge in self.graph.edges_directed(lhs1, Direction::Incoming) {
            if *edge.weight() == ConstraintEdge::Store {
                let source = self.graph.node_weight(edge.source()).copied().unwrap();
                sources.push(source);
            }
        }
        sources
    }

    /// ? = *rhs
    /// rhs--|load|-->?
    fn load_targets(&self, rhs: &ConstraintNode<'tcx>) -> Vec<ConstraintNode<'tcx>> {
        let rhs = self.get_node(rhs).unwrap();
        let mut targets = Vec::new();
        for edge in self.graph.edges_directed(rhs, Direction::Outgoing) {
            if *edge.weight() == ConstraintEdge::Load {
                let target = self.graph.node_weight(edge.target()).copied().unwrap();
                targets.push(target);
            }
        }
        targets
    }

    /// ? = rhs
    /// rhs--|copy|-->?
    fn copy_targets(&self, rhs: &ConstraintNode<'tcx>) -> Vec<ConstraintNode<'tcx>> {
        let rhs = self.get_node(rhs).unwrap();
        let mut targets = Vec::new();
        for edge in self.graph.edges_directed(rhs, Direction::Outgoing) {
            if *edge.weight() == ConstraintEdge::Copy {
                let target = self.graph.node_weight(edge.target()).copied().unwrap();
                match target{
                    ConstraintNode::Alloc(_) => {
                        let rhs_target = self.get_node(&target).unwrap();
                        for edge1 in self.graph.edges_directed(rhs_target, Direction::Outgoing) {
                            if *edge1.weight() == ConstraintEdge::Address {
                                let target1 = self.graph.node_weight(edge1.target()).copied().unwrap();
                                targets.push(target1);
                                break;
                            }
                        }
                    },
                    _ => {
                        targets.push(target);
                    }
                }
            }
        }
        targets
    }

    /// X = Arc::clone(rhs) or X = ptr::read(rhs)
    /// ? = &X
    ///
    /// rhs--|alias_copy|-->X,
    /// X--|address|-->?
    fn alias_copy_targets(&self, rhs: &ConstraintNode<'tcx>) -> Vec<ConstraintNode<'tcx>> {
        let rhs = self.get_node(rhs).unwrap();
        self.graph
            .edges_directed(rhs, Direction::Outgoing)
            .filter_map(|edge| {
                if *edge.weight() == ConstraintEdge::AliasCopy {
                    Some(edge.target())
                } else {
                    None
                }
            })
            .fold(Vec::new(), |mut acc, copy_alias_target| {
                let address_targets = self
                    .graph
                    .edges_directed(copy_alias_target, Direction::Outgoing)
                    .filter_map(|edge| {
                        if *edge.weight() == ConstraintEdge::Address {
                            Some(self.graph.node_weight(edge.target()).copied().unwrap())
                        } else {
                            None
                        }
                    });
                acc.extend(address_targets);
                acc
            })
    }

    /// if edge `from--|weight|-->to` not exists,
    /// then add the edge and return true
    fn insert_edge(
        &mut self,
        from: ConstraintNode<'tcx>,
        to: ConstraintNode<'tcx>,
        weight: ConstraintEdge,
    ) -> bool {
        let from = self.get_node(&from).unwrap();
        let to = self.get_node(&to).unwrap();
        if let Some(edge) = self.graph.find_edge(from, to) {
            if let Some(w) = self.graph.edge_weight(edge) {
                if *w == weight {
                    return false;
                }
            }
        }
        self.graph.add_edge(from, to, weight);
        true
    }

    /// Print the callgraph in dot format.
    #[allow(dead_code)]
    pub fn dot(&self) {
        println!(
            "{:?}",
            Dot::with_config(&self.graph, &[Config::GraphContentOnly])
        );
    }
}

/// Generate `ConstraintGraph` by visiting MIR body.
struct ConstraintGraphCollector<'a, 'tcx> {
    body: &'a Body<'tcx>,
    tcx: TyCtxt<'tcx>,
    graph: ConstraintGraph<'tcx>,
}

impl<'a, 'tcx> ConstraintGraphCollector<'a, 'tcx> {
    fn new(body: &'a Body<'tcx>, tcx: TyCtxt<'tcx>) -> Self {
        Self {
            body,
            tcx,
            graph: ConstraintGraph::default(),
        }
    }

    fn process_assignment(&mut self, place: &Place<'tcx>, rvalue: &Rvalue<'tcx>) {
        let lhs_pattern = Self::process_place(place.as_ref());
        let rhs_pattern = Self::process_rvalue(rvalue);
        
        match (lhs_pattern, rhs_pattern) {
            // a = &b 
            (AccessPattern::Direct(lhs), Some(AccessPattern::Ref(rhs))) => {
                // a = &*b <==> a = b && b = *b
                match rhs.clone() {
                    PlaceRef {
                        local: l,
                        projection: [ProjectionElem::Deref, ref remain @ ..],
                    } => {
                        let deref = PlaceRef {
                                local: l,
                                projection: &[ProjectionElem::Deref],
                            };
                        let place = PlaceRef {
                                local: l,
                                projection: remain,
                            };
                        self.graph.add_load(place, deref);
                        self.graph.add_copy(lhs, place);
                    },
                    _ => {
                        self.graph.add_address(lhs, rhs);
                    },
                }
                
            }
            // a = b
            (AccessPattern::Direct(lhs), Some(AccessPattern::Direct(rhs))) => {
                self.graph.add_copy(lhs, rhs);
            }
            // a = Constant
            (AccessPattern::Direct(lhs), Some(AccessPattern::Constant(rhs))) => {
                self.graph.add_copy_constant(lhs, rhs);
            }
            // a = *b
            (AccessPattern::Direct(lhs), Some(AccessPattern::Indirect(rhs))) => {
                self.graph.add_load(lhs, rhs);
            }
            // *a = b
            (AccessPattern::Indirect(lhs), Some(AccessPattern::Direct(rhs))) => {
                self.graph.add_store(lhs, rhs);
            }
            // *a = Constant
            (AccessPattern::Indirect(lhs), Some(AccessPattern::Constant(rhs))) => {
                self.graph.add_store_constant(lhs, rhs);
            }
            // a = imp::Waiter { thread: move _7, signaled: move _10, next: move _11 } TODO WangC
            (AccessPattern::Direct(lhs), Some(AccessPattern::Initialize(rhs))) => {
                self.graph.add_initialize_copy(lhs, rhs);
            }
            // *a = imp::Waiter { thread: move _7, signaled: move _10, next: move _11 }
            (AccessPattern::Indirect(lhs), Some(AccessPattern::Initialize(rhs))) => {
                self.graph.add_initialize_store(lhs, rhs);
            }
            _ => {}
        }
    }

    fn process_place(place_ref: PlaceRef<'tcx>) -> AccessPattern<'tcx> { 
        match place_ref {
            PlaceRef {
                local: l,
                projection: [ProjectionElem::Deref, ref remain @ ..],
            } => AccessPattern::Indirect(PlaceRef {
                local: l,
                projection: remain,
            }),
            _ => AccessPattern::Direct(place_ref),
        }
    }

    fn process_rvalue(rvalue: &Rvalue<'tcx>) -> Option<AccessPattern<'tcx>> {
        match rvalue {
            Rvalue::Use(operand) | Rvalue::Repeat(operand, _) | Rvalue::Cast(_, operand, _) => {
                match operand {
                    Operand::Move(place) | Operand::Copy(place) => {
                        if let [ProjectionElem::Deref, _] = place.as_ref().projection {
                            Some(AccessPattern::Indirect(place.as_ref()))
                        } else {
                            Some(AccessPattern::Direct(place.as_ref()))
                        }
                        
                    }
                    Operand::Constant(box Constant {
                        span: _,
                        user_ty: _,
                        literal,
                    }) => {
                        Some(AccessPattern::Constant(*literal))
                    },
                }
            },
            Rvalue::Ref(_, _, place) | Rvalue::AddressOf(_, place) |  Rvalue::CopyForDeref(place) => {
                Some(AccessPattern::Ref(place.as_ref()))
            }
            Rvalue::Aggregate(_, operand) => {
                if operand.len() != 0 {
                    match operand[0] {
                        Operand::Move(place) | Operand::Copy(place) => {
                            Some(AccessPattern::Initialize(place.as_ref()))
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }, 
            _ => None,
        }
    }

    /// dest: *const T = Vec::as_ptr(arg: &Vec<T>) =>
    /// arg--|copy|-->dest
    fn process_call_arg_dest(&mut self, arg: PlaceRef<'tcx>, dest: PlaceRef<'tcx>) {
        self.graph.add_copy(dest, arg);
    }

    /// For complex function calls, this is just a marker, indicating that the local is returned from a complex function marker
    /// arg[0]--|FunctionRet|-->dest
    fn process_complix_func_ret(&mut self, arg: PlaceRef<'tcx>, dest: PlaceRef<'tcx>) {
        self.graph.add_func_ret(dest, arg);
        // mark the variable as a function's argument.
        self.graph.add_parameter_into(arg, dest);
    }

    /// Box, Arc, and Rc transform raw pointers into their respective smart pointer types. Given that these smart pointers 
    /// inherently implement the Deref trait, it logically follows that they enable the dereferencing of pointers.
    fn process_smart_pointer(&mut self, arg: PlaceRef<'tcx>, dest: PlaceRef<'tcx>) {
        self.graph.add_smart_pointer(arg, dest);
    }

    /// dest: Arc<T> = Arc::clone(arg: &Arc<T>) or dest: T = ptr::read(arg: *const T) =>
    /// arg--|load|-->dest and
    /// arg--|alias_copy|-->dest
    fn process_alias_copy(&mut self, arg: PlaceRef<'tcx>, dest: PlaceRef<'tcx>) {
        // TODOWC
        self.graph.add_copy(dest, arg);
        self.graph.add_alias_copy(dest, arg);
    }

    /// forall (p1, p2) where p1 is prefix of p2, add `p1 = p2`.
    /// e.g. Place1{local1, &[f0]}, Place2{local1, &[f0,f1]},
    /// since they have the same local
    /// and Place1.projection is prefix of Place2.projection,
    /// Add constraint `Place1 = Place2`.
    fn add_partial_copy(&mut self) {
        let nodes = self.graph.nodes();
        for (idx, n1) in nodes.iter().enumerate() {
            for n2 in nodes.iter().skip(idx + 1) {
                if let (ConstraintNode::Place(p1), ConstraintNode::Place(p2)) = (n1, n2) {
                    if p1.local == p2.local {
                        if p1.projection.len() > p2.projection.len() {
                            if &p1.projection[..p2.projection.len()] == p2.projection {
                                self.graph.add_copy(*p2, *p1);
                            }
                        } else if &p2.projection[..p1.projection.len()] == p1.projection {
                            self.graph.add_copy(*p1, *p2);
                        }
                    }
                }
            }
        }
    }

    fn finish(mut self) -> ConstraintGraph<'tcx> {
        self.add_partial_copy();
        self.graph
    }
}

impl<'a, 'tcx> Visitor<'tcx> for ConstraintGraphCollector<'a, 'tcx> {
    fn visit_statement(&mut self, statement: &Statement<'tcx>, _location: Location) {

        match &statement.kind{
            StatementKind::Assign(box (place, rvalue)) => {
                self.process_assignment(place, rvalue);
            },
            _ => {},
        }
    }

    /// For destination = Arc::clone(move arg0) and destination = ptr::read(move arg0),
    /// destination = alias copy args0
    /// For other callsites like `destination = call fn(move args0)`,
    /// heuristically assumes that
    /// destination = copy args0
    /// For many complex function calls like `destination = call fn(move args0, move args1, move args2, move args3 ...)`
    /// TODO
    fn visit_terminator(&mut self, terminator: &Terminator<'tcx>, _location: Location) {
        if let TerminatorKind::Call {
            func,
            args,
            destination,
            ..
        } = &terminator.kind
        {   
            let func_ty = func.ty(self.body, self.tcx);
            if let (&[Operand::Move(arg)] | &[Operand::Copy(arg)], dest) = (args.as_slice(), destination) {
                match func_ty.kind() {
                    TyKind::FnDef(def_id, substs)
                        if ownership::is_arc_or_rc_clone(*def_id, *substs, self.tcx)
                            || ownership::is_ptr_operate(*def_id, self.tcx) 
                            || ownership::is_addr(*def_id, self.tcx) => {
                        return self.process_alias_copy(arg.as_ref(), dest.as_ref());
                    }
                    _ => {}
                }
                // self.process_complix_func_ret(arg.as_ref(), destination.as_ref());
                self.process_call_arg_dest(arg.as_ref(), dest.as_ref());
            };

            // Handle atomic and is_map_addr operations separately, and mark other functions as complex function calls
            match func_ty.kind() {
                TyKind::FnDef(def_id, substs) => {
                    if ownership::is_get_unchecked(*def_id, self.tcx) 
                    || ownership::is_atomic_operate(*def_id, self.tcx) 
                    || ownership::is_addr(*def_id, self.tcx) 
                    || ownership::is_ptr_operate(*def_id, self.tcx) {
                        
                        let arg = args.get(0).unwrap().place().unwrap();
                        self.process_call_arg_dest(arg.as_ref(), destination.as_ref());
                    } else if ownership::is_smart_pointers(*def_id, self.tcx)  {
                        if let Operand::Move(place) | Operand::Copy(place) = args[0] {
                            self.process_smart_pointer(place.as_ref(), destination.as_ref());
                        }
                    } else if !ownership::is_arc_or_rc_clone(*def_id, *substs, self.tcx) 
                        && !ownership::is_null(*def_id, self.tcx) 
                        && args.len() > 0 {  
                        // Ignore function calls that don't have arguments
                        for arg in args {
                            if let Operand::Move(place) | Operand::Copy(place) = arg {
                                self.process_complix_func_ret(place.as_ref(), destination.as_ref());
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

// / We do not use Must/May/Not since the pointer analysis implementation is overapproximate.
// / Instead, we use probably, possibly, unlikely as alias kinds.
// / We will report bugs of probaly and possibly kinds.
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum ApproximateAliasKind {
//     Probably,
//     Possibly,
//     Unlikely,
//     Unknown,
// }

// /// Probably > Possibly > Unlikey > Unknown
// impl PartialOrd for ApproximateAliasKind {
//     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
//         use ApproximateAliasKind::*;
//         match (*self, *other) {
//             (Probably, Probably)
//             | (Possibly, Possibly)
//             | (Unlikely, Unlikely)
//             | (Unknown, Unknown) => Some(Ordering::Equal),
//             (Probably, _) | (Possibly, Unlikely) | (Possibly, Unknown) | (Unlikely, Unknown) => {
//                 Some(Ordering::Greater)
//             }
//             (_, Probably) | (Unlikely, Possibly) | (Unknown, Possibly) | (Unknown, Unlikely) => {
//                 Some(Ordering::Less)
//             }
//         }
//     }
// }

/// `AliasId` identifies a unique memory cell interprocedurally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AliasId {
    pub instance_id: InstanceId,
    pub local: Local,
}


/// Alias analysis based on points-to info.
/// It answers if two memory cells alias with each other.
/// It performs an underlying points-to analysis if needed.
/// The points-to info will be cached into `pts` for future queries.
pub struct AliasAnalysis<'tcx> {
    tcx: TyCtxt<'tcx>,
    pts: FxHashMap<DefId, PointsToMap<'tcx>>,
}

impl<'tcx> AliasAnalysis<'tcx> {
    pub fn new(tcx: TyCtxt<'tcx>) -> Self {
        Self {
            tcx,
            pts: Default::default(),
        }
    }


    pub fn load_corrlation(&mut self, body: &Body<'tcx>, load_interimval: &HashSet<PlaceRef<'tcx>>) -> bool {
        let mut collector = ConstraintGraphCollector::new(body, self.tcx);
        collector.visit_body(body);
        let graph = collector.finish();
        let edges = graph.graph.clone().into_nodes_edges().1;
        
        for local in load_interimval {
            for edge in edges.clone() {
                let source = graph.graph.node_weight(edge.source()).unwrap();
                if let ConstraintNode::Alloc(place) | ConstraintNode::Place(place) = source {
                    if place.local == local.local && edge.weight == ConstraintEdge::Load {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// Get the points-to info from cache `pts`.
    /// If not exists, then perform points-to analysis
    /// and add the obtained points-to info to cache.
    pub fn get_or_insert_pts(&mut self, def_id: DefId, body: &Body<'tcx>) -> PointsToMap<'tcx> {
        if self.pts.contains_key(&def_id) {
            self.pts.get(&def_id).unwrap().clone()
        } else {
            let mut pointer_analysis = Andersen::new(body, self.tcx);
            
            pointer_analysis.analyze();
            let pts = pointer_analysis.finish();
            self.pts.entry(def_id).or_insert(pts.clone()).clone()
        }
    }

    // pub fn is_atomic_in_adt(
    //     &mut self,
    //     node: ConstraintNode<'tcx>,
    //     body: &'tcx Body<'tcx>,
    //     points_to_map: & PointsToMap<'tcx>,
    // ) -> bool {
    //     let pts = points_to_map.get(&node).unwrap();
    //     for pointee in pts {
    //         match pointee {
    //             ConstraintNode::Alloc(place1) | ConstraintNode::Place(place1)
    //                 if !place1.projection.is_empty() => 
    //                 {
    //                     match body.local_decls[place1.local].ty.kind() {
    //                         ty::TyKind::Adt(_, _) => {
    //                             return true;
    //                         },
    //                         ty::TyKind::Array(var_ty, _) |
    //                         ty::TyKind::Slice(var_ty) |
    //                         ty::TyKind::Ref(_, var_ty, _) => {
    //                             if let ty::TyKind::Adt(_, _) = var_ty.kind() {
    //                                 return true;
    //                             }
    //                         },
    //                         ty::TyKind::RawPtr(var_ty) => {
    //                             if let ty::TyKind::Adt(_, _) = var_ty.ty.kind() {
    //                                 return true;
    //                             }
    //                         },
    //                         _ => {},
    //                     }
    //                 },
    //             _ => {}
    //         }
    //     }
    //     return false;
    // }


    // pub fn get_fields_of_struct(
    //     &mut self,
    //     node: ConstraintNode<'tcx>,
    //     body: &'tcx Body<'tcx>,
    //     points_to_map: &PointsToMap<'tcx>,
    // ) -> Option<HashSet<ConstraintNode<'tcx>>> {
    //     let mut fields = HashSet::default();
    //     let pts = points_to_map.get(&node)?;
    //     for pointee in pts {
    //         if let ConstraintNode::Alloc(place) | ConstraintNode::Place(place) = pointee {
    //             if place.projection.is_empty() {
    //                 continue;
    //             }
                
    //             let ty = &body.local_decls[place.local].ty;
    //             if is_adt_or_contains_adt(ty) {
    //                 Self::collect_fields(place, points_to_map, &mut fields);
    //             }
    //         }
    //     }
    
    //     Some(fields)
    // }
    
    
    
    // fn collect_fields(
    //     place1: &PlaceRef<'tcx>,
    //     points_to_map: &PointsToMap<'tcx>,
    //     fields: &mut HashSet<ConstraintNode<'tcx>>,
    // ) {
    //     for node in points_to_map.keys() {
    //         if let ConstraintNode::Alloc(place2) | ConstraintNode::Place(place2) = node {
    //             if place2.local == place1.local && place1.projection != place2.projection && !place2.projection.is_empty() {
    //                 fields.insert(*node);
    //             }
    //         }
    //     }
    // }

    // pub fn get_var_struct_fields(
    //     &mut self,
    //     node: ConstraintNode<'tcx>,
    //     body: &'tcx Body<'tcx>,
    //     points_to_map: & PointsToMap<'tcx>,
    // ) -> Option<FxHashSet<ConstraintNode<'tcx>>> { 
    //     let mut fields = FxHashSet::default();
    //     let pts = points_to_map.get(&node)?;
    //     for pointee in pts {
    //         match pointee {
    //             ConstraintNode::Alloc(place1) | ConstraintNode::Place(place1)
    //                 if !place1.projection.is_empty() => 
    //                 {
    //                     let node_parents = ConstraintNode::Place(Place::from(place1.local).as_ref());
    //                     match body.local_decls[place1.local].ty.kind() {
    //                         ty::TyKind::Adt(adt_def, SubstsRef) => {
    //                             let point_parents = points_to_map.get(&node_parents)?;
    //                             for point_parent in point_parents {
    //                                 match point_parent {
    //                                     ConstraintNode::Alloc(place2) | ConstraintNode::Place(place2)
    //                                         if (place2.local == place1.local) & (place2.projection != place1.projection) => {
    //                                             fields.insert(*point_parent);
    //                                         }
    //                                     _ => {}
    //                                 }
    //                             }
    //                         },
    //                         ty::TyKind::Array(var_ty, _) |
    //                         ty::TyKind::Slice(var_ty) |
    //                         ty::TyKind::Ref(_, var_ty, _) => {
    //                             if let ty::TyKind::Adt(adt_def, SubstsRef) = var_ty.kind() {
    //                                 let point_parents = points_to_map.get(&node_parents)?;
    //                                 for point_parent in point_parents {
    //                                     match point_parent {
    //                                         ConstraintNode::Alloc(place2) | ConstraintNode::Place(place2)
    //                                             if (place2.local == place1.local) & (place2.projection != place1.projection) => {
    //                                                 fields.insert(*point_parent);
    //                                             }
    //                                         _ => {}
    //                                     }
    //                                 }
    //                             }
    //                         },
    //                         ty::TyKind::RawPtr(var_ty) => {
    //                             if let ty::TyKind::Adt(adt_def, SubstsRef) = var_ty.ty.kind() {
    //                                 let point_parents = points_to_map.get(&node_parents)?;
    //                                 for point_parent in point_parents {
    //                                     match point_parent {
    //                                         ConstraintNode::Alloc(place2) | ConstraintNode::Place(place2)
    //                                             if (place2.local == place1.local) & (place2.projection != place1.projection) => {
    //                                                 // fields.insert(place2.projection);
    //                                                 fields.insert(*point_parent);
    //                                             }
    //                                         _ => {}
    //                                     }
    //                                 }
    //                             }
    //                         },
    //                         _ => {},
    //                     }
    //                 },
    //             _ => {}
    //         }
    //     }
    //     // return Some((fields, struct_node));
    //     return Some(fields);
    // }

}
