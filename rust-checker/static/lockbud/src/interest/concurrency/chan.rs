//! Denotes chan APIs in std (crossbeam).
//!
//! 1. create mpsc: std::sync::mpsc::channel::<T>() -> (std::sync::mpsc::Sender<T>, std::sync::mpsc::Receiver<T>)
//! 2. send to mpsc: std::sync::mpsc::Sender::<T>::send(move &std::sync::mpsc::Sender<T>, T) -> std::result::Result<(), std::sync::mpmc::SendError<i32>>;
//! 3. recv from mpsc: std::sync::mpsc::Receiver::<T>::recv(&std::sync::mpsc::Receiver<T>) -> std::result::Result<(), std::sync::mpmc::SendError<i32>>;
extern crate rustc_hash;
extern crate rustc_middle;

use rustc_middle::ty::{Instance, TyCtxt};
use rustc_hash::{FxHashMap, FxHashSet};

#[derive(Clone, Copy, Debug)]
pub enum ChanApi {
    Std(StdMpscChanApi),
}

#[derive(Clone, Copy, Debug)]
pub enum StdMpscChanApi {
    Create,
    Send,
    Recv,
}

impl ChanApi {
    pub fn from_instance<'tcx>(instance: &Instance<'tcx>, tcx: TyCtxt<'tcx>) -> Option<Self> {
        let path = tcx.def_path_str_with_args(instance.def_id(), instance.args);
        let std_mpsc_chan = "std::sync::mpsc::";
        if path.starts_with(std_mpsc_chan) {
            let tail = &path.as_bytes()[std_mpsc_chan.len()..];
            let std_mpsc_chan_api = if tail.starts_with("channel::".as_bytes()) {
                Some(ChanApi::Std(StdMpscChanApi::Create))
            } else if tail.starts_with("Sender::".as_bytes()) && tail.ends_with("send".as_bytes()) {
                Some(ChanApi::Std(StdMpscChanApi::Send))
            } else if tail.starts_with("Receiver::".as_bytes()) && tail.ends_with("recv".as_bytes()) {
                Some(ChanApi::Std(StdMpscChanApi::Recv))
            } else {
                None
            };
            std_mpsc_chan_api
        } else {
            None
        }
    }
}