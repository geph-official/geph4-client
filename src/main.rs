use geph4client::{
    dispatch,
    // ios::{call_geph, check_bridges, get_logs},
    Opt,
};
// use rand::AsByteSliceMut;
// use std::{ffi::CString, time::Duration};
use structopt::StructOpt;


fn main() -> anyhow::Result<()> {
    std::env::set_var("GEPH_RECURSIVE", "1"); // no forking in iOS
    let args = Opt::from_args();
    dispatch(args)
}
 