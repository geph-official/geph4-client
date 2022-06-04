use geph4client::{dispatch, Opt};
use structopt::StructOpt;

fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::from_args();
    dispatch(opt)
}
 