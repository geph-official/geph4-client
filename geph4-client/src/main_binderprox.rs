use std::net::SocketAddr;

use structopt::StructOpt;

use crate::CommonOpt;

#[derive(Debug, StructOpt)]
pub struct BinderProxOpt {
    #[structopt(flatten)]
    common: CommonOpt,

    /// Where to listen for HTTP requests
    #[structopt(long)]
    listen: SocketAddr,
}

pub async fn main_binderprox(opt: BinderProxOpt) -> anyhow::Result<()> {
    unimplemented!()
}
